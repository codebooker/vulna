"""Read-only Microsoft Azure virtual-machine inventory through Resource Graph."""

from __future__ import annotations

import re
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, cast

from app.models.passive_inventory import InventoryConnector
from app.services.passive_inventory import InventoryConnectorError, NormalizedObservation
from app.services.ticket_adapters.http import JsonResponse, TicketHttpError, request_json

SendJson = Callable[..., Awaitable[JsonResponse]]


@dataclass(frozen=True)
class _Cloud:
    authority_host: str
    resource_manager_host: str
    scope: str


@dataclass(frozen=True)
class _ResourceQuery:
    label: str
    table: str
    resource_type: str
    source_kind: str

    @property
    def query(self) -> str:
        return (
            f"{self.table}\n"
            f"| where type =~ '{self.resource_type}'\n"
            "| project id=tostring(id), name=tostring(name), "
            "subscriptionId=tostring(subscriptionId), "
            "resourceGroup=tostring(resourceGroup), location=tostring(location), "
            "vmId=tostring(properties.vmId), "
            "computerName=tostring(properties.osProfile.computerName), "
            "osType=tostring(properties.storageProfile.osDisk.osType), "
            "vmSize=tostring(properties.hardwareProfile.vmSize), "
            "provisioningState=tostring(properties.provisioningState), "
            "powerState=tostring(properties.extended.instanceView.powerState.code)\n"
            "| order by id asc"
        )


_CLOUDS = {
    "global": _Cloud(
        "login.microsoftonline.com",
        "management.azure.com",
        "https://management.azure.com/.default",
    ),
    "us_government": _Cloud(
        "login.microsoftonline.us",
        "management.usgovcloudapi.net",
        "https://management.usgovcloudapi.net/.default",
    ),
    "china": _Cloud(
        "login.chinacloudapi.cn",
        "management.chinacloudapi.cn",
        "https://management.chinacloudapi.cn/.default",
    ),
}
_VIRTUAL_MACHINES = _ResourceQuery(
    "virtual machines",
    "Resources",
    "microsoft.compute/virtualmachines",
    "vm",
)
_SCALE_SET_VIRTUAL_MACHINES = _ResourceQuery(
    "scale set virtual machines",
    "ComputeResources",
    "microsoft.compute/virtualmachinescalesets/virtualmachines",
    "vmss-vm",
)
_ALLOWED_CONFIG_FIELDS = frozenset(
    {
        "tenant_id",
        "client_id",
        "subscription_ids",
        "cloud",
        "include_scale_set_instances",
        "timeout_seconds",
        "page_size",
        "record_limit",
    }
)
_HOST_LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
_MAX_SUBSCRIPTIONS = 50
_MAX_PAGE_SIZE = 1_000
_MAX_RECORDS = 10_000
_MAX_PAGES = 1_000


class AzureInventoryAdapter:
    """Collect VM projections without accepting arbitrary ARM queries or endpoints."""

    def __init__(self, sender: SendJson = request_json) -> None:
        self._sender = sender

    async def test(
        self,
        connector: InventoryConnector,
        secret: str | None,
        *,
        source_data: bytes | None,
    ) -> dict[str, Any]:
        del source_data
        observations, received, subscriptions, cloud_name, resources = await self._read(
            connector, secret, cursor={}
        )
        return {
            "records_received": received,
            "records_visible": len(observations),
            "subscriptions": len(subscriptions),
            "cloud": cloud_name,
            "resources": resources,
            "permission": "Microsoft.ResourceGraph/resources/read",
            "read_only": True,
        }

    async def collect(
        self,
        connector: InventoryConnector,
        secret: str | None,
        *,
        cursor: dict[str, Any],
        source_data: bytes | None,
    ) -> tuple[list[NormalizedObservation], dict[str, Any]]:
        del source_data
        observations, _, _, _, _ = await self._read(connector, secret, cursor=cursor)
        return observations, {}

    async def _read(
        self,
        connector: InventoryConnector,
        secret: str | None,
        *,
        cursor: dict[str, Any],
    ) -> tuple[list[NormalizedObservation], int, list[str], str, list[str]]:
        if not isinstance(cursor, dict) or cursor:
            raise InventoryConnectorError("Azure connector cursor must be empty")
        if connector.base_url:
            raise InventoryConnectorError("Azure connector does not accept a base URL")
        config = connector.config_json
        if not isinstance(config, dict) or set(config) - _ALLOWED_CONFIG_FIELDS:
            raise InventoryConnectorError("Azure connector config contains unknown fields")
        tenant_id = _uuid(config.get("tenant_id"), "tenant_id")
        client_id = _uuid(config.get("client_id"), "client_id")
        subscriptions = _uuid_list(config.get("subscription_ids"), "subscription_ids")
        cloud_name, cloud = _cloud(config.get("cloud", "global"))
        if not isinstance(secret, str) or not secret or len(secret) > 4_096:
            raise InventoryConnectorError("Azure client secret is required")
        include_scale_sets = _boolean(config, "include_scale_set_instances", default=True)
        timeout_seconds = _bounded_int(config.get("timeout_seconds", 15), "timeout_seconds", 1, 60)
        page_size = _bounded_int(config.get("page_size", 500), "page_size", 1, _MAX_PAGE_SIZE)
        record_limit = _bounded_int(
            config.get("record_limit", _MAX_RECORDS), "record_limit", 1, _MAX_RECORDS
        )
        token = await self._access_token(
            cloud,
            tenant_id=tenant_id,
            client_id=client_id,
            client_secret=secret,
            timeout_seconds=timeout_seconds,
        )
        query_specs = [_VIRTUAL_MACHINES]
        if include_scale_sets:
            query_specs.append(_SCALE_SET_VIRTUAL_MACHINES)
        records: list[tuple[dict[str, Any], _ResourceQuery, str]] = []
        pages = 0
        for subscription_id in subscriptions:
            for spec in query_specs:
                page, pages = await self._query_resources(
                    cloud,
                    token=token,
                    subscription_id=subscription_id,
                    spec=spec,
                    page_size=page_size,
                    record_limit=record_limit - len(records),
                    pages=pages,
                    timeout_seconds=timeout_seconds,
                )
                records.extend((item, spec, subscription_id) for item in page)
        observed_at = datetime.now(UTC)
        observations = [
            _observation(
                item,
                tenant_id=tenant_id,
                subscription_id=subscription_id,
                spec=spec,
                observed_at=observed_at,
            )
            for item, spec, subscription_id in records
        ]
        source_ids = [item.source_record_id for item in observations]
        if len(source_ids) != len(set(source_ids)):
            raise InventoryConnectorError("Azure Resource Graph returned duplicate VM IDs")
        return (
            observations,
            len(records),
            subscriptions,
            cloud_name,
            [spec.label for spec in query_specs],
        )

    async def _access_token(
        self,
        cloud: _Cloud,
        *,
        tenant_id: str,
        client_id: str,
        client_secret: str,
        timeout_seconds: int,
    ) -> str:
        try:
            response = await self._sender(
                "POST",
                f"https://{cloud.authority_host}/{tenant_id}/oauth2/v2.0/token",
                headers={"Accept": "application/json"},
                form_body={
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "grant_type": "client_credentials",
                    "scope": cloud.scope,
                },
                timeout_seconds=timeout_seconds,
                allow_private=False,
                user_agent="Vulna-Azure-Inventory/1",
            )
        except TicketHttpError as exc:
            raise InventoryConnectorError(_safe_provider_error(exc, "authentication")) from exc
        if not isinstance(response.data, dict):
            raise InventoryConnectorError("Azure authentication returned invalid JSON")
        token = response.data.get("access_token")
        token_type = response.data.get("token_type")
        if (
            not isinstance(token, str)
            or not token
            or len(token) > 32_768
            or not isinstance(token_type, str)
            or token_type.lower() != "bearer"
        ):
            raise InventoryConnectorError("Azure authentication response is invalid")
        return token

    async def _query_resources(
        self,
        cloud: _Cloud,
        *,
        token: str,
        subscription_id: str,
        spec: _ResourceQuery,
        page_size: int,
        record_limit: int,
        pages: int,
        timeout_seconds: int,
    ) -> tuple[list[dict[str, Any]], int]:
        url = (
            f"https://{cloud.resource_manager_host}/providers/"
            "Microsoft.ResourceGraph/resources?api-version=2024-04-01"
        )
        records: list[dict[str, Any]] = []
        skip_token: str | None = None
        seen_tokens: set[str] = set()
        while True:
            pages += 1
            if pages > _MAX_PAGES:
                raise InventoryConnectorError("Azure Resource Graph pagination exceeded its limit")
            options: dict[str, Any] = {
                "$top": page_size,
                "resultFormat": "objectArray",
            }
            if skip_token is not None:
                options["$skipToken"] = skip_token
            try:
                response = await self._sender(
                    "POST",
                    url,
                    headers={"Accept": "application/json", "Authorization": f"Bearer {token}"},
                    json_body={
                        "query": spec.query,
                        "subscriptions": [subscription_id],
                        "options": options,
                    },
                    timeout_seconds=timeout_seconds,
                    allow_private=False,
                    user_agent="Vulna-Azure-Inventory/1",
                )
            except TicketHttpError as exc:
                raise InventoryConnectorError(
                    _safe_provider_error(exc, f"{spec.label} read")
                ) from exc
            page, next_token, truncated = _resource_page(response.data, page_size=page_size)
            if len(records) + len(page) > record_limit:
                raise InventoryConnectorError("Azure Resource Graph read exceeded the record limit")
            records.extend(page)
            if next_token is None:
                if truncated:
                    raise InventoryConnectorError(
                        "Azure Resource Graph truncated results without a continuation token"
                    )
                break
            if next_token in seen_tokens:
                raise InventoryConnectorError(
                    "Azure Resource Graph pagination repeated a continuation token"
                )
            seen_tokens.add(next_token)
            skip_token = next_token
        return records, pages


def _resource_page(value: Any, *, page_size: int) -> tuple[list[dict[str, Any]], str | None, bool]:
    if not isinstance(value, dict) or not isinstance(value.get("data"), list):
        raise InventoryConnectorError("Azure Resource Graph response is invalid")
    raw_page = value["data"]
    count = value.get("count")
    if (
        len(raw_page) > page_size
        or not all(isinstance(item, dict) for item in raw_page)
        or isinstance(count, bool)
        or not isinstance(count, int)
        or count != len(raw_page)
    ):
        raise InventoryConnectorError("Azure Resource Graph page exceeded its requested size")
    token = value.get("$skipToken")
    if token is not None and (
        not isinstance(token, str)
        or not token
        or len(token) > 4_096
        or any(ord(character) < 32 for character in token)
    ):
        raise InventoryConnectorError("Azure Resource Graph continuation token is invalid")
    truncated_value = value.get("resultTruncated", False)
    if isinstance(truncated_value, bool):
        truncated = truncated_value
    elif isinstance(truncated_value, str) and truncated_value.lower() in {"true", "false"}:
        truncated = truncated_value.lower() == "true"
    else:
        raise InventoryConnectorError("Azure Resource Graph truncation state is invalid")
    return cast(list[dict[str, Any]], raw_page), token, truncated


def _observation(
    record: dict[str, Any],
    *,
    tenant_id: str,
    subscription_id: str,
    spec: _ResourceQuery,
    observed_at: datetime,
) -> NormalizedObservation:
    response_subscription = _uuid(record.get("subscriptionId"), "response subscriptionId")
    if response_subscription != subscription_id:
        raise InventoryConnectorError("Azure Resource Graph response crossed subscriptions")
    vm_id = _uuid(record.get("vmId"), "VM vmId")
    resource_id = _resource_id(record.get("id"), subscription_id=subscription_id, spec=spec)
    name = _required_text(record.get("name"), "VM name", maximum=256)
    computer_name = _optional_text(record.get("computerName"), "computerName", maximum=253)
    hostname = _hostname(computer_name)
    identifiers: list[dict[str, Any]] = [
        {
            "type": "cloud_instance_id",
            "value": f"azure:{tenant_id}:{subscription_id}:{vm_id}",
        }
    ]
    if hostname:
        identifiers.append({"type": "fqdn" if "." in hostname else "hostname", "value": hostname})
        identifiers.append({"type": "smb_name", "value": hostname.split(".", 1)[0]})
    attributes: dict[str, Any] = {
        "canonical_name": hostname or name,
        "asset_type": "virtual_machine",
        "manufacturer": "Microsoft",
        "azure_tenant_id": tenant_id,
        "azure_subscription_id": subscription_id,
        "azure_vm_id": vm_id,
        "azure_resource_id": resource_id,
        "azure_resource_kind": spec.source_kind,
        "azure_resource_group": _required_text(
            record.get("resourceGroup"), "resourceGroup", maximum=256
        ),
    }
    _copy_optional_text(
        record,
        attributes,
        {
            "location": "azure_location",
            "osType": "operating_system",
            "vmSize": "azure_vm_size",
            "provisioningState": "azure_provisioning_state",
            "powerState": "azure_power_state",
        },
    )
    return NormalizedObservation(
        source_record_id=f"azure:{spec.source_kind}:{subscription_id}:{vm_id}",
        observed_at=observed_at,
        identifiers=identifiers,
        attributes=attributes,
    )


def _resource_id(value: Any, *, subscription_id: str, spec: _ResourceQuery) -> str:
    result = _required_text(value, "resource id", maximum=2_048)
    lowered = result.lower()
    prefix = f"/subscriptions/{subscription_id}/resourcegroups/"
    expected = (
        "/providers/microsoft.compute/virtualmachines/"
        if spec is _VIRTUAL_MACHINES
        else "/providers/microsoft.compute/virtualmachinescalesets/"
    )
    if not lowered.startswith(prefix) or expected not in lowered or "//" in lowered:
        raise InventoryConnectorError("Azure Resource Graph resource id is invalid")
    if (
        spec is _SCALE_SET_VIRTUAL_MACHINES
        and "/virtualmachines/" not in lowered.split(expected, 1)[1]
    ):
        raise InventoryConnectorError("Azure Resource Graph scale set VM id is invalid")
    return result


def _copy_optional_text(
    source: dict[str, Any], target: dict[str, Any], mapping: dict[str, str]
) -> None:
    for source_name, target_name in mapping.items():
        value = _optional_text(source.get(source_name), source_name, maximum=512)
        if value:
            target[target_name] = value


def _hostname(value: str | None) -> str | None:
    if not value:
        return None
    candidate = value.rstrip(".").lower()
    if len(candidate) > 253:
        return None
    labels = candidate.split(".")
    if not labels or any(not _HOST_LABEL_RE.fullmatch(label) for label in labels):
        return None
    return candidate


def _required_text(value: Any, field: str, *, maximum: int) -> str:
    result = _optional_text(value, field, maximum=maximum)
    if result is None:
        raise InventoryConnectorError(f"Azure {field} is required")
    return result


def _optional_text(value: Any, field: str, *, maximum: int) -> str | None:
    if value in (None, ""):
        return None
    if not isinstance(value, str):
        raise InventoryConnectorError(f"Azure {field} must be a string or null")
    result = value.strip()
    if not result or len(result) > maximum or any(ord(character) < 32 for character in result):
        raise InventoryConnectorError(f"Azure {field} is invalid")
    return result


def _uuid(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise InventoryConnectorError(f"Azure {field} must be a UUID")
    try:
        return str(uuid.UUID(value.strip()))
    except (ValueError, AttributeError) as exc:
        raise InventoryConnectorError(f"Azure {field} must be a UUID") from exc


def _uuid_list(value: Any, field: str) -> list[str]:
    if not isinstance(value, list) or not value or len(value) > _MAX_SUBSCRIPTIONS:
        raise InventoryConnectorError(
            f"Azure {field} must contain 1-{_MAX_SUBSCRIPTIONS} subscription UUIDs"
        )
    result = [_uuid(item, "subscription ID") for item in value]
    if len(result) != len(set(result)):
        raise InventoryConnectorError("Azure subscription_ids must not contain duplicates")
    return result


def _cloud(value: Any) -> tuple[str, _Cloud]:
    if not isinstance(value, str) or value not in _CLOUDS:
        raise InventoryConnectorError("Azure cloud must be global, us_government, or china")
    return value, _CLOUDS[value]


def _bounded_int(value: Any, field: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool):
        raise InventoryConnectorError(f"Azure {field} must be an integer")
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise InventoryConnectorError(f"Azure {field} must be an integer") from exc
    if str(parsed) != str(value).strip() or not minimum <= parsed <= maximum:
        raise InventoryConnectorError(f"Azure {field} must be between {minimum} and {maximum}")
    return parsed


def _boolean(config: dict[str, Any], key: str, *, default: bool) -> bool:
    value = config.get(key, default)
    if not isinstance(value, bool):
        raise InventoryConnectorError(f"Azure {key} must be a boolean")
    return value


def _safe_provider_error(exc: TicketHttpError, operation: str) -> str:
    message = str(exc).replace("ticket provider", "Azure provider")
    message = message.replace("Ticket connector", "Azure connector")
    return f"Azure {operation} failed: {message}"
