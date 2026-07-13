"""Worker-backed, read-only passive inventory connector contract."""

from __future__ import annotations

import base64
import hashlib
import json
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol, cast
from urllib.parse import urlsplit, urlunsplit

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.models.background_task import BackgroundTask
from app.models.enums import ConnectorRunStatus, PassiveConnectorType
from app.models.passive_inventory import AssetObservation, ConnectorRun, InventoryConnector
from app.services import background_tasks, reconciliation
from app.services.secret_crypto import SecretPurpose, decrypt_secret, encrypt_secret

_SECRET_FRAGMENTS = {
    "secret",
    "token",
    "password",
    "private_key",
    "credential",
    "api_key",
    "authorization",
}
MAX_CSV_SOURCE_BYTES = 5 * 1024 * 1024


class InventoryConnectorError(ValueError):
    """Connector configuration or output violated the read-only contract."""


@dataclass(frozen=True)
class NormalizedObservation:
    source_record_id: str
    observed_at: datetime
    identifiers: list[dict[str, Any]]
    attributes: dict[str, Any]


class InventoryAdapter(Protocol):
    """Provider adapters may only test and collect; no mutation method exists."""

    async def test(
        self,
        connector: InventoryConnector,
        secret: str | None,
        *,
        source_data: bytes | None,
    ) -> dict[str, Any]: ...

    async def collect(
        self,
        connector: InventoryConnector,
        secret: str | None,
        *,
        cursor: dict[str, Any],
        source_data: bytes | None,
    ) -> tuple[list[NormalizedObservation], dict[str, Any]]: ...


ADAPTERS: dict[PassiveConnectorType, InventoryAdapter] = {}


def register_adapter(connector_type: PassiveConnectorType, adapter: InventoryAdapter) -> None:
    ADAPTERS[connector_type] = adapter


def register_builtin_adapters() -> None:
    from app.services.inventory_csv import CsvInventoryAdapter
    from app.services.inventory_generic_api import GenericApiInventoryAdapter

    register_adapter(PassiveConnectorType.CSV, CsvInventoryAdapter())
    register_adapter(PassiveConnectorType.GENERIC_API, GenericApiInventoryAdapter())


def validate_public_config(value: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(value, dict) or len(value) > 50:
        raise InventoryConnectorError("connector config must contain at most 50 fields")
    result: dict[str, Any] = {}
    for key, item in value.items():
        normalized = str(key).strip()
        lowered = normalized.lower()
        if (
            not normalized
            or len(normalized) > 64
            or any(fragment in lowered for fragment in _SECRET_FRAGMENTS)
        ):
            raise InventoryConnectorError("connector config contains a reserved field")
        if (
            isinstance(item, bool | int | float)
            or item is None
            or isinstance(item, str)
            and len(item) <= 4096
        ):
            result[normalized] = item
        elif (
            isinstance(item, list)
            and len(item) <= 100
            and all(isinstance(entry, str) and len(entry) <= 512 for entry in item)
        ):
            result[normalized] = list(item)
        else:
            raise InventoryConnectorError(
                "connector config values must be bounded scalars or string lists"
            )
    return result


def validate_base_url(value: str | None) -> str | None:
    if value is None:
        return None
    parts = urlsplit(value)
    if parts.scheme != "https" or not parts.hostname or parts.username or parts.password:
        raise InventoryConnectorError("connector URL must be an https URL without credentials")
    if parts.query or parts.fragment:
        raise InventoryConnectorError("connector URL must not include a query or fragment")
    return urlunsplit((parts.scheme, parts.netloc, parts.path.rstrip("/"), "", ""))


def encrypt_connector_secret(settings: Settings, plaintext: str) -> str:
    if not plaintext or len(plaintext) > 32768:
        raise InventoryConnectorError("connector secret must contain 1-32768 characters")
    if not settings.secret_key:
        raise InventoryConnectorError("application secret key is required for connector encryption")
    return encrypt_secret(settings.secret_key, SecretPurpose.INVENTORY_CONNECTOR_SECRET, plaintext)


def decrypt_connector_secret(settings: Settings, ciphertext: str | None) -> str | None:
    if ciphertext is None:
        return None
    if not settings.secret_key:
        raise InventoryConnectorError("application secret key is required for connector decryption")
    return decrypt_secret(settings.secret_key, SecretPurpose.INVENTORY_CONNECTOR_SECRET, ciphertext)


def encrypt_source_data(settings: Settings, value: bytes) -> str:
    if not settings.secret_key:
        raise InventoryConnectorError("application secret key is required for source encryption")
    encoded = base64.b64encode(value).decode("ascii")
    return encrypt_secret(settings.secret_key, SecretPurpose.INVENTORY_CSV_SOURCE, encoded)


def decrypt_source_data(settings: Settings, ciphertext: str | None) -> bytes | None:
    if ciphertext is None:
        return None
    if not settings.secret_key:
        raise InventoryConnectorError("application secret key is required for source decryption")
    encoded = decrypt_secret(settings.secret_key, SecretPurpose.INVENTORY_CSV_SOURCE, ciphertext)
    try:
        return base64.b64decode(encoded, validate=True)
    except ValueError as exc:
        raise InventoryConnectorError("encrypted source data is invalid") from exc


async def test_connector(connector: InventoryConnector, settings: Settings) -> dict[str, Any]:
    adapter = ADAPTERS.get(connector.connector_type)
    if adapter is None:
        raise InventoryConnectorError(f"{connector.connector_type.value} adapter is not installed")
    secret = decrypt_connector_secret(settings, connector.encrypted_secret)
    try:
        result = await adapter.test(
            connector,
            secret,
            source_data=decrypt_source_data(settings, connector.encrypted_source_data),
        )
        _ensure_secret_absent(result, secret, label="connector test metadata")
        return _bounded_mapping(result, label="connector test metadata")
    except InventoryConnectorError:
        raise
    except Exception as exc:
        raise InventoryConnectorError(_safe_error(exc, secret)) from exc


async def enqueue_run(
    session: AsyncSession,
    connector: InventoryConnector,
    *,
    created_by_user_id: uuid.UUID | None,
    client_idempotency_key: str | None = None,
) -> tuple[ConnectorRun, BackgroundTask, bool]:
    run = ConnectorRun(
        organization_id=connector.organization_id,
        site_id=connector.site_id,
        connector_id=connector.id,
        status=ConnectorRunStatus.QUEUED,
    )
    session.add(run)
    await session.flush()
    key = (
        background_tasks.scoped_idempotency_key(f"inventory:{connector.id}", client_idempotency_key)
        if client_idempotency_key
        else f"inventory:{connector.id}:{run.id}"
    )
    task, created = await background_tasks.enqueue_task(
        session,
        task_type="inventory.collect",
        idempotency_key=key,
        payload={"run_id": str(run.id)},
        organization_id=connector.organization_id,
        created_by_user_id=created_by_user_id,
        max_attempts=5,
    )
    if not created:
        await session.delete(run)
        existing_run_id = task.payload_json.get("run_id")
        existing = (
            await session.get(ConnectorRun, uuid.UUID(str(existing_run_id)))
            if existing_run_id
            else None
        )
        if existing is None:
            raise InventoryConnectorError("idempotent connector task has no run record")
        return existing, task, False
    run.background_task_id = task.id
    return run, task, True


async def schedule_due_connectors(
    session: AsyncSession,
    organization_id: uuid.UUID,
    *,
    now: datetime,
) -> int:
    connectors = (
        (
            await session.execute(
                select(InventoryConnector).where(
                    InventoryConnector.organization_id == organization_id,
                    InventoryConnector.enabled.is_(True),
                    InventoryConnector.successful_test_at.is_not(None),
                    InventoryConnector.interval_minutes.is_not(None),
                    InventoryConnector.next_run_at <= now,
                )
            )
        )
        .scalars()
        .all()
    )
    created = 0
    for connector in connectors:
        due_at = connector.next_run_at
        if due_at is None:
            continue
        _, _, was_created = await enqueue_run(
            session,
            connector,
            created_by_user_id=None,
            client_idempotency_key=f"scheduled:{due_at.isoformat()}",
        )
        created += int(was_created)
        interval = connector.interval_minutes
        if interval is None:
            continue
        while connector.next_run_at is not None:
            comparable = (
                connector.next_run_at
                if connector.next_run_at.tzinfo
                else connector.next_run_at.replace(tzinfo=UTC)
            )
            if comparable > now:
                break
            connector.next_run_at += timedelta(minutes=interval)
    return created


def _payload_hash(observation: NormalizedObservation) -> str:
    return hashlib.sha256(
        json.dumps(
            {
                "source_record_id": observation.source_record_id,
                "observed_at": observation.observed_at.isoformat(),
                "identifiers": observation.identifiers,
                "attributes": observation.attributes,
            },
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        ).encode()
    ).hexdigest()


def _safe_error(exc: Exception, secret: str | None) -> str:
    message = f"{type(exc).__name__}: {exc}"
    if secret:
        message = message.replace(secret, "[REDACTED]")
    return message[:1024]


def _ensure_secret_absent(value: Any, secret: str | None, *, label: str) -> None:
    if not secret:
        return
    encoded = json.dumps(value, default=str)
    if encoded == json.dumps(secret) or (len(secret) >= 8 and secret in encoded):
        raise InventoryConnectorError(f"{label} contains connector secret material")


def _bounded_mapping(value: dict[str, Any], *, label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or len(value) > 100:
        raise InventoryConnectorError(f"{label} must contain at most 100 fields")
    encoded = json.dumps(value, default=str)
    if len(encoded.encode()) > 256_000:
        raise InventoryConnectorError(f"{label} exceeds 256 KiB")
    pending: list[Any] = [value]
    while pending:
        item = pending.pop()
        if isinstance(item, dict):
            if any(fragment in str(key).lower() for key in item for fragment in _SECRET_FRAGMENTS):
                raise InventoryConnectorError(f"{label} contains a reserved secret field")
            pending.extend(item.values())
        elif isinstance(item, list):
            pending.extend(item)
    return cast(dict[str, Any], json.loads(encoded))


async def execute_connector_task(
    session: AsyncSession, task: BackgroundTask, settings: Settings
) -> dict[str, Any]:
    run = await session.scalar(
        select(ConnectorRun).where(
            ConnectorRun.id == uuid.UUID(str(task.payload_json["run_id"])),
            ConnectorRun.organization_id == task.organization_id,
        )
    )
    if run is None:
        raise InventoryConnectorError("connector run no longer exists")
    connector = await session.get(InventoryConnector, run.connector_id)
    if connector is None or connector.organization_id != task.organization_id:
        raise InventoryConnectorError("connector run ownership is invalid")
    if run.status == ConnectorRunStatus.SUCCEEDED:
        return {"run_id": str(run.id), "observations": run.observations_created, "replayed": True}
    now = datetime.now(UTC)
    run.status = ConnectorRunStatus.RUNNING
    run.started_at = run.started_at or now
    run.finished_at = None
    run.error = None
    try:
        if not connector.enabled or connector.successful_test_at is None:
            raise InventoryConnectorError("connector must be tested and enabled before collection")
        adapter = ADAPTERS.get(connector.connector_type)
        if adapter is None:
            raise InventoryConnectorError(
                f"{connector.connector_type.value} adapter is not installed"
            )
        connector_secret = decrypt_connector_secret(settings, connector.encrypted_secret)
        observations, cursor = await adapter.collect(
            connector,
            connector_secret,
            cursor=run.cursor_json,
            source_data=decrypt_source_data(settings, connector.encrypted_source_data),
        )
        if len(observations) > 100_000:
            raise InventoryConnectorError("connector run exceeds the 100000-record safety limit")
        _ensure_secret_absent(cursor, connector_secret, label="connector cursor")
        bounded_cursor = _bounded_mapping(cursor, label="connector cursor")
        existing_source_ids = set(
            (
                await session.execute(
                    select(AssetObservation.source_record_id).where(
                        AssetObservation.run_id == run.id
                    )
                )
            ).scalars()
        )
        created = 0
        for item in observations:
            source_id = item.source_record_id.strip()
            if not source_id or len(source_id) > 512:
                raise InventoryConnectorError("source record IDs must contain 1-512 characters")
            if source_id in existing_source_ids:
                continue
            if item.observed_at.tzinfo is None or item.observed_at.utcoffset() is None:
                raise InventoryConnectorError("observation timestamps must include a timezone")
            if item.observed_at > now + timedelta(days=1):
                raise InventoryConnectorError("observation timestamps are too far in the future")
            _ensure_secret_absent(source_id, connector_secret, label="source record ID")
            _ensure_secret_absent(item.identifiers, connector_secret, label="identifiers")
            _ensure_secret_absent(item.attributes, connector_secret, label="observation attributes")
            identifiers = reconciliation.normalize_identifiers(item.identifiers)
            attributes = _bounded_mapping(item.attributes, label="observation attributes")
            stored = AssetObservation(
                organization_id=connector.organization_id,
                site_id=connector.site_id,
                connector_id=connector.id,
                run_id=run.id,
                source_record_id=source_id,
                observed_at=item.observed_at,
                identifiers_json=identifiers,
                attributes_json=attributes,
                payload_hash=_payload_hash(item),
            )
            session.add(stored)
            await session.flush()
            await reconciliation.reconcile_observation(session, stored, now=now)
            existing_source_ids.add(source_id)
            created += 1
    except Exception as exc:  # noqa: BLE001 - persist bounded connector failure history
        run.status = ConnectorRunStatus.FAILED
        run.finished_at = now
        run.error = _safe_error(exc, locals().get("connector_secret"))[:2048]
        connector.last_run_at = now
        await session.flush()
        raise background_tasks.PersistedTaskFailure(run.error) from exc
    run.status = ConnectorRunStatus.SUCCEEDED
    run.finished_at = now
    run.records_read = len(observations)
    run.observations_created = len(existing_source_ids)
    run.cursor_json = bounded_cursor
    run.error = None
    connector.last_run_at = now
    if connector.interval_minutes:
        connector.next_run_at = now + timedelta(minutes=connector.interval_minutes)
    return {
        "run_id": str(run.id),
        "observations": run.observations_created,
        "created_this_attempt": created,
    }


register_builtin_adapters()
