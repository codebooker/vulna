"""Idempotent worker-only ticket synchronization contract and orchestration."""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol
from urllib.parse import urlsplit, urlunsplit

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.models.background_task import BackgroundTask
from app.models.enums import (
    FindingStatus,
    TicketConnectorType,
    TicketSyncAction,
    TicketSyncStatus,
)
from app.models.finding import Finding
from app.models.ticketing import TicketConnector, TicketSync, TicketSyncEvent
from app.services import background_tasks
from app.services.secret_crypto import SecretPurpose, decrypt_secret, encrypt_secret


class TicketingError(ValueError):
    """A connector configuration or synchronization request is unsafe."""


@dataclass(frozen=True)
class TicketResult:
    external_id: str
    external_url: str | None
    metadata: dict[str, Any]


class TicketAdapter(Protocol):
    """Common connector contract; implementations must make operations idempotent."""

    async def test(self, connector: TicketConnector, secret: str) -> dict[str, Any]: ...

    async def upsert(
        self,
        connector: TicketConnector,
        secret: str,
        payload: dict[str, Any],
        *,
        external_id: str | None,
        idempotency_key: str,
    ) -> TicketResult: ...

    async def close(
        self,
        connector: TicketConnector,
        secret: str,
        payload: dict[str, Any],
        *,
        external_id: str,
        idempotency_key: str,
    ) -> TicketResult: ...


ADAPTERS: dict[TicketConnectorType, TicketAdapter] = {}
_SECRET_KEY_FRAGMENTS = {
    "secret",
    "token",
    "password",
    "private_key",
    "credential",
    "api_key",
}


def register_adapter(connector_type: TicketConnectorType, adapter: TicketAdapter) -> None:
    ADAPTERS[connector_type] = adapter


def register_builtin_adapters() -> None:
    # Imported lazily to avoid a cycle: provider modules implement this module's
    # protocol and return TicketResult values.
    from app.services.ticket_adapters.github import GitHubIssuesAdapter
    from app.services.ticket_adapters.gitlab import GitLabIssuesAdapter
    from app.services.ticket_adapters.glpi import GlpiTicketAdapter

    register_adapter(TicketConnectorType.GITHUB, GitHubIssuesAdapter())
    register_adapter(TicketConnectorType.GITLAB, GitLabIssuesAdapter())
    register_adapter(TicketConnectorType.GLPI, GlpiTicketAdapter())


def validate_public_config(value: dict[str, Any]) -> dict[str, Any]:
    """Reject secret-shaped keys and unbounded/nested executable configuration."""

    if not isinstance(value, dict) or len(value) > 30:
        raise TicketingError("connector config must be an object with at most 30 fields")
    result: dict[str, Any] = {}
    for key, item in value.items():
        normalized_key = str(key).strip()
        lowered = normalized_key.lower()
        if (
            not normalized_key
            or len(normalized_key) > 64
            or any(fragment in lowered for fragment in _SECRET_KEY_FRAGMENTS)
        ):
            raise TicketingError("connector config contains a reserved or invalid field")
        if (
            isinstance(item, bool | int | float)
            or item is None
            or isinstance(item, str)
            and len(item) <= 2048
        ):
            result[normalized_key] = item
        elif (
            isinstance(item, list)
            and len(item) <= 50
            and all(isinstance(entry, str) and len(entry) <= 255 for entry in item)
        ):
            result[normalized_key] = list(item)
        else:
            raise TicketingError("connector config values must be bounded scalars or string lists")
    return result


def validate_connector_url(value: str) -> str:
    parts = urlsplit(value)
    if parts.scheme != "https" or not parts.hostname or parts.username or parts.password:
        raise TicketingError("connector URL must be an https origin without embedded credentials")
    if parts.fragment:
        raise TicketingError("connector URL must not contain a fragment")
    return urlunsplit((parts.scheme, parts.netloc, parts.path.rstrip("/"), parts.query, ""))


def encrypt_connector_secret(settings: Settings, plaintext: str) -> str:
    if not plaintext or len(plaintext) > 16384:
        raise TicketingError("connector secret must contain 1-16384 characters")
    if not settings.secret_key:
        raise TicketingError("application secret key is required for ticket connector encryption")
    return encrypt_secret(
        settings.secret_key, SecretPurpose.TICKET_CONNECTOR_SECRET, plaintext
    )


def decrypt_connector_secret(settings: Settings, ciphertext: str) -> str:
    if not settings.secret_key:
        raise TicketingError("application secret key is required for ticket connector decryption")
    return decrypt_secret(settings.secret_key, SecretPurpose.TICKET_CONNECTOR_SECRET, ciphertext)


def selected_finding_payload(finding: Finding) -> dict[str, Any]:
    """Build the only fields permitted to leave Vulna; evidence is excluded."""

    return {
        "version": "1",
        "finding_id": str(finding.id),
        "site_id": str(finding.site_id),
        "asset_id": str(finding.asset_id) if finding.asset_id else None,
        "title": finding.title,
        "summary": (finding.description or "")[:4000],
        "severity": finding.severity.value,
        "priority": (
            "critical"
            if finding.risk_score is not None and finding.risk_score >= 85
            else "high"
            if finding.risk_score is not None and finding.risk_score >= 65
            else "medium"
            if finding.risk_score is not None and finding.risk_score >= 40
            else "low"
        ),
        "status": finding.status.value,
        "cve_ids": sorted(set(finding.cve_ids_json))[:50],
        "remediation": (finding.remediation or "")[:4000],
        "due_at": finding.due_at.isoformat() if finding.due_at else None,
        "last_verified_at": (
            finding.last_verified_at.isoformat() if finding.last_verified_at else None
        ),
    }


def payload_hash(payload: dict[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode()
    ).hexdigest()


async def get_or_create_sync(
    session: AsyncSession, connector: TicketConnector, finding: Finding
) -> TicketSync:
    sync = await session.scalar(
        select(TicketSync).where(
            TicketSync.connector_id == connector.id,
            TicketSync.finding_id == finding.id,
        )
    )
    if sync is None:
        sync = TicketSync(
            organization_id=finding.organization_id,
            site_id=finding.site_id,
            connector_id=connector.id,
            finding_id=finding.id,
            status=TicketSyncStatus.PENDING,
            last_action=TicketSyncAction.UPSERT,
        )
        session.add(sync)
        await session.flush()
    return sync


async def enqueue_sync(
    session: AsyncSession,
    connector: TicketConnector,
    finding: Finding,
    *,
    action: TicketSyncAction,
    created_by_user_id: uuid.UUID | None,
    client_idempotency_key: str | None = None,
    explicit_close_reason: str | None = None,
) -> tuple[BackgroundTask, bool]:
    sync = await get_or_create_sync(session, connector, finding)
    payload = selected_finding_payload(finding)
    digest = payload_hash(payload)
    key = (
        background_tasks.scoped_idempotency_key(
            f"ticket:{connector.id}:{finding.id}:{action.value}", client_idempotency_key
        )
        if client_idempotency_key
        else f"ticket:{connector.id}:{finding.id}:{action.value}:{digest}:{uuid.uuid4()}"
    )
    task, created = await background_tasks.enqueue_task(
        session,
        task_type="tickets.sync",
        idempotency_key=key,
        payload={
            "sync_id": str(sync.id),
            "action": action.value,
            "payload_hash": digest,
            "explicit_close_reason": explicit_close_reason,
        },
        organization_id=finding.organization_id,
        created_by_user_id=created_by_user_id,
        max_attempts=5,
    )
    sync.status = TicketSyncStatus.PENDING
    sync.last_action = action
    sync.last_error = None
    return task, created


async def test_connector(
    connector: TicketConnector, settings: Settings
) -> dict[str, Any]:
    adapter = ADAPTERS.get(connector.connector_type)
    if adapter is None:
        raise TicketingError(f"{connector.connector_type.value} connector is not installed")
    secret = decrypt_connector_secret(settings, connector.encrypted_secret)
    return await adapter.test(connector, secret)


async def execute_sync_task(
    session: AsyncSession, task: BackgroundTask, settings: Settings
) -> dict[str, Any]:
    """Execute one connector attempt and persist failure without raising.

    A remote outage therefore cannot roll back a finding or poison unrelated
    persistence. Operators may inspect and requeue the durable failed sync.
    """

    sync_id = uuid.UUID(str(task.payload_json["sync_id"]))
    sync = await session.scalar(
        select(TicketSync).where(
            TicketSync.id == sync_id,
            TicketSync.organization_id == task.organization_id,
        )
    )
    if sync is None:
        raise TicketingError("ticket sync no longer exists")
    connector = await session.get(TicketConnector, sync.connector_id)
    finding = await session.get(Finding, sync.finding_id)
    if (
        connector is None
        or finding is None
        or connector.organization_id != task.organization_id
        or finding.organization_id != task.organization_id
    ):
        raise TicketingError("ticket sync ownership is invalid")
    action = TicketSyncAction(str(task.payload_json["action"]))
    idempotency_key = task.idempotency_key
    prior = await session.scalar(
        select(TicketSyncEvent).where(
            TicketSyncEvent.background_task_id == task.id,
            TicketSyncEvent.status == TicketSyncStatus.SUCCEEDED,
        )
    )
    if prior is not None:
        return {"sync_id": str(sync.id), "status": prior.status.value, "replayed": True}

    payload = selected_finding_payload(finding)
    digest = payload_hash(payload)
    event_status = TicketSyncStatus.SUCCEEDED
    response: dict[str, Any] = {}
    error: str | None = None
    try:
        if not connector.enabled:
            raise TicketingError("ticket connector is disabled")
        if connector.successful_test_at is None:
            raise TicketingError("ticket connector must pass a test before use")
        adapter = ADAPTERS.get(connector.connector_type)
        if adapter is None:
            raise TicketingError(f"{connector.connector_type.value} connector is not installed")
        secret = decrypt_connector_secret(settings, connector.encrypted_secret)
        if action == TicketSyncAction.CLOSE:
            explicit_reason = str(task.payload_json.get("explicit_close_reason") or "").strip()
            verified = (
                finding.status == FindingStatus.RESOLVED and finding.last_verified_at is not None
            )
            if not verified and not explicit_reason:
                raise TicketingError(
                    "tickets close only after successful verification or an explicit audited reason"
                )
            if sync.external_ticket_id is None:
                raise TicketingError("cannot close a ticket that has not been created")
            result = await adapter.close(
                connector,
                secret,
                payload,
                external_id=sync.external_ticket_id,
                idempotency_key=idempotency_key,
            )
        else:
            result = await adapter.upsert(
                connector,
                secret,
                payload,
                external_id=sync.external_ticket_id,
                idempotency_key=idempotency_key,
            )
        sync.external_ticket_id = result.external_id
        sync.external_ticket_url = result.external_url
        response = result.metadata
        sync.last_synced_at = datetime.now(UTC)
        sync.last_error = None
    except Exception as exc:  # noqa: BLE001 - connector failure boundary
        event_status = TicketSyncStatus.FAILED
        error = f"{type(exc).__name__}: {exc}"[:2048]
        sync.last_error = error

    sync.status = event_status
    sync.last_action = action
    sync.last_payload_hash = digest
    attempt_key = background_tasks.scoped_idempotency_key(
        f"ticket-attempt:{task.id}", str(task.attempts)
    )
    session.add(
        TicketSyncEvent(
            organization_id=sync.organization_id,
            site_id=sync.site_id,
            sync_id=sync.id,
            background_task_id=task.id,
            action=action,
            status=event_status,
            idempotency_key=attempt_key,
            payload_hash=digest,
            response_json=response,
            error=error,
        )
    )
    await session.flush()
    if event_status == TicketSyncStatus.FAILED:
        raise background_tasks.PersistedTaskFailure(error or "ticket synchronization failed")
    return {
        "sync_id": str(sync.id),
        "status": event_status.value,
        "external_ticket_id": sync.external_ticket_id,
    }


register_builtin_adapters()
