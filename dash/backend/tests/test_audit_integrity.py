"""Tamper-evident audit-chain coverage."""

from __future__ import annotations

from app.models.audit import AuditEvent
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession


async def test_audit_events_are_authenticated_chained_and_verifiable(
    client: AsyncClient,
    admin_headers: dict[str, str],
    db_session: AsyncSession,
) -> None:
    first = await client.post(
        "/api/v1/sites",
        json={"name": "Audit site one", "code": "AUD1", "timezone": "UTC"},
        headers=admin_headers,
    )
    second = await client.post(
        "/api/v1/sites",
        json={"name": "Audit site two", "code": "AUD2", "timezone": "UTC"},
        headers=admin_headers,
    )
    assert first.status_code == 201
    assert second.status_code == 201

    result = await client.get("/api/v1/audit/integrity", headers=admin_headers)
    assert result.status_code == 200, result.text
    body = result.json()
    assert body["valid"] is True
    assert body["events_checked"] >= 2
    assert body["last_hash"]

    rows = list(
        (
            await db_session.execute(select(AuditEvent).order_by(AuditEvent.chain_sequence.asc()))
        ).scalars()
    )
    assert rows[-1].previous_hash == rows[-2].chain_hash
    assert rows[-1].event_signature != "0" * 64
    assert rows[-1].integrity_key_id != "legacy"


async def test_audit_integrity_detects_database_tampering(
    client: AsyncClient,
    admin_headers: dict[str, str],
    db_session: AsyncSession,
) -> None:
    created = await client.post(
        "/api/v1/sites",
        json={"name": "Tamper target", "code": "TAMP", "timezone": "UTC"},
        headers=admin_headers,
    )
    assert created.status_code == 201
    row = (
        (
            await db_session.execute(
                select(AuditEvent)
                .where(AuditEvent.action == "site.created")
                .order_by(AuditEvent.chain_sequence.desc())
            )
        )
        .scalars()
        .first()
    )
    assert row is not None

    # SQLite is used by the unit suite and does not install the PostgreSQL
    # mutation-rejection trigger. Mutating a row here simulates a database-level
    # bypass; its off-database HMAC must still expose the change.
    row.metadata_json = {"forged": True}
    await db_session.flush()

    result = await client.get("/api/v1/audit/integrity", headers=admin_headers)
    assert result.status_code == 200
    assert result.json()["valid"] is False
    assert "signature mismatch" in result.json()["failure"]
