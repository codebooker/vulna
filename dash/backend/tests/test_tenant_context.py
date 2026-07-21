"""Portable guards around database tenant-context assignment."""

from __future__ import annotations

import uuid

import pytest
from app.db.session import set_maintenance_context, set_tenant_context
from sqlalchemy.ext.asyncio import AsyncSession


async def test_tenant_context_is_sticky_and_cannot_escalate(
    db_session: AsyncSession,
) -> None:
    organization_id = uuid.uuid4()
    await set_tenant_context(db_session, organization_id)
    await set_tenant_context(db_session, organization_id)

    with pytest.raises(RuntimeError, match="cannot change"):
        await set_tenant_context(db_session, uuid.uuid4())
    with pytest.raises(RuntimeError, match="tenant-scoped"):
        await set_maintenance_context(db_session)
