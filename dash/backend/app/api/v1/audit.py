"""Read-only audit-log endpoints.

The audit log is append-only: there are intentionally no create/update/delete
endpoints. Auditors and administrators may read it (build plan Section 5).
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import require_permission
from app.db.session import get_session
from app.models.audit import AuditEvent
from app.models.user import User
from app.schemas.audit import AuditEventRead, AuditIntegrityRead
from app.schemas.common import Page
from app.services.audit import verify_audit_chain

router = APIRouter(prefix="/audit", tags=["audit"])

_reader = require_permission("audit.read")


@router.get(
    "/integrity",
    response_model=AuditIntegrityRead,
    summary="Verify the organization's tamper-evident audit chain",
)
async def audit_integrity(
    reader: Annotated[User, Depends(_reader)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> AuditIntegrityRead:
    return AuditIntegrityRead.model_validate(
        await verify_audit_chain(session, reader.organization_id)
    )


@router.get("", response_model=Page[AuditEventRead], summary="List audit events")
async def list_audit_events(
    reader: Annotated[User, Depends(_reader)],
    session: Annotated[AsyncSession, Depends(get_session)],
    action: Annotated[str | None, Query(description="Filter by exact action")] = None,
    target_type: Annotated[str | None, Query(description="Filter by target type")] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Page[AuditEventRead]:
    """List audit events for the caller's organization, newest first."""
    filters = [AuditEvent.organization_id == reader.organization_id]
    if action is not None:
        filters.append(AuditEvent.action == action)
    if target_type is not None:
        filters.append(AuditEvent.target_type == target_type)

    total = await session.scalar(select(func.count()).select_from(AuditEvent).where(*filters))
    result = await session.execute(
        select(AuditEvent)
        .where(*filters)
        .order_by(AuditEvent.created_at.desc())
        .limit(limit)
        .offset(offset)
    )
    events = result.scalars().all()
    return Page[AuditEventRead](
        items=[AuditEventRead.model_validate(e) for e in events],
        total=total or 0,
        limit=limit,
        offset=offset,
    )
