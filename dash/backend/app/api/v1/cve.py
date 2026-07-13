"""CVE intelligence lookup: a CVE record joined with its threat-intel signals."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import require_permission
from app.db.session import get_session
from app.models.cve import CveRecord, ThreatIntelEnrichment
from app.models.user import User
from app.schemas.intelligence import CveDetail, CveRecordRead, EnrichmentRead

router = APIRouter(prefix="/cve", tags=["cve"])


@router.get("/{cve_id}", response_model=CveDetail, summary="Get a CVE with enrichment")
async def get_cve(
    cve_id: str,
    current_user: Annotated[User, Depends(require_permission("feeds.read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> CveDetail:
    """Return a locally cached CVE record and its KEV/EPSS enrichment."""
    record = await session.get(CveRecord, cve_id)
    if record is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="CVE not found")
    enrichment = await session.get(ThreatIntelEnrichment, cve_id)
    return CveDetail(
        cve=CveRecordRead.model_validate(record),
        enrichment=EnrichmentRead.model_validate(enrichment) if enrichment else None,
    )
