"""Contextual help endpoints.

Serve the help catalogue and the administrator exposure checklist so the UI can
deep-link from errors, setup steps, findings, and maintenance warnings to a
plain-language explanation and the right documentation page.
"""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

from fastapi import APIRouter, HTTPException, status

from app.auth.dependencies import CurrentUser
from app.services import help_topics

router = APIRouter(prefix="/help", tags=["help"])


@router.get("/topics", summary="Help topic catalogue")
async def topics(current_user: CurrentUser) -> dict[str, Any]:
    return {"topics": [asdict(t) for t in help_topics.HELP_TOPICS.values()]}


@router.get("/topics/{key}", summary="A single help topic")
async def topic(key: str, current_user: CurrentUser) -> dict[str, Any]:
    found = help_topics.topic_for(key)
    if found is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="unknown help topic")
    return asdict(found)


@router.get("/exposure-checklist", summary="Checklist for exposing Vulna beyond a LAN")
async def exposure_checklist(current_user: CurrentUser) -> dict[str, Any]:
    return {"checklist": help_topics.EXPOSURE_CHECKLIST}
