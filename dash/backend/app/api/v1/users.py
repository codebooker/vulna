"""User management endpoints (Administrator only).

Users view their own profile via ``/auth/me``. These endpoints let an
administrator manage the accounts within their organization.
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.context import RequestContext, get_request_context
from app.auth.dependencies import get_user_by_email, require_admin
from app.auth.password import hash_password
from app.db.session import get_session
from app.models.user import User
from app.schemas.common import Page
from app.schemas.user import UserCreate, UserRead, UserUpdate
from app.services.audit import record_audit

router = APIRouter(prefix="/users", tags=["users"])


async def _get_owned_user(session: AsyncSession, user_id: uuid.UUID, org_id: uuid.UUID) -> User:
    user = await session.get(User, user_id)
    if user is None or user.organization_id != org_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return user


@router.get("", response_model=Page[UserRead], summary="List users")
async def list_users(
    admin: Annotated[User, Depends(require_admin)],
    session: Annotated[AsyncSession, Depends(get_session)],
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Page[UserRead]:
    org_id = admin.organization_id
    total = await session.scalar(
        select(func.count()).select_from(User).where(User.organization_id == org_id)
    )
    result = await session.execute(
        select(User)
        .where(User.organization_id == org_id)
        .order_by(User.created_at.asc())
        .limit(limit)
        .offset(offset)
    )
    users = result.scalars().all()
    return Page[UserRead](
        items=[UserRead.model_validate(u) for u in users],
        total=total or 0,
        limit=limit,
        offset=offset,
    )


@router.get("/{user_id}", response_model=UserRead, summary="Get a user")
async def get_user(
    user_id: uuid.UUID,
    admin: Annotated[User, Depends(require_admin)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> UserRead:
    user = await _get_owned_user(session, user_id, admin.organization_id)
    return UserRead.model_validate(user)


@router.post(
    "",
    response_model=UserRead,
    status_code=status.HTTP_201_CREATED,
    summary="Create a user",
)
async def create_user(
    payload: UserCreate,
    admin: Annotated[User, Depends(require_admin)],
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> UserRead:
    """Create a user in the administrator's organization."""
    normalized_email = payload.email.strip().lower()
    if await get_user_by_email(session, normalized_email) is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A user with that email already exists",
        )

    user = User(
        organization_id=admin.organization_id,
        email=normalized_email,
        hashed_password=hash_password(payload.password),
        full_name=payload.full_name,
        role=payload.role,
        is_active=payload.is_active,
    )
    session.add(user)
    await session.flush()

    record_audit(
        session,
        action="user.created",
        actor=admin,
        organization_id=admin.organization_id,
        target_type="user",
        target_id=user.id,
        source_ip=context.source_ip,
        user_agent=context.user_agent,
        request_id=context.request_id,
        metadata={"email": normalized_email, "role": user.role.value},
    )
    return UserRead.model_validate(user)


@router.patch("/{user_id}", response_model=UserRead, summary="Update a user")
async def update_user(
    user_id: uuid.UUID,
    payload: UserUpdate,
    admin: Annotated[User, Depends(require_admin)],
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> UserRead:
    """Update a user (Administrator only)."""
    user = await _get_owned_user(session, user_id, admin.organization_id)
    changes = payload.model_dump(exclude_unset=True)

    # Guard against an admin locking themselves out of admin.
    if user.id == admin.id and "role" in changes and changes["role"] != admin.role:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You cannot change your own role",
        )
    if user.id == admin.id and changes.get("is_active") is False:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You cannot deactivate your own account",
        )

    audited_fields = sorted(changes.keys())
    if "password" in changes:
        new_password = changes.pop("password")
        user.hashed_password = hash_password(new_password)
    for field, value in changes.items():
        setattr(user, field, value)
    await session.flush()

    record_audit(
        session,
        action="user.updated",
        actor=admin,
        organization_id=admin.organization_id,
        target_type="user",
        target_id=user.id,
        source_ip=context.source_ip,
        user_agent=context.user_agent,
        request_id=context.request_id,
        metadata={"changed_fields": audited_fields},
    )
    return UserRead.model_validate(user)


@router.delete(
    "/{user_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    response_model=None,
    summary="Delete a user",
)
async def delete_user(
    user_id: uuid.UUID,
    admin: Annotated[User, Depends(require_admin)],
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> None:
    """Delete a user (Administrator only). Administrators cannot delete themselves."""
    if user_id == admin.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You cannot delete your own account",
        )
    user = await _get_owned_user(session, user_id, admin.organization_id)
    record_audit(
        session,
        action="user.deleted",
        actor=admin,
        organization_id=admin.organization_id,
        target_type="user",
        target_id=user.id,
        source_ip=context.source_ip,
        user_agent=context.user_agent,
        request_id=context.request_id,
        metadata={"email": user.email},
    )
    await session.delete(user)
