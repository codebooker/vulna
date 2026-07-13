"""Phase 36 TOTP, recovery-code, WebAuthn, and MFA policy APIs."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated, NoReturn

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from webauthn.helpers.exceptions import WebAuthnException

from app.api.context import RequestContext, get_request_context
from app.auth.dependencies import MfaIdentity, StepUpIdentity, require_admin
from app.auth.tokens import create_access_token
from app.core.config import Settings, get_settings
from app.db.session import get_session
from app.models.enums import UserRole
from app.models.mfa import TotpFactor, WebAuthnCredential
from app.models.organization import Organization
from app.models.session import UserSession
from app.models.user import User
from app.schemas.mfa import (
    MfaPolicyRead,
    MfaPolicyUpdate,
    MfaStatusRead,
    MfaVerifyResult,
    RecoveryCodesRead,
    TotpCodeRequest,
    TotpConfirmRead,
    TotpConfirmRequest,
    TotpSetupRead,
    WebAuthnAuthenticationFinish,
    WebAuthnBeginRead,
    WebAuthnCredentialRead,
    WebAuthnRegistrationFinish,
    WebAuthnRegistrationRead,
)
from app.services import auth_throttle, mfa, sso
from app.services import webauthn as webauthn_service
from app.services.audit import record_audit
from app.services.sessions import ACCESS_TOKEN_MINUTES, aware, session_policy

router = APIRouter(prefix="/mfa", tags=["mfa"])
TOTP_SETUP_TTL = timedelta(minutes=10)


def _required_session(identity: MfaIdentity) -> UserSession:
    if identity.session is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="A revocable browser session is required",
        )
    return identity.session


def _token(
    settings: Settings, user: User, user_session: UserSession, method: str
) -> MfaVerifyResult:
    access = create_access_token(
        settings,
        user_id=user.id,
        role=user.role.value,
        organization_id=user.organization_id,
        auth_version=user.auth_version,
        session_id=user_session.id,
        authenticated_at=user_session.authenticated_at,
        expires_delta=timedelta(minutes=ACCESS_TOKEN_MINUTES),
    )
    return MfaVerifyResult(
        access_token=access,
        expires_in=ACCESS_TOKEN_MINUTES * 60,
        method=method,
    )


async def _require_recent_password(
    session: AsyncSession, identity: MfaIdentity
) -> UserSession:
    user_session = _required_session(identity)
    org = await session.get(Organization, identity.user.organization_id)
    if org is None:
        raise HTTPException(status_code=404, detail="Organization not found")
    # Avoid a second authorization dependency so an MFA-pending session can
    # enroll after a just-completed password check.
    if datetime.now(UTC) - aware(user_session.authenticated_at) > timedelta(
        minutes=session_policy(org).privileged_window_minutes
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "step_up_required", "message": "Enter your password again"},
        )
    return user_session


async def _throttle_mfa(
    session: AsyncSession,
    user: User,
    source_ip: str | None,
) -> None:
    wait = await auth_throttle.retry_after(session, user.email, source_ip)
    if wait:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Verification failed",
            headers={"Retry-After": str(wait)},
        )


async def _failed_mfa(
    session: AsyncSession,
    user: User,
    source_ip: str | None,
) -> NoReturn:
    wait = await auth_throttle.record_failure(session, user.email, source_ip)
    await session.commit()
    raise HTTPException(
        status_code=(status.HTTP_429_TOO_MANY_REQUESTS if wait else status.HTTP_401_UNAUTHORIZED),
        detail="Verification failed",
        headers={"Retry-After": str(wait)} if wait else None,
    )


def _credential_read(value: WebAuthnCredential) -> WebAuthnCredentialRead:
    return WebAuthnCredentialRead(
        id=value.id,
        label=value.label,
        device_type=value.device_type,
        backed_up=value.backed_up,
        transports=value.transports_json,
        created_at=value.created_at,
        last_used_at=value.last_used_at,
    )


def _record_mfa_success(
    session: AsyncSession,
    identity: MfaIdentity,
    context: RequestContext,
    method: str,
) -> None:
    record_audit(
        session,
        action="auth.mfa_succeeded",
        actor=identity.user,
        target_type="user",
        target_id=identity.user.id,
        source_ip=context.source_ip,
        user_agent=context.user_agent,
        request_id=context.request_id,
        metadata={"method": method, "session_id": str(_required_session(identity).id)},
    )


@router.get("/status", response_model=MfaStatusRead, summary="Current MFA status")
async def mfa_status(
    identity: MfaIdentity,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> MfaStatusRead:
    policy = await mfa.get_policy(session, identity.user.organization_id)
    enrolled_methods = await mfa.methods(session, identity.user)
    credentials = await mfa.active_webauthn(session, identity.user)
    remaining = await mfa.recovery_count(session, identity.user)
    return MfaStatusRead(
        required=mfa.required_for_user(policy, identity.user),
        enrolled=bool(set(enrolled_methods) & {"totp", "webauthn"}),
        grace_expires_at=identity.user.mfa_grace_expires_at,
        totp="totp" in enrolled_methods,
        webauthn_credentials=len(credentials),
        recovery_codes_remaining=remaining,
        methods=enrolled_methods,
    )


@router.post("/totp/setup", response_model=TotpSetupRead, summary="Begin TOTP enrollment")
async def begin_totp_setup(
    identity: MfaIdentity,
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> TotpSetupRead:
    await _require_recent_password(session, identity)
    if await mfa.active_totp(session, identity.user):
        raise HTTPException(status_code=409, detail="TOTP is already enrolled")
    org = await session.get(Organization, identity.user.organization_id)
    if org is None:
        raise HTTPException(status_code=404, detail="Organization not found")
    factor, secret, uri = await mfa.begin_totp(session, settings, identity.user, org)
    return TotpSetupRead(factor_id=factor.id, secret=secret, provisioning_uri=uri)


@router.post("/totp/confirm", response_model=TotpConfirmRead, summary="Confirm TOTP enrollment")
async def confirm_totp_setup(
    payload: TotpConfirmRequest,
    identity: MfaIdentity,
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> TotpConfirmRead:
    user_session = await _require_recent_password(session, identity)
    await _throttle_mfa(session, identity.user, context.source_ip)
    factor = await session.scalar(
        select(TotpFactor).where(
            TotpFactor.id == payload.factor_id,
            TotpFactor.user_id == identity.user.id,
            TotpFactor.organization_id == identity.user.organization_id,
            TotpFactor.confirmed_at.is_(None),
            TotpFactor.disabled_at.is_(None),
        )
    )
    if factor is not None and datetime.now(UTC) - aware(factor.created_at) > TOTP_SETUP_TTL:
        await session.delete(factor)
        factor = None
    if factor is None or not mfa.verify_totp(settings, factor, payload.code):
        await _failed_mfa(session, identity.user, context.source_ip)
    factor.confirmed_at = datetime.now(UTC)
    await mfa.complete_session_mfa(session, user_session, "totp")
    _record_mfa_success(session, identity, context, "totp")
    codes = await mfa.generate_recovery_codes(session, identity.user)
    await mfa.revoke_other_sessions_for_mfa_change(session, identity.user, user_session)
    await auth_throttle.reset_success(session, identity.user.email, context.source_ip)
    record_audit(
        session,
        action="auth.mfa_totp_enrolled",
        actor=identity.user,
        target_type="totp_factor",
        target_id=factor.id,
        source_ip=context.source_ip,
        user_agent=context.user_agent,
        request_id=context.request_id,
    )
    await mfa.emit_security_notification(
        session,
        identity.user,
        title="Authenticator app added",
        summary="A TOTP authenticator was added to your Vulna account.",
    )
    return TotpConfirmRead(
        verification=_token(settings, identity.user, user_session, "totp"),
        recovery_codes=RecoveryCodesRead(codes=codes),
    )


@router.post("/totp/verify", response_model=MfaVerifyResult, summary="Complete MFA with TOTP")
async def verify_totp_login(
    payload: TotpCodeRequest,
    identity: MfaIdentity,
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> MfaVerifyResult:
    user_session = _required_session(identity)
    await _throttle_mfa(session, identity.user, context.source_ip)
    factor = await mfa.active_totp(session, identity.user)
    if factor is None or not mfa.verify_totp(settings, factor, payload.code):
        await _failed_mfa(session, identity.user, context.source_ip)
    await mfa.complete_session_mfa(session, user_session, "totp")
    await auth_throttle.reset_success(session, identity.user.email, context.source_ip)
    _record_mfa_success(session, identity, context, "totp")
    return _token(settings, identity.user, user_session, "totp")


@router.post(
    "/recovery/verify",
    response_model=MfaVerifyResult,
    summary="Complete MFA with a recovery code",
)
async def verify_recovery_code(
    payload: TotpCodeRequest,
    identity: MfaIdentity,
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> MfaVerifyResult:
    user_session = _required_session(identity)
    await _throttle_mfa(session, identity.user, context.source_ip)
    has_strong_factor = bool(
        await mfa.active_totp(session, identity.user)
        or await mfa.active_webauthn(session, identity.user)
    )
    if not has_strong_factor or not await mfa.consume_recovery_code(
        session, identity.user, payload.code
    ):
        await _failed_mfa(session, identity.user, context.source_ip)
    await mfa.complete_session_mfa(session, user_session, "recovery_code")
    await auth_throttle.reset_success(session, identity.user.email, context.source_ip)
    _record_mfa_success(session, identity, context, "recovery_code")
    remaining = await mfa.recovery_count(session, identity.user)
    await mfa.emit_security_notification(
        session,
        identity.user,
        title="Recovery code used",
        summary=f"A recovery code was used to sign in. {remaining} codes remain.",
    )
    result = _token(settings, identity.user, user_session, "recovery_code")
    result.recovery_codes_remaining = remaining
    return result


@router.post(
    "/recovery/regenerate",
    response_model=RecoveryCodesRead,
    summary="Replace recovery codes",
)
async def regenerate_recovery_codes(
    identity: MfaIdentity,
    step_up: StepUpIdentity,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> RecoveryCodesRead:
    codes = await mfa.generate_recovery_codes(session, identity.user)
    return RecoveryCodesRead(codes=codes)


@router.delete("/totp", status_code=204, summary="Disable TOTP")
async def disable_totp(
    identity: MfaIdentity,
    step_up: StepUpIdentity,
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> None:
    user_session = _required_session(identity)
    factor = await mfa.active_totp(session, identity.user)
    if factor is None:
        raise HTTPException(status_code=404, detail="TOTP factor not found")
    policy = await mfa.get_policy(session, identity.user.organization_id)
    if mfa.required_for_user(policy, identity.user) and not await mfa.active_webauthn(
        session, identity.user
    ):
        raise HTTPException(
            status_code=409,
            detail="Enroll another strong factor before removing required MFA",
        )
    if not await mfa.active_webauthn(session, identity.user):
        try:
            await sso.ensure_break_glass_eligibility_can_be_removed(
                session, identity.user
            )
        except sso.SsoError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
    factor.disabled_at = datetime.now(UTC)
    await mfa.revoke_other_sessions_for_mfa_change(session, identity.user, user_session)
    record_audit(
        session,
        action="auth.mfa_totp_disabled",
        actor=identity.user,
        target_type="totp_factor",
        target_id=factor.id,
        source_ip=context.source_ip,
        user_agent=context.user_agent,
        request_id=context.request_id,
    )
    await mfa.emit_security_notification(
        session,
        identity.user,
        title="Authenticator app removed",
        summary="TOTP authentication was removed from your Vulna account.",
    )


def _request_origin(request: Request) -> str:
    return f"{request.url.scheme}://{request.url.netloc}"


@router.get(
    "/webauthn/credentials",
    response_model=list[WebAuthnCredentialRead],
    summary="List WebAuthn credentials",
)
async def list_webauthn_credentials(
    identity: MfaIdentity,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> list[WebAuthnCredentialRead]:
    return [_credential_read(value) for value in await mfa.active_webauthn(session, identity.user)]


@router.post(
    "/webauthn/register/options",
    response_model=WebAuthnBeginRead,
    summary="Begin WebAuthn registration",
)
async def begin_webauthn_registration(
    request: Request,
    identity: MfaIdentity,
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> WebAuthnBeginRead:
    user_session = await _require_recent_password(session, identity)
    try:
        rp = webauthn_service.relying_party(settings, _request_origin(request))
        challenge, options = await webauthn_service.registration_options(
            session, identity.user, user_session, rp
        )
    except (ValueError, webauthn_service.WebAuthnConfigurationError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return WebAuthnBeginRead(challenge_id=challenge.id, public_key=options)


@router.post(
    "/webauthn/register/verify",
    response_model=WebAuthnRegistrationRead,
    summary="Verify WebAuthn registration",
)
async def finish_webauthn_registration(
    payload: WebAuthnRegistrationFinish,
    request: Request,
    identity: MfaIdentity,
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> WebAuthnRegistrationRead:
    user_session = await _require_recent_password(session, identity)
    try:
        rp = webauthn_service.relying_party(settings, _request_origin(request))
        challenge = await webauthn_service.consume_challenge(
            session, payload.challenge_id, identity.user, user_session, "registration"
        )
        verified = webauthn_service.verify_registration(payload.credential, challenge, rp)
    except (ValueError, WebAuthnException) as exc:
        await session.commit()
        raise HTTPException(status_code=400, detail="WebAuthn registration failed") from exc
    response = payload.credential.get("response")
    transports = response.get("transports", []) if isinstance(response, dict) else []
    credential = WebAuthnCredential(
        organization_id=identity.user.organization_id,
        user_id=identity.user.id,
        credential_id=webauthn_service.credential_id(verified.credential_id),
        credential_public_key=verified.credential_public_key,
        sign_count=verified.sign_count,
        label=payload.label,
        transports_json=[str(value) for value in transports if isinstance(value, str)],
        device_type=verified.credential_device_type.value,
        backed_up=verified.credential_backed_up,
    )
    session.add(credential)
    await session.flush()
    await mfa.complete_session_mfa(session, user_session, "webauthn")
    _record_mfa_success(session, identity, context, "webauthn")
    recovery: RecoveryCodesRead | None = None
    if await mfa.recovery_count(session, identity.user) == 0:
        recovery = RecoveryCodesRead(
            codes=await mfa.generate_recovery_codes(session, identity.user)
        )
    await mfa.revoke_other_sessions_for_mfa_change(session, identity.user, user_session)
    record_audit(
        session,
        action="auth.mfa_webauthn_enrolled",
        actor=identity.user,
        target_type="webauthn_credential",
        target_id=credential.id,
        source_ip=context.source_ip,
        user_agent=context.user_agent,
        request_id=context.request_id,
    )
    await mfa.emit_security_notification(
        session,
        identity.user,
        title="Security key added",
        summary="A WebAuthn credential was added to your Vulna account.",
    )
    return WebAuthnRegistrationRead(
        credential=_credential_read(credential),
        verification=_token(settings, identity.user, user_session, "webauthn"),
        recovery_codes=recovery,
    )


@router.post(
    "/webauthn/authenticate/options",
    response_model=WebAuthnBeginRead,
    summary="Begin WebAuthn authentication",
)
async def begin_webauthn_authentication(
    request: Request,
    identity: MfaIdentity,
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> WebAuthnBeginRead:
    user_session = _required_session(identity)
    try:
        rp = webauthn_service.relying_party(settings, _request_origin(request))
        challenge, options = await webauthn_service.authentication_options(
            session, identity.user, user_session, rp
        )
    except (ValueError, webauthn_service.WebAuthnConfigurationError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return WebAuthnBeginRead(challenge_id=challenge.id, public_key=options)


@router.post(
    "/webauthn/authenticate/verify",
    response_model=MfaVerifyResult,
    summary="Complete MFA with WebAuthn",
)
async def finish_webauthn_authentication(
    payload: WebAuthnAuthenticationFinish,
    request: Request,
    identity: MfaIdentity,
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> MfaVerifyResult:
    user_session = _required_session(identity)
    await _throttle_mfa(session, identity.user, context.source_ip)
    credential_id = payload.credential.get("id")
    credential = await session.scalar(
        select(WebAuthnCredential).where(
            WebAuthnCredential.credential_id == credential_id,
            WebAuthnCredential.user_id == identity.user.id,
            WebAuthnCredential.organization_id == identity.user.organization_id,
            WebAuthnCredential.disabled_at.is_(None),
        )
    )
    if credential is None:
        await _failed_mfa(session, identity.user, context.source_ip)
    try:
        rp = webauthn_service.relying_party(settings, _request_origin(request))
        challenge = await webauthn_service.consume_challenge(
            session, payload.challenge_id, identity.user, user_session, "authentication"
        )
        verified = webauthn_service.verify_authentication(
            payload.credential, challenge, credential, rp
        )
    except (ValueError, WebAuthnException):
        await _failed_mfa(session, identity.user, context.source_ip)
    credential.sign_count = verified.new_sign_count
    credential.device_type = verified.credential_device_type.value
    credential.backed_up = verified.credential_backed_up
    credential.last_used_at = datetime.now(UTC)
    await mfa.complete_session_mfa(session, user_session, "webauthn")
    await auth_throttle.reset_success(session, identity.user.email, context.source_ip)
    _record_mfa_success(session, identity, context, "webauthn")
    return _token(settings, identity.user, user_session, "webauthn")


@router.delete(
    "/webauthn/credentials/{credential_id}",
    status_code=204,
    summary="Disable a WebAuthn credential",
)
async def disable_webauthn_credential(
    credential_id: uuid.UUID,
    identity: MfaIdentity,
    step_up: StepUpIdentity,
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> None:
    user_session = _required_session(identity)
    credential = await session.scalar(
        select(WebAuthnCredential).where(
            WebAuthnCredential.id == credential_id,
            WebAuthnCredential.user_id == identity.user.id,
            WebAuthnCredential.organization_id == identity.user.organization_id,
            WebAuthnCredential.disabled_at.is_(None),
        )
    )
    if credential is None:
        raise HTTPException(status_code=404, detail="WebAuthn credential not found")
    policy = await mfa.get_policy(session, identity.user.organization_id)
    other_webauthn = [
        value
        for value in await mfa.active_webauthn(session, identity.user)
        if value.id != credential.id
    ]
    if (
        mfa.required_for_user(policy, identity.user)
        and await mfa.active_totp(session, identity.user) is None
        and not other_webauthn
    ):
        raise HTTPException(
            status_code=409,
            detail="Enroll another strong factor before removing required MFA",
        )
    if await mfa.active_totp(session, identity.user) is None and not other_webauthn:
        try:
            await sso.ensure_break_glass_eligibility_can_be_removed(
                session, identity.user
            )
        except sso.SsoError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
    credential.disabled_at = datetime.now(UTC)
    await mfa.revoke_other_sessions_for_mfa_change(session, identity.user, user_session)
    record_audit(
        session,
        action="auth.mfa_webauthn_disabled",
        actor=identity.user,
        target_type="webauthn_credential",
        target_id=credential.id,
        source_ip=context.source_ip,
        user_agent=context.user_agent,
        request_id=context.request_id,
    )


@router.get("/policy", response_model=MfaPolicyRead, summary="Organization MFA policy")
async def read_mfa_policy(
    admin: Annotated[User, Depends(require_admin)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> MfaPolicyRead:
    value = await mfa.get_policy(session, admin.organization_id)
    return MfaPolicyRead(**mfa.policy_dict(value))


@router.patch("/policy", response_model=MfaPolicyRead, summary="Update MFA policy")
async def update_mfa_policy(
    payload: MfaPolicyUpdate,
    admin: Annotated[User, Depends(require_admin)],
    step_up: StepUpIdentity,
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> MfaPolicyRead:
    policy = await mfa.get_policy(session, admin.organization_id)
    old = mfa.policy_dict(policy)
    changes = payload.model_dump(exclude_none=True)
    if "required_roles" in changes:
        allowed = {role.value for role in UserRole}
        unknown = set(changes["required_roles"]) - allowed
        if unknown:
            raise HTTPException(status_code=422, detail=f"Unknown roles: {sorted(unknown)}")
        policy.required_roles_json = changes["required_roles"]
    if "mode" in changes:
        policy.mode = changes["mode"]
    if "grace_period_days" in changes:
        policy.grace_period_days = changes["grace_period_days"]

    if policy.mode == "required":
        users = list(
            (
                await session.execute(
                    select(User).where(User.organization_id == admin.organization_id)
                )
            ).scalars()
        )
        now = datetime.now(UTC)
        for user in users:
            if mfa.required_for_user(policy, user) and not (
                set(await mfa.methods(session, user)) & {"totp", "webauthn"}
            ) and user.mfa_grace_expires_at is None:
                user.mfa_grace_expires_at = now + timedelta(days=policy.grace_period_days)
    record_audit(
        session,
        action="organization.mfa_policy_updated",
        actor=admin,
        target_type="mfa_policy",
        target_id=policy.id,
        source_ip=context.source_ip,
        user_agent=context.user_agent,
        request_id=context.request_id,
        metadata={"old": old, "new": mfa.policy_dict(policy)},
    )
    return MfaPolicyRead(**mfa.policy_dict(policy))
