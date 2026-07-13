"""SCIM 2.0 protocol primitives, token authentication, and access mapping."""

from __future__ import annotations

import hashlib
import json
import re
import secrets
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Annotated

from email_validator import EmailNotValidError, validate_email
from fastapi import Depends, Request
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import delete, func, select
from sqlalchemy.dialects.postgresql import insert as postgresql_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.context import get_request_context
from app.core.config import Settings, get_settings
from app.db.session import get_session
from app.models.enums import (
    AccountStatus,
    ActorType,
    AuthenticationSource,
    SiteAccessMode,
    UserRole,
)
from app.models.scim import (
    ScimGroup,
    ScimGroupMember,
    ScimGroupSiteMapping,
    ScimProvisioningLog,
    ScimRateLimitWindow,
    ScimToken,
)
from app.models.user import User
from app.models.user_lifecycle import UserSiteAssignment
from app.services.audit import record_audit
from app.services.sessions import revoke_user_sessions
from app.services.user_lifecycle import active_admin_count, lifecycle_event

SCIM_USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
SCIM_GROUP_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:Group"
SCIM_ENTERPRISE_USER_SCHEMA = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
SCIM_LIST_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
SCIM_PATCH_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
SCIM_ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error"
SCIM_SERVICE_PROVIDER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"
SCIM_RESOURCE_TYPE_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:ResourceType"
SCIM_SCHEMA_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:Schema"
SCIM_MEDIA_TYPE = "application/scim+json"

_TOKEN_PREFIX = "vscim"  # noqa: S105 - identifying prefix, not a credential
_bearer = HTTPBearer(auto_error=False, description="Organization SCIM bearer token")
_ROLE_PRIORITY = {
    UserRole.ADMINISTRATOR: 60,
    UserRole.SECURITY_OPERATOR: 50,
    UserRole.PENTEST_APPROVER: 40,
    UserRole.REMEDIATION_OWNER: 30,
    UserRole.AUDITOR: 20,
    UserRole.VIEWER: 10,
}


def aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=UTC)


def utcnow() -> datetime:
    return datetime.now(UTC)


def _iso(value: datetime) -> str:
    return aware(value).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True)
class GeneratedScimToken:
    secret: str
    token_hash: str
    token_prefix: str


def hash_token(secret: str) -> str:
    return hashlib.sha256(secret.strip().encode("utf-8")).hexdigest()


def generate_token() -> GeneratedScimToken:
    secret = f"{_TOKEN_PREFIX}_{secrets.token_urlsafe(48)}"
    return GeneratedScimToken(
        secret=secret,
        token_hash=hash_token(secret),
        token_prefix=secret[:18],
    )


class ScimError(Exception):
    """Expected protocol error serialized using the RFC 7644 error schema."""

    def __init__(self, status_code: int, detail: str, scim_type: str | None = None) -> None:
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail
        self.scim_type = scim_type


def error_response(error: ScimError) -> JSONResponse:
    body: dict[str, object] = {
        "schemas": [SCIM_ERROR_SCHEMA],
        "status": str(error.status_code),
        "detail": error.detail,
    }
    if error.scim_type:
        body["scimType"] = error.scim_type
    headers = {"WWW-Authenticate": "Bearer"} if error.status_code == 401 else None
    return JSONResponse(
        status_code=error.status_code,
        content=body,
        media_type=SCIM_MEDIA_TYPE,
        headers=headers,
    )


@dataclass(frozen=True)
class ScimContext:
    token_id: uuid.UUID
    organization_id: uuid.UUID
    source_ip: str | None
    request_id: str | None


async def get_scim_context(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> ScimContext:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise ScimError(401, "Authentication is required")
    token = await session.scalar(
        select(ScimToken).where(ScimToken.token_hash == hash_token(credentials.credentials))
    )
    now = utcnow()
    if token is None or token.revoked_at is not None or aware(token.expires_at) <= now:
        raise ScimError(401, "The SCIM bearer token is invalid or expired")

    context = get_request_context(request)
    scim_context = ScimContext(
        token_id=token.id,
        organization_id=token.organization_id,
        source_ip=context.source_ip,
        request_id=context.request_id,
    )
    request.state.scim_context = scim_context
    request.state.scim_bind = session.bind
    token.last_used_at = now
    token.last_used_ip = context.source_ip

    window_start = now.replace(second=0, microsecond=0)
    request_count = await _increment_rate_limit(session, token.id, window_start)
    # Persist token usage and the counter before route work. A rejected request
    # must still consume its rate-limit slot even when route mutations roll back.
    await session.commit()
    if request_count > settings.scim_rate_limit_per_minute:
        raise ScimError(429, "SCIM request rate limit exceeded", "tooMany")
    return scim_context


ScimIdentity = Annotated[ScimContext, Depends(get_scim_context)]


async def _increment_rate_limit(
    session: AsyncSession, token_id: uuid.UUID, window_start: datetime
) -> int:
    """Atomically increment the fixed window on SQLite and PostgreSQL."""
    bind = session.get_bind()
    values = {
        "id": uuid.uuid4(),
        "token_id": token_id,
        "window_started_at": window_start,
        "request_count": 1,
    }
    if bind.dialect.name == "postgresql":
        pg_statement = postgresql_insert(ScimRateLimitWindow).values(**values)
        await session.execute(
            pg_statement.on_conflict_do_update(
                index_elements=["token_id", "window_started_at"],
                set_={
                    "request_count": ScimRateLimitWindow.request_count + 1,
                },
            )
        )
    elif bind.dialect.name == "sqlite":
        sqlite_statement = sqlite_insert(ScimRateLimitWindow).values(**values)
        await session.execute(
            sqlite_statement.on_conflict_do_update(
                index_elements=["token_id", "window_started_at"],
                set_={
                    "request_count": ScimRateLimitWindow.request_count + 1,
                },
            )
        )
    else:
        window = await session.scalar(
            select(ScimRateLimitWindow).where(
                ScimRateLimitWindow.token_id == token_id,
                ScimRateLimitWindow.window_started_at == window_start,
            )
        )
        if window is None:
            window = ScimRateLimitWindow(**values)
            session.add(window)
        else:
            window.request_count += 1
    count = await session.scalar(
        select(ScimRateLimitWindow.request_count).where(
            ScimRateLimitWindow.token_id == token_id,
            ScimRateLimitWindow.window_started_at == window_start,
        )
    )
    return int(count or 0)


def log_provisioning(
    session: AsyncSession,
    *,
    context: ScimContext,
    operation: str,
    status_code: int,
    succeeded: bool,
    resource_type: str | None = None,
    resource_id: str | uuid.UUID | None = None,
    external_id: str | None = None,
    detail: str | None = None,
    changes: dict[str, object] | None = None,
) -> ScimProvisioningLog:
    value = ScimProvisioningLog(
        organization_id=context.organization_id,
        token_id=context.token_id,
        operation=operation[:32],
        resource_type=resource_type[:32] if resource_type else None,
        resource_id=str(resource_id) if resource_id is not None else None,
        external_id=external_id[:512] if external_id else None,
        status_code=status_code,
        succeeded=succeeded,
        detail=detail[:1024] if detail else None,
        request_id=context.request_id,
        source_ip=context.source_ip,
        changes_json=changes or {},
    )
    session.add(value)
    record_audit(
        session,
        action=f"scim.{operation}",
        actor_type=ActorType.SYSTEM,
        organization_id=context.organization_id,
        target_type=f"scim_{resource_type.lower()}" if resource_type else "scim",
        target_id=resource_id,
        source_ip=context.source_ip,
        request_id=context.request_id,
        metadata={
            "token_id": str(context.token_id),
            "status_code": status_code,
            "succeeded": succeeded,
            **(changes or {}),
        },
    )
    return value


async def log_failed_request(request: Request, error: ScimError) -> None:
    """Persist valid-token protocol failures in a separate transaction."""
    context = getattr(request.state, "scim_context", None)
    if not isinstance(context, ScimContext):
        return
    bind = getattr(request.state, "scim_bind", None)
    if bind is None:
        return
    resource_type: str | None = None
    parts = [part for part in request.url.path.split("/") if part]
    if len(parts) >= 3 and parts[2] in {"Users", "Groups"}:
        resource_type = parts[2][:-1]
    async with AsyncSession(bind=bind, expire_on_commit=False) as session:
        log_provisioning(
            session,
            context=context,
            operation=request.method.lower(),
            status_code=error.status_code,
            succeeded=False,
            resource_type=resource_type,
            detail=error.detail,
            changes={"scim_type": error.scim_type} if error.scim_type else {},
        )
        await session.commit()


def base_url(request: Request, settings: Settings) -> str:
    return (settings.public_base_url or str(request.base_url)).rstrip("/") + "/scim/v2"


def _version(value: object) -> str:
    digest = hashlib.sha256(json.dumps(value, sort_keys=True, default=str).encode()).hexdigest()
    return f'W/"{digest[:24]}"'


async def user_resource(session: AsyncSession, user: User, resource_base: str) -> dict[str, object]:
    memberships = list(
        (
            await session.execute(
                select(ScimGroup)
                .join(ScimGroupMember, ScimGroupMember.group_id == ScimGroup.id)
                .where(
                    ScimGroupMember.organization_id == user.organization_id,
                    ScimGroupMember.user_id == user.id,
                )
                .order_by(ScimGroup.display_name.asc())
            )
        ).scalars()
    )
    value: dict[str, object] = {
        "schemas": [SCIM_USER_SCHEMA],
        "id": str(user.id),
        "userName": user.email,
        "active": user.account_status == AccountStatus.ACTIVE and user.is_active,
        "emails": [{"value": user.email, "type": "work", "primary": True}],
        "roles": [{"value": user.role.value, "primary": True}],
        "groups": [
            {
                "value": str(group.id),
                "$ref": f"{resource_base}/Groups/{group.id}",
                "display": group.display_name,
                "type": "direct",
            }
            for group in memberships
        ],
        "meta": {
            "resourceType": "User",
            "created": _iso(user.created_at),
            "lastModified": _iso(user.updated_at),
            "location": f"{resource_base}/Users/{user.id}",
            "version": _version(
                [user.updated_at, user.email, user.account_status, user.scim_external_id]
            ),
        },
    }
    if user.scim_external_id:
        value["externalId"] = user.scim_external_id
    if user.full_name:
        value["displayName"] = user.full_name
        value["name"] = {"formatted": user.full_name}
    return value


async def group_resource(
    session: AsyncSession, group: ScimGroup, resource_base: str
) -> dict[str, object]:
    members = list(
        (
            await session.execute(
                select(User)
                .join(ScimGroupMember, ScimGroupMember.user_id == User.id)
                .where(
                    ScimGroupMember.organization_id == group.organization_id,
                    ScimGroupMember.group_id == group.id,
                )
                .order_by(User.email.asc())
            )
        ).scalars()
    )
    value: dict[str, object] = {
        "schemas": [SCIM_GROUP_SCHEMA],
        "id": str(group.id),
        "displayName": group.display_name,
        "members": [
            {
                "value": str(user.id),
                "$ref": f"{resource_base}/Users/{user.id}",
                "display": user.email,
                "type": "User",
            }
            for user in members
        ],
        "meta": {
            "resourceType": "Group",
            "created": _iso(group.created_at),
            "lastModified": _iso(group.updated_at),
            "location": f"{resource_base}/Groups/{group.id}",
            "version": _version(
                [
                    group.updated_at,
                    group.display_name,
                    group.external_id,
                    [user.id for user in members],
                ]
            ),
        },
    }
    if group.external_id:
        value["externalId"] = group.external_id
    return value


def project_resource(
    resource: dict[str, object], attributes: str | None, excluded_attributes: str | None
) -> dict[str, object]:
    """Apply RFC attribute projection while retaining common required fields."""
    required = {"schemas", "id", "meta"}
    result = dict(resource)
    if attributes:
        wanted = {
            item.strip().split(".", 1)[0].lower() for item in attributes.split(",") if item.strip()
        }
        result = {
            key: value
            for key, value in resource.items()
            if key in required or key.lower() in wanted
        }
    if excluded_attributes:
        excluded = {
            item.strip().split(".", 1)[0].lower()
            for item in excluded_attributes.split(",")
            if item.strip()
        }
        result = {
            key: value
            for key, value in result.items()
            if key in required or key.lower() not in excluded
        }
    return result


# ---- Safe SCIM filter parser -------------------------------------------------

_FILTER_TOKEN = re.compile(
    r'\s*(?:(?P<string>"(?:[^"\\]|\\.)*")|(?P<number>-?\d+(?:\.\d+)?)|'
    r"(?P<word>[A-Za-z_$][A-Za-z0-9_$:.-]*)|(?P<lparen>\()|(?P<rparen>\))|"
    r"(?P<lbracket>\[)|(?P<rbracket>\]))"
)


class _FilterParser:
    def __init__(self, expression: str) -> None:
        self.tokens: list[tuple[str, object]] = []
        position = 0
        while position < len(expression):
            match = _FILTER_TOKEN.match(expression, position)
            if match is None:
                raise ScimError(400, "The SCIM filter is invalid", "invalidFilter")
            position = match.end()
            kind = match.lastgroup
            raw = match.group(kind) if kind else ""
            if kind == "string":
                try:
                    self.tokens.append(("value", json.loads(raw)))
                except json.JSONDecodeError as exc:
                    raise ScimError(400, "The SCIM filter is invalid", "invalidFilter") from exc
            elif kind == "number":
                self.tokens.append(("value", float(raw) if "." in raw else int(raw)))
            elif kind == "word":
                lower = raw.lower()
                if lower == "true":
                    self.tokens.append(("value", True))
                elif lower == "false":
                    self.tokens.append(("value", False))
                elif lower == "null":
                    self.tokens.append(("value", None))
                else:
                    self.tokens.append(("word", raw))
            else:
                self.tokens.append((kind or "", raw))
        self.position = 0

    def parse(self) -> object:
        value = self._or()
        if self.position != len(self.tokens):
            raise ScimError(400, "The SCIM filter is invalid", "invalidFilter")
        return value

    def _peek(self, kind: str, value: str | None = None) -> bool:
        if self.position >= len(self.tokens):
            return False
        token_kind, token_value = self.tokens[self.position]
        return token_kind == kind and (value is None or str(token_value).lower() == value.lower())

    def _take(self, kind: str, value: str | None = None) -> object:
        if not self._peek(kind, value):
            raise ScimError(400, "The SCIM filter is invalid", "invalidFilter")
        token = self.tokens[self.position][1]
        self.position += 1
        return token

    def _or(self) -> object:
        value = self._and()
        while self._peek("word", "or"):
            self._take("word")
            value = ("or", value, self._and())
        return value

    def _and(self) -> object:
        value = self._not()
        while self._peek("word", "and"):
            self._take("word")
            value = ("and", value, self._not())
        return value

    def _not(self) -> object:
        if self._peek("word", "not"):
            self._take("word")
            return ("not", self._not())
        return self._primary()

    def _primary(self) -> object:
        if self._peek("lparen"):
            self._take("lparen")
            value = self._or()
            self._take("rparen")
            return value
        attribute = str(self._take("word"))
        if self._peek("lbracket"):
            self._take("lbracket")
            nested = self._or()
            self._take("rbracket")
            return ("path", attribute, nested)
        operator = str(self._take("word")).lower()
        if operator == "pr":
            return ("compare", attribute, operator, None)
        if operator not in {"eq", "ne", "co", "sw", "ew", "gt", "ge", "lt", "le"}:
            raise ScimError(400, "The SCIM filter operator is unsupported", "invalidFilter")
        if not self._peek("value"):
            raise ScimError(400, "The SCIM filter value is invalid", "invalidFilter")
        return ("compare", attribute, operator, self._take("value"))


def _case_get(value: dict[str, object], key: str) -> object:
    lower = key.lower()
    for candidate, item in value.items():
        if candidate.lower() == lower:
            return item
    return None


def _attribute_values(resource: object, path: str) -> list[object]:
    values = [resource]
    for part in path.split("."):
        next_values: list[object] = []
        for value in values:
            if isinstance(value, dict):
                item = _case_get(value, part)
                if isinstance(item, list):
                    next_values.extend(item)
                elif item is not None:
                    next_values.append(item)
            elif isinstance(value, list):
                next_values.extend(value)
        values = next_values
    return values


def _equal(left: object, right: object) -> bool:
    if isinstance(left, str) and isinstance(right, str):
        return left.casefold() == right.casefold()
    return left == right


def _compare(left: object, operator: str, right: object) -> bool:
    if operator == "eq":
        return _equal(left, right)
    if operator == "ne":
        return not _equal(left, right)
    if operator in {"co", "sw", "ew"}:
        if not isinstance(left, str) or not isinstance(right, str):
            return False
        lhs, rhs = left.casefold(), right.casefold()
        return (
            rhs in lhs
            if operator == "co"
            else (lhs.startswith(rhs) if operator == "sw" else lhs.endswith(rhs))
        )
    try:
        if operator == "gt":
            return bool(left > right)  # type: ignore[operator]
        if operator == "ge":
            return bool(left >= right)  # type: ignore[operator]
        if operator == "lt":
            return bool(left < right)  # type: ignore[operator]
        if operator == "le":
            return bool(left <= right)  # type: ignore[operator]
    except TypeError:
        return False
    return False


def _evaluate_filter(node: object, resource: dict[str, object]) -> bool:
    if not isinstance(node, tuple):
        return False
    kind = node[0]
    if kind == "and":
        return _evaluate_filter(node[1], resource) and _evaluate_filter(node[2], resource)
    if kind == "or":
        return _evaluate_filter(node[1], resource) or _evaluate_filter(node[2], resource)
    if kind == "not":
        return not _evaluate_filter(node[1], resource)
    if kind == "path":
        values = _attribute_values(resource, str(node[1]))
        return any(isinstance(item, dict) and _evaluate_filter(node[2], item) for item in values)
    if kind == "compare":
        values = _attribute_values(resource, str(node[1]))
        operator = str(node[2])
        if operator == "pr":
            return bool(values)
        if operator == "ne":
            return bool(values) and all(_compare(value, operator, node[3]) for value in values)
        return any(_compare(value, operator, node[3]) for value in values)
    return False


def filter_resources(
    resources: list[dict[str, object]], expression: str | None
) -> list[dict[str, object]]:
    if not expression:
        return resources
    if len(expression) > 2048:
        raise ScimError(400, "The SCIM filter is too long", "invalidFilter")
    ast = _FilterParser(expression).parse()
    return [resource for resource in resources if _evaluate_filter(ast, resource)]


def page_resources(
    resources: list[dict[str, object]], start_index: int, count: int
) -> dict[str, object]:
    start = max(1, start_index)
    offset = start - 1
    page = resources[offset : offset + max(0, count)]
    return {
        "schemas": [SCIM_LIST_SCHEMA],
        "totalResults": len(resources),
        "startIndex": start,
        "itemsPerPage": len(page),
        "Resources": page,
    }


def require_schema(payload: dict[str, object], schema: str) -> None:
    schemas = payload.get("schemas")
    if not isinstance(schemas, list) or schema not in schemas:
        raise ScimError(400, "The required SCIM schema is missing", "invalidSyntax")


def normalized_email(payload: dict[str, object]) -> str:
    candidate = payload.get("userName")
    if not isinstance(candidate, str) or not candidate.strip():
        emails = payload.get("emails")
        if isinstance(emails, list):
            primary = next(
                (
                    value.get("value")
                    for value in emails
                    if isinstance(value, dict) and value.get("primary") is True
                ),
                None,
            )
            if not isinstance(primary, str):
                primary = next(
                    (
                        value.get("value")
                        for value in emails
                        if isinstance(value, dict) and isinstance(value.get("value"), str)
                    ),
                    None,
                )
            candidate = primary
    if not isinstance(candidate, str) or not candidate.strip():
        raise ScimError(400, "userName is required", "invalidValue")
    try:
        return validate_email(candidate, check_deliverability=False).normalized.lower()
    except EmailNotValidError as exc:
        raise ScimError(400, "userName must be a valid email address", "invalidValue") from exc


def display_name(payload: dict[str, object]) -> str | None:
    direct = payload.get("displayName")
    if isinstance(direct, str) and direct.strip():
        return direct.strip()[:255]
    name = payload.get("name")
    if isinstance(name, dict):
        formatted = name.get("formatted")
        if isinstance(formatted, str) and formatted.strip():
            return formatted.strip()[:255]
        parts = [name.get("givenName"), name.get("familyName")]
        combined = " ".join(str(value).strip() for value in parts if value)
        return combined[:255] or None
    return None


def external_id(payload: dict[str, object]) -> str | None:
    value = payload.get("externalId")
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip() or len(value.strip()) > 512:
        raise ScimError(400, "externalId is invalid", "invalidValue")
    return value.strip()


async def ensure_user_unique(
    session: AsyncSession,
    *,
    organization_id: uuid.UUID,
    email: str,
    external: str | None,
    exclude_user_id: uuid.UUID | None = None,
) -> None:
    email_stmt = select(User.id).where(func.lower(User.email) == email.lower())
    if exclude_user_id:
        email_stmt = email_stmt.where(User.id != exclude_user_id)
    if await session.scalar(email_stmt):
        raise ScimError(409, "A user with that userName already exists", "uniqueness")
    if external:
        external_stmt = select(User.id).where(
            User.organization_id == organization_id,
            User.scim_external_id == external,
        )
        if exclude_user_id:
            external_stmt = external_stmt.where(User.id != exclude_user_id)
        if await session.scalar(external_stmt):
            raise ScimError(409, "A user with that externalId already exists", "uniqueness")


async def ensure_group_unique(
    session: AsyncSession,
    *,
    organization_id: uuid.UUID,
    name: str,
    external: str | None,
    exclude_group_id: uuid.UUID | None = None,
) -> None:
    name_stmt = select(ScimGroup.id).where(
        ScimGroup.organization_id == organization_id,
        func.lower(ScimGroup.display_name) == name.lower(),
    )
    if exclude_group_id:
        name_stmt = name_stmt.where(ScimGroup.id != exclude_group_id)
    if await session.scalar(name_stmt):
        raise ScimError(409, "A group with that displayName already exists", "uniqueness")
    if external:
        ext_stmt = select(ScimGroup.id).where(
            ScimGroup.organization_id == organization_id,
            ScimGroup.external_id == external,
        )
        if exclude_group_id:
            ext_stmt = ext_stmt.where(ScimGroup.id != exclude_group_id)
        if await session.scalar(ext_stmt):
            raise ScimError(409, "A group with that externalId already exists", "uniqueness")


async def replace_group_members(
    session: AsyncSession,
    *,
    group: ScimGroup,
    member_ids: set[uuid.UUID],
) -> set[uuid.UUID]:
    existing_ids = set(
        (
            await session.execute(
                select(ScimGroupMember.user_id).where(
                    ScimGroupMember.organization_id == group.organization_id,
                    ScimGroupMember.group_id == group.id,
                )
            )
        ).scalars()
    )
    if member_ids:
        found = set(
            (
                await session.execute(
                    select(User.id).where(
                        User.organization_id == group.organization_id,
                        User.authentication_source == AuthenticationSource.SCIM,
                        User.id.in_(member_ids),
                    )
                )
            ).scalars()
        )
        if found != member_ids:
            raise ScimError(400, "One or more group members do not exist", "invalidValue")
    await session.execute(delete(ScimGroupMember).where(ScimGroupMember.group_id == group.id))
    session.add_all(
        [
            ScimGroupMember(
                organization_id=group.organization_id,
                group_id=group.id,
                user_id=user_id,
            )
            for user_id in sorted(member_ids, key=str)
        ]
    )
    return existing_ids | member_ids


def member_ids(payload: dict[str, object]) -> set[uuid.UUID]:
    raw_members = payload.get("members", [])
    if raw_members is None:
        return set()
    if not isinstance(raw_members, list) or len(raw_members) > 10000:
        raise ScimError(400, "members must be an array", "invalidValue")
    result: set[uuid.UUID] = set()
    for member in raw_members:
        if not isinstance(member, dict) or not isinstance(member.get("value"), str):
            raise ScimError(400, "Every group member must include value", "invalidValue")
        if str(member.get("type", "User")).lower() != "user":
            raise ScimError(400, "Nested SCIM groups are not supported", "invalidValue")
        try:
            result.add(uuid.UUID(member["value"]))
        except (ValueError, TypeError) as exc:
            raise ScimError(400, "A group member id is invalid", "invalidValue") from exc
    return result


async def recompute_scim_access(
    session: AsyncSession,
    user: User,
    *,
    actor: User | None = None,
) -> bool:
    """Derive compatibility role/site access from all direct SCIM memberships."""
    if user.authentication_source != AuthenticationSource.SCIM:
        return False
    groups = list(
        (
            await session.execute(
                select(ScimGroup)
                .join(ScimGroupMember, ScimGroupMember.group_id == ScimGroup.id)
                .where(
                    ScimGroupMember.organization_id == user.organization_id,
                    ScimGroupMember.user_id == user.id,
                )
            )
        ).scalars()
    )
    roles = [group.mapped_role for group in groups if group.mapped_role is not None]
    desired_role = max(roles, key=lambda role: _ROLE_PRIORITY[role]) if roles else UserRole.VIEWER
    grants_all = any(group.grants_all_sites for group in groups)
    group_ids = [group.id for group in groups]
    site_ids: set[uuid.UUID] = set()
    if group_ids and not grants_all:
        site_ids = set(
            (
                await session.execute(
                    select(ScimGroupSiteMapping.site_id).where(
                        ScimGroupSiteMapping.organization_id == user.organization_id,
                        ScimGroupSiteMapping.group_id.in_(group_ids),
                    )
                )
            ).scalars()
        )
    desired_mode = SiteAccessMode.ALL if grants_all else SiteAccessMode.ASSIGNED
    previous_site_ids = set(
        (
            await session.execute(
                select(UserSiteAssignment.site_id).where(
                    UserSiteAssignment.organization_id == user.organization_id,
                    UserSiteAssignment.user_id == user.id,
                )
            )
        ).scalars()
    )
    changed = (
        user.role != desired_role
        or user.site_access_mode != desired_mode
        or (not grants_all and previous_site_ids != site_ids)
        or (grants_all and bool(previous_site_ids))
    )
    if not changed:
        return False
    if (
        user.role == UserRole.ADMINISTRATOR
        and desired_role != UserRole.ADMINISTRATOR
        and user.account_status == AccountStatus.ACTIVE
        and await active_admin_count(session, user.organization_id, exclude_user_id=user.id) == 0
    ):
        raise ScimError(409, "The last active administrator cannot be demoted", "mutability")

    previous = {
        "role": user.role.value,
        "site_access_mode": user.site_access_mode.value,
        "site_ids": sorted(str(value) for value in previous_site_ids),
    }
    user.role = desired_role
    user.site_access_mode = desired_mode
    await session.execute(delete(UserSiteAssignment).where(UserSiteAssignment.user_id == user.id))
    if not grants_all:
        session.add_all(
            [
                UserSiteAssignment(
                    organization_id=user.organization_id,
                    user_id=user.id,
                    site_id=site_id,
                    assigned_by_user_id=actor.id if actor else None,
                )
                for site_id in sorted(site_ids, key=str)
            ]
        )
    user.auth_version += 1
    await revoke_user_sessions(session, user.id, reason="SCIM access mapping changed")
    lifecycle_event(
        session,
        user=user,
        event_type="scim_access_mapped",
        actor=actor,
        reason="SCIM group mappings changed",
        metadata={
            "previous": previous,
            "role": desired_role.value,
            "site_access_mode": desired_mode.value,
            "site_ids": sorted(str(value) for value in site_ids),
        },
    )
    return True


async def recompute_users(
    session: AsyncSession,
    organization_id: uuid.UUID,
    user_ids: set[uuid.UUID],
    *,
    actor: User | None = None,
) -> int:
    if not user_ids:
        return 0
    users = list(
        (
            await session.execute(
                select(User).where(
                    User.organization_id == organization_id,
                    User.id.in_(user_ids),
                )
            )
        ).scalars()
    )
    changed = 0
    for user in users:
        changed += int(await recompute_scim_access(session, user, actor=actor))
    return changed
