"""Guided first-run logic (Phase 19).

Security-relevant rules live here as small, unit-testable functions:

* Detected local ranges are **advisory only** — this module never creates or
  approves a scope; it only *suggests* private ranges the operator must approve.
* Scope previews reuse the same validation as real scopes, so ``0.0.0.0/0``,
  ``::/0``, malformed input, and (by default) public ranges are rejected before
  anything is saved.
* Recovery codes are generated with a CSPRNG, shown once, and stored only as
  Argon2 hashes — consumed one at a time.
"""

from __future__ import annotations

import ipaddress
import secrets
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.password import hash_password, verify_password
from app.models.onboarding import ONBOARDING_STEPS, OnboardingState
from app.models.user import User
from app.services import presets as presetsvc
from app.services.scopes import ScopeValidationError, normalize_cidr, validate_cidr

# Thresholds for pre-approval warnings (advisory; they never block a valid,
# in-policy private range, but broad ranges require an extra confirmation).
LARGE_HOST_COUNT = 1024
BROAD_HOST_COUNT = 4096

# The isolated demo target: the local Scout assessing itself over loopback. It is
# private by construction and can never reach another host or be exposed publicly.
DEMO_TARGET = "127.0.0.1/32"

RECOVERY_CODE_COUNT = 10


# --------------------------------------------------------------------------- #
# Scan presets
# --------------------------------------------------------------------------- #

# Onboarding presents the built-in presets from the Phase 21 registry so the
# wizard and the presets API never drift. The dict shape stays what the wizard
# schema expects.
def _preset_dict(p: presetsvc.Preset) -> dict[str, Any]:
    return {
        "key": p.key,
        "name": p.name,
        "mode": p.mode,
        "description": p.description,
        "checks": [s.label for s in p.stages()],
        "intrusive": p.intrusive,
        "active_web": p.active_web,
        "uses_credentials": p.uses_credentials,
        "resource_class": p.workload_class,
        "duration_class": p.duration_class,
    }


SCAN_PRESETS: list[dict[str, Any]] = [_preset_dict(p) for p in presetsvc.list_presets()]


def get_preset(key: str) -> dict[str, Any]:
    """Return a scan preset by key, or raise ValueError."""
    try:
        return _preset_dict(presetsvc.get_preset(key))
    except presetsvc.PresetError as exc:
        raise ValueError(str(exc)) from exc


# --------------------------------------------------------------------------- #
# Advisory network detection
# --------------------------------------------------------------------------- #


def network_candidates_from_health(health: dict[str, Any] | None) -> list[str]:
    """Return advisory private CIDR suggestions from a Scout's reported health.

    Only well-formed, **private** (RFC1918 / unique-local / link-local) ranges are
    returned. Public ranges are dropped so the wizard can never suggest scanning
    the internet. The result is a suggestion list — never an approved scope.
    """
    if not health:
        return []
    raw = health.get("network_candidates")
    if not isinstance(raw, list):
        return []
    out: list[str] = []
    seen: set[str] = set()
    for item in raw:
        if not isinstance(item, str):
            continue
        try:
            net = normalize_cidr(item)
        except ScopeValidationError:
            continue
        if net.prefixlen == 0 or not net.is_private:
            continue
        canonical = str(net)
        if canonical not in seen:
            seen.add(canonical)
            out.append(canonical)
    return out


# --------------------------------------------------------------------------- #
# Scope preview and pre-scan summary
# --------------------------------------------------------------------------- #


def _host_estimate(net: ipaddress.IPv4Network | ipaddress.IPv6Network) -> int:
    """Estimate the number of scannable hosts in a network."""
    if isinstance(net, ipaddress.IPv6Network):
        # IPv6 ranges are effectively unbounded; report the address count capped.
        return min(net.num_addresses, BROAD_HOST_COUNT * 16)
    if net.prefixlen >= 31:
        return net.num_addresses  # /31, /32 have no network/broadcast reservation
    return net.num_addresses - 2  # usable hosts (exclude network + broadcast)


def scope_preview(cidr: str, *, allow_public: bool = False) -> dict[str, Any]:
    """Validate a proposed CIDR and return an advisory preview.

    Raises :class:`ScopeValidationError` for a default route, malformed input, or a
    public range without ``allow_public`` — exactly like real scope creation, so
    the wizard rejects them before saving anything. Returns host estimate and
    non-blocking warnings for large/broad/public ranges (``requires_confirmation``
    is set for public or broad ranges).
    """
    canonical = validate_cidr(cidr, allow_public=allow_public)
    net = normalize_cidr(canonical)
    hosts = _host_estimate(net)

    warnings: list[str] = []
    requires_confirmation = False
    if not net.is_private:
        warnings.append(
            "This is public IP address space. Only scan systems you are explicitly "
            "authorized to assess."
        )
        requires_confirmation = True
    if hosts >= BROAD_HOST_COUNT:
        warnings.append(
            f"This range covers about {hosts} hosts, which is unusually broad for a "
            "first assessment and will take longer and use more resources."
        )
        requires_confirmation = True
    elif hosts >= LARGE_HOST_COUNT:
        warnings.append(
            f"This range covers about {hosts} hosts; expect a longer scan."
        )

    return {
        "cidr": canonical,
        "host_estimate": hosts,
        "is_private": bool(net.is_private),
        "warnings": warnings,
        "requires_confirmation": requires_confirmation,
    }


def scan_summary(
    preset_key: str, targets: list[str], *, retention_days: int, demo: bool = False
) -> dict[str, Any]:
    """Build a pre-scan summary: targets, host estimate, checks, resource and
    duration class, and data-retention behavior. Raises on an unknown preset or an
    invalid target (default route / malformed / public)."""
    preset = get_preset(preset_key)
    total_hosts = 0
    canonical_targets: list[str] = []
    for target in targets:
        # Demo loopback and private ranges only; public would raise here.
        allow_public = False
        info = scope_preview(target, allow_public=allow_public)
        canonical_targets.append(info["cidr"])
        total_hosts += int(info["host_estimate"])

    return {
        "preset": preset["key"],
        "preset_name": preset["name"],
        "targets": canonical_targets,
        "host_estimate": total_hosts,
        "checks": preset["checks"],
        "intrusive": preset["intrusive"],
        "active_web": preset["active_web"],
        "uses_credentials": preset["uses_credentials"],
        "resource_class": preset["resource_class"],
        "duration_class": preset["duration_class"],
        "demo": demo,
        "data_retention": (
            f"Findings persist in your database; generated reports are downloadable "
            f"for {retention_days} days. Nothing is sent off-host."
        ),
    }


# --------------------------------------------------------------------------- #
# Recovery codes
# --------------------------------------------------------------------------- #


def _new_recovery_code() -> str:
    """Return a readable one-time recovery code (e.g. ``k7f2-9m3q-x84p``)."""
    alphabet = "abcdefghijkmnpqrstuvwxyz23456789"  # no ambiguous chars
    groups = ["".join(secrets.choice(alphabet) for _ in range(4)) for _ in range(3)]
    return "-".join(groups)


async def generate_recovery_codes(
    session: AsyncSession, user: User, count: int = RECOVERY_CODE_COUNT
) -> list[str]:
    """Generate, store (hashed), and return fresh one-time recovery codes.

    The plaintext codes are returned to the caller to show once; only Argon2
    hashes are persisted. Any previously generated codes are replaced.
    """
    codes = [_new_recovery_code() for _ in range(count)]
    user.recovery_codes_json = [hash_password(c) for c in codes]
    user.recovery_codes_generated_at = datetime.now(UTC)
    session.add(user)
    await session.flush()
    return codes


async def verify_and_consume_recovery_code(
    session: AsyncSession, user: User, code: str
) -> bool:
    """Verify a submitted recovery code and consume it if valid.

    Returns True and removes the matching hash on success; False otherwise. The
    comparison uses the same Argon2 verification as passwords.
    """
    remaining = list(user.recovery_codes_json or [])
    normalized = code.strip().lower()
    for i, hashed in enumerate(remaining):
        if verify_password(normalized, hashed):
            del remaining[i]
            user.recovery_codes_json = remaining
            session.add(user)
            await session.flush()
            return True
    return False


# --------------------------------------------------------------------------- #
# Wizard state
# --------------------------------------------------------------------------- #


async def get_or_create_state(session: AsyncSession, org_id: Any) -> OnboardingState:
    """Return the organization's onboarding state, creating it if absent."""
    result = await session.execute(
        select(OnboardingState).where(OnboardingState.organization_id == org_id)
    )
    state = result.scalar_one_or_none()
    if state is not None:
        return state
    state = OnboardingState(organization_id=org_id, current_step="admin")
    session.add(state)
    await session.flush()
    return state


def _next_step(step: str) -> str:
    try:
        idx = ONBOARDING_STEPS.index(step)
    except ValueError:
        return step
    if idx + 1 < len(ONBOARDING_STEPS):
        return ONBOARDING_STEPS[idx + 1]
    return step


async def complete_step(
    session: AsyncSession,
    state: OnboardingState,
    step: str,
    **refs: Any,
) -> OnboardingState:
    """Mark a step complete (idempotent) and advance the resume point.

    Re-completing an already-done step is a no-op — refreshing the browser never
    duplicates work. ``refs`` sets soft references (site_id, scope_id,
    first_job_id, demo_used).
    """
    if step not in ONBOARDING_STEPS:
        raise ValueError(f"Unknown onboarding step '{step}'")

    done = list(state.completed_steps_json or [])
    if step not in done:
        done.append(step)
        state.completed_steps_json = done

    for key in ("site_id", "scope_id", "first_job_id", "demo_used"):
        if key in refs and refs[key] is not None:
            setattr(state, key, refs[key])

    # Advance the resume pointer to the furthest not-yet-done step.
    nxt = _next_step(step)
    cur_idx = (
        ONBOARDING_STEPS.index(state.current_step)
        if state.current_step in ONBOARDING_STEPS
        else 0
    )
    if ONBOARDING_STEPS.index(nxt) > cur_idx:
        state.current_step = nxt

    if all(s in done for s in ONBOARDING_STEPS) and state.completed_at is None:
        state.completed_at = datetime.now(UTC)

    session.add(state)
    await session.flush()
    return state
