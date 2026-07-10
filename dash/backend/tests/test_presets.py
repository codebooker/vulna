"""Opinionated scan presets, tuning, and custom-preset validation (Phase 21)."""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable

import pytest
from app.models.probe import Probe
from app.services import presets as ps
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

EnrolledProbe = dict[str, str]


# --------------------------------------------------------------------------- #
# Registry + resolution
# --------------------------------------------------------------------------- #


def test_builtin_presets_present_and_safe() -> None:
    keys = {p.key for p in ps.list_presets()}
    assert {"quick", "standard", "fragile", "web_tls", "deep_safe"} <= keys
    # No built-in preset may be intrusive or enable active web / credentials, and
    # every stage must be passive/safe (intrusive never hidden in a preset).
    for preset in ps.list_presets():
        assert not preset.intrusive and not preset.active_web and not preset.uses_credentials
        for stage in preset.stages():
            assert stage.classification in ps.SAFE_CLASSES


def test_get_preset_version_pinning() -> None:
    p = ps.get_preset("standard", version=1)
    assert p.version == 1
    with pytest.raises(ps.PresetError):
        ps.get_preset("standard", version=999)
    with pytest.raises(ps.PresetError):
        ps.get_preset("does-not-exist")


def test_fragile_uses_conservative_rates() -> None:
    fragile = ps.get_preset("fragile")
    standard = ps.get_preset("standard")
    assert fragile.rate.packets_per_second < standard.rate.packets_per_second
    assert fragile.rate.concurrency <= standard.rate.concurrency


def test_resolve_stages_missing_scanner_blocks_without_downgrade() -> None:
    standard = ps.get_preset("standard")
    only_nmap = {"nmap"}
    res = ps.resolve_stages(standard, only_nmap, allow_downgrade=False)
    assert res.blocked is True
    skipped_stages = {s.stage for s in res.skipped}
    assert "vuln" in skipped_stages and "tls" in skipped_stages
    assert all(s.reason for s in res.skipped)  # every omission is explained


def test_resolve_stages_downgrade_runs_available_only() -> None:
    standard = ps.get_preset("standard")
    res = ps.resolve_stages(standard, {"nmap"}, allow_downgrade=True)
    assert res.blocked is False
    assert {s.key for s in res.run} == {"discovery", "service_detection"}


def test_estimate_is_ranges_not_precision() -> None:
    est = ps.estimate(ps.get_preset("standard"), host_count=300)
    assert est["size_class"] == "large"
    assert "minute" in est["duration_range"] or "hour" in est["duration_range"]


def test_tuning_never_exceeds_policy_limits() -> None:
    deep = ps.get_preset("deep_safe")  # concurrency 6
    tuned = ps.recommend_tuning(
        deep, cpu_count=32, memory_bytes=64 << 30, max_pps=50, max_concurrency=2
    )
    assert tuned.concurrency <= 2  # hard policy clamp wins over hardware
    assert tuned.packets_per_second <= 50


# --------------------------------------------------------------------------- #
# Custom-preset validation (security-critical)
# --------------------------------------------------------------------------- #


def test_custom_valid() -> None:
    p = ps.validate_custom(
        {"name": "My Preset", "stage_keys": ["discovery", "tls"], "packets_per_second": 50}
    )
    assert p.key == "custom"
    assert {s.key for s in p.stages()} == {"discovery", "tls"}


def test_custom_rejects_unknown_stage() -> None:
    with pytest.raises(ps.PresetError):
        ps.validate_custom({"name": "x", "stage_keys": ["exploit_everything"]})


def test_custom_rejects_raw_commands() -> None:
    # Any attempt to smuggle raw commands/scripts/templates is refused.
    for forbidden in ("command", "args", "script", "scripts", "templates", "shell", "exec"):
        with pytest.raises(ps.PresetError):
            ps.validate_custom(
                {"name": "x", "stage_keys": ["discovery"], forbidden: "nmap --script vuln"}
            )


def test_custom_rejects_out_of_bounds_rates() -> None:
    with pytest.raises(ps.PresetError):
        ps.validate_custom(
            {"name": "x", "stage_keys": ["discovery"], "packets_per_second": 100000}
        )
    with pytest.raises(ps.PresetError):
        ps.validate_custom({"name": "x", "stage_keys": ["discovery"], "concurrency": 999})


def test_custom_rejects_bad_severities() -> None:
    with pytest.raises(ps.PresetError):
        ps.validate_custom(
            {"name": "x", "stage_keys": ["vuln"], "severities": ["catastrophic"]}
        )


# --------------------------------------------------------------------------- #
# API
# --------------------------------------------------------------------------- #


async def test_list_and_get_presets(
    client: AsyncClient, admin_headers: dict[str, str]
) -> None:
    r = await client.get("/api/v1/presets", headers=admin_headers)
    assert r.status_code == 200
    keys = [p["key"] for p in r.json()["presets"]]
    assert "standard" in keys and "fragile" in keys

    one = await client.get("/api/v1/presets/standard?version=1", headers=admin_headers)
    assert one.status_code == 200
    assert one.json()["intrusive"] is False

    missing = await client.get("/api/v1/presets/nope", headers=admin_headers)
    assert missing.status_code == 404


async def test_preview_no_probe_runs_full_pack(
    client: AsyncClient, admin_headers: dict[str, str]
) -> None:
    r = await client.post(
        "/api/v1/presets/preview",
        json={"preset_key": "standard", "host_count": 100},
        headers=admin_headers,
    )
    assert r.status_code == 200
    body = r.json()
    assert body["blocked"] is False
    assert len(body["stages_to_run"]) == 4
    assert body["estimate"]["duration_range"]
    assert body["tuning"]["concurrency"] >= 1


async def test_preview_missing_scanner_blocks(
    client: AsyncClient,
    admin_headers: dict[str, str],
    db_session: AsyncSession,
    enroll_probe: Callable[..., Awaitable[EnrolledProbe]],
) -> None:
    probe = await enroll_probe()
    # This Scout only has nmap installed.
    row = await db_session.get(Probe, uuid.UUID(probe["probe_id"]))
    assert row is not None
    row.capabilities_json = ["nmap"]
    db_session.add(row)
    await db_session.commit()

    r = await client.post(
        "/api/v1/presets/preview",
        json={"preset_key": "standard", "probe_id": probe["probe_id"], "allow_downgrade": False},
        headers=admin_headers,
    )
    assert r.status_code == 200
    body = r.json()
    assert body["blocked"] is True  # missing scanner surfaces before the job runs
    assert any(s["stage"] == "vuln" for s in body["skipped"])


async def test_custom_validate_endpoint(
    client: AsyncClient, admin_headers: dict[str, str]
) -> None:
    ok = await client.post(
        "/api/v1/presets/custom/validate",
        json={"name": "Mine", "stage_keys": ["discovery", "tls"]},
        headers=admin_headers,
    )
    assert ok.status_code == 200

    bad = await client.post(
        "/api/v1/presets/custom/validate",
        json={"name": "Mine", "stage_keys": ["definitely-not-a-stage"]},
        headers=admin_headers,
    )
    assert bad.status_code == 422
