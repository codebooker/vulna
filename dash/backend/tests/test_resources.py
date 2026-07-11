"""Unit tests for the low-resource operating profile and backpressure (Phase 27)."""

from __future__ import annotations

from app.services.resources import (
    ACCEPT,
    FULL,
    LITE,
    PAUSE,
    REJECT,
    STANDARD,
    HostResources,
    SystemPressure,
    admit,
    capability_warning,
    choose_profile,
    plan,
)

PI = HostResources(cpu_count=2, memory_mb=1024, disk_free_mb=8000, disk_total_mb=16000)
NUC = HostResources(cpu_count=4, memory_mb=4096, disk_free_mb=100_000, disk_total_mb=250_000)
SERVER = HostResources(cpu_count=16, memory_mb=32768, disk_free_mb=800_000, disk_total_mb=1_000_000)


def test_profile_selection_by_memory() -> None:
    assert choose_profile(PI) == LITE
    assert choose_profile(NUC) == STANDARD
    assert choose_profile(SERVER) == FULL


def test_unknown_memory_defaults_to_standard() -> None:
    res = HostResources(cpu_count=4, memory_mb=0, disk_free_mb=10, disk_total_mb=100)
    assert choose_profile(res) == STANDARD


def test_lite_plan_serializes_heavy_and_disables_expensive() -> None:
    p = plan(PI, max_concurrency=8)
    assert p.profile == LITE
    assert p.one_heavy_stage_at_a_time is True
    assert p.max_concurrency <= 2
    disabled = {d.component for d in p.disabled}
    assert "active_web_zap" in disabled
    assert "high_frequency_feed_matching" in disabled
    # Every disabled component names a reason.
    assert all(d.reason for d in p.disabled)


def test_plan_clamps_concurrency_to_policy() -> None:
    # A capable host, but policy only permits concurrency 3.
    p = plan(SERVER, max_concurrency=3)
    assert p.max_concurrency == 3


def test_full_profile_keeps_components_and_bigger_budgets() -> None:
    full = plan(SERVER)
    lite = plan(PI)
    assert full.profile == FULL
    assert not full.disabled
    # Budgets scale down under Lite.
    assert lite.stage_budgets["vuln"].max_wall_seconds < full.stage_budgets["vuln"].max_wall_seconds
    assert lite.stage_budgets["vuln"].max_targets < full.stage_budgets["vuln"].max_targets


def test_capability_warning_for_heavy_preset_on_lite() -> None:
    warn = capability_warning(PI, workload_class="heavy")
    assert warn is not None and warn.exceeds
    # A light preset on the same host does not warn.
    assert capability_warning(PI, workload_class="light") is None
    # A heavy preset on a big host does not warn.
    assert capability_warning(SERVER, workload_class="heavy") is None


# --- admission / backpressure (fail closed) --------------------------------- #

HEALTHY = SystemPressure(disk_free_pct=60.0, queue_depth=1, queue_max=16, ingestion_backlog=0)


def test_admits_when_healthy() -> None:
    d = admit(HEALTHY, heavy=True)
    assert d.action == ACCEPT and d.admitted


def test_storage_critical_rejects_heavy() -> None:
    d = admit(
        SystemPressure(disk_free_pct=3.0, queue_depth=1, queue_max=16, ingestion_backlog=0),
        heavy=True,
    )
    assert d.action == REJECT
    assert d.component == "storage"
    assert d.impact and d.next_step  # named problem + next step


def test_storage_low_pauses() -> None:
    d = admit(
        SystemPressure(disk_free_pct=8.0, queue_depth=1, queue_max=16, ingestion_backlog=0)
    )
    assert d.action == PAUSE and d.reason == "storage_low"


def test_full_queue_pauses() -> None:
    d = admit(
        SystemPressure(disk_free_pct=60.0, queue_depth=16, queue_max=16, ingestion_backlog=0)
    )
    assert d.action == PAUSE and d.reason == "queue_full"


def test_backlog_pauses() -> None:
    d = admit(
        SystemPressure(disk_free_pct=60.0, queue_depth=1, queue_max=16, ingestion_backlog=200)
    )
    assert d.action == PAUSE and d.reason == "ingestion_backlog"


def test_intrusive_fails_closed_under_any_pressure() -> None:
    # Disk merely low (would only *pause* a normal job) -> intrusive is rejected.
    d = admit(
        SystemPressure(disk_free_pct=8.0, queue_depth=1, queue_max=16, ingestion_backlog=0),
        intrusive=True,
    )
    assert d.action == REJECT and d.reason == "intrusive_under_pressure"


def test_intrusive_allowed_when_no_pressure() -> None:
    d = admit(HEALTHY, intrusive=True)
    assert d.action == ACCEPT
