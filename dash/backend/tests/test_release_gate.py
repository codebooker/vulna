"""Meta-tests for the Phase 32 release gate and support matrix.

These guard the release-qualification machinery itself: the release-blocking
regression suite must keep covering the security-critical domains, and the
published support matrix must stay well-formed. They are not themselves part of
the gate (removing a marker must fail *this* test regardless).
"""

from __future__ import annotations

import json
import tomllib
from pathlib import Path

# tests/ -> backend/ -> dash/ -> repo root
REPO_ROOT = Path(__file__).resolve().parents[3]
BACKEND = REPO_ROOT / "dash" / "backend"

# Every security-critical module the release gate must cover (Phase 32 acceptance:
# setup, target enforcement, job signatures, cancellation, restore, authorization,
# plus relay egress and fail-closed deletion).
REQUIRED_GATE_MODULES = [
    "test_enrollment.py",
    "test_probe_status.py",
    "test_scopes.py",
    "test_scope_validation.py",
    "test_signing.py",
    "test_policy.py",
    "test_jobs.py",
    "test_isolation.py",
    "test_rbac.py",
    "test_auth.py",
    "test_backup_center.py",
    "test_relay.py",
    "test_maintenance.py",
    "test_experience.py",
    "test_user_lifecycle.py",
    "test_sessions.py",
    "test_mfa.py",
    "test_sso.py",
    "test_scim.py",
]


def test_release_gate_marker_registered() -> None:
    config = tomllib.loads((BACKEND / "pyproject.toml").read_text())
    markers = config["tool"]["pytest"]["ini_options"]["markers"]
    assert any(m.startswith("release_gate:") for m in markers)


def test_every_required_module_is_in_the_gate() -> None:
    for name in REQUIRED_GATE_MODULES:
        text = (BACKEND / "tests" / name).read_text()
        assert "pytestmark = pytest.mark.release_gate" in text, (
            f"{name} must carry the release_gate mark; it is release-blocking."
        )


def test_release_gate_script_runs_the_marked_suite() -> None:
    script = (REPO_ROOT / "deploy" / "release" / "release_gate.sh").read_text()
    assert "-m release_gate" in script
    assert "Do not promote" in script  # fail path is explicit


def test_support_matrix_is_well_formed() -> None:
    matrix = json.loads((REPO_ROOT / "deploy" / "release" / "support-matrix.json").read_text())
    for key in (
        "linux_distributions",
        "container_runtime",
        "architectures",
        "single_host_resource_tiers",
        "browsers",
        "compatibility",
        "scanners",
        "release_channels",
    ):
        assert key in matrix, f"support matrix missing '{key}'"
    assert set(matrix["architectures"]) == {"amd64", "arm64"}
    assert {c["channel"] for c in matrix["release_channels"]} == {"stable", "maintenance"}


def test_capability_matrix_does_not_claim_production_readiness() -> None:
    text = (REPO_ROOT / "docs" / "capabilities.md").read_text().lower()
    assert "production-ready remains false" in text
    for phase in range(34, 45):
        assert f"phase {phase}" in text
