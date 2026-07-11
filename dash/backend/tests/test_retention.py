"""Unit tests for the fail-closed retention eligibility logic (Phase 28)."""

from __future__ import annotations

import uuid

import pytest
from app.services.retention import (
    MIN_RETENTION_DAYS,
    RetentionError,
    RetentionPolicy,
    _artifact_protection,
)

JOB = uuid.uuid4()


def test_eligible_when_nothing_references_the_job() -> None:
    assert _artifact_protection(JOB, set(), set(), set(), set()) is None


def test_protected_when_job_active() -> None:
    r = _artifact_protection(JOB, {JOB}, set(), set(), set())
    assert r and "active" in r


def test_protected_by_legal_hold() -> None:
    r = _artifact_protection(JOB, set(), {JOB}, set(), set())
    assert r and "hold" in r


def test_protected_by_active_finding() -> None:
    r = _artifact_protection(JOB, set(), set(), {JOB}, set())
    assert r and "finding" in r


def test_protected_by_retained_report() -> None:
    r = _artifact_protection(JOB, set(), set(), set(), {JOB})
    assert r and "report" in r


def test_policy_floor_enforced() -> None:
    with pytest.raises(RetentionError):
        RetentionPolicy.from_request(raw_output_days=1, report_days=365)
    ok = RetentionPolicy.from_request(raw_output_days=MIN_RETENTION_DAYS, report_days=None)
    assert ok.raw_output_days == MIN_RETENTION_DAYS
