"""Unit tests for CIDR scope validation (build plan Section 27.1)."""

from __future__ import annotations

import pytest
from app.services.scopes import (
    ScopeValidationError,
    find_overlaps,
    normalize_cidr,
    validate_cidr,
)


def test_normalize_masks_host_bits() -> None:
    assert str(normalize_cidr("10.20.0.5/24")) == "10.20.0.0/24"


def test_normalize_rejects_garbage() -> None:
    with pytest.raises(ScopeValidationError):
        normalize_cidr("not-a-cidr")


def test_validate_accepts_private_range() -> None:
    assert validate_cidr("10.0.0.0/8") == "10.0.0.0/8"
    assert validate_cidr("192.168.1.0/24") == "192.168.1.0/24"


@pytest.mark.parametrize("default_route", ["0.0.0.0/0", "::/0"])
def test_validate_rejects_default_route(default_route: str) -> None:
    with pytest.raises(ScopeValidationError, match="default route"):
        validate_cidr(default_route)


def test_validate_rejects_default_route_even_when_public_allowed() -> None:
    with pytest.raises(ScopeValidationError, match="default route"):
        validate_cidr("0.0.0.0/0", allow_public=True)


def test_validate_denies_public_by_default() -> None:
    with pytest.raises(ScopeValidationError, match="public"):
        validate_cidr("8.8.8.0/24")


def test_validate_allows_public_when_opted_in() -> None:
    assert validate_cidr("8.8.8.0/24", allow_public=True) == "8.8.8.0/24"


def test_find_overlaps_detects_containment() -> None:
    overlaps = find_overlaps("10.0.1.0/24", ["10.0.0.0/16", "192.168.0.0/24"])
    assert overlaps == ["10.0.0.0/16"]


def test_find_overlaps_none_when_disjoint() -> None:
    assert find_overlaps("10.0.1.0/24", ["10.0.2.0/24", "172.16.0.0/24"]) == []


def test_find_overlaps_ignores_other_ip_version() -> None:
    assert find_overlaps("10.0.1.0/24", ["fd00::/8"]) == []
