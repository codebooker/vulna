"""API tests for Phase 27: upload idempotency, resource profile, offline bundles."""

from __future__ import annotations

import base64
import hashlib
import uuid
from collections.abc import Awaitable, Callable

from app.api.v1.probes import _result_idempotency_key
from app.services.signing import get_signer, reset_signer_cache
from httpx import AsyncClient

from tests.conftest import probe_cert_headers
from tests.test_assets import _XML_HEADERS, SAMPLE_XML, _create_job
from tests.test_jobs import _ready_probe

EnrollFactory = Callable[..., Awaitable[dict[str, str]]]


def test_result_idempotency_cross_language_vectors() -> None:
    job_id = uuid.UUID("00000000-0000-0000-0000-000000000001")
    raw = b"<nmaprun/>"
    assert (
        _result_idempotency_key(job_id, "discovery", "nmap", raw, complete=False)
        == "7925f9328a62d64b5240bf5f03dc567a49605b7cef1f0f27e8f9456158fb9bee"
    )
    assert (
        _result_idempotency_key(job_id, "discovery", "nmap", raw, complete=True)
        == "144aaa9e7646833b5767f7b303ad6e65ef4ea9e3b005819d7106d358dd7f5274"
    )


async def test_resend_with_idempotency_key_does_not_duplicate(
    client: AsyncClient, admin_headers: dict[str, str], enroll_probe: EnrollFactory
) -> None:
    probe = await _ready_probe(client, admin_headers, enroll_probe)
    job_id, attempt_headers = await _create_job(client, admin_headers, probe)
    url = f"/api/v1/probes/{probe['probe_id']}/jobs/{job_id}/results"
    headers = {
        **probe_cert_headers(probe["fingerprint"]),
        **_XML_HEADERS,
        "Idempotency-Key": "abc123",
        **attempt_headers,
    }

    first = await client.post(url, content=SAMPLE_XML, headers=headers)
    assert first.status_code == 201
    assert first.json()["assets_created"] == 1
    assert first.json()["duplicate"] is False

    # A reconnecting Scout replays the same batch: it must be a no-op.
    second = await client.post(url, content=SAMPLE_XML, headers=headers)
    assert second.status_code == 200
    assert second.json()["duplicate"] is True
    assert second.json()["assets_created"] == 0

    # No duplicate observation: still exactly one asset.
    listed = await client.get("/api/v1/assets", headers=admin_headers)
    assert listed.json()["total"] == 1


async def test_versioned_result_envelope_rejects_scanner_format_mismatch(
    client: AsyncClient, admin_headers: dict[str, str], enroll_probe: EnrollFactory
) -> None:
    probe = await _ready_probe(client, admin_headers, enroll_probe)
    job_id, attempt_headers = await _create_job(client, admin_headers, probe)
    digest = hashlib.sha256(SAMPLE_XML).hexdigest()
    response = await client.post(
        f"/api/v1/probes/{probe['probe_id']}/jobs/{job_id}/results?stage=discovery&scanner=nmap",
        json={
            "schema_version": 1,
            "job_id": job_id,
            "probe_id": probe["probe_id"],
            "stage": "discovery",
            "scanner": "nmap",
            "complete": False,
            "content_hash": f"sha256:{digest}",
            "payload_encoding": "base64",
            "result_format": "zap_json",
            "byte_length": len(SAMPLE_XML),
            "payload": base64.b64encode(SAMPLE_XML).decode(),
        },
        headers={
            **probe_cert_headers(probe["fingerprint"]),
            **attempt_headers,
            "Content-Type": "application/vnd.vulna.result+json",
            "Idempotency-Key": "a" * 64,
        },
    )
    assert response.status_code == 422
    assert "format" in response.json()["detail"]


async def test_resource_profile_endpoint(
    client: AsyncClient, admin_headers: dict[str, str]
) -> None:
    resp = await client.get("/api/v1/resources", headers=admin_headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["profile"] in ("lite", "standard", "full")
    assert "max_concurrency" in body["plan"]
    assert "stage_budgets" in body["plan"]
    assert body["admission"]["action"] in ("accept", "pause", "reject")
    assert len(body["reference_tiers"]) == 3


async def test_preview_warns_when_preset_exceeds_lite_scout(
    client: AsyncClient, admin_headers: dict[str, str], enroll_probe: EnrollFactory
) -> None:
    probe = await _ready_probe(client, admin_headers, enroll_probe)
    # Report Lite-tier resources for the Scout.
    hb = await client.post(
        f"/api/v1/probes/{probe['probe_id']}/heartbeat",
        json={
            "capabilities": ["nmap", "nuclei", "testssl", "zap"],
            "health": {"cpu_count": 2, "memory_mb": 1024},
        },
        headers=probe_cert_headers(probe["fingerprint"]),
    )
    assert hb.status_code in (200, 204)

    resp = await client.post(
        "/api/v1/presets/preview",
        json={"preset_key": "deep_safe", "probe_id": probe["probe_id"], "host_count": 32},
        headers=admin_headers,
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["profile"] == "lite"
    assert body["capability_warning"]  # heavy preset on lite hardware warns


async def test_offline_bundle_inspect_and_import(
    client: AsyncClient, admin_headers: dict[str, str]
) -> None:
    # The endpoints verify against the deployment signer; sign a bundle with it.
    reset_signer_cache()
    signer = get_signer()
    manifest = signer.sign_document(
        {
            "kind": "intel",
            "created_at": "2026-07-01T00:00:00+00:00",
            "feed_age_days": 5,
            "content_versions": {"nvd": "2026-07-01"},
            "items": [{"cve": "CVE-2026-1"}],
        }
    )

    ins = await client.post(
        "/api/v1/resources/offline-bundle/inspect",
        json={"manifest": manifest},
        headers=admin_headers,
    )
    assert ins.status_code == 200
    assert ins.json()["signature_valid"] is True
    assert ins.json()["kind"] == "intel"

    imp = await client.post(
        "/api/v1/resources/offline-bundle/import",
        json={"manifest": manifest},
        headers=admin_headers,
    )
    assert imp.status_code == 200
    assert imp.json()["imported"] is True

    hist = await client.get("/api/v1/resources/offline-bundle/history", headers=admin_headers)
    assert hist.status_code == 200
    assert len(hist.json()["history"]) == 1
    assert hist.json()["history"][0]["kind"] == "intel"


async def test_offline_bundle_rejects_tampered(
    client: AsyncClient, admin_headers: dict[str, str]
) -> None:
    reset_signer_cache()
    signer = get_signer()
    manifest = signer.sign_document(
        {
            "kind": "intel",
            "created_at": "2026-07-01T00:00:00+00:00",
            "feed_age_days": 5,
            "content_versions": {},
            "items": [],
        }
    )
    manifest["items"] = [{"cve": "TAMPERED"}]  # break the signature

    imp = await client.post(
        "/api/v1/resources/offline-bundle/import",
        json={"manifest": manifest},
        headers=admin_headers,
    )
    assert imp.status_code == 400  # fails closed


async def test_offline_bundle_rejects_non_admin(
    client: AsyncClient, viewer_headers: dict[str, str]
) -> None:
    resp = await client.post(
        "/api/v1/resources/offline-bundle/import",
        json={"manifest": {"kind": "intel"}},
        headers=viewer_headers,
    )
    assert resp.status_code == 403
