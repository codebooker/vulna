"""Help catalogue + documentation integrity tests (Phase 30)."""

from __future__ import annotations

from pathlib import Path

from app.services import help_topics
from httpx import AsyncClient

# tests/ -> backend/ -> dash/ -> repo root
REPO_ROOT = Path(__file__).resolve().parents[3]

# New Phase-30 guides + the security-sensitive ones must not recommend insecure
# practices (roadmap security constraint).
LINTED_DOCS = [
    "docs/quickstart.md",
    "docs/troubleshooting.md",
    "docs/terminology.md",
    "docs/understanding-findings.md",
    "docs/demo.md",
    "docs/administration/exposure-checklist.md",
]

BANNED_RECOMMENDATIONS = [
    "insecure_skip_verify=true",
    "--privileged",
    "verify=false",
    "trust_all_certs",
    "password=password",
    "password=admin",
]


def test_every_help_topic_doc_exists() -> None:
    for topic in help_topics.HELP_TOPICS.values():
        path = REPO_ROOT / topic.doc
        assert path.exists(), f"help topic '{topic.key}' points at missing doc {topic.doc}"


def test_error_and_domain_help_reference_known_topics() -> None:
    keys = set(help_topics.HELP_TOPICS)
    for target in list(help_topics.ERROR_HELP.values()) + list(help_topics.DOMAIN_HELP.values()):
        assert target in keys, f"help mapping points at unknown topic '{target}'"


def test_new_guides_have_no_insecure_recommendations() -> None:
    for rel in LINTED_DOCS:
        path = REPO_ROOT / rel
        assert path.exists(), f"expected guide {rel} to exist"
        text = path.read_text().lower()
        for banned in BANNED_RECOMMENDATIONS:
            assert banned not in text, f"{rel} must not recommend '{banned}'"


async def test_help_endpoints(client: AsyncClient, admin_headers: dict[str, str]) -> None:
    topics = await client.get("/api/v1/help/topics", headers=admin_headers)
    assert topics.status_code == 200
    assert any(t["key"] == "getting-started" for t in topics.json()["topics"])

    one = await client.get("/api/v1/help/topics/troubleshooting", headers=admin_headers)
    assert one.status_code == 200 and one.json()["doc"] == "docs/troubleshooting.md"

    missing = await client.get("/api/v1/help/topics/nope", headers=admin_headers)
    assert missing.status_code == 404

    checklist = await client.get("/api/v1/help/exposure-checklist", headers=admin_headers)
    assert checklist.status_code == 200 and len(checklist.json()["checklist"]) >= 5
