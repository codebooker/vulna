"""Unit tests for the VulnaWatch feed parsers, CPE matching, and retry helper."""

from __future__ import annotations

import gzip
import json

import pytest
from app.intelligence.epss import parse_epss
from app.intelligence.fetchers import FetchError, fetch_with_retry
from app.intelligence.kev import parse_kev
from app.intelligence.matching import match_confidence, parse_cpe
from app.intelligence.nvd import cvss_base_score, parse_nvd
from app.models.enums import MatchConfidence

NVD_SAMPLE = json.dumps(
    {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2021-44228",
                    "published": "2021-12-10T10:15:09.143",
                    "lastModified": "2023-04-03T20:15:08.960",
                    "vulnStatus": "Analyzed",
                    "descriptions": [
                        {"lang": "es", "value": "Apache Log4j2 ..."},
                        {"lang": "en", "value": "Apache Log4j2 JNDI features do not protect..."},
                    ],
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "type": "Primary",
                                "cvssData": {
                                    "version": "3.1",
                                    "baseScore": 10.0,
                                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                                },
                            }
                        ],
                    },
                    "weaknesses": [
                        {"description": [{"lang": "en", "value": "CWE-502"}]},
                    ],
                    "configurations": [
                        {
                            "nodes": [
                                {
                                    "cpeMatch": [
                                        {
                                            "vulnerable": True,
                                            "criteria": "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*",
                                            "versionStartIncluding": "2.0",
                                            "versionEndExcluding": "2.15.0",
                                        }
                                    ]
                                }
                            ]
                        }
                    ],
                    "references": [{"url": "https://logging.apache.org/"}],
                }
            },
            {"cve": {"id": "CVE-2020-0001", "vulnStatus": "Rejected", "descriptions": []}},
            {"cve": {}},  # malformed: no id, skipped
        ]
    }
).encode()


def test_parse_nvd_extracts_fields() -> None:
    records = parse_nvd(NVD_SAMPLE)
    assert len(records) == 2  # malformed entry skipped
    log4j = records[0]
    assert log4j.cve_id == "CVE-2021-44228"
    assert log4j.description.startswith("Apache Log4j2 JNDI")  # English preferred
    assert cvss_base_score(log4j.cvss_v3) == 10.0
    assert log4j.cwe_ids == ["CWE-502"]
    assert log4j.cpe_matches[0]["versionEndExcluding"] == "2.15.0"
    assert log4j.references == ["https://logging.apache.org/"]
    assert log4j.rejected is False
    assert records[1].rejected is True


def test_parse_nvd_rejects_bad_json() -> None:
    with pytest.raises(ValueError):
        parse_nvd(b"{not json")


KEV_SAMPLE = json.dumps(
    {
        "title": "CISA KEV",
        "catalogVersion": "2024.01.01",
        "dateReleased": "2024-01-01T12:00:00.000Z",
        "vulnerabilities": [
            {
                "cveID": "CVE-2021-44228",
                "dateAdded": "2021-12-10",
                "dueDate": "2021-12-24",
                "requiredAction": "Apply updates.",
                "knownRansomwareCampaignUse": "Known",
            },
            {
                "cveID": "CVE-2019-0001",
                "dateAdded": "2022-01-01",
                "knownRansomwareCampaignUse": "Unknown",
            },
            {"dateAdded": "2022-01-01"},  # no cveID, skipped
        ],
    }
).encode()


def test_parse_kev() -> None:
    catalog = parse_kev(KEV_SAMPLE)
    assert catalog.catalog_version == "2024.01.01"
    assert len(catalog.entries) == 2
    first = catalog.entries[0]
    assert first.cve_id == "CVE-2021-44228"
    assert first.known_ransomware_use is True
    assert str(first.date_added) == "2021-12-10"
    assert catalog.entries[1].known_ransomware_use is False


EPSS_SAMPLE = (
    b"#model_version:v2024.01.01,score_date:2024-01-01T00:00:00+0000\n"
    b"cve,epss,percentile\n"
    b"CVE-2021-44228,0.97540,0.99980\n"
    b"CVE-2019-0001,0.00042,0.10000\n"
    b"malformed,not-a-number,0.5\n"
)


def test_parse_epss_plain_and_gzip() -> None:
    for raw in (EPSS_SAMPLE, gzip.compress(EPSS_SAMPLE)):
        data = parse_epss(raw)
        assert data.score_date == "2024-01-01T00:00:00+0000"
        assert len(data.entries) == 2  # malformed row skipped
        assert data.entries[0].cve_id == "CVE-2021-44228"
        assert data.entries[0].epss == pytest.approx(0.97540)


def test_parse_cpe() -> None:
    cpe = parse_cpe("cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*")
    assert cpe is not None
    assert cpe.vendor == "apache" and cpe.product == "log4j" and cpe.version == "2.14.1"
    assert parse_cpe("not-a-cpe") is None


def test_match_confidence_version_in_range() -> None:
    matches = parse_nvd(NVD_SAMPLE)[0].cpe_matches
    # log4j 2.14.1 is within [2.0, 2.15.0) -> medium (banner-based)
    assert match_confidence(matches, product="log4j", version="2.14.1") == MatchConfidence.MEDIUM
    # 2.16.0 is outside the range -> no match
    assert match_confidence(matches, product="log4j", version="2.16.0") is None
    # different product -> no match
    assert match_confidence(matches, product="nginx", version="1.0") is None


def test_match_confidence_exact_service_cpe_is_high() -> None:
    matches = parse_nvd(NVD_SAMPLE)[0].cpe_matches
    conf = match_confidence(
        matches,
        product="log4j",
        version="2.14.1",
        service_cpe="cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*",
    )
    assert conf == MatchConfidence.HIGH


class _FlakyFetcher:
    def __init__(self, fail_times: int, body: bytes = b"ok") -> None:
        self.calls = 0
        self.fail_times = fail_times
        self.body = body

    async def fetch(self, url: str, *, params: object = None) -> bytes:
        self.calls += 1
        if self.calls <= self.fail_times:
            raise FetchError("transient")
        return self.body


async def test_fetch_with_retry_succeeds_after_failures() -> None:
    sleeps: list[float] = []

    async def fake_sleep(d: float) -> None:
        sleeps.append(d)

    fetcher = _FlakyFetcher(fail_times=2)
    body, attempts = await fetch_with_retry(
        fetcher, "http://x", retries=3, backoff_base=1.0, sleep=fake_sleep
    )
    assert body == b"ok"
    assert attempts == 3
    assert sleeps == [1.0, 2.0]  # exponential backoff between the 2 failures


async def test_fetch_with_retry_exhausts_and_raises() -> None:
    async def fake_sleep(d: float) -> None:
        return None

    fetcher = _FlakyFetcher(fail_times=99)
    with pytest.raises(FetchError):
        await fetch_with_retry(fetcher, "http://x", retries=2, sleep=fake_sleep)
    assert fetcher.calls == 3  # initial + 2 retries
