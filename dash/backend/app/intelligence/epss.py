"""Parser for the FIRST EPSS daily CSV.

The EPSS CSV begins with a ``#model_version:...,score_date:...`` comment line,
then a ``cve,epss,percentile`` header, then one row per CVE. We parse the score
date from the comment for feed-health reporting and skip malformed rows.
"""

from __future__ import annotations

import csv
import gzip
import io
from dataclasses import dataclass, field


@dataclass
class EpssEntry:
    cve_id: str
    epss: float
    percentile: float


@dataclass
class EpssData:
    score_date: str | None = None
    model_version: str | None = None
    entries: list[EpssEntry] = field(default_factory=list)


def _parse_meta(line: str) -> dict[str, str]:
    meta: dict[str, str] = {}
    for part in line.lstrip("#").split(","):
        if ":" in part:
            key, _, val = part.partition(":")
            meta[key.strip()] = val.strip()
    return meta


def _to_float(value: str) -> float | None:
    try:
        return float(value)
    except (ValueError, TypeError):
        return None


def parse_epss(raw: bytes | str) -> EpssData:
    """Parse the EPSS CSV into :class:`EpssData`.

    The published feed is gzip-compressed (``.csv.gz``); it is transparently
    decompressed when the gzip magic bytes are present.
    """
    if isinstance(raw, bytes):
        if raw[:2] == b"\x1f\x8b":
            raw = gzip.decompress(raw)
        text = raw.decode("utf-8", "replace")
    else:
        text = raw
    lines = text.splitlines()
    data = EpssData()
    body: list[str] = []
    for line in lines:
        if line.startswith("#"):
            meta = _parse_meta(line)
            data.score_date = meta.get("score_date", data.score_date)
            data.model_version = meta.get("model_version", data.model_version)
        else:
            body.append(line)
    reader = csv.reader(io.StringIO("\n".join(body)))
    for row in reader:
        if len(row) < 3 or row[0].strip().lower() in ("cve", ""):
            continue
        epss = _to_float(row[1])
        pct = _to_float(row[2])
        if epss is None or pct is None:
            continue
        data.entries.append(EpssEntry(cve_id=row[0].strip(), epss=epss, percentile=pct))
    return data
