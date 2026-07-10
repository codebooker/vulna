"""Report generation for VulnaDash (build plan Section 16).

A report is produced from a point-in-time :func:`snapshot.build_snapshot` of a
scan's data, so every artifact (PDF/CSV/JSON) is internally consistent and
reproducible from the stored file. :func:`generate.generate_reports` renders the
requested artifacts, writes them to disk with a SHA-256, and records ``Report``
rows.
"""

from app.services.reports.generate import ARTIFACTS, generate_reports
from app.services.reports.snapshot import build_snapshot

__all__ = ["ARTIFACTS", "build_snapshot", "generate_reports"]
