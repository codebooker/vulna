"""cve product index for version-based correlation

Revision ID: cve1prod2idx3
Revises: 0b1c2d3e4f5a
"""

from __future__ import annotations

import json
from typing import Any

import sqlalchemy as sa
from alembic import op

revision: str = "cve1prod2idx3"
down_revision: str | None = "0b1c2d3e4f5a"
branch_labels: str | None = None
depends_on: str | None = None


def _products(cpe_matches: Any) -> set[str]:
    """Distinct application/OS product names in a CVE's CPE matches. Inlined
    (not imported from app code) so this migration stays stable over time."""
    products: set[str] = set()
    if not isinstance(cpe_matches, list):
        return products
    for m in cpe_matches:
        if not isinstance(m, dict):
            continue
        criteria = m.get("criteria", "")
        if not isinstance(criteria, str) or not criteria.startswith("cpe:2.3:"):
            continue
        fields = criteria.split(":")
        if len(fields) < 6:
            continue
        part, product = fields[2], fields[4].lower()
        if part in ("a", "o") and product not in ("*", "-", ""):
            products.add(product)
    return products


def upgrade() -> None:
    op.create_table(
        "cve_product_index",
        sa.Column("product", sa.String(length=255), primary_key=True, nullable=False),
        sa.Column("cve_id", sa.String(length=32), primary_key=True, nullable=False),
    )

    # Backfill from CVEs already synced, so correlation works immediately instead
    # of only after a full NVD re-sync.
    conn = op.get_bind()
    rows = conn.execute(sa.text("SELECT cve_id, cpe_matches_json FROM cve_records")).fetchall()
    insert = sa.text("INSERT INTO cve_product_index (product, cve_id) VALUES (:product, :cve_id)")
    batch: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for cve_id, cpe_json in rows:
        matches: Any = cpe_json
        if isinstance(cpe_json, (str, bytes)):
            try:
                matches = json.loads(cpe_json)
            except (ValueError, TypeError):
                matches = []
        for product in _products(matches):
            key = (product, cve_id)
            if key in seen:
                continue
            seen.add(key)
            batch.append({"product": product, "cve_id": cve_id})
            if len(batch) >= 1000:
                conn.execute(insert, batch)
                batch = []
    if batch:
        conn.execute(insert, batch)


def downgrade() -> None:
    op.drop_table("cve_product_index")
