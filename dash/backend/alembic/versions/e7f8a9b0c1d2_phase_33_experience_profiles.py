"""phase 33: organization experience profiles

Revision ID: e7f8a9b0c1d2
Revises: d6e7f8a9b0c1
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "e7f8a9b0c1d2"
down_revision: str | None = "d6e7f8a9b0c1"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.add_column(
        "organizations",
        sa.Column(
            "experience_profile",
            sa.String(length=32),
            nullable=False,
            server_default="small_business",
        ),
    )
    op.add_column(
        "organizations",
        sa.Column(
            "feature_overrides_json",
            sa.JSON(),
            nullable=False,
            server_default=sa.text("'{}'"),
        ),
    )


def downgrade() -> None:
    # Presentation preferences are discarded; feature configuration and all
    # security controls live elsewhere and are unaffected.
    op.drop_column("organizations", "feature_overrides_json")
    op.drop_column("organizations", "experience_profile")
