"""phase 40 asset context, normalized tags, groups, and ownership

Revision ID: a5b6c7d8e9f0
Revises: f4a5b6c7d8e9
"""

from __future__ import annotations

import unicodedata
import uuid
from typing import Any

import sqlalchemy as sa
from alembic import op

revision: str = "a5b6c7d8e9f0"
down_revision: str | None = "f4a5b6c7d8e9"
branch_labels: str | None = None
depends_on: str | None = None


def _timestamps() -> list[sa.Column[Any]]:
    return [
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
    ]


def _created_at() -> sa.Column[Any]:
    return sa.Column(
        "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
    )


def _normalize(value: str) -> str:
    return " ".join(unicodedata.normalize("NFKC", value).strip().split()).casefold()


def upgrade() -> None:
    with op.batch_alter_table("assets") as batch:
        batch.add_column(sa.Column("department", sa.String(255)))
        batch.add_column(sa.Column("business_function", sa.String(255)))
        batch.add_column(
            sa.Column("environment", sa.String(32), server_default="unknown", nullable=False)
        )
        batch.add_column(
            sa.Column("criticality", sa.String(32), server_default="unknown", nullable=False)
        )
        batch.add_column(
            sa.Column(
                "data_classification", sa.String(32), server_default="unknown", nullable=False
            )
        )
        batch.add_column(
            sa.Column("internet_exposed", sa.Boolean(), server_default=sa.false(), nullable=False)
        )
        batch.add_column(sa.Column("owner_user_id", sa.Uuid()))
        batch.add_column(sa.Column("context_json", sa.JSON(), server_default="{}", nullable=False))
        batch.create_foreign_key(
            "fk_assets_owner_user_id", "users", ["owner_user_id"], ["id"], ondelete="SET NULL"
        )
        for column in (
            "department",
            "environment",
            "criticality",
            "data_classification",
            "owner_user_id",
        ):
            batch.create_index(f"ix_assets_{column}", [column])

    with op.batch_alter_table("sites") as batch:
        batch.add_column(sa.Column("owner_user_id", sa.Uuid()))
        batch.create_foreign_key(
            "fk_sites_owner_user_id", "users", ["owner_user_id"], ["id"], ondelete="SET NULL"
        )
        batch.create_index("ix_sites_owner_user_id", ["owner_user_id"])

    op.create_table(
        "asset_tags",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("normalized_name", sa.String(128), nullable=False),
        sa.Column("description", sa.String(1024)),
        sa.Column("color", sa.String(16)),
        sa.Column("id", sa.Uuid(), nullable=False),
        *_timestamps(),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("organization_id", "normalized_name", name="uq_asset_tag_org_name"),
    )
    op.create_index("ix_asset_tags_organization_id", "asset_tags", ["organization_id"])

    op.create_table(
        "asset_tag_assignments",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("asset_id", sa.Uuid(), nullable=False),
        sa.Column("tag_id", sa.Uuid(), nullable=False),
        sa.Column("source", sa.String(32), nullable=False),
        sa.Column("metadata_json", sa.JSON(), nullable=False),
        sa.Column("assigned_by_user_id", sa.Uuid()),
        sa.Column("id", sa.Uuid(), nullable=False),
        _created_at(),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["tag_id"], ["asset_tags.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["assigned_by_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("asset_id", "tag_id", name="uq_asset_tag_assignment"),
    )
    for column in ("organization_id", "asset_id", "tag_id"):
        op.create_index(f"ix_asset_tag_assignments_{column}", "asset_tag_assignments", [column])

    op.create_table(
        "asset_groups",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("site_id", sa.Uuid()),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.String(1024)),
        sa.Column("group_type", sa.String(32), nullable=False),
        sa.Column("rule_json", sa.JSON()),
        sa.Column("priority", sa.Integer(), server_default="0", nullable=False),
        sa.Column("owner_user_id", sa.Uuid()),
        sa.Column("enabled", sa.Boolean(), server_default=sa.true(), nullable=False),
        sa.Column("created_by_user_id", sa.Uuid()),
        sa.Column("last_evaluated_at", sa.DateTime(timezone=True)),
        sa.Column("id", sa.Uuid(), nullable=False),
        *_timestamps(),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["site_id"], ["sites.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["owner_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["created_by_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("organization_id", "name", name="uq_asset_group_org_name"),
    )
    for column in ("organization_id", "site_id", "group_type", "priority", "owner_user_id"):
        op.create_index(f"ix_asset_groups_{column}", "asset_groups", [column])

    op.create_table(
        "asset_group_memberships",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("group_id", sa.Uuid(), nullable=False),
        sa.Column("asset_id", sa.Uuid(), nullable=False),
        sa.Column("source", sa.String(32), nullable=False),
        sa.Column("explanation_json", sa.JSON(), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        *_timestamps(),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["group_id"], ["asset_groups.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("group_id", "asset_id", name="uq_asset_group_membership"),
    )
    for column in ("organization_id", "group_id", "asset_id"):
        op.create_index(f"ix_asset_group_memberships_{column}", "asset_group_memberships", [column])

    op.create_table(
        "department_owners",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("department", sa.String(255), nullable=False),
        sa.Column("department_key", sa.String(255), nullable=False),
        sa.Column("owner_user_id", sa.Uuid(), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        *_timestamps(),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["owner_user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("organization_id", "department_key", name="uq_department_owner"),
    )
    op.create_index(
        "ix_department_owners_organization_id", "department_owners", ["organization_id"]
    )
    op.create_index("ix_department_owners_owner_user_id", "department_owners", ["owner_user_id"])

    op.create_table(
        "asset_ownership_history",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("asset_id", sa.Uuid(), nullable=False),
        sa.Column("finding_id", sa.Uuid()),
        sa.Column("owner_user_id", sa.Uuid()),
        sa.Column("source", sa.String(32), nullable=False),
        sa.Column("source_id", sa.Uuid()),
        sa.Column("explanation_json", sa.JSON(), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        _created_at(),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["finding_id"], ["findings.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["owner_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    for column in ("organization_id", "asset_id", "finding_id", "owner_user_id"):
        op.create_index(f"ix_asset_ownership_history_{column}", "asset_ownership_history", [column])

    # Normalize the retained legacy tag list without changing or discarding it.
    bind = op.get_bind()
    assets_table = sa.table(
        "assets",
        sa.column("id", sa.Uuid()),
        sa.column("organization_id", sa.Uuid()),
        sa.column("tags_json", sa.JSON()),
        sa.column("metadata_json", sa.JSON()),
    )
    tags_table = sa.table(
        "asset_tags",
        sa.column("id", sa.Uuid()),
        sa.column("organization_id", sa.Uuid()),
        sa.column("name", sa.String()),
        sa.column("normalized_name", sa.String()),
        sa.column("description", sa.String()),
        sa.column("color", sa.String()),
    )
    assignments_table = sa.table(
        "asset_tag_assignments",
        sa.column("id", sa.Uuid()),
        sa.column("organization_id", sa.Uuid()),
        sa.column("asset_id", sa.Uuid()),
        sa.column("tag_id", sa.Uuid()),
        sa.column("source", sa.String()),
        sa.column("metadata_json", sa.JSON()),
        sa.column("assigned_by_user_id", sa.Uuid()),
    )
    known: dict[tuple[uuid.UUID, str], uuid.UUID] = {}
    for row in bind.execute(sa.select(assets_table)).mappings():
        org_id = row["organization_id"]
        asset_id = row["id"]
        values = row["tags_json"] or []
        assigned_tag_ids: set[uuid.UUID] = set()
        for position, raw_name in enumerate(values):
            if not isinstance(raw_name, str) or not _normalize(raw_name):
                continue
            normalized = _normalize(raw_name)
            key = (org_id, normalized)
            tag_id = known.get(key)
            if tag_id is None:
                tag_id = uuid.uuid5(uuid.NAMESPACE_URL, f"vulna:asset-tag:{org_id}:{normalized}")
                known[key] = tag_id
                bind.execute(
                    tags_table.insert().values(
                        id=tag_id,
                        organization_id=org_id,
                        name=" ".join(raw_name.strip().split()),
                        normalized_name=normalized,
                        description=None,
                        color=None,
                    )
                )
            if tag_id in assigned_tag_ids:
                continue
            assigned_tag_ids.add(tag_id)
            assignment_id = uuid.uuid5(
                uuid.NAMESPACE_URL, f"vulna:asset-tag-assignment:{asset_id}:{tag_id}"
            )
            bind.execute(
                assignments_table.insert().values(
                    id=assignment_id,
                    organization_id=org_id,
                    asset_id=asset_id,
                    tag_id=tag_id,
                    source="migrated",
                    metadata_json={
                        "legacy_value": raw_name,
                        "legacy_position": position,
                        "asset_metadata": row["metadata_json"] or {},
                    },
                    assigned_by_user_id=None,
                )
            )


def downgrade() -> None:
    # tags_json is intentionally retained and kept current by the application,
    # so removing normalized context does not erase the compatibility tag list.
    op.drop_table("asset_ownership_history")
    op.drop_table("department_owners")
    op.drop_table("asset_group_memberships")
    op.drop_table("asset_groups")
    op.drop_table("asset_tag_assignments")
    op.drop_table("asset_tags")

    with op.batch_alter_table("sites") as batch:
        batch.drop_index("ix_sites_owner_user_id")
        batch.drop_constraint("fk_sites_owner_user_id", type_="foreignkey")
        batch.drop_column("owner_user_id")

    with op.batch_alter_table("assets") as batch:
        for column in (
            "owner_user_id",
            "data_classification",
            "criticality",
            "environment",
            "department",
        ):
            batch.drop_index(f"ix_assets_{column}")
        batch.drop_constraint("fk_assets_owner_user_id", type_="foreignkey")
        for column in (
            "context_json",
            "owner_user_id",
            "internet_exposed",
            "data_classification",
            "criticality",
            "environment",
            "business_function",
            "department",
        ):
            batch.drop_column(column)
