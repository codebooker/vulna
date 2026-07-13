"""phase 41 explainable risk, remediation units, and finding decisions

Revision ID: b6c7d8e9f0a1
Revises: a5b6c7d8e9f0
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import sqlalchemy as sa
from alembic import op

revision: str = "b6c7d8e9f0a1"
down_revision: str | None = "a5b6c7d8e9f0"
branch_labels: str | None = None
depends_on: str | None = None

DEFAULT_WEIGHTS = {
    "severity": 30.0,
    "cvss": 20.0,
    "known_exploited": 20.0,
    "epss": 10.0,
    "confidence": 10.0,
    "validation": 15.0,
    "internet_exposure": 10.0,
    "asset_criticality": 15.0,
}
SEVERITY = {"info": -1.0, "low": -0.5, "medium": 0.0, "high": 0.5, "critical": 1.0}
VALIDATION = {
    "confirmed_non_exploit": -1.0,
    "not_applicable": -1.0,
    "inconclusive": -0.25,
    "unvalidated": 0.0,
    "likely": 0.5,
    "confirmed_exploitable": 1.0,
}
CRITICALITY = {
    "unknown": 0.0,
    "low": -1.0,
    "moderate": -0.25,
    "high": 0.5,
    "mission_critical": 1.0,
}


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


def upgrade() -> None:
    op.create_table(
        "risk_profiles",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("description", sa.String(1024)),
        sa.Column("weights_json", sa.JSON(), nullable=False),
        sa.Column("is_default", sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.Column("created_by_user_id", sa.Uuid()),
        sa.Column("id", sa.Uuid(), nullable=False),
        _created_at(),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["created_by_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "organization_id", "name", "version", name="uq_risk_profile_org_name_version"
        ),
    )
    op.create_index("ix_risk_profiles_organization_id", "risk_profiles", ["organization_id"])
    op.create_index("ix_risk_profiles_is_default", "risk_profiles", ["is_default"])

    op.create_table(
        "finding_score_snapshots",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("site_id", sa.Uuid(), nullable=False),
        sa.Column("finding_id", sa.Uuid(), nullable=False),
        sa.Column("risk_profile_id", sa.Uuid(), nullable=False),
        sa.Column("profile_version", sa.Integer(), nullable=False),
        sa.Column("score", sa.Float(), nullable=False),
        sa.Column("weighted_sum", sa.Float(), nullable=False),
        sa.Column("positive_maximum", sa.Float(), nullable=False),
        sa.Column("source_values_json", sa.JSON(), nullable=False),
        sa.Column("factors_json", sa.JSON(), nullable=False),
        sa.Column("input_hash", sa.String(64), nullable=False),
        sa.Column("created_by_user_id", sa.Uuid()),
        sa.Column("id", sa.Uuid(), nullable=False),
        _created_at(),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["site_id"], ["sites.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["finding_id"], ["findings.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["risk_profile_id"], ["risk_profiles.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["created_by_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    for column in (
        "organization_id",
        "site_id",
        "finding_id",
        "risk_profile_id",
        "score",
        "input_hash",
    ):
        op.create_index(f"ix_finding_score_snapshots_{column}", "finding_score_snapshots", [column])

    op.create_table(
        "remediation_units",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("site_id", sa.Uuid(), nullable=False),
        sa.Column("key_type", sa.String(32), nullable=False),
        sa.Column("exact_key", sa.String(512), nullable=False),
        sa.Column("title", sa.String(512), nullable=False),
        sa.Column("description", sa.Text()),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("owner_user_id", sa.Uuid()),
        sa.Column("automatically_created", sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.Column("created_by_user_id", sa.Uuid()),
        sa.Column("id", sa.Uuid(), nullable=False),
        *_timestamps(),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["site_id"], ["sites.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["owner_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["created_by_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "organization_id",
            "site_id",
            "key_type",
            "exact_key",
            name="uq_remediation_unit_exact_key",
        ),
    )
    for column in ("organization_id", "site_id", "key_type", "status", "owner_user_id"):
        op.create_index(f"ix_remediation_units_{column}", "remediation_units", [column])

    op.create_table(
        "remediation_unit_findings",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("remediation_unit_id", sa.Uuid(), nullable=False),
        sa.Column("finding_id", sa.Uuid(), nullable=False),
        sa.Column("match_basis_json", sa.JSON(), nullable=False),
        sa.Column("added_by_user_id", sa.Uuid()),
        sa.Column("id", sa.Uuid(), nullable=False),
        _created_at(),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["remediation_unit_id"], ["remediation_units.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(["finding_id"], ["findings.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["added_by_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("remediation_unit_id", "finding_id", name="uq_remediation_membership"),
    )
    for column in ("organization_id", "remediation_unit_id", "finding_id"):
        op.create_index(
            f"ix_remediation_unit_findings_{column}", "remediation_unit_findings", [column]
        )

    op.create_table(
        "remediation_suggestions",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("site_id", sa.Uuid(), nullable=False),
        sa.Column("remediation_unit_id", sa.Uuid(), nullable=False),
        sa.Column("finding_id", sa.Uuid(), nullable=False),
        sa.Column("similarity", sa.Float(), nullable=False),
        sa.Column("explanation_json", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("reviewed_by_user_id", sa.Uuid()),
        sa.Column("reviewed_at", sa.DateTime(timezone=True)),
        sa.Column("id", sa.Uuid(), nullable=False),
        *_timestamps(),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["site_id"], ["sites.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["remediation_unit_id"], ["remediation_units.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(["finding_id"], ["findings.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["reviewed_by_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "remediation_unit_id", "finding_id", name="uq_remediation_suggestion_membership"
        ),
    )
    for column in (
        "organization_id",
        "site_id",
        "remediation_unit_id",
        "finding_id",
        "status",
    ):
        op.create_index(f"ix_remediation_suggestions_{column}", "remediation_suggestions", [column])

    op.create_table(
        "finding_decisions",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("site_id", sa.Uuid(), nullable=False),
        sa.Column("finding_id", sa.Uuid(), nullable=False),
        sa.Column("decision_type", sa.String(32), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("evidence_json", sa.JSON(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("duplicate_of_finding_id", sa.Uuid()),
        sa.Column("previous_status", sa.String(32), nullable=False),
        sa.Column("created_by_user_id", sa.Uuid()),
        sa.Column("revoked_by_user_id", sa.Uuid()),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
        sa.Column("id", sa.Uuid(), nullable=False),
        _created_at(),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["site_id"], ["sites.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["finding_id"], ["findings.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["duplicate_of_finding_id"], ["findings.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["created_by_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["revoked_by_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    for column in (
        "organization_id",
        "site_id",
        "finding_id",
        "decision_type",
        "status",
        "expires_at",
        "duplicate_of_finding_id",
    ):
        op.create_index(f"ix_finding_decisions_{column}", "finding_decisions", [column])

    with op.batch_alter_table("findings") as batch:
        batch.add_column(sa.Column("current_score_snapshot_id", sa.Uuid()))
        batch.add_column(sa.Column("risk_score", sa.Float()))
        batch.add_column(sa.Column("risk_profile_version", sa.Integer()))
        batch.add_column(sa.Column("risk_input_hash", sa.String(64)))
        batch.add_column(sa.Column("risk_scored_at", sa.DateTime(timezone=True)))
        batch.create_index("ix_findings_risk_score", ["risk_score"])

    _backfill_scores()


def _backfill_scores() -> None:
    bind = op.get_bind()
    organizations = sa.table("organizations", sa.column("id", sa.Uuid()))
    profiles = sa.table(
        "risk_profiles",
        sa.column("id", sa.Uuid()),
        sa.column("organization_id", sa.Uuid()),
        sa.column("name", sa.String()),
        sa.column("version", sa.Integer()),
        sa.column("description", sa.String()),
        sa.column("weights_json", sa.JSON()),
        sa.column("is_default", sa.Boolean()),
        sa.column("created_by_user_id", sa.Uuid()),
    )
    findings = sa.table(
        "findings",
        sa.column("id", sa.Uuid()),
        sa.column("organization_id", sa.Uuid()),
        sa.column("site_id", sa.Uuid()),
        sa.column("asset_id", sa.Uuid()),
        sa.column("severity", sa.String()),
        sa.column("cvss_score", sa.Float()),
        sa.column("known_exploited", sa.Boolean()),
        sa.column("epss_score", sa.Float()),
        sa.column("confidence", sa.Integer()),
        sa.column("validation_status", sa.String()),
        sa.column("status", sa.String()),
        sa.column("false_positive_reason", sa.Text()),
        sa.column("current_score_snapshot_id", sa.Uuid()),
        sa.column("risk_score", sa.Float()),
        sa.column("risk_profile_version", sa.Integer()),
        sa.column("risk_input_hash", sa.String()),
        sa.column("risk_scored_at", sa.DateTime(timezone=True)),
    )
    assets = sa.table(
        "assets",
        sa.column("id", sa.Uuid()),
        sa.column("internet_exposed", sa.Boolean()),
        sa.column("criticality", sa.String()),
    )
    snapshots = sa.table(
        "finding_score_snapshots",
        sa.column("id", sa.Uuid()),
        sa.column("organization_id", sa.Uuid()),
        sa.column("site_id", sa.Uuid()),
        sa.column("finding_id", sa.Uuid()),
        sa.column("risk_profile_id", sa.Uuid()),
        sa.column("profile_version", sa.Integer()),
        sa.column("score", sa.Float()),
        sa.column("weighted_sum", sa.Float()),
        sa.column("positive_maximum", sa.Float()),
        sa.column("source_values_json", sa.JSON()),
        sa.column("factors_json", sa.JSON()),
        sa.column("input_hash", sa.String()),
        sa.column("created_by_user_id", sa.Uuid()),
    )
    decisions = sa.table(
        "finding_decisions",
        sa.column("id", sa.Uuid()),
        sa.column("organization_id", sa.Uuid()),
        sa.column("site_id", sa.Uuid()),
        sa.column("finding_id", sa.Uuid()),
        sa.column("decision_type", sa.String()),
        sa.column("status", sa.String()),
        sa.column("reason", sa.Text()),
        sa.column("evidence_json", sa.JSON()),
        sa.column("expires_at", sa.DateTime(timezone=True)),
        sa.column("duplicate_of_finding_id", sa.Uuid()),
        sa.column("previous_status", sa.String()),
        sa.column("created_by_user_id", sa.Uuid()),
        sa.column("revoked_by_user_id", sa.Uuid()),
        sa.column("revoked_at", sa.DateTime(timezone=True)),
    )
    profile_ids: dict[uuid.UUID, uuid.UUID] = {}
    for row in bind.execute(sa.select(organizations.c.id)):
        organization_id = row[0]
        profile_id = uuid.uuid5(
            uuid.NAMESPACE_URL, f"vulna:risk-profile:{organization_id}:default:1"
        )
        profile_ids[organization_id] = profile_id
        bind.execute(
            profiles.insert().values(
                id=profile_id,
                organization_id=organization_id,
                name="Vulna default",
                version=1,
                description="Balanced local-first risk profile",
                weights_json=DEFAULT_WEIGHTS,
                is_default=True,
                created_by_user_id=None,
            )
        )
    asset_rows = {row["id"]: row for row in bind.execute(sa.select(assets)).mappings()}
    for row in bind.execute(sa.select(findings)).mappings():
        asset = asset_rows.get(row["asset_id"])
        severity = str(row["severity"]).lower()
        validation = str(row["validation_status"]).lower()
        sources = {
            "severity": severity,
            "cvss": row["cvss_score"],
            "known_exploited": bool(row["known_exploited"]),
            "epss": row["epss_score"],
            "confidence": row["confidence"],
            "validation": validation,
            "internet_exposure": bool(asset["internet_exposed"]) if asset else None,
            "asset_criticality": asset["criticality"] if asset else None,
        }
        normalized = {
            "severity": SEVERITY[severity],
            "cvss": max(-1.0, min(1.0, (row["cvss_score"] / 5.0) - 1.0))
            if row["cvss_score"] is not None
            else 0.0,
            "known_exploited": 1.0 if row["known_exploited"] else -1.0,
            "epss": max(-1.0, min(1.0, row["epss_score"] * 2.0 - 1.0))
            if row["epss_score"] is not None
            else 0.0,
            "confidence": max(-1.0, min(1.0, row["confidence"] / 50.0 - 1.0)),
            "validation": VALIDATION[validation],
            "internet_exposure": (1.0 if asset["internet_exposed"] else -1.0) if asset else 0.0,
            "asset_criticality": CRITICALITY[asset["criticality"]] if asset else 0.0,
        }
        profile_id = profile_ids[row["organization_id"]]
        document = {
            "profile_id": str(profile_id),
            "profile_version": 1,
            "source_values": sources,
            "normalized": normalized,
            "weights": DEFAULT_WEIGHTS,
        }
        input_hash = hashlib.sha256(
            json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        factors = []
        weighted_sum = 0.0
        for key in sorted(DEFAULT_WEIGHTS):
            contribution = normalized[key] * DEFAULT_WEIGHTS[key]
            weighted_sum += contribution
            factors.append(
                {
                    "factor": key,
                    "source_value": sources[key],
                    "normalized_value": round(normalized[key], 6),
                    "weight": DEFAULT_WEIGHTS[key],
                    "contribution": round(contribution, 6),
                }
            )
        positive_maximum = sum(abs(value) for value in DEFAULT_WEIGHTS.values())
        score = round(max(0.0, min(100.0, weighted_sum / positive_maximum * 100.0)), 2)
        snapshot_id = uuid.uuid5(
            uuid.NAMESPACE_URL, f"vulna:finding-score:{row['id']}:{input_hash}"
        )
        bind.execute(
            snapshots.insert().values(
                id=snapshot_id,
                organization_id=row["organization_id"],
                site_id=row["site_id"],
                finding_id=row["id"],
                risk_profile_id=profile_id,
                profile_version=1,
                score=score,
                weighted_sum=round(weighted_sum, 6),
                positive_maximum=positive_maximum,
                source_values_json=sources,
                factors_json=factors,
                input_hash=input_hash,
                created_by_user_id=None,
            )
        )
        bind.execute(
            findings.update()
            .where(findings.c.id == row["id"])
            .values(
                current_score_snapshot_id=snapshot_id,
                risk_score=score,
                risk_profile_version=1,
                risk_input_hash=input_hash,
                risk_scored_at=sa.func.now(),
            )
        )
        legacy_decision_types = {
            "FALSE_POSITIVE": "false_positive",
            "DUPLICATE": "duplicate",
            "SUPPRESSED": "suppression",
        }
        legacy_type = legacy_decision_types.get(str(row["status"]).upper())
        if legacy_type:
            decision_id = uuid.uuid5(
                uuid.NAMESPACE_URL, f"vulna:legacy-finding-decision:{row['id']}"
            )
            reason = row["false_positive_reason"] or (
                "Migrated legacy finding workflow decision; review supporting evidence."
            )
            bind.execute(
                decisions.insert().values(
                    id=decision_id,
                    organization_id=row["organization_id"],
                    site_id=row["site_id"],
                    finding_id=row["id"],
                    decision_type=legacy_type,
                    status="active",
                    reason=reason,
                    evidence_json=[
                        {
                            "type": "migration_record",
                            "reference": f"legacy-finding:{row['id']}",
                        }
                    ],
                    expires_at=datetime.now(UTC) + timedelta(days=90),
                    duplicate_of_finding_id=None,
                    previous_status="new",
                    created_by_user_id=None,
                    revoked_by_user_id=None,
                    revoked_at=None,
                )
            )


def downgrade() -> None:
    with op.batch_alter_table("findings") as batch:
        batch.drop_index("ix_findings_risk_score")
        for column in (
            "risk_scored_at",
            "risk_input_hash",
            "risk_profile_version",
            "risk_score",
            "current_score_snapshot_id",
        ):
            batch.drop_column(column)
    op.drop_table("finding_decisions")
    op.drop_table("remediation_suggestions")
    op.drop_table("remediation_unit_findings")
    op.drop_table("remediation_units")
    op.drop_table("finding_score_snapshots")
    op.drop_table("risk_profiles")
