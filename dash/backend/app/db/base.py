"""SQLAlchemy declarative base and shared metadata.

A deterministic naming convention is configured so that Alembic autogenerates
stable, predictable constraint and index names across dialects.
"""

from __future__ import annotations

from sqlalchemy import MetaData
from sqlalchemy.orm import DeclarativeBase

# Consistent constraint naming keeps migrations reproducible and diffs clean.
NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    """Declarative base for all VulnaDash ORM models.

    ``eager_defaults`` makes the ORM fetch server-generated values (e.g.
    ``created_at`` / ``updated_at`` from ``func.now()``) immediately after
    INSERT and UPDATE, so serializing a just-modified object never triggers a
    lazy reload outside the async context.
    """

    metadata = MetaData(naming_convention=NAMING_CONVENTION)
    __mapper_args__ = {"eager_defaults": True}
