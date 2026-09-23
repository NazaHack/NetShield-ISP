"""Declarative base and shared table metadata.

The explicit naming convention is not cosmetic: Alembic autogenerate needs
deterministic constraint names to emit reversible migrations, and predictable
index names make it possible to reason about tenant-scoped query plans in
production.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import MetaData
from sqlalchemy.orm import DeclarativeBase

#: Deterministic names for every constraint and index SQLAlchemy creates.
NAMING_CONVENTION: dict[str, str] = {
    "ix": "ix_%(table_name)s_%(column_0_N_name)s",
    "uq": "uq_%(table_name)s_%(column_0_N_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}

metadata = MetaData(naming_convention=NAMING_CONVENTION)


class Base(DeclarativeBase):
    """Common declarative base for every NetShield-ISP ORM model."""

    metadata = metadata

    def __repr__(self) -> str:
        """Readable representation that never dumps full row contents."""
        identifier: Any = getattr(self, "id", None)
        return f"<{type(self).__name__} id={identifier!r}>"
