"""Reusable model mixins.

``TenantScopedMixin`` is the structural half of NetShield-ISP's isolation
guarantee: it makes ``tenant_id`` mandatory, indexed and foreign-keyed on every
business table. The behavioural half — filtering every query by the caller's
tenant — is enforced in the repository layer, because a column alone cannot
stop a developer from writing an unscoped ``SELECT``.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, ClassVar, Final

from sqlalchemy import DateTime, ForeignKey, Index, func
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, declared_attr, mapped_column
from sqlalchemy.schema import SchemaItem

#: Name of the tenants table that every scoped model points at.
TENANT_TABLE_NAME: Final[str] = "tenants"


class UUIDPrimaryKeyMixin:
    """Adds a database-generated UUIDv4 primary key.

    UUIDs rather than serial integers: identifiers appear in API paths, and
    sequential keys would leak tenant volume and allow trivial enumeration of
    another tenant's resource identifiers.
    """

    id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=func.gen_random_uuid(),
        nullable=False,
    )


class TimestampMixin:
    """Adds server-side creation and update timestamps in UTC."""

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        index=True,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )


class SoftDeleteMixin:
    """Adds a nullable deletion timestamp.

    Audit records are never hard-deleted: an ISP must be able to prove what was
    scanned and when, even after a customer offboards.
    """

    deleted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        default=None,
        index=True,
    )

    @property
    def is_deleted(self) -> bool:
        """True when the row has been soft-deleted."""
        return self.deleted_at is not None


class TenantScopedMixin:
    """Binds a model to exactly one tenant.

    Every business table in NetShield-ISP must inherit this mixin. The column is
    non-nullable and cascades on tenant deletion, and the accompanying index
    exists because effectively every production query filters on it first.

    Because the mixin owns ``__table_args__``, a concrete model contributes its
    own table-level constraints through :attr:`__extra_table_args__` rather than
    by redefining ``__table_args__`` and silently dropping the tenant index.
    """

    #: Table-level constraints contributed by the concrete model. Merged into
    #: ``__table_args__`` after the tenant index.
    __extra_table_args__: ClassVar[tuple[SchemaItem, ...]] = ()

    #: Whether to emit a direct foreign key from ``tenant_id`` to ``tenants.id``.
    #:
    #: A model may set this to ``False`` only when it guarantees tenant
    #: consistency by a stronger means. The one case in this codebase is
    #: ``ScanResult``, which carries a composite foreign key onto its parent
    #: scan: that constraint makes a result whose tenant differs from its scan's
    #: tenant impossible to insert at all, which a plain single-column reference
    #: to ``tenants`` cannot do.
    __tenant_foreign_key__: ClassVar[bool] = True

    @declared_attr
    @classmethod
    def tenant_id(cls) -> Mapped[uuid.UUID]:
        """Owning tenant. Non-nullable by design; there is no global row."""
        column_args: list[Any] = [PGUUID(as_uuid=True)]
        if cls.__tenant_foreign_key__:
            column_args.append(ForeignKey(f"{TENANT_TABLE_NAME}.id", ondelete="CASCADE"))
        return mapped_column(*column_args, nullable=False, index=True)

    @declared_attr.directive
    @classmethod
    def __table_args__(cls) -> tuple[SchemaItem, ...]:
        """Tenant access index, followed by the model's own constraints."""
        table_name = getattr(cls, "__tablename__", cls.__name__.lower())
        tenant_index = Index(
            f"ix_{table_name}_tenant_id_created_at",
            "tenant_id",
            "created_at",
        )
        return (tenant_index, *cls.__extra_table_args__)
