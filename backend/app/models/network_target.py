"""Network targets: the address ranges a tenant has declared it may audit.

Every value stored in :attr:`NetworkTarget.ip_address_or_cidr` eventually becomes
an argument to Nmap. The column is therefore validated on write and never
accepts anything outside the IP address and CIDR grammar.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar, Final

from sqlalchemy import CheckConstraint, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship, validates
from sqlalchemy.schema import SchemaItem

from app.core.network import MAX_TARGET_LENGTH, normalise_network
from app.db.base import Base
from app.models.mixins import TenantScopedMixin, TimestampMixin, UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from app.models.tenant import Tenant

#: Maximum length of the operator-facing label.
MAX_TARGET_LABEL_LENGTH: Final[int] = 150


class NetworkTarget(UUIDPrimaryKeyMixin, TenantScopedMixin, TimestampMixin, Base):
    """An address or CIDR block that one tenant is authorised to scan."""

    __tablename__ = "network_targets"

    __extra_table_args__: ClassVar[tuple[SchemaItem, ...]] = (
        # A label is how an operator recognises a range in the dashboard, so two
        # ranges sharing one label inside a tenant would be actively misleading.
        UniqueConstraint("tenant_id", "label", name="uq_network_targets_tenant_id_label"),
        # The same range registered twice would silently double a tenant's scan
        # volume and duplicate every finding.
        UniqueConstraint(
            "tenant_id",
            "ip_address_or_cidr",
            name="uq_network_targets_tenant_id_ip_address_or_cidr",
        ),
        # Defence in depth behind the Python validator: a manual INSERT must not
        # be able to plant a value that later reaches a command line.
        CheckConstraint(
            "ip_address_or_cidr ~ '^[0-9a-fA-F:.]+/[0-9]{1,3}$'",
            name="ip_address_or_cidr_is_cidr",
        ),
        CheckConstraint("length(btrim(label)) > 0", name="label_not_blank"),
    )

    label: Mapped[str] = mapped_column(
        String(MAX_TARGET_LABEL_LENGTH),
        nullable=False,
        doc="Operator-facing name for this range, unique within the tenant.",
    )

    ip_address_or_cidr: Mapped[str] = mapped_column(
        String(MAX_TARGET_LENGTH),
        nullable=False,
        index=True,
        doc=(
            "Canonical CIDR block. A bare address is stored as a single-host "
            "network, so every row has the same shape."
        ),
    )

    description: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        default=None,
        doc="Free-form note explaining what this range is and who owns it.",
    )

    tenant: Mapped[Tenant] = relationship(
        back_populates="network_targets",
        lazy="raise",
    )

    @validates("ip_address_or_cidr")
    def _validate_network(self, _key: str, value: str) -> str:
        """Reject anything that is not an IP address or CIDR block.

        Raises:
            InvalidNetworkError: Propagated from the parser. It subclasses
                ``ValueError``, so callers that already handle validation errors
                need no special case.
        """
        return normalise_network(value)

    @validates("label")
    def _validate_label(self, _key: str, value: str) -> str:
        """Trim the label and reject a blank one."""
        candidate = value.strip()
        if not candidate:
            msg = "Network target label must not be blank."
            raise ValueError(msg)
        if len(candidate) > MAX_TARGET_LABEL_LENGTH:
            msg = f"Network target label must be at most {MAX_TARGET_LABEL_LENGTH} characters."
            raise ValueError(msg)
        return candidate

    def __repr__(self) -> str:
        """Identify the target without dumping the whole row."""
        return (
            f"<NetworkTarget id={getattr(self, 'id', None)!r} "
            f"label={self.label!r} range={self.ip_address_or_cidr!r}>"
        )
