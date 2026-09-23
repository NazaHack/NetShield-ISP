"""Per-host findings produced by a scan.

One row per host that answered. The open-port detail is stored as JSONB rather
than as a child table: it is written once by the worker, read back whole by the
dashboard, and its shape follows whatever Nmap reported rather than a schema the
platform controls.
"""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING, ClassVar, Final, TypedDict

from sqlalchemy import CheckConstraint, ForeignKeyConstraint, Index, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship, validates
from sqlalchemy.schema import SchemaItem

from app.core.network import MAX_TARGET_LENGTH, normalise_host_address
from app.db.base import Base
from app.models.mixins import TenantScopedMixin, TimestampMixin, UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from app.models.scan import Scan

#: Transport protocols Nmap reports. Anything else is rejected on write, because
#: the value is rendered in the dashboard and filtered on in queries.
ALLOWED_PROTOCOLS: Final[frozenset[str]] = frozenset({"tcp", "udp", "sctp"})

#: Valid TCP/UDP port numbers.
MIN_PORT: Final[int] = 1
MAX_PORT: Final[int] = 65535


class OpenPort(TypedDict):
    """One open port as recorded in :attr:`ScanResult.open_ports`.

    ``service`` and ``version`` are optional because they depend on whether
    service detection ran and on whether the service answered informatively.
    """

    port: int
    protocol: str
    service: str | None
    version: str | None


class ScanResult(UUIDPrimaryKeyMixin, TenantScopedMixin, TimestampMixin, Base):
    """The findings for a single host within one scan.

    The ``tenant_id`` column is not part of the field list this table was
    specified with. It is present because the platform's isolation rule requires
    every business table to be filterable by tenant without a join, and because
    it enables the composite foreign key below, which makes a result belonging
    to a different tenant than its scan impossible to insert.
    """

    __tablename__ = "scan_results"

    # The composite foreign key below is the only reference this table needs to
    # establish tenancy, and it is strictly stronger than a direct reference to
    # `tenants` would be. Emitting both would create two overlapping foreign
    # keys over `tenant_id` for no additional guarantee.
    __tenant_foreign_key__: ClassVar[bool] = False

    __extra_table_args__: ClassVar[tuple[SchemaItem, ...]] = (
        # The heart of this table's isolation guarantee: a result's tenant must
        # be the tenant of the scan that produced it. Enforced by the database,
        # so no application bug can violate it.
        ForeignKeyConstraint(
            ["scan_id", "tenant_id"],
            ["scans.id", "scans.tenant_id"],
            ondelete="CASCADE",
            name="fk_scan_results_scan_id_tenant_id_scans",
        ),
        # A host appears at most once per scan; a second row would double every
        # count in the dashboard.
        Index("uq_scan_results_scan_id_host_ip", "scan_id", "host_ip", unique=True),
        # Supports "which hosts in this tenant expose port 23?", the query an
        # ISP audit actually runs. A GIN index is what makes JSONB containment
        # usable at scale.
        Index(
            "ix_scan_results_open_ports",
            "open_ports",
            postgresql_using="gin",
        ),
        CheckConstraint(
            "jsonb_typeof(open_ports) = 'array'",
            name="open_ports_is_array",
        ),
    )

    scan_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True),
        nullable=False,
        index=True,
        doc=(
            "The scan that produced this result. The reference itself is the "
            "composite foreign key declared above, which carries tenant_id too."
        ),
    )

    host_ip: Mapped[str] = mapped_column(
        String(MAX_TARGET_LENGTH),
        nullable=False,
        index=True,
        doc="Canonical address of the host that answered.",
    )

    open_ports: Mapped[list[OpenPort]] = mapped_column(
        JSONB,
        nullable=False,
        default=list,
        server_default="[]",
        doc=(
            "Open ports as a JSON array of objects with port, protocol, service "
            "and version. Reassign the whole list rather than mutating it in "
            "place: plain JSONB does not track in-place changes."
        ),
    )

    raw_output: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        default=None,
        doc=(
            "Unparsed scanner output for this host, kept as evidence. Treat it "
            "as untrusted: it contains banners controlled by the scanned host."
        ),
    )

    scan: Mapped[Scan] = relationship(
        back_populates="results",
        lazy="raise",
    )

    @validates("host_ip")
    def _validate_host_ip(self, _key: str, value: str) -> str:
        """Reject anything that is not a single IP address."""
        return normalise_host_address(value)

    @validates("open_ports")
    def _validate_open_ports(self, _key: str, value: object) -> list[OpenPort]:
        """Validate the JSONB payload before it is persisted.

        JSONB accepts any well-formed JSON, so the shape has to be enforced
        here. Without it a malformed entry would only surface when the dashboard
        tried to render it, long after the scan that produced it finished.
        """
        if not isinstance(value, list):
            msg = "open_ports must be a list."
            raise TypeError(msg)

        validated: list[OpenPort] = []
        for index, entry in enumerate(value):
            if not isinstance(entry, dict):
                msg = f"open_ports[{index}] must be an object."
                raise TypeError(msg)

            port = entry.get("port")
            if not isinstance(port, int) or isinstance(port, bool):
                msg = f"open_ports[{index}].port must be an integer."
                raise TypeError(msg)
            if not MIN_PORT <= port <= MAX_PORT:
                msg = f"open_ports[{index}].port must be between {MIN_PORT} and {MAX_PORT}."
                raise ValueError(msg)

            protocol = entry.get("protocol")
            if not isinstance(protocol, str) or protocol.lower() not in ALLOWED_PROTOCOLS:
                allowed = ", ".join(sorted(ALLOWED_PROTOCOLS))
                msg = f"open_ports[{index}].protocol must be one of: {allowed}."
                raise ValueError(msg)

            service = entry.get("service")
            version = entry.get("version")
            for field_name, field_value in (("service", service), ("version", version)):
                if field_value is not None and not isinstance(field_value, str):
                    msg = f"open_ports[{index}].{field_name} must be a string or null."
                    raise TypeError(msg)

            validated.append(
                OpenPort(
                    port=port,
                    protocol=protocol.lower(),
                    service=service,
                    version=version,
                )
            )
        return validated

    def __repr__(self) -> str:
        """Identify the result without dumping the whole row."""
        return (
            f"<ScanResult id={getattr(self, 'id', None)!r} "
            f"host_ip={self.host_ip!r} open_ports={len(self.open_ports)}>"
        )
