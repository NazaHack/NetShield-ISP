"""The scan job model.

A scan is the unit of work the API enqueues and a Celery worker executes. Its
row is the authoritative record of whether an audit ran, so the status column is
a database enum rather than free text: an unknown value cannot be written.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING, ClassVar

from sqlalchemy import CheckConstraint, DateTime, Enum, Index, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.schema import SchemaItem

from app.db.base import Base
from app.models.enums import SCAN_STATUS_ENUM_NAME, ScanStatus
from app.models.mixins import TenantScopedMixin, TimestampMixin, UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from app.models.scan_result import ScanResult
    from app.models.tenant import Tenant


class Scan(UUIDPrimaryKeyMixin, TenantScopedMixin, TimestampMixin, Base):
    """One scan job belonging to exactly one tenant."""

    __tablename__ = "scans"

    __extra_table_args__: ClassVar[tuple[SchemaItem, ...]] = (
        # Target of the composite foreign key on `scan_results`. Redundant with
        # the primary key on its own, but PostgreSQL requires a unique
        # constraint over exactly the referenced columns, and that constraint is
        # what makes a cross-tenant scan result impossible to insert.
        UniqueConstraint("id", "tenant_id", name="uq_scans_id_tenant_id"),
        # Only a finished scan may carry a completion time, and it cannot have
        # finished before it was created.
        CheckConstraint(
            "(finished_at IS NULL) OR (status IN ('COMPLETED', 'FAILED'))",
            name="finished_at_only_when_terminal",
        ),
        CheckConstraint(
            "(finished_at IS NULL) OR (finished_at >= created_at)",
            name="finished_at_after_created_at",
        ),
        # The dashboard's default view is "this tenant's scans by state, newest
        # first", and the worker quota check counts active scans per tenant.
        Index("ix_scans_tenant_id_status_created_at", "tenant_id", "status", "created_at"),
    )

    status: Mapped[ScanStatus] = mapped_column(
        Enum(
            ScanStatus,
            name=SCAN_STATUS_ENUM_NAME,
            # Store the member name, which equals the value for this enum. Being
            # explicit keeps the stored representation stable if values change.
            values_callable=lambda enum_type: [member.value for member in enum_type],
            native_enum=True,
        ),
        nullable=False,
        default=ScanStatus.PENDING,
        server_default=ScanStatus.PENDING.value,
        index=True,
        doc="Lifecycle state. Transitions are PENDING -> RUNNING -> COMPLETED|FAILED.",
    )

    finished_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        default=None,
        doc="When the scan reached a terminal state. NULL while it is pending or running.",
    )

    tenant: Mapped[Tenant] = relationship(
        back_populates="scans",
        lazy="raise",
    )

    results: Mapped[list[ScanResult]] = relationship(
        back_populates="scan",
        cascade="all, delete-orphan",
        passive_deletes=True,
        lazy="raise",
        order_by="ScanResult.host_ip",
    )

    @property
    def is_terminal(self) -> bool:
        """True when the scan has finished, successfully or not."""
        return self.status.is_terminal

    def mark_running(self) -> None:
        """Move a pending scan into the running state.

        Raises:
            ValueError: If the scan is not pending. Re-entering RUNNING would
                mean two workers believe they own the same job.
        """
        if self.status is not ScanStatus.PENDING:
            msg = f"Cannot start a scan in state {self.status.value}."
            raise ValueError(msg)
        self.status = ScanStatus.RUNNING

    def mark_finished(self, *, status: ScanStatus) -> None:
        """Move a running scan into a terminal state and stamp the finish time.

        Args:
            status: Either ``COMPLETED`` or ``FAILED``.

        Raises:
            ValueError: If the target state is not terminal, or if the scan has
                already finished.
        """
        if not status.is_terminal:
            msg = f"{status.value} is not a terminal state."
            raise ValueError(msg)
        if self.status.is_terminal:
            msg = f"Scan has already finished in state {self.status.value}."
            raise ValueError(msg)
        self.status = status
        self.finished_at = datetime.now(UTC)

    def __repr__(self) -> str:
        """Identify the scan without dumping the whole row."""
        return f"<Scan id={getattr(self, 'id', None)!r} status={self.status.value!r}>"
