"""The audit event model.

An audit trail must outlive the things it describes: the record of who deleted a
tenant is worthless if it vanishes with the tenant. So this table is deliberately
the one place in the schema that does **not** use foreign keys or cascades. The
actor and tenant are stored as plain identifiers alongside denormalised copies of
their email, role and code name, so an event stays complete and readable even
after the referenced rows are gone.

The table is append-only in practice. Nothing updates or deletes a row; it is
written once at the moment an action happens and only ever read afterwards.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Final

from sqlalchemy import Index, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.models.mixins import TimestampMixin, UUIDPrimaryKeyMixin

#: Longest action name stored. Actions are short dotted slugs like "scan.launched".
MAX_ACTION_LENGTH: Final[int] = 64


class AuditAction:
    """The action names recorded in the audit trail.

    A plain string column rather than a database enum: the taxonomy grows often,
    and a migration per new action would be friction for no benefit, since the
    column is only ever read back as text and filtered on.
    """

    LOGIN_SUCCEEDED: Final[str] = "login.succeeded"
    LOGIN_FAILED: Final[str] = "login.failed"
    LOGIN_RATE_LIMITED: Final[str] = "login.rate_limited"
    PASSWORD_CHANGED: Final[str] = "password.changed"  # noqa: S105  # action name, not a secret
    PASSWORD_RESET: Final[str] = "password.reset"  # noqa: S105  # action name, not a secret
    TENANT_CREATED: Final[str] = "tenant.created"
    TENANT_DELETED: Final[str] = "tenant.deleted"
    USER_CREATED: Final[str] = "user.created"
    USER_DELETED: Final[str] = "user.deleted"
    SCAN_LAUNCHED: Final[str] = "scan.launched"


class AuditEvent(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """One recorded action, kept for as long as the platform runs."""

    __tablename__ = "audit_events"

    __table_args__ = (
        # The trail is read newest-first, usually filtered by action or by the
        # tenant an action concerned.
        Index("ix_audit_events_action_created_at", "action", "created_at"),
        Index("ix_audit_events_tenant_id_created_at", "tenant_id", "created_at"),
    )

    action: Mapped[str] = mapped_column(
        String(MAX_ACTION_LENGTH),
        nullable=False,
        index=True,
        doc="Short dotted slug naming what happened, e.g. 'scan.launched'.",
    )

    # Actor. No foreign key: the event must survive the actor's deletion. The
    # id may be absent for an unauthenticated action such as a failed login.
    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), nullable=True, default=None
    )
    actor_email: Mapped[str | None] = mapped_column(
        String(254), nullable=True, default=None, doc="Denormalised so it survives user deletion."
    )
    actor_role: Mapped[str | None] = mapped_column(String(32), nullable=True, default=None)

    # Tenant the action concerned, if any. No foreign key, for the same reason.
    tenant_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), nullable=True, default=None
    )
    tenant_code_name: Mapped[str | None] = mapped_column(
        String(63), nullable=True, default=None, doc="Denormalised so it survives tenant deletion."
    )

    # What was acted on, and any extra context.
    target: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
        default=None,
        doc="Human-readable identifier of the affected resource, e.g. an email or a scan id.",
    )
    detail: Mapped[dict[str, Any] | None] = mapped_column(
        JSONB, nullable=True, default=None, doc="Extra structured context, free-form per action."
    )
    source_ip: Mapped[str | None] = mapped_column(String(64), nullable=True, default=None)

    def __repr__(self) -> str:
        """Identify the event without dumping its detail payload."""
        stamp: datetime | None = getattr(self, "created_at", None)
        return f"<AuditEvent action={self.action!r} actor={self.actor_email!r} at={stamp!r}>"
