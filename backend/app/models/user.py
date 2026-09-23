"""User accounts.

A user is either a platform administrator or a member of exactly one tenant, and
the database enforces that pairing rather than trusting the application to keep
it straight. An administrator with a tenant, or a tenant user without one, would
be an identity the authorisation layer could not classify, so such a row cannot
be inserted at all.

``User`` deliberately does not inherit ``TenantScopedMixin``: administrators
belong to no tenant, so the column has to be nullable, which is exactly the
property that mixin exists to forbid everywhere else.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Final

from sqlalchemy import CheckConstraint, DateTime, Enum, ForeignKey, Index, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship, validates

from app.db.base import Base
from app.models.enums import USER_ROLE_ENUM_NAME, UserRole
from app.models.mixins import TENANT_TABLE_NAME, TimestampMixin, UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from app.models.tenant import Tenant

#: Maximum length of an email address. 254 is the practical RFC 5321 ceiling.
MAX_EMAIL_LENGTH: Final[int] = 254

#: Maximum length of the display name.
MAX_FULL_NAME_LENGTH: Final[int] = 200


class User(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """An account that can sign in to the platform."""

    __tablename__ = "users"

    __table_args__ = (
        UniqueConstraint("email", name="uq_users_email"),
        # The structural invariant: role and tenancy must agree.
        CheckConstraint(
            "(role = 'PLATFORM_ADMIN' AND tenant_id IS NULL) OR "
            "(role = 'TENANT_USER' AND tenant_id IS NOT NULL)",
            name="role_matches_tenancy",
        ),
        # Emails are stored lowercase, so a plain uniqueness constraint is
        # enough; this check stops a manual INSERT bypassing the normalisation.
        CheckConstraint("email = lower(email)", name="email_is_lowercase"),
        CheckConstraint("length(btrim(email)) > 0", name="email_not_blank"),
        Index("ix_users_tenant_id_email", "tenant_id", "email"),
    )

    email: Mapped[str] = mapped_column(
        String(MAX_EMAIL_LENGTH),
        nullable=False,
        index=True,
        doc="Sign-in identifier, stored lowercase and unique across the platform.",
    )

    full_name: Mapped[str] = mapped_column(
        String(MAX_FULL_NAME_LENGTH),
        nullable=False,
        doc="Display name shown in the console.",
    )

    password_hash: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        doc=(
            "Argon2id hash. Never rendered, never logged, and never included in "
            "a response model."
        ),
    )

    role: Mapped[UserRole] = mapped_column(
        Enum(
            UserRole,
            name=USER_ROLE_ENUM_NAME,
            values_callable=lambda enum_type: [member.value for member in enum_type],
            native_enum=True,
        ),
        nullable=False,
        index=True,
        doc="PLATFORM_ADMIN manages customers; TENANT_USER belongs to exactly one.",
    )

    tenant_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey(f"{TENANT_TABLE_NAME}.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
        doc="Owning tenant. NULL for platform administrators, required otherwise.",
    )

    is_active: Mapped[bool] = mapped_column(
        nullable=False,
        default=True,
        server_default="true",
        doc=(
            "Disabled accounts are refused at login. Deactivating rather than "
            "deleting keeps the audit trail of who ran which scan intact."
        ),
    )

    last_login_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        default=None,
        doc="When this account last signed in successfully.",
    )

    tenant: Mapped[Tenant | None] = relationship(
        back_populates="users",
        lazy="raise",
    )

    @validates("email")
    def _normalise_email(self, _key: str, value: str) -> str:
        """Lowercase and trim the address so lookups are case-insensitive."""
        candidate = value.strip().lower()
        if not candidate:
            msg = "Email must not be blank."
            raise ValueError(msg)
        if len(candidate) > MAX_EMAIL_LENGTH:
            msg = f"Email must be at most {MAX_EMAIL_LENGTH} characters."
            raise ValueError(msg)
        if "@" not in candidate:
            msg = f"{value!r} is not an email address."
            raise ValueError(msg)
        return candidate

    @validates("full_name")
    def _validate_full_name(self, _key: str, value: str) -> str:
        """Reject a blank display name."""
        candidate = value.strip()
        if not candidate:
            msg = "Full name must not be blank."
            raise ValueError(msg)
        if len(candidate) > MAX_FULL_NAME_LENGTH:
            msg = f"Full name must be at most {MAX_FULL_NAME_LENGTH} characters."
            raise ValueError(msg)
        return candidate

    @property
    def is_platform_admin(self) -> bool:
        """True when this account administers the platform."""
        return self.role.is_platform_admin

    def __repr__(self) -> str:
        """Identify the user without exposing the hash or the display name."""
        return (
            f"<User id={getattr(self, 'id', None)!r} email={self.email!r} role={self.role.value}>"
        )
