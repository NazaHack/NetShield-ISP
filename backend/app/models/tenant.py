"""The tenant model.

A tenant is one ISP customer account. It is the root of every ownership chain in
the platform: deleting a tenant cascades to its targets, scans and results,
because retaining a former customer's network map is a liability rather than an
asset.
"""

from __future__ import annotations

import re
import uuid
from typing import TYPE_CHECKING, Final

from sqlalchemy import CheckConstraint, String
from sqlalchemy.orm import Mapped, mapped_column, relationship, validates

from app.db.base import Base
from app.models.mixins import TimestampMixin, UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from app.models.network_target import NetworkTarget
    from app.models.scan import Scan
    from app.models.user import User

#: Maximum length of the human-readable tenant name.
MAX_TENANT_NAME_LENGTH: Final[int] = 200

#: Maximum length of the machine-readable code name. 63 characters matches the
#: DNS label limit, so a code name can safely become a subdomain or a queue name.
MAX_TENANT_CODE_NAME_LENGTH: Final[int] = 63

#: Prefix of the code name given to an operator's ad-hoc scan workspace.
#:
#: Ad-hoc scans still belong to a tenant: every scan, result and audit record in
#: the platform does, and carving out an exception would mean a row the
#: isolation rules do not cover. The workspace exists so that an operator can
#: scan a range without first inventing a customer to attach it to.
#:
#: One workspace per operator rather than one for the platform, because the
#: per-tenant concurrency quota exists to stop a single actor monopolising the
#: workers. A shared workspace would make every operator on the platform compete
#: for the same three slots.
ADHOC_WORKSPACE_PREFIX: Final[str] = "adhoc-"


def adhoc_workspace_code_name(user_id: uuid.UUID) -> str:
    """Return the code name of one operator's ad-hoc workspace."""
    return f"{ADHOC_WORKSPACE_PREFIX}{user_id.hex}"


def adhoc_workspace_name(email: str) -> str:
    """Return the display name of one operator's ad-hoc workspace."""
    return f"Ad-hoc scans ({email})"


#: Code names are slugs: lowercase alphanumerics separated by single hyphens,
#: never leading or trailing. Keeping the grammar this tight means a code name
#: is safe to interpolate into an identifier without escaping.
CODE_NAME_PATTERN: Final[str] = r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$"

_CODE_NAME_RE = re.compile(CODE_NAME_PATTERN)


class Tenant(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """An ISP customer account that owns targets, scans and results."""

    __tablename__ = "tenants"

    __table_args__ = (
        # Enforced in the database as well as in Python: an application bug or a
        # manual INSERT must not be able to create a code name that downstream
        # code assumes is a safe slug.
        CheckConstraint(
            f"code_name ~ '{CODE_NAME_PATTERN}'",
            name="code_name_is_slug",
        ),
        CheckConstraint("length(btrim(name)) > 0", name="name_not_blank"),
    )

    name: Mapped[str] = mapped_column(
        String(MAX_TENANT_NAME_LENGTH),
        nullable=False,
        doc="Human-readable customer name, shown in the dashboard.",
    )

    code_name: Mapped[str] = mapped_column(
        String(MAX_TENANT_CODE_NAME_LENGTH),
        nullable=False,
        unique=True,
        index=True,
        doc="Stable machine-readable slug, unique across the platform.",
    )

    is_system: Mapped[bool] = mapped_column(
        nullable=False,
        default=False,
        server_default="false",
        index=True,
        doc=(
            "True for a workspace the platform provisions for itself rather than "
            "an ISP customer. System workspaces are hidden from the customer "
            "list, because an operator who never created one should not have to "
            "wonder what it is."
        ),
    )

    network_targets: Mapped[list[NetworkTarget]] = relationship(
        back_populates="tenant",
        cascade="all, delete-orphan",
        passive_deletes=True,
        # `raise` rather than a lazy load: an implicit query inside an async
        # request would fail confusingly, and inside a loop it would be an N+1.
        lazy="raise",
    )

    scans: Mapped[list[Scan]] = relationship(
        back_populates="tenant",
        cascade="all, delete-orphan",
        passive_deletes=True,
        lazy="raise",
    )

    users: Mapped[list[User]] = relationship(
        back_populates="tenant",
        cascade="all, delete-orphan",
        passive_deletes=True,
        lazy="raise",
    )

    @validates("code_name")
    def _validate_code_name(self, _key: str, value: str) -> str:
        """Normalise and validate the code name before it reaches the database."""
        candidate = value.strip().lower()
        if not _CODE_NAME_RE.match(candidate):
            msg = (
                f"Tenant code_name {value!r} must be a slug: lowercase letters, "
                "digits and single hyphens, not starting or ending with a hyphen."
            )
            raise ValueError(msg)
        if len(candidate) > MAX_TENANT_CODE_NAME_LENGTH:
            msg = f"Tenant code_name must be at most {MAX_TENANT_CODE_NAME_LENGTH} characters."
            raise ValueError(msg)
        return candidate

    @validates("name")
    def _validate_name(self, _key: str, value: str) -> str:
        """Reject a blank display name, which would render as an empty row."""
        candidate = value.strip()
        if not candidate:
            msg = "Tenant name must not be blank."
            raise ValueError(msg)
        if len(candidate) > MAX_TENANT_NAME_LENGTH:
            msg = f"Tenant name must be at most {MAX_TENANT_NAME_LENGTH} characters."
            raise ValueError(msg)
        return candidate

    def __repr__(self) -> str:
        """Identify the tenant without dumping the whole row."""
        return f"<Tenant id={getattr(self, 'id', None)!r} code_name={self.code_name!r}>"
