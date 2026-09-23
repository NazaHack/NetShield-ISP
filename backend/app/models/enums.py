"""Enumerations shared by the ORM models and the API schemas.

These are declared in one place so that a value can never drift between the
database enum, the task payloads and the HTTP contract.
"""

from __future__ import annotations

from enum import StrEnum


class ScanStatus(StrEnum):
    """Lifecycle of a scan job.

    The progression is ``PENDING -> RUNNING -> COMPLETED | FAILED``. A job is
    created ``PENDING`` by the API, moved to ``RUNNING`` by the worker that
    claims it, and reaches exactly one terminal state.
    """

    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"

    @property
    def is_terminal(self) -> bool:
        """True when no further transition is possible.

        Used to decide whether a scan may be retried and whether its row can be
        safely read as a final record.
        """
        return self in {ScanStatus.COMPLETED, ScanStatus.FAILED}

    @property
    def is_active(self) -> bool:
        """True while the scan still occupies a slot in the tenant's quota."""
        return self in {ScanStatus.PENDING, ScanStatus.RUNNING}


#: Name of the PostgreSQL enum type backing :class:`ScanStatus`. Referenced by
#: the model and by the Alembic migration that creates and drops the type.
SCAN_STATUS_ENUM_NAME = "scan_status"


class UserRole(StrEnum):
    """What a user account is allowed to do.

    The two roles are structurally different rather than a permission scale.
    A platform administrator belongs to no tenant and manages the customer list;
    a tenant user belongs to exactly one tenant and can never leave it. The
    database enforces that pairing with a check constraint, so a row cannot
    exist that is half of each.
    """

    PLATFORM_ADMIN = "PLATFORM_ADMIN"
    TENANT_USER = "TENANT_USER"

    @property
    def is_platform_admin(self) -> bool:
        """True when the role administers the platform rather than one tenant."""
        return self is UserRole.PLATFORM_ADMIN


#: Name of the PostgreSQL enum type backing :class:`UserRole`.
USER_ROLE_ENUM_NAME = "user_role"
