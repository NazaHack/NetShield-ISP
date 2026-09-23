"""SQLAlchemy ORM models.

Importing this package registers every table on ``Base.metadata``, which is what
lets Alembic autogenerate see the full schema. Nothing else should import the
model modules individually for that purpose.

Ownership chain: a :class:`Tenant` owns its :class:`NetworkTarget` ranges and its
:class:`Scan` jobs, and each scan owns its :class:`ScanResult` rows. Deleting a
tenant cascades through all of it.
"""

from app.models.enums import (
    SCAN_STATUS_ENUM_NAME,
    USER_ROLE_ENUM_NAME,
    ScanStatus,
    UserRole,
)
from app.models.mixins import (
    TENANT_TABLE_NAME,
    SoftDeleteMixin,
    TenantScopedMixin,
    TimestampMixin,
    UUIDPrimaryKeyMixin,
)
from app.models.network_target import NetworkTarget
from app.models.scan import Scan
from app.models.scan_result import OpenPort, ScanResult
from app.models.tenant import Tenant
from app.models.user import User

__all__ = [
    "SCAN_STATUS_ENUM_NAME",
    "TENANT_TABLE_NAME",
    "USER_ROLE_ENUM_NAME",
    "NetworkTarget",
    "OpenPort",
    "Scan",
    "ScanResult",
    "ScanStatus",
    "SoftDeleteMixin",
    "Tenant",
    "TenantScopedMixin",
    "TimestampMixin",
    "UUIDPrimaryKeyMixin",
    "User",
    "UserRole",
]
