"""Response schema for the audit trail."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict


class AuditEventRead(BaseModel):
    """One audit event as returned by the API."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    created_at: datetime
    action: str
    actor_user_id: uuid.UUID | None
    actor_email: str | None
    actor_role: str | None
    tenant_id: uuid.UUID | None
    tenant_code_name: str | None
    target: str | None
    detail: dict[str, Any] | None
    source_ip: str | None
