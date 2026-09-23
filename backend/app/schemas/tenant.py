"""Request and response schemas for tenants."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.models.tenant import (
    CODE_NAME_PATTERN,
    MAX_TENANT_CODE_NAME_LENGTH,
    MAX_TENANT_NAME_LENGTH,
)


class TenantCreate(BaseModel):
    """Payload for registering a new ISP customer."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str = Field(
        min_length=1,
        max_length=MAX_TENANT_NAME_LENGTH,
        description="Human-readable customer name.",
        examples=["Acme ISP"],
    )
    code_name: str = Field(
        min_length=1,
        max_length=MAX_TENANT_CODE_NAME_LENGTH,
        pattern=CODE_NAME_PATTERN,
        description=(
            "Stable machine-readable slug, unique across the platform. Lowercase "
            "letters, digits and single hyphens."
        ),
        examples=["acme-isp"],
    )

    @field_validator("name")
    @classmethod
    def _name_not_blank(cls, value: str) -> str:
        """Reject a name that is only whitespace."""
        candidate = value.strip()
        if not candidate:
            msg = "name must not be blank"
            raise ValueError(msg)
        return candidate


class TenantUpdate(BaseModel):
    """Payload for editing a tenant.

    ``code_name`` is deliberately absent. It is the stable identifier other
    systems key on, and letting it change would silently break every one of
    them; a customer that needs a different slug gets a new tenant.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str = Field(min_length=1, max_length=MAX_TENANT_NAME_LENGTH)

    @field_validator("name")
    @classmethod
    def _name_not_blank(cls, value: str) -> str:
        """Reject a name that is only whitespace."""
        candidate = value.strip()
        if not candidate:
            msg = "name must not be blank"
            raise ValueError(msg)
        return candidate


class TenantRead(BaseModel):
    """A tenant as returned by the API."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    code_name: str
    is_system: bool = Field(
        default=False,
        description=(
            "True for a workspace the platform provisions for itself, such as the "
            "owner of ad-hoc scans. Not an ISP customer."
        ),
    )
    created_at: datetime
    updated_at: datetime
