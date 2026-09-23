"""Request and response schemas for network targets.

The address field is validated here as well as in the model. Rejecting a bad
value at the edge means the caller gets a 422 naming the field, rather than a
500 from an exception raised deep inside the ORM.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.core.network import MAX_TARGET_LENGTH, InvalidNetworkError, normalise_network
from app.models.network_target import MAX_TARGET_LABEL_LENGTH


def _validate_network(value: str) -> str:
    """Normalise a range, re-raising as a plain ValueError for Pydantic."""
    try:
        return normalise_network(value)
    except InvalidNetworkError as exc:
        raise ValueError(str(exc)) from exc


class NetworkTargetCreate(BaseModel):
    """Payload for registering a range the tenant is authorised to audit."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    label: str = Field(
        min_length=1,
        max_length=MAX_TARGET_LABEL_LENGTH,
        description="Operator-facing name, unique within the tenant.",
        examples=["CGNAT customer pool"],
    )
    ip_address_or_cidr: str = Field(
        min_length=1,
        max_length=MAX_TARGET_LENGTH,
        description=(
            "An IP address or CIDR block. A bare address is stored as a "
            "single-host network. A prefix with host bits set is rejected "
            "rather than widened."
        ),
        examples=["100.64.0.0/22"],
    )
    description: str | None = Field(
        default=None,
        max_length=2000,
        description="Free-form note explaining what this range is and who owns it.",
    )

    @field_validator("ip_address_or_cidr")
    @classmethod
    def _check_network(cls, value: str) -> str:
        """Reject anything outside the IP address and CIDR grammar."""
        return _validate_network(value)

    @field_validator("label")
    @classmethod
    def _label_not_blank(cls, value: str) -> str:
        """Reject a label that is only whitespace."""
        candidate = value.strip()
        if not candidate:
            msg = "label must not be blank"
            raise ValueError(msg)
        return candidate


class NetworkTargetUpdate(BaseModel):
    """Payload for editing a range. Every field is optional."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    label: str | None = Field(default=None, min_length=1, max_length=MAX_TARGET_LABEL_LENGTH)
    ip_address_or_cidr: str | None = Field(default=None, min_length=1, max_length=MAX_TARGET_LENGTH)
    description: str | None = Field(default=None, max_length=2000)

    @field_validator("ip_address_or_cidr")
    @classmethod
    def _check_network(cls, value: str | None) -> str | None:
        """Reject anything outside the IP address and CIDR grammar."""
        return None if value is None else _validate_network(value)

    @field_validator("label")
    @classmethod
    def _label_not_blank(cls, value: str | None) -> str | None:
        """Reject a label that is only whitespace."""
        if value is None:
            return None
        candidate = value.strip()
        if not candidate:
            msg = "label must not be blank"
            raise ValueError(msg)
        return candidate


class NetworkTargetRead(BaseModel):
    """A registered range as returned by the API."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    tenant_id: uuid.UUID
    label: str
    ip_address_or_cidr: str
    description: str | None
    created_at: datetime
    updated_at: datetime
