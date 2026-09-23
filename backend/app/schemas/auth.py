"""Request and response schemas for authentication and account management."""

from __future__ import annotations

import re
import uuid
from datetime import datetime
from typing import Annotated

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, field_validator

from app.core.passwords import MAX_PASSWORD_LENGTH, MIN_PASSWORD_LENGTH
from app.models.enums import UserRole
from app.models.user import MAX_EMAIL_LENGTH, MAX_FULL_NAME_LENGTH

#: Pragmatic address shape: something, an @, a domain with a dot, no spaces.
#:
#: Deliberately not `EmailStr`. Its validator rejects special-use domains such
#: as `.local` and `.internal`, which are exactly what an on-premises ISP
#: deployment uses for its own operator accounts. Deliverability is not this
#: field's problem: the address is an identifier matched against stored data,
#: and a bounced email is a support ticket rather than a security event.
_EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _normalise_email(value: str) -> str:
    """Trim, lowercase and sanity-check a sign-in address."""
    candidate = value.strip().lower()
    if len(candidate) > MAX_EMAIL_LENGTH:
        msg = f"Email must be at most {MAX_EMAIL_LENGTH} characters"
        raise ValueError(msg)
    if not _EMAIL_PATTERN.match(candidate):
        msg = "Not a valid email address"
        raise ValueError(msg)
    return candidate


#: A normalised sign-in address.
EmailAddress = Annotated[str, AfterValidator(_normalise_email)]


class LoginRequest(BaseModel):
    """Credentials presented at sign-in."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    email: EmailAddress = Field(description="Sign-in address, matched case-insensitively.")
    password: str = Field(
        min_length=1,
        max_length=MAX_PASSWORD_LENGTH,
        description="The account's password.",
    )


class UserRead(BaseModel):
    """An account as returned by the API.

    The password hash has no field here, so it cannot leak by someone adding a
    column to the table and forgetting about the response model.
    """

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    email: str
    full_name: str
    role: UserRole
    tenant_id: uuid.UUID | None
    is_active: bool
    last_login_at: datetime | None
    created_at: datetime


class LoginResponse(BaseModel):
    """A successful sign-in."""

    model_config = ConfigDict(frozen=True)

    access_token: str
    # The OAuth 2.0 bearer scheme name, not a credential. The linter's
    # heuristic flags the field name, so the value is set through Field.
    token_type: str = Field(default="bearer", description="Always 'bearer'.")
    expires_in_seconds: int = Field(description="Lifetime of the token from now.")
    user: UserRead


class UserCreate(BaseModel):
    """Payload for creating an account.

    ``tenant_id`` is absent on purpose. A tenant user is created through the
    tenant's own path, which is where the caller's authority for that tenant has
    already been checked, and a platform administrator has no tenant at all.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    email: EmailAddress
    full_name: str = Field(min_length=1, max_length=MAX_FULL_NAME_LENGTH)
    password: str = Field(
        min_length=MIN_PASSWORD_LENGTH,
        max_length=MAX_PASSWORD_LENGTH,
        description=(
            f"At least {MIN_PASSWORD_LENGTH} characters. Length is required rather "
            "than a composition rule, which only pushes people toward predictable "
            "substitutions."
        ),
    )

    @field_validator("full_name")
    @classmethod
    def _name_not_blank(cls, value: str) -> str:
        """Reject a display name that is only whitespace."""
        candidate = value.strip()
        if not candidate:
            msg = "full_name must not be blank"
            raise ValueError(msg)
        return candidate


class PasswordChange(BaseModel):
    """Payload for changing one's own password."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    current_password: str = Field(min_length=1, max_length=MAX_PASSWORD_LENGTH)
    new_password: str = Field(min_length=MIN_PASSWORD_LENGTH, max_length=MAX_PASSWORD_LENGTH)
