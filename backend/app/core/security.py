"""Authentication primitives.

The API is multi-tenant, so "who is calling?" has to be a fact the server
establishes, never something the caller asserts. A tenant identifier read from a
path or a header would make every isolation check decorative.

Callers sign in with an email and password and receive a signed bearer token.
The token names the account, and the account is what determines both the role
and the tenant, so neither can be changed without the signing key.

Two kinds of principal exist:

``tenant``
    A member of exactly one tenant, who can never reach another's data.

``admin``
    A platform administrator, who manages the customer list. That is inherently
    cross-tenant: a tenant cannot create itself. Administrator access to tenant
    data is permitted for operator support and every such access is logged.

The account is re-read from the database on every request rather than trusted
from the token, so deactivating a user takes effect immediately instead of when
their token happens to expire.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any, Final

import jwt

from app.core.config import settings
from app.models.enums import UserRole

#: Issuer and audience claims, both verified on decode so that a credential
#: minted for another service sharing the signing key is still rejected here.
#: These are public identifiers, not secrets.
JWT_ISSUER: Final[str] = "netshield-isp"
JWT_AUDIENCE: Final[str] = "netshield-isp-api"


class PrincipalScope(StrEnum):
    """What a token is allowed to act as."""

    TENANT = "tenant"
    ADMIN = "admin"

    @classmethod
    def for_role(cls, role: UserRole) -> PrincipalScope:
        """Map a user's role onto the scope its token carries."""
        return cls.ADMIN if role.is_platform_admin else cls.TENANT


class AuthenticationError(Exception):
    """Raised when a credential is absent, malformed, expired or untrustworthy.

    Deliberately carries no detail about *why*. Telling an anonymous caller that
    a signature was valid but expired, as opposed to simply invalid, is a small
    oracle that costs nothing to remove.
    """


@dataclass(frozen=True, slots=True)
class TokenClaims:
    """What a verified token asserts, before the account is looked up."""

    user_id: uuid.UUID
    scope: PrincipalScope
    tenant_id: uuid.UUID | None
    token_id: str


@dataclass(frozen=True, slots=True)
class Principal:
    """The authenticated identity behind a request, resolved from a live account."""

    user_id: uuid.UUID
    email: str
    full_name: str
    role: UserRole

    #: The tenant this principal acts for. ``None`` for an administrator.
    tenant_id: uuid.UUID | None

    #: Token identifier, carried into logs so a request can be traced back to
    #: the credential that made it.
    token_id: str

    @property
    def scope(self) -> PrincipalScope:
        """The scope this principal acts with."""
        return PrincipalScope.for_role(self.role)

    @property
    def is_admin(self) -> bool:
        """True when this principal may manage tenants."""
        return self.role.is_platform_admin

    def may_act_for(self, tenant_id: uuid.UUID) -> bool:
        """Whether this principal may read or write the named tenant's data."""
        if self.is_admin:
            return True
        return self.tenant_id == tenant_id

    def describe(self) -> str:
        """Short, log-safe description of the identity.

        The email is included because an operator reading an audit trail needs
        to know who acted, and it is not a secret.
        """
        if self.is_admin:
            return f"admin:{self.email}"
        return f"tenant:{self.tenant_id}:{self.email}"


def create_access_token(
    *,
    user_id: uuid.UUID,
    role: UserRole,
    tenant_id: uuid.UUID | None = None,
    expires_in: timedelta | None = None,
) -> str:
    """Mint a bearer token for an account.

    Args:
        user_id: The account the token names.
        role: The account's role, which decides the scope claim.
        tenant_id: Required for a tenant user, rejected for an administrator.
        expires_in: Lifetime. Defaults to the configured access-token expiry.

    Returns:
        The encoded JWT.

    Raises:
        ValueError: If the role and tenant argument disagree.
    """
    scope = PrincipalScope.for_role(role)

    if scope is PrincipalScope.TENANT and tenant_id is None:
        msg = "A tenant user's token requires a tenant_id."
        raise ValueError(msg)
    if scope is PrincipalScope.ADMIN and tenant_id is not None:
        msg = "A platform administrator's token must not carry a tenant_id."
        raise ValueError(msg)

    issued_at = datetime.now(UTC)
    lifetime = expires_in or timedelta(minutes=settings.access_token_expire_minutes)

    claims: dict[str, Any] = {
        "sub": str(user_id),
        "scope": scope.value,
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
        "iat": issued_at,
        "exp": issued_at + lifetime,
        "jti": uuid.uuid4().hex,
    }
    if tenant_id is not None:
        claims["tenant_id"] = str(tenant_id)

    return jwt.encode(
        claims,
        settings.secret_key.get_secret_value(),
        algorithm=settings.jwt_algorithm,
    )


def decode_access_token(token: str) -> TokenClaims:
    """Verify a bearer token and return the claims it asserts.

    The algorithm is pinned to the configured one. Accepting whatever the token
    header names would allow an attacker to present an unsigned ``none`` token,
    or to have an RSA public key treated as an HMAC secret.

    This does not consult the database: the caller resolves the account, which
    is where deactivation and role changes take effect.

    Args:
        token: The raw JWT from the Authorization header.

    Returns:
        The verified claims.

    Raises:
        AuthenticationError: The token is malformed, expired, signed with the
            wrong key, issued for another audience, or carries claims that do
            not form a coherent identity.
    """
    try:
        claims: dict[str, Any] = jwt.decode(
            token,
            settings.secret_key.get_secret_value(),
            algorithms=[settings.jwt_algorithm],
            issuer=JWT_ISSUER,
            audience=JWT_AUDIENCE,
            options={"require": ["exp", "iat", "sub", "iss", "aud", "jti"]},
        )
    except jwt.InvalidTokenError as exc:
        raise AuthenticationError from exc

    raw_scope = claims.get("scope")
    if not isinstance(raw_scope, str):
        raise AuthenticationError
    try:
        scope = PrincipalScope(raw_scope)
    except ValueError as exc:
        raise AuthenticationError from exc

    try:
        user_id = uuid.UUID(str(claims.get("sub")))
    except ValueError as exc:
        raise AuthenticationError from exc

    token_id = str(claims.get("jti", ""))
    raw_tenant = claims.get("tenant_id")

    if scope is PrincipalScope.ADMIN:
        if raw_tenant is not None:
            # A token claiming admin scope while also naming a tenant is
            # incoherent. Refuse rather than guess which claim to honour.
            raise AuthenticationError
        return TokenClaims(user_id=user_id, scope=scope, tenant_id=None, token_id=token_id)

    if raw_tenant is None:
        raise AuthenticationError
    try:
        tenant_id = uuid.UUID(str(raw_tenant))
    except ValueError as exc:
        raise AuthenticationError from exc

    return TokenClaims(user_id=user_id, scope=scope, tenant_id=tenant_id, token_id=token_id)
