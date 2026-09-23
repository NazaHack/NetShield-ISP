"""Request dependencies: authentication and tenant scoping.

Isolation in this API rests on a single rule, applied here rather than in every
endpoint: **the tenant a request may touch is derived from the caller's token,
never from the request itself.** A path parameter or a body field naming a
tenant is treated as an assertion to be checked against the token, not as an
instruction to be obeyed.

A cross-tenant attempt is answered with ``404 Not Found`` rather than
``403 Forbidden``. A 403 confirms that the resource exists, which tells one
customer that another customer's scan or target is real. For a platform whose
whole promise is that tenants cannot observe each other, that acknowledgement is
itself a leak.
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import Depends, HTTPException, Path, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import bind_log_context, get_logger
from app.core.security import AuthenticationError, Principal, decode_access_token
from app.db.session import get_async_session
from app.models import Tenant
from app.repositories.tenant import get_tenant_by_id
from app.repositories.user import get_user_by_id

logger = get_logger(__name__)

#: `auto_error=False` so that a missing header produces this module's uniform
#: 401 with a `WWW-Authenticate` challenge, rather than FastAPI's bare 403.
_bearer_scheme = HTTPBearer(auto_error=False, scheme_name="BearerToken")

#: Returned whenever a caller may not see a resource, whether because it does
#: not exist or because it belongs to somebody else.
_NOT_FOUND_DETAIL = "Resource not found."


def _unauthorized() -> HTTPException:
    """Build the uniform 401 used for every authentication failure."""
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Not authenticated.",
        headers={"WWW-Authenticate": "Bearer"},
    )


def _not_found() -> HTTPException:
    """Build the uniform 404 used for both absent and forbidden resources."""
    return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=_NOT_FOUND_DETAIL)


async def get_principal(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer_scheme)],
    session: Annotated[AsyncSession, Depends(get_async_session)],
) -> Principal:
    """Authenticate the request and return the acting principal.

    The token is verified and then the account it names is re-read from the
    database. Trusting the token's own claims would be faster, but a deactivated
    user would keep their access until it happened to expire, and a role change
    would not take effect at all. Reading the row is a primary-key lookup, and
    correctness is worth it.

    Raises:
        HTTPException: 401 when the credential is absent, not trustworthy, names
            an account that no longer exists, or names a disabled account.
    """
    if credentials is None or not credentials.credentials:
        raise _unauthorized()

    try:
        claims = decode_access_token(credentials.credentials)
    except AuthenticationError:
        logger.warning("api.authentication_failed", path=request.url.path)
        raise _unauthorized() from None

    user = await get_user_by_id(session, user_id=claims.user_id)
    if user is None or not user.is_active:
        logger.warning(
            "api.authentication_rejected",
            reason="unknown or disabled account",
            user_id=str(claims.user_id),
        )
        raise _unauthorized()

    # The token's tenant is checked against the account's rather than trusted.
    # They can only differ if the account moved after the token was issued, and
    # the account is the authority.
    if claims.tenant_id != user.tenant_id:
        logger.warning("api.token_tenant_mismatch", user_id=str(user.id))
        raise _unauthorized()

    principal = Principal(
        user_id=user.id,
        email=user.email,
        full_name=user.full_name,
        role=user.role,
        tenant_id=user.tenant_id,
        token_id=claims.token_id,
    )

    # Every log line emitted while handling this request now carries the acting
    # identity, which is what makes an incident reconstructable after the fact.
    bind_log_context(
        principal=principal.describe(),
        token_id=principal.token_id,
        tenant_id=str(principal.tenant_id) if principal.tenant_id else None,
    )
    return principal


async def require_admin(principal: Annotated[Principal, Depends(get_principal)]) -> Principal:
    """Require a platform administrator.

    Managing the tenant list is inherently cross-tenant, so it is the one area a
    tenant token may never reach. The failure is a 403 rather than a 404 here:
    the caller is authenticated and the endpoint's existence is not a secret,
    only their authority to use it.

    Raises:
        HTTPException: 403 when the principal is scoped to a tenant.
    """
    if not principal.is_admin:
        logger.warning("api.admin_required", principal=principal.describe())
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This operation requires platform administrator access.",
        )
    return principal


class TenantScope:
    """A tenant the caller has been authorised to act on, plus how they got there.

    Endpoints depend on this rather than on a raw path parameter, so the
    identifier they pass to a repository has already been checked against the
    token.
    """

    __slots__ = ("principal", "tenant")

    def __init__(self, tenant: Tenant, principal: Principal) -> None:
        """Bind an authorised tenant to the principal that was authorised for it."""
        self.tenant = tenant
        self.principal = principal

    @property
    def tenant_id(self) -> uuid.UUID:
        """The only tenant identifier this request may use in a query."""
        return self.tenant.id

    @property
    def is_impersonated(self) -> bool:
        """True when an administrator is acting on a tenant's behalf."""
        return self.principal.is_admin


async def resolve_tenant_scope(
    principal: Annotated[Principal, Depends(get_principal)],
    session: Annotated[AsyncSession, Depends(get_async_session)],
    tenant_id: Annotated[uuid.UUID, Path(description="Tenant that owns the resource.")],
) -> TenantScope:
    """Authorise the caller for the tenant named in the path.

    Both failure modes -- the tenant does not exist, and the tenant exists but
    belongs to someone else -- return the same 404, so the response cannot be
    used to enumerate tenants.

    Raises:
        HTTPException: 404 when the caller may not act for this tenant.
    """
    if not principal.may_act_for(tenant_id):
        logger.warning(
            "api.cross_tenant_attempt",
            principal=principal.describe(),
            requested_tenant_id=str(tenant_id),
        )
        raise _not_found()

    tenant = await get_tenant_by_id(session, tenant_id=tenant_id)
    if tenant is None:
        raise _not_found()

    if principal.is_admin:
        # Operator support access is legitimate but must never be silent.
        logger.info(
            "api.admin_impersonation",
            tenant_id=str(tenant_id),
            token_id=principal.token_id,
        )

    bind_log_context(tenant_id=str(tenant_id))
    return TenantScope(tenant=tenant, principal=principal)


# --------------------------------------------------------------------------- #
# Annotated aliases, so endpoint signatures stay readable
# --------------------------------------------------------------------------- #

#: An open database session for the request.
SessionDep = Annotated[AsyncSession, Depends(get_async_session)]

#: The authenticated caller, with no tenant authorisation implied.
PrincipalDep = Annotated[Principal, Depends(get_principal)]

#: A platform administrator.
AdminDep = Annotated[Principal, Depends(require_admin)]

#: A tenant the caller is authorised to act on, resolved from the path.
TenantScopeDep = Annotated[TenantScope, Depends(resolve_tenant_scope)]


def not_found() -> HTTPException:
    """The uniform 404, for endpoints that need to raise it themselves."""
    return _not_found()
