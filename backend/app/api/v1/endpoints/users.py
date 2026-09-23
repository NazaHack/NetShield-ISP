"""Account management.

Two separate surfaces, because they answer to different authorities:

* ``/users`` creates and lists platform administrators. Administrator only.
* ``/tenants/{tenant_id}/users`` manages one customer's members, and is reached
  through the same tenant scope as their targets and scans.
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Path, status

from app.api.dependencies import AdminDep, SessionDep, TenantScopeDep, not_found
from app.core.logging import get_logger
from app.core.passwords import PasswordTooWeakError, hash_password
from app.models import UserRole
from app.repositories.user import (
    count_platform_admins,
    create_user,
    delete_user,
    get_user_by_email,
    get_user_by_id,
    list_users,
)
from app.schemas.auth import UserCreate, UserRead
from app.schemas.common import Page, Pagination, pagination_params

logger = get_logger(__name__)

admin_users_router = APIRouter(prefix="/users", tags=["accounts"])
tenant_users_router = APIRouter(prefix="/tenants/{tenant_id}/users", tags=["accounts"])

UserIdPath = Annotated[uuid.UUID, Path(description="Account identifier.")]


async def _reject_duplicate_email(session: SessionDep, email: str) -> None:
    """Refuse an address that is already registered.

    Raises:
        HTTPException: 409 when the address is taken. Checking explicitly turns
            what would be a 500 from the unique constraint into a clear
            conflict, and the address is one the caller already supplied, so
            confirming it is not a disclosure.
    """
    if await get_user_by_email(session, email=email) is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"An account already exists for {email}.",
        )


def _hash_or_reject(password: str) -> str:
    """Hash a password, turning a weakness into a 422.

    Raises:
        HTTPException: 422 when the password does not meet the requirements.
    """
    try:
        return hash_password(password)
    except PasswordTooWeakError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "detail": "Request validation failed.",
                "errors": [
                    {"field": "body.password", "message": str(exc), "type": "password_too_weak"}
                ],
            },
        ) from exc


# --------------------------------------------------------------------------- #
# Platform administrators
# --------------------------------------------------------------------------- #


@admin_users_router.post(
    "",
    response_model=UserRead,
    status_code=status.HTTP_201_CREATED,
    summary="Create a platform administrator",
)
async def create_admin_user(
    payload: UserCreate,
    session: SessionDep,
    admin: AdminDep,
) -> UserRead:
    """Create another administrator account."""
    await _reject_duplicate_email(session, payload.email)

    user = await create_user(
        session,
        email=payload.email,
        full_name=payload.full_name,
        password_hash=_hash_or_reject(payload.password),
        role=UserRole.PLATFORM_ADMIN,
        tenant_id=None,
    )
    await session.commit()

    logger.info("api.admin_created", created_user_id=str(user.id), created_by=str(admin.user_id))
    return UserRead.model_validate(user)


@admin_users_router.get("", response_model=Page[UserRead], summary="List every account")
async def list_all_users(
    session: SessionDep,
    _admin: AdminDep,
    pagination: Annotated[Pagination, Depends(pagination_params)],
) -> Page[UserRead]:
    """Return a page of every account on the platform."""
    users, total = await list_users(
        session, tenant_id=None, limit=pagination.limit, offset=pagination.offset
    )
    return Page[UserRead](
        items=[UserRead.model_validate(user) for user in users],
        total=total,
        limit=pagination.limit,
        offset=pagination.offset,
    )


@admin_users_router.delete(
    "/{user_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    response_model=None,
    summary="Remove an account",
)
async def delete_user_endpoint(
    user_id: UserIdPath,
    session: SessionDep,
    admin: AdminDep,
) -> None:
    """Delete an account.

    Two removals are refused outright: your own account, and the last active
    administrator. Either would leave the platform with no way back in through
    the API.

    Raises:
        HTTPException: 404 when the account does not exist, 409 when removing it
            would lock everyone out.
    """
    if user_id == admin.user_id:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="You cannot remove your own account.",
        )

    user = await get_user_by_id(session, user_id=user_id)
    if user is None:
        raise not_found()

    if user.role is UserRole.PLATFORM_ADMIN and await count_platform_admins(session) <= 1:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="This is the last platform administrator and cannot be removed.",
        )

    email = user.email
    await delete_user(session, user=user)
    await session.commit()

    logger.warning(
        "api.user_deleted", deleted_user_id=str(user_id), email=email, by=str(admin.user_id)
    )


# --------------------------------------------------------------------------- #
# Tenant members
# --------------------------------------------------------------------------- #


@tenant_users_router.post(
    "",
    response_model=UserRead,
    status_code=status.HTTP_201_CREATED,
    summary="Create a sign-in for this client",
)
async def create_tenant_user(
    payload: UserCreate,
    session: SessionDep,
    scope: TenantScopeDep,
) -> UserRead:
    """Create an account that belongs to this client.

    The tenant comes from the authorised scope, never from the payload, so an
    account cannot be created inside a client the caller may not act for.
    """
    await _reject_duplicate_email(session, payload.email)

    user = await create_user(
        session,
        email=payload.email,
        full_name=payload.full_name,
        password_hash=_hash_or_reject(payload.password),
        role=UserRole.TENANT_USER,
        tenant_id=scope.tenant_id,
    )
    await session.commit()

    logger.info(
        "api.tenant_user_created",
        created_user_id=str(user.id),
        tenant_id=str(scope.tenant_id),
        impersonated=scope.is_impersonated,
    )
    return UserRead.model_validate(user)


@tenant_users_router.get("", response_model=Page[UserRead], summary="List this client's sign-ins")
async def list_tenant_users(
    session: SessionDep,
    scope: TenantScopeDep,
    pagination: Annotated[Pagination, Depends(pagination_params)],
) -> Page[UserRead]:
    """Return a page of the client's accounts."""
    users, total = await list_users(
        session,
        tenant_id=scope.tenant_id,
        limit=pagination.limit,
        offset=pagination.offset,
    )
    return Page[UserRead](
        items=[UserRead.model_validate(user) for user in users],
        total=total,
        limit=pagination.limit,
        offset=pagination.offset,
    )


@tenant_users_router.delete(
    "/{user_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    response_model=None,
    summary="Remove one of this client's sign-ins",
)
async def delete_tenant_user(
    user_id: UserIdPath,
    session: SessionDep,
    scope: TenantScopeDep,
) -> None:
    """Delete an account belonging to this client.

    The lookup is scoped to the tenant, so an account in another client is not
    found rather than forbidden.

    Raises:
        HTTPException: 404 when the account is not this client's, 409 when
            removing your own.
    """
    user = await get_user_by_id(session, user_id=user_id)
    if user is None or user.tenant_id != scope.tenant_id:
        raise not_found()

    if user.id == scope.principal.user_id:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="You cannot remove your own account.",
        )

    email = user.email
    await delete_user(session, user=user)
    await session.commit()

    logger.warning(
        "api.tenant_user_deleted",
        deleted_user_id=str(user_id),
        email=email,
        tenant_id=str(scope.tenant_id),
    )
