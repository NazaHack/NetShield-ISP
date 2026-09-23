"""Tenant management.

Every route here requires a platform administrator. Managing the tenant list is
inherently cross-tenant -- a tenant cannot create itself, and listing tenants
would expose the customer base -- so it is the one area a tenant-scoped token
can never reach.
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Path, status

from app.api.dependencies import AdminDep, SessionDep, TenantScopeDep, not_found
from app.core.logging import get_logger
from app.repositories.tenant import (
    create_tenant,
    delete_tenant,
    get_tenant_by_code_name,
    get_tenant_by_id,
    list_tenants,
)
from app.schemas.common import Page, Pagination, pagination_params
from app.schemas.tenant import TenantCreate, TenantRead, TenantUpdate

router = APIRouter(prefix="/tenants", tags=["tenants"])
logger = get_logger(__name__)

TenantIdPath = Annotated[uuid.UUID, Path(description="Tenant identifier.")]


@router.post(
    "",
    response_model=TenantRead,
    status_code=status.HTTP_201_CREATED,
    summary="Register an ISP customer",
)
async def create_tenant_endpoint(
    payload: TenantCreate,
    session: SessionDep,
    admin: AdminDep,
) -> TenantRead:
    """Create a tenant.

    Raises:
        HTTPException: 409 when the code name is already taken. The check is
            explicit so the caller gets a clear conflict rather than a 500 from
            the unique constraint.
    """
    existing = await get_tenant_by_code_name(session, code_name=payload.code_name)
    if existing is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A tenant with code_name {payload.code_name!r} already exists.",
        )

    tenant = await create_tenant(session, name=payload.name, code_name=payload.code_name)
    await session.commit()

    logger.info(
        "api.tenant_created",
        created_tenant_id=str(tenant.id),
        code_name=tenant.code_name,
        token_id=admin.token_id,
    )
    return TenantRead.model_validate(tenant)


@router.get("", response_model=Page[TenantRead], summary="List ISP customers")
async def list_tenants_endpoint(
    session: SessionDep,
    _admin: AdminDep,
    pagination: Annotated[Pagination, Depends(pagination_params)],
) -> Page[TenantRead]:
    """Return a page of tenants, newest first."""
    tenants, total = await list_tenants(session, limit=pagination.limit, offset=pagination.offset)
    return Page[TenantRead](
        items=[TenantRead.model_validate(tenant) for tenant in tenants],
        total=total,
        limit=pagination.limit,
        offset=pagination.offset,
    )


@router.get("/{tenant_id}", response_model=TenantRead, summary="Read one ISP customer")
async def get_tenant_endpoint(scope: TenantScopeDep) -> TenantRead:
    """Return one tenant.

    Unlike the other routes in this module, a tenant may read its own record.
    The authorisation is handled by the scope dependency, which answers with a
    404 for any tenant the caller may not act on.
    """
    return TenantRead.model_validate(scope.tenant)


@router.patch("/{tenant_id}", response_model=TenantRead, summary="Edit an ISP customer")
async def update_tenant_endpoint(
    tenant_id: TenantIdPath,
    payload: TenantUpdate,
    session: SessionDep,
    admin: AdminDep,
) -> TenantRead:
    """Update a tenant's display name."""
    tenant = await get_tenant_by_id(session, tenant_id=tenant_id)
    if tenant is None:
        raise not_found()

    tenant.name = payload.name
    await session.commit()
    await session.refresh(tenant)

    logger.info("api.tenant_updated", updated_tenant_id=str(tenant.id), token_id=admin.token_id)
    return TenantRead.model_validate(tenant)


@router.delete(
    "/{tenant_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    # Explicit `None`: FastAPI would otherwise infer `NoneType` from the
    # return annotation and treat it as a response model, which a 204 may
    # not have.
    response_model=None,
    summary="Remove an ISP customer and everything it owns",
)
async def delete_tenant_endpoint(
    tenant_id: TenantIdPath,
    session: SessionDep,
    admin: AdminDep,
) -> None:
    """Delete a tenant.

    This cascades to the tenant's targets, scans and results. Retaining a former
    customer's network map is a liability rather than an asset, so the removal
    is deliberate and complete.
    """
    tenant = await get_tenant_by_id(session, tenant_id=tenant_id)
    if tenant is None:
        raise not_found()

    code_name = tenant.code_name
    await delete_tenant(session, tenant=tenant)
    await session.commit()

    logger.warning(
        "api.tenant_deleted",
        deleted_tenant_id=str(tenant_id),
        code_name=code_name,
        token_id=admin.token_id,
    )
