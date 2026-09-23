"""Network target management, nested under a tenant.

Every route depends on ``TenantScopeDep``, so the tenant identifier used in each
query has already been checked against the caller's token. A target belonging to
another tenant is not found rather than forbidden.
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Path, status

from app.api.dependencies import SessionDep, TenantScopeDep, not_found
from app.core.logging import get_logger
from app.repositories.network_target import (
    create_target,
    delete_target,
    get_target,
    list_targets,
)
from app.schemas.common import Page, Pagination, pagination_params
from app.schemas.network_target import (
    NetworkTargetCreate,
    NetworkTargetRead,
    NetworkTargetUpdate,
)
from app.workers.scanning.command import TargetNotPermittedError, assert_target_is_permitted

router = APIRouter(prefix="/tenants/{tenant_id}/targets", tags=["network targets"])
logger = get_logger(__name__)

TargetIdPath = Annotated[uuid.UUID, Path(description="Network target identifier.")]


def _reject_forbidden_range(value: str) -> None:
    """Refuse a range that platform policy will never scan.

    Storing a range the engine would skip anyway is a trap: the target looks
    registered in the dashboard and silently contributes nothing to every scan.
    Rejecting it here tells the operator at the moment they can fix it.

    Raises:
        HTTPException: 422 naming the offending field and the reason.
    """
    try:
        assert_target_is_permitted(value)
    except TargetNotPermittedError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "detail": "Request validation failed.",
                "errors": [
                    {
                        "field": "body.ip_address_or_cidr",
                        "message": str(exc),
                        "type": "target_not_permitted",
                    }
                ],
            },
        ) from exc


@router.post(
    "",
    response_model=NetworkTargetRead,
    status_code=status.HTTP_201_CREATED,
    summary="Register a range the tenant may audit",
)
async def create_target_endpoint(
    payload: NetworkTargetCreate,
    session: SessionDep,
    scope: TenantScopeDep,
) -> NetworkTargetRead:
    """Add a network target to the tenant.

    Raises:
        HTTPException: 409 when the label or the range is already registered for
            this tenant, 422 when policy forbids the range.
    """
    _reject_forbidden_range(payload.ip_address_or_cidr)

    existing, _ = await list_targets(session, tenant_id=scope.tenant_id, limit=1000, offset=0)
    for target in existing:
        if target.label == payload.label:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"A target labelled {payload.label!r} already exists for this tenant.",
            )
        if target.ip_address_or_cidr == payload.ip_address_or_cidr:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"{payload.ip_address_or_cidr} is already registered for this tenant.",
            )

    target = await create_target(
        session,
        tenant_id=scope.tenant_id,
        label=payload.label,
        ip_address_or_cidr=payload.ip_address_or_cidr,
        description=payload.description,
    )
    await session.commit()

    logger.info(
        "api.target_created",
        target_id=str(target.id),
        network=target.ip_address_or_cidr,
        impersonated=scope.is_impersonated,
    )
    return NetworkTargetRead.model_validate(target)


@router.get("", response_model=Page[NetworkTargetRead], summary="List the tenant's ranges")
async def list_targets_endpoint(
    session: SessionDep,
    scope: TenantScopeDep,
    pagination: Annotated[Pagination, Depends(pagination_params)],
) -> Page[NetworkTargetRead]:
    """Return a page of the tenant's registered ranges, ordered by label."""
    targets, total = await list_targets(
        session,
        tenant_id=scope.tenant_id,
        limit=pagination.limit,
        offset=pagination.offset,
    )
    return Page[NetworkTargetRead](
        items=[NetworkTargetRead.model_validate(target) for target in targets],
        total=total,
        limit=pagination.limit,
        offset=pagination.offset,
    )


@router.get("/{target_id}", response_model=NetworkTargetRead, summary="Read one range")
async def get_target_endpoint(
    target_id: TargetIdPath,
    session: SessionDep,
    scope: TenantScopeDep,
) -> NetworkTargetRead:
    """Return one of the tenant's ranges."""
    target = await get_target(session, tenant_id=scope.tenant_id, target_id=target_id)
    if target is None:
        raise not_found()
    return NetworkTargetRead.model_validate(target)


@router.patch("/{target_id}", response_model=NetworkTargetRead, summary="Edit a range")
async def update_target_endpoint(
    target_id: TargetIdPath,
    payload: NetworkTargetUpdate,
    session: SessionDep,
    scope: TenantScopeDep,
) -> NetworkTargetRead:
    """Update the fields supplied; anything omitted is left unchanged."""
    target = await get_target(session, tenant_id=scope.tenant_id, target_id=target_id)
    if target is None:
        raise not_found()

    if payload.ip_address_or_cidr is not None:
        _reject_forbidden_range(payload.ip_address_or_cidr)
        target.ip_address_or_cidr = payload.ip_address_or_cidr
    if payload.label is not None:
        target.label = payload.label
    if payload.description is not None:
        target.description = payload.description

    await session.commit()
    await session.refresh(target)

    logger.info("api.target_updated", target_id=str(target.id))
    return NetworkTargetRead.model_validate(target)


@router.delete(
    "/{target_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    # Explicit `None`: FastAPI would otherwise infer `NoneType` from the
    # return annotation and treat it as a response model, which a 204 may
    # not have.
    response_model=None,
    summary="Remove a range",
)
async def delete_target_endpoint(
    target_id: TargetIdPath,
    session: SessionDep,
    scope: TenantScopeDep,
) -> None:
    """Delete one of the tenant's ranges.

    Past scan results are unaffected: they record what was observed, and are
    evidence rather than configuration.
    """
    target = await get_target(session, tenant_id=scope.tenant_id, target_id=target_id)
    if target is None:
        raise not_found()

    network = target.ip_address_or_cidr
    await delete_target(session, target=target)
    await session.commit()

    logger.info("api.target_deleted", target_id=str(target_id), network=network)
