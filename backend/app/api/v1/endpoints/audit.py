"""The audit trail endpoint.

Reading the trail is platform-wide, so it is administrator only. There is no
tenant-scoped view: a tenant user seeing "who did what" across the platform, or
even across their own tenant's operators, is a separate product decision not
made here.
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Query

from app.api.dependencies import AdminDep, SessionDep
from app.repositories.audit import list_events
from app.schemas.audit import AuditEventRead
from app.schemas.common import Page, Pagination, pagination_params

router = APIRouter(prefix="/audit", tags=["audit"])


@router.get(
    "/events",
    response_model=Page[AuditEventRead],
    summary="Read the audit trail, newest first",
)
async def list_audit_events(
    session: SessionDep,
    _admin: AdminDep,
    pagination: Annotated[Pagination, Depends(pagination_params)],
    action: Annotated[str | None, Query(description="Only events with this action.")] = None,
    tenant_id: Annotated[
        uuid.UUID | None, Query(description="Only events concerning this tenant.")
    ] = None,
    actor_email: Annotated[
        str | None, Query(description="Only events by this actor's email.")
    ] = None,
) -> Page[AuditEventRead]:
    """Return a page of audit events, filterable by action, tenant or actor."""
    events, total = await list_events(
        session,
        limit=pagination.limit,
        offset=pagination.offset,
        action=action,
        tenant_id=tenant_id,
        actor_email=actor_email,
    )
    return Page[AuditEventRead](
        items=[AuditEventRead.model_validate(event) for event in events],
        total=total,
        limit=pagination.limit,
        offset=pagination.offset,
    )
