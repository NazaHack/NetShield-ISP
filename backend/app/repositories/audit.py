"""Audit trail persistence.

Writing an event never uses a foreign key and never cascades, so recording what
happened cannot fail because of, or be undone by, a change to the actor or
tenant it refers to. Reads are platform-wide and belong to administrators only;
there is no tenant-scoped variant here on purpose.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import Principal
from app.models import AuditEvent


def add_event(
    session: AsyncSession,
    *,
    action: str,
    actor: Principal | None = None,
    actor_user_id: uuid.UUID | None = None,
    actor_email: str | None = None,
    actor_role: str | None = None,
    tenant_id: uuid.UUID | None = None,
    tenant_code_name: str | None = None,
    target: str | None = None,
    detail: dict[str, Any] | None = None,
    source_ip: str | None = None,
) -> None:
    """Stage an audit event onto the session, to be committed with the action.

    Adding rather than committing keeps the event atomic with the operation it
    records: for a tenant creation, either the tenant and its audit event both
    land or neither does. Callers whose action has no business transaction, such
    as a failed login, commit the session themselves.

    The acting identity can be given three ways, in order of precedence: a
    ``Principal`` (the usual case, for an authenticated request), the explicit
    ``actor_*`` fields (for a just-authenticated user before a principal exists,
    such as at sign-in), or ``actor_email`` alone (for an unauthenticated
    attempt, such as a failed login for a known-looking address).
    """
    session.add(
        AuditEvent(
            action=action,
            actor_user_id=actor.user_id if actor else actor_user_id,
            actor_email=(actor.email if actor else actor_email),
            actor_role=(actor.role.value if actor else actor_role),
            tenant_id=tenant_id,
            tenant_code_name=tenant_code_name,
            target=target,
            detail=detail,
            source_ip=source_ip,
        )
    )


async def list_events(
    session: AsyncSession,
    *,
    limit: int,
    offset: int,
    action: str | None = None,
    tenant_id: uuid.UUID | None = None,
    actor_email: str | None = None,
) -> tuple[Sequence[AuditEvent], int]:
    """Return a page of audit events, newest first, with the total match count.

    Every filter is optional; combined, they narrow to "what happened to this
    tenant", "every failed login", "everything this operator did", and so on.
    """
    filters = []
    if action is not None:
        filters.append(AuditEvent.action == action)
    if tenant_id is not None:
        filters.append(AuditEvent.tenant_id == tenant_id)
    if actor_email is not None:
        filters.append(AuditEvent.actor_email == actor_email.strip().lower())

    total = await session.scalar(select(func.count()).select_from(AuditEvent).where(*filters)) or 0
    rows = await session.scalars(
        select(AuditEvent)
        .where(*filters)
        .order_by(AuditEvent.created_at.desc())
        .limit(limit)
        .offset(offset)
    )
    return rows.all(), total
