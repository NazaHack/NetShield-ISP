"""Tenant persistence.

Tenants are the one entity that is not itself tenant-scoped, so these functions
take no tenant filter. They are reachable only through the administrator
dependency.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Tenant
from app.models.tenant import adhoc_workspace_code_name, adhoc_workspace_name


async def get_tenant_by_id(session: AsyncSession, *, tenant_id: uuid.UUID) -> Tenant | None:
    """Return one tenant, or ``None`` when it does not exist."""
    tenant: Tenant | None = await session.get(Tenant, tenant_id)
    return tenant


async def get_tenant_by_code_name(session: AsyncSession, *, code_name: str) -> Tenant | None:
    """Return one tenant by its stable slug, or ``None``."""
    tenant: Tenant | None = await session.scalar(
        select(Tenant).where(Tenant.code_name == code_name)
    )
    return tenant


async def list_tenants(
    session: AsyncSession, *, limit: int, offset: int, include_system: bool = False
) -> tuple[Sequence[Tenant], int]:
    """Return a page of tenants, newest first, with the total count.

    System workspaces are excluded by default. An operator who never created one
    should not have to wonder what it is, and it is not a customer.
    """
    filters = [] if include_system else [Tenant.is_system.is_(False)]

    total = await session.scalar(select(func.count()).select_from(Tenant).where(*filters)) or 0
    rows = await session.scalars(
        select(Tenant)
        .where(*filters)
        .order_by(Tenant.created_at.desc())
        .limit(limit)
        .offset(offset)
    )
    return rows.all(), total


async def get_adhoc_workspace(session: AsyncSession, *, user_id: uuid.UUID) -> Tenant | None:
    """Return one operator's ad-hoc workspace, or ``None`` if they have none.

    Separate from :func:`get_or_create_adhoc_workspace` because listing an
    operator's scans must not bring a workspace into existence: an operator who
    has never run one should see an empty list, not acquire a tenant row by
    looking at a page.
    """
    workspace: Tenant | None = await session.scalar(
        select(Tenant).where(Tenant.code_name == adhoc_workspace_code_name(user_id))
    )
    return workspace


async def get_or_create_adhoc_workspace(
    session: AsyncSession, *, user_id: uuid.UUID, email: str
) -> Tenant:
    """Return the workspace owning one operator's scans run without a customer.

    Created on first use rather than by a migration: an operator who never runs
    an ad-hoc scan has no reason to carry the row, and provisioning it here keeps
    the concept next to the only code that needs it.

    One per operator, so the per-tenant concurrency quota bounds each of them
    independently rather than having them share three slots platform-wide.
    """
    code_name = adhoc_workspace_code_name(user_id)

    workspace = await session.scalar(select(Tenant).where(Tenant.code_name == code_name))
    if workspace is not None:
        return workspace

    workspace = Tenant(
        name=adhoc_workspace_name(email),
        code_name=code_name,
        is_system=True,
    )
    session.add(workspace)
    await session.flush()
    await session.refresh(workspace)
    return workspace


async def create_tenant(session: AsyncSession, *, name: str, code_name: str) -> Tenant:
    """Insert a tenant and return it with its generated identifier."""
    tenant = Tenant(name=name, code_name=code_name)
    session.add(tenant)
    await session.flush()
    await session.refresh(tenant)
    return tenant


async def delete_tenant(session: AsyncSession, *, tenant: Tenant) -> None:
    """Remove a tenant and, by cascade, everything it owns."""
    await session.delete(tenant)
    await session.flush()
