"""Network target persistence, always scoped to one tenant."""

from __future__ import annotations

import uuid
from collections.abc import Sequence

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import NetworkTarget


async def get_target(
    session: AsyncSession, *, tenant_id: uuid.UUID, target_id: uuid.UUID
) -> NetworkTarget | None:
    """Return one target belonging to the tenant, or ``None``.

    The tenant filter is part of the lookup rather than a check afterwards: a
    target belonging to another tenant is simply not found.
    """
    target: NetworkTarget | None = await session.scalar(
        select(NetworkTarget).where(
            NetworkTarget.id == target_id,
            NetworkTarget.tenant_id == tenant_id,
        )
    )
    return target


async def list_targets(
    session: AsyncSession, *, tenant_id: uuid.UUID, limit: int, offset: int
) -> tuple[Sequence[NetworkTarget], int]:
    """Return a page of the tenant's targets, ordered by label, with the total."""
    total = (
        await session.scalar(
            select(func.count())
            .select_from(NetworkTarget)
            .where(NetworkTarget.tenant_id == tenant_id)
        )
        or 0
    )
    rows = await session.scalars(
        select(NetworkTarget)
        .where(NetworkTarget.tenant_id == tenant_id)
        .order_by(NetworkTarget.label)
        .limit(limit)
        .offset(offset)
    )
    return rows.all(), total


async def list_target_ranges(session: AsyncSession, *, tenant_id: uuid.UUID) -> list[str]:
    """Return just the tenant's registered ranges, for pre-flight validation."""
    rows = await session.scalars(
        select(NetworkTarget.ip_address_or_cidr).where(NetworkTarget.tenant_id == tenant_id)
    )
    return list(rows)


async def create_target(
    session: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    label: str,
    ip_address_or_cidr: str,
    description: str | None,
) -> NetworkTarget:
    """Insert a target owned by the tenant."""
    target = NetworkTarget(
        tenant_id=tenant_id,
        label=label,
        ip_address_or_cidr=ip_address_or_cidr,
        description=description,
    )
    session.add(target)
    await session.flush()
    await session.refresh(target)
    return target


async def delete_target(session: AsyncSession, *, target: NetworkTarget) -> None:
    """Remove a target the caller has already been authorised for."""
    await session.delete(target)
    await session.flush()
