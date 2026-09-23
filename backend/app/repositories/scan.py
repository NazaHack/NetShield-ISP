"""Scan and scan-result persistence, always scoped to one tenant."""

from __future__ import annotations

import uuid
from collections.abc import Sequence

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Scan, ScanResult, ScanStatus

#: States that still occupy a slot in the tenant's concurrency quota.
ACTIVE_STATUSES: tuple[ScanStatus, ...] = (ScanStatus.PENDING, ScanStatus.RUNNING)


async def get_scan(
    session: AsyncSession, *, tenant_id: uuid.UUID, scan_id: uuid.UUID
) -> Scan | None:
    """Return one scan belonging to the tenant, or ``None``."""
    scan: Scan | None = await session.scalar(
        select(Scan).where(Scan.id == scan_id, Scan.tenant_id == tenant_id)
    )
    return scan


async def list_scans(
    session: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    limit: int,
    offset: int,
    status: ScanStatus | None = None,
) -> tuple[Sequence[Scan], int]:
    """Return a page of the tenant's scans, newest first, with the total count."""
    filters = [Scan.tenant_id == tenant_id]
    if status is not None:
        filters.append(Scan.status == status)

    total = await session.scalar(select(func.count()).select_from(Scan).where(*filters)) or 0
    rows = await session.scalars(
        select(Scan).where(*filters).order_by(Scan.created_at.desc()).limit(limit).offset(offset)
    )
    return rows.all(), total


async def count_active_scans(session: AsyncSession, *, tenant_id: uuid.UUID) -> int:
    """How many of the tenant's scans are queued or running."""
    return (
        await session.scalar(
            select(func.count())
            .select_from(Scan)
            .where(Scan.tenant_id == tenant_id, Scan.status.in_(ACTIVE_STATUSES))
        )
        or 0
    )


async def create_scan(session: AsyncSession, *, tenant_id: uuid.UUID) -> Scan:
    """Insert a pending scan for the tenant."""
    scan = Scan(tenant_id=tenant_id, status=ScanStatus.PENDING)
    session.add(scan)
    await session.flush()
    await session.refresh(scan)
    return scan


async def list_scan_results(
    session: AsyncSession, *, tenant_id: uuid.UUID, scan_id: uuid.UUID
) -> Sequence[ScanResult]:
    """Return the per-host findings of one scan, ordered by host address.

    Filtered by tenant as well as by scan. The composite foreign key already
    makes a mismatched pair impossible to store, so this is belt and braces, but
    it keeps every statement in this package readable as tenant-scoped on its
    own.
    """
    rows = await session.scalars(
        select(ScanResult)
        .where(ScanResult.scan_id == scan_id, ScanResult.tenant_id == tenant_id)
        .order_by(ScanResult.host_ip)
    )
    return rows.all()


async def get_previous_completed_scan(
    session: AsyncSession, *, tenant_id: uuid.UUID, excluding_scan_id: uuid.UUID
) -> Scan | None:
    """Return the tenant's most recent completed scan other than this one."""
    previous: Scan | None = await session.scalar(
        select(Scan)
        .where(
            Scan.tenant_id == tenant_id,
            Scan.id != excluding_scan_id,
            Scan.status == ScanStatus.COMPLETED,
        )
        .order_by(Scan.finished_at.desc(), Scan.created_at.desc())
        .limit(1)
    )
    return previous
