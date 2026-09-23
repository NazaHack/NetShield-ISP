"""Scan launching and retrieval."""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from typing import Annotated

from celery.exceptions import CeleryError
from fastapi import APIRouter, Depends, HTTPException, Path, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import PrincipalDep, SessionDep, TenantScopeDep, not_found
from app.core.config import settings
from app.core.logging import get_logger
from app.core.network import is_contained_in
from app.core.risk import Severity, assess_port
from app.core.security import Principal
from app.models import AuditAction, Scan, ScanResult, ScanStatus
from app.repositories.audit import add_event
from app.repositories.network_target import list_target_ranges
from app.repositories.scan import (
    count_active_scans,
    create_scan,
    get_previous_completed_scan,
    get_scan,
    list_scan_results,
    list_scans,
)
from app.repositories.tenant import get_adhoc_workspace, get_or_create_adhoc_workspace
from app.schemas.common import Page, Pagination, pagination_params
from app.schemas.scan import (
    AssessmentSummary,
    NotableFinding,
    OpenPortRead,
    ScanDetailRead,
    ScanDiffRead,
    ScanLaunchRequest,
    ScanLaunchResponse,
    ScanRead,
    ScanResultRead,
)
from app.workers.celery_app import celery_app
from app.workers.scanning.command import TargetNotPermittedError, select_scannable_targets
from app.workers.scanning.diff import compare_scans
from app.workers.tasks.scanning import RUN_NETWORK_SCAN_TASK

logger = get_logger(__name__)

scans_router = APIRouter(prefix="/scans", tags=["scans"])
tenant_scans_router = APIRouter(prefix="/tenants/{tenant_id}/scans", tags=["scans"])

ScanIdPath = Annotated[uuid.UUID, Path(description="Scan identifier.")]

#: Findings at or above this severity are called out in the summary.
_NOTABLE_THRESHOLD = Severity.HIGH

#: How many notable findings the summary carries, worst first. A whole /24 of
#: the same exposure should headline, not flood the report.
_MAX_NOTABLE = 100


def _assess_results(
    results: Sequence[ScanResult],
) -> tuple[list[ScanResultRead], AssessmentSummary]:
    """Enrich each port with an exposure verdict and roll the scan up.

    Pure over the stored findings, like the diff: it changes nothing and can be
    recomputed at any time. Returns the per-host results with severities filled
    in, and a scan-level summary.
    """
    read_results: list[ScanResultRead] = []
    counts: dict[str, int] = {level.label: 0 for level in Severity}
    notable: list[NotableFinding] = []
    highest = Severity.INFO

    for result in results:
        ports: list[OpenPortRead] = []
        for port in result.open_ports:
            verdict = assess_port(port)
            counts[verdict.severity.label] += 1
            highest = max(highest, verdict.severity)
            ports.append(
                OpenPortRead(
                    port=port["port"],
                    protocol=port["protocol"],
                    service=port.get("service"),
                    version=port.get("version"),
                    severity=verdict.severity.label,
                    severity_reason=verdict.reason,
                )
            )
            if verdict.severity >= _NOTABLE_THRESHOLD:
                notable.append(
                    NotableFinding(
                        host_ip=result.host_ip,
                        port=port["port"],
                        protocol=port["protocol"],
                        service=port.get("service"),
                        severity=verdict.severity.label,
                        reason=verdict.reason,
                    )
                )
        read_results.append(
            ScanResultRead(
                id=result.id,
                host_ip=result.host_ip,
                open_ports=ports,
                created_at=result.created_at,
            )
        )

    # Worst first, then by host and port so the order is stable across runs.
    notable.sort(
        key=lambda finding: (-Severity[finding.severity.upper()], finding.host_ip, finding.port)
    )

    summary = AssessmentSummary(
        counts=counts,
        highest_severity=highest.label,
        notable=notable[:_MAX_NOTABLE],
    )
    return read_results, summary


async def _build_diff(
    session: AsyncSession, *, tenant_id: uuid.UUID, scan: Scan
) -> ScanDiffRead | None:
    """Compare a completed scan against the tenant's previous completed one.

    Returns ``None`` for a scan that has not completed: a partial comparison
    could be mistaken for a final one.

    The diff is derived on read rather than stored. Both snapshots are
    persisted, so the comparison is always current with however differences are
    defined today.
    """
    if scan.status is not ScanStatus.COMPLETED:
        return None

    current = await list_scan_results(session, tenant_id=tenant_id, scan_id=scan.id)
    current_snapshot = {result.host_ip: list(result.open_ports) for result in current}

    previous_scan = await get_previous_completed_scan(
        session, tenant_id=tenant_id, excluding_scan_id=scan.id
    )
    previous_snapshot = None
    if previous_scan is not None:
        previous_results = await list_scan_results(
            session, tenant_id=tenant_id, scan_id=previous_scan.id
        )
        previous_snapshot = {result.host_ip: list(result.open_ports) for result in previous_results}

    diff = compare_scans(previous_snapshot, current_snapshot)
    payload = diff.as_dict()
    payload["previous_scan_id"] = previous_scan.id if previous_scan is not None else None
    return ScanDiffRead.model_validate(payload)


async def _resolve_owner(
    session: AsyncSession, payload: ScanLaunchRequest, principal: Principal
) -> tuple[uuid.UUID, bool]:
    """Decide which tenant owns this scan.

    Returns:
        The owning tenant and whether this is an ad-hoc scan.

    Raises:
        HTTPException: 404 when the caller may not act for the named tenant.
    """
    if payload.tenant_id is not None:
        if not principal.may_act_for(payload.tenant_id):
            logger.warning(
                "api.cross_tenant_attempt",
                principal=principal.describe(),
                requested_tenant_id=str(payload.tenant_id),
            )
            raise not_found()
        return payload.tenant_id, False

    # No client named. A tenant user has exactly one, so use it; an
    # administrator gets the platform's own workspace, provisioned on demand.
    if principal.tenant_id is not None:
        return principal.tenant_id, False

    workspace = await get_or_create_adhoc_workspace(
        session, user_id=principal.user_id, email=principal.email
    )
    await session.commit()
    return workspace.id, True


async def _resolve_targets(
    session: AsyncSession,
    payload: ScanLaunchRequest,
    principal: Principal,
    tenant_id: uuid.UUID,
) -> list[str]:
    """Decide what this scan will cover.

    Inline targets replace the client's registered ranges. For a tenant user
    each one must fall inside a range already registered to their client:
    registration is how a customer declares what they are authorised to audit,
    and letting them type any address would make that declaration meaningless.
    An administrator is the platform operator and is not constrained this way.

    Raises:
        HTTPException: 422 when an inline target is outside the caller's
            registered ranges.
    """
    if payload.targets is None:
        return await list_target_ranges(session, tenant_id=tenant_id)

    if principal.is_admin:
        return payload.targets

    registered = await list_target_ranges(session, tenant_id=tenant_id)
    outside = [
        target
        for target in payload.targets
        if not any(is_contained_in(target, allowed) for allowed in registered)
    ]
    if outside:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=(
                f"{', '.join(outside)} is not inside any range registered for this "
                "client. Register it first, or ask an administrator to run the scan."
            ),
        )
    return payload.targets


@scans_router.post(
    "/launch",
    response_model=ScanLaunchResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Queue a scan of a client's registered ranges, or of ranges given inline",
)
async def launch_scan(
    payload: ScanLaunchRequest,
    session: SessionDep,
    principal: PrincipalDep,
) -> ScanLaunchResponse:
    """Create a scan and dispatch it to a worker.

    Either name a client, whose registered ranges are scanned, or supply
    ``targets`` for a one-off check of a range registered nowhere. An ad-hoc
    scan still belongs to a tenant, because every scan and result in the
    platform does; when no client is named it is attributed to the platform's
    own workspace.

    The response is 202: the scan row exists and the job is queued, but no
    scanning has happened yet.

    Two pre-flight checks run before anything is written, so that a scan which
    could only fail is never created:

    * at least one range must be scannable under platform policy;
    * the owning tenant must be under its concurrent-scan quota.

    Raises:
        HTTPException: 404 when the caller may not act for the named client, 409
            when the quota is exhausted, 422 when no range is scannable, 503
            when the job could not be queued.
    """
    tenant_id, is_adhoc = await _resolve_owner(session, payload, principal)

    active = await count_active_scans(session, tenant_id=tenant_id)
    if active >= settings.max_concurrent_scans_per_tenant:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"There are already {active} scans queued or running here, which is "
                f"the configured limit of {settings.max_concurrent_scans_per_tenant}."
            ),
        )

    ranges = await _resolve_targets(session, payload, principal, tenant_id)
    try:
        selection = select_scannable_targets(ranges)
    except TargetNotPermittedError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc

    scan = await create_scan(session, tenant_id=tenant_id)
    await session.commit()

    try:
        async_result = celery_app.send_task(
            RUN_NETWORK_SCAN_TASK,
            args=[str(scan.id)],
            kwargs={
                "tenant_id": str(tenant_id),
                "profile": payload.profile.value,
                "port_range": payload.port_range,
                "targets": list(selection.accepted),
            },
        )
    except (CeleryError, OSError) as exc:
        # The scan row exists but nothing will ever pick it up. Fail it now
        # rather than leaving a job that is pending forever.
        scan.status = ScanStatus.FAILED
        await session.commit()
        logger.error("api.scan_dispatch_failed", scan_id=str(scan.id), error=str(exc))
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="The scan could not be queued. Try again shortly.",
        ) from exc

    # The scan row and its dispatch are already committed; record the audit event
    # in its own commit so a trail write cannot undo a queued scan.
    add_event(
        session,
        action=AuditAction.SCAN_LAUNCHED,
        actor=principal,
        tenant_id=tenant_id,
        target=str(scan.id),
        detail={
            "profile": payload.profile.value,
            "targets": list(selection.accepted),
            "addresses": selection.total_addresses,
            "adhoc": is_adhoc,
        },
    )
    await session.commit()

    logger.info(
        "api.scan_launched",
        scan_id=str(scan.id),
        task_id=async_result.id,
        targets=len(selection.accepted),
        addresses=selection.total_addresses,
        profile=payload.profile.value,
        port_range=payload.port_range,
        adhoc=is_adhoc,
    )

    return ScanLaunchResponse(
        scan_id=scan.id,
        tenant_id=tenant_id,
        status=scan.status,
        task_id=async_result.id,
        created_at=scan.created_at,
        targets=list(selection.accepted),
        profile=payload.profile,
        is_adhoc=is_adhoc,
    )


@scans_router.get(
    "",
    response_model=Page[ScanRead],
    summary="List the scans this account owns directly",
)
async def list_own_scans(
    session: SessionDep,
    principal: PrincipalDep,
    pagination: Annotated[Pagination, Depends(pagination_params)],
    status_filter: Annotated[
        ScanStatus | None,
        Query(alias="status", description="Return only scans in this state."),
    ] = None,
) -> Page[ScanRead]:
    """Return the caller's own scan history, newest first.

    For a tenant user that is their client's scans. For an administrator it is
    the ad-hoc scans they ran without naming a client, which would otherwise be
    unreachable: their workspace is hidden from the customer list by design, so
    without this endpoint a quick scan's report could only be opened from the
    link shown immediately after launching it.

    A client's history remains at ``/tenants/{tenant_id}/scans/history``.
    """
    if principal.tenant_id is not None:
        owner_id = principal.tenant_id
    else:
        workspace = await get_adhoc_workspace(session, user_id=principal.user_id)
        if workspace is None:
            # An operator who has never run an ad-hoc scan has no workspace, and
            # looking at this page must not create one.
            return Page[ScanRead](
                items=[], total=0, limit=pagination.limit, offset=pagination.offset
            )
        owner_id = workspace.id

    scans, total = await list_scans(
        session,
        tenant_id=owner_id,
        limit=pagination.limit,
        offset=pagination.offset,
        status=status_filter,
    )
    return Page[ScanRead](
        items=[ScanRead.model_validate(scan) for scan in scans],
        total=total,
        limit=pagination.limit,
        offset=pagination.offset,
    )


@scans_router.get(
    "/{scan_id}",
    response_model=ScanDetailRead,
    summary="Read a scan's status and, once finished, its results",
)
async def get_scan_detail(
    scan_id: ScanIdPath,
    session: SessionDep,
    principal: PrincipalDep,
) -> ScanDetailRead:
    """Return one scan.

    A pending or running scan comes back with its status and no findings. A
    completed scan carries its per-host results and the comparison against the
    tenant's previous completed scan.

    The scan is looked up with the caller's tenant applied, so a scan belonging
    to another tenant is not found rather than forbidden. An administrator may
    read any scan, and that access is logged.

    Raises:
        HTTPException: 404 when the scan does not exist or is not the caller's.
    """
    if principal.tenant_id is not None:
        scan = await get_scan(session, tenant_id=principal.tenant_id, scan_id=scan_id)
    else:
        # Administrator: no tenant filter is available, so the scan is fetched
        # by identifier and the access is recorded.
        scan = await session.get(Scan, scan_id)
        if scan is not None:
            logger.info(
                "api.admin_scan_access",
                scan_id=str(scan_id),
                tenant_id=str(scan.tenant_id),
                token_id=principal.token_id,
            )

    if scan is None:
        raise not_found()

    results = await list_scan_results(session, tenant_id=scan.tenant_id, scan_id=scan.id)
    diff = await _build_diff(session, tenant_id=scan.tenant_id, scan=scan)

    read_results, assessment = _assess_results(results)

    return ScanDetailRead(
        id=scan.id,
        tenant_id=scan.tenant_id,
        status=scan.status,
        created_at=scan.created_at,
        finished_at=scan.finished_at,
        is_finished=scan.status.is_terminal,
        host_count=len(results),
        open_port_count=sum(len(result.open_ports) for result in results),
        results=read_results,
        assessment=assessment if scan.status is ScanStatus.COMPLETED else None,
        diff=diff,
    )


@tenant_scans_router.get(
    "/history",
    response_model=Page[ScanRead],
    summary="List a tenant's scans, newest first",
)
async def get_scan_history(
    session: SessionDep,
    scope: TenantScopeDep,
    pagination: Annotated[Pagination, Depends(pagination_params)],
    status_filter: Annotated[
        ScanStatus | None,
        Query(alias="status", description="Return only scans in this state."),
    ] = None,
) -> Page[ScanRead]:
    """Return a page of the tenant's scan history."""
    scans, total = await list_scans(
        session,
        tenant_id=scope.tenant_id,
        limit=pagination.limit,
        offset=pagination.offset,
        status=status_filter,
    )
    return Page[ScanRead](
        items=[ScanRead.model_validate(scan) for scan in scans],
        total=total,
        limit=pagination.limit,
        offset=pagination.offset,
    )
