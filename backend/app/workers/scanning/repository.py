"""Every database access the scanning engine performs.

Collected in one module so that the tenant filter is auditable in a single
place. No function here takes a scan or a target without also taking the tenant
that must own it, and every statement filters on both.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from datetime import UTC, datetime

from sqlalchemy import delete, select, update
from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.models import NetworkTarget, Scan, ScanResult, ScanStatus
from app.models.scan_result import OpenPort
from app.workers.scanning.parser import HostFinding

logger = get_logger(__name__)


def claim_scan(session: Session, *, scan_id: uuid.UUID, tenant_id: uuid.UUID) -> Scan | None:
    """Atomically move a pending scan to RUNNING and return it.

    The transition is a conditional ``UPDATE`` rather than a read followed by a
    write. Celery acknowledges tasks late, so a job can legitimately be
    redelivered after a worker dies, and two workers must never both believe
    they own the same scan.

    Returns:
        The claimed scan, or ``None`` when it does not exist, belongs to another
        tenant, or is no longer pending. All three cases mean "do not run", and
        the caller does not need to tell them apart.
    """
    claimed = session.execute(
        update(Scan)
        .where(
            Scan.id == scan_id,
            Scan.tenant_id == tenant_id,
            Scan.status == ScanStatus.PENDING,
        )
        .values(status=ScanStatus.RUNNING)
        .returning(Scan)
    ).scalar_one_or_none()

    if claimed is None:
        logger.warning("scan.claim_failed", scan_id=str(scan_id))
    return claimed


def load_tenant_targets(session: Session, *, tenant_id: uuid.UUID) -> list[str]:
    """Return every network range the tenant has registered.

    Ordered by label so that a scan covers the same ranges in the same order on
    every run, which keeps Nmap's behaviour and the resulting reports stable.
    """
    rows = session.execute(
        select(NetworkTarget.ip_address_or_cidr)
        .where(NetworkTarget.tenant_id == tenant_id)
        .order_by(NetworkTarget.label)
    ).scalars()
    return list(rows)


def replace_scan_results(
    session: Session,
    *,
    scan_id: uuid.UUID,
    tenant_id: uuid.UUID,
    findings: Sequence[HostFinding],
) -> int:
    """Store the findings of a scan, replacing anything already recorded for it.

    The delete makes the write idempotent: a scan retried after a partial write
    must not end up with two rows for one host, which the unique constraint
    would reject anyway but with a confusing error.

    Returns:
        How many result rows were written.
    """
    session.execute(
        delete(ScanResult).where(
            ScanResult.scan_id == scan_id,
            ScanResult.tenant_id == tenant_id,
        )
    )

    for finding in findings:
        session.add(
            ScanResult(
                tenant_id=tenant_id,
                scan_id=scan_id,
                host_ip=finding.host_ip,
                open_ports=[dict(port) for port in finding.open_ports],
                raw_output=finding.raw_output or None,
            )
        )

    return len(findings)


def load_previous_completed_scan_results(
    session: Session,
    *,
    tenant_id: uuid.UUID,
    excluding_scan_id: uuid.UUID,
) -> dict[str, list[OpenPort]] | None:
    """Return the findings of the tenant's most recent completed scan.

    Args:
        session: An open synchronous session.
        tenant_id: The only tenant whose scans may be considered.
        excluding_scan_id: The scan currently running, which must not compare
            against itself.

    Returns:
        ``{host: [ports]}`` for the previous completed scan, or ``None`` when the
        tenant has never completed one.
    """
    previous_scan_id = session.execute(
        select(Scan.id)
        .where(
            Scan.tenant_id == tenant_id,
            Scan.id != excluding_scan_id,
            Scan.status == ScanStatus.COMPLETED,
        )
        # `finished_at` is the moment the network was observed, which is what a
        # comparison should be ordered by. `created_at` breaks ties for scans
        # that finished within the same clock tick.
        .order_by(Scan.finished_at.desc(), Scan.created_at.desc())
        .limit(1)
    ).scalar_one_or_none()

    if previous_scan_id is None:
        return None

    rows = session.execute(
        select(ScanResult.host_ip, ScanResult.open_ports).where(
            ScanResult.scan_id == previous_scan_id,
            ScanResult.tenant_id == tenant_id,
        )
    ).all()

    logger.info(
        "scan.baseline_loaded",
        previous_scan_id=str(previous_scan_id),
        host_count=len(rows),
    )
    return {host_ip: list(open_ports) for host_ip, open_ports in rows}


def finish_scan(
    session: Session,
    *,
    scan_id: uuid.UUID,
    tenant_id: uuid.UUID,
    status: ScanStatus,
) -> bool:
    """Move a scan into a terminal state and stamp its finish time.

    Uses a statement rather than the ORM helper so that it can run in a fresh
    transaction after a failure, when the in-memory scan object may be attached
    to a session that was rolled back.

    Returns:
        Whether a row was updated.
    """
    if not status.is_terminal:
        msg = f"{status.value} is not a terminal state."
        raise ValueError(msg)

    # `RETURNING` rather than `rowcount`: it is typed precisely and makes the
    # "already terminal, nothing to do" case explicit.
    updated_id = session.execute(
        update(Scan)
        .where(
            Scan.id == scan_id,
            Scan.tenant_id == tenant_id,
            Scan.status.notin_([ScanStatus.COMPLETED, ScanStatus.FAILED]),
        )
        .values(status=status, finished_at=datetime.now(UTC))
        .returning(Scan.id)
    ).scalar_one_or_none()

    return updated_id is not None


def load_scan_results(
    session: Session,
    *,
    scan_id: uuid.UUID,
    tenant_id: uuid.UUID,
) -> dict[str, list[OpenPort]]:
    """Return the findings of one scan as ``{host: [ports]}``."""
    rows = session.execute(
        select(ScanResult.host_ip, ScanResult.open_ports).where(
            ScanResult.scan_id == scan_id,
            ScanResult.tenant_id == tenant_id,
        )
    ).all()
    return {host_ip: list(open_ports) for host_ip, open_ports in rows}
