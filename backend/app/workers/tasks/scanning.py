"""The scan execution task.

This is the only place in the platform where a scan actually runs. It owns the
whole lifecycle: claiming the job, resolving the tenant's targets, invoking the
scanner, persisting findings, comparing against the previous scan, and reaching
a terminal state exactly once whatever happens in between.

Failure handling deserves a note. The failure path runs in a *new* transaction,
because the transaction that was writing results has been rolled back by the
time the exception surfaces. Marking the scan FAILED inside the aborted
transaction would itself be discarded, leaving the row stuck in RUNNING forever.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from celery.exceptions import SoftTimeLimitExceeded

from app.core.config import settings
from app.core.logging import get_logger
from app.db.session import session_scope
from app.models import ScanStatus
from app.workers.celery_app import TenantAwareTask, celery_app
from app.workers.scanning.command import (
    DEFAULT_SCAN_PROFILE,
    ScanProfile,
    TargetNotPermittedError,
    build_scan_command,
    select_scannable_targets,
)
from app.workers.scanning.diff import ScanDiff, compare_scans
from app.workers.scanning.parser import NmapParseError, NmapReport, parse_nmap_xml
from app.workers.scanning.repository import (
    claim_scan,
    finish_scan,
    load_previous_completed_scan_results,
    load_tenant_targets,
    replace_scan_results,
)
from app.workers.scanning.runner import ScanExecutionError, run_nmap

logger = get_logger(__name__)

#: Name under which the task is registered. The `netshield.scans.` prefix routes
#: it to the dedicated scan queue.
RUN_NETWORK_SCAN_TASK = "netshield.scans.run_network_scan"


class ScanAlreadyHandledError(RuntimeError):
    """Raised when a scan is not in a state this worker may take."""


@dataclass(frozen=True, slots=True)
class _Identifiers:
    """Validated identifiers for one scan run."""

    scan_id: uuid.UUID
    tenant_id: uuid.UUID


def _parse_identifiers(scan_id: str, tenant_id: str) -> _Identifiers:
    """Convert the task's string arguments into UUIDs.

    Task arguments arrive as JSON, so they are strings by the time they reach
    here. Parsing them before any query means a malformed identifier fails
    immediately rather than as a database error.
    """
    try:
        return _Identifiers(scan_id=uuid.UUID(scan_id), tenant_id=uuid.UUID(tenant_id))
    except (ValueError, AttributeError, TypeError) as exc:
        msg = "scan_id and tenant_id must both be UUID strings."
        raise ValueError(msg) from exc


def _execute_scan(
    identifiers: _Identifiers,
    *,
    profile: ScanProfile,
    port_range: str | None,
    targets: Sequence[str] | None,
) -> dict[str, Any]:
    """Run the scan and persist its outcome. Returns the task result payload."""
    with session_scope() as session:
        scan = claim_scan(session, scan_id=identifiers.scan_id, tenant_id=identifiers.tenant_id)
        if scan is None:
            msg = (
                f"Scan {identifiers.scan_id} is not pending for this tenant; "
                "it may already have been claimed or finished."
            )
            raise ScanAlreadyHandledError(msg)

        # Explicit targets come from an ad-hoc request, which the API has
        # already authorised and validated. They are re-checked here anyway:
        # the queue is a trust boundary, and a task must not assume its
        # arguments were produced by the code that normally produces them.
        raw_targets = (
            list(targets)
            if targets is not None
            else load_tenant_targets(session, tenant_id=identifiers.tenant_id)
        )
        selection = select_scannable_targets(raw_targets)

        for rejected_target, reason in selection.rejected:
            logger.warning("scan.target_rejected", target=rejected_target, reason=reason)

        # The baseline is read before the new findings are written, so the
        # comparison is against the previous scan rather than against this one.
        baseline = load_previous_completed_scan_results(
            session,
            tenant_id=identifiers.tenant_id,
            excluding_scan_id=identifiers.scan_id,
        )

    # Nmap runs outside the transaction. A scan can take the better part of an
    # hour, and holding a database connection open for it would exhaust the pool
    # long before the scan finished.
    command = build_scan_command(selection.accepted, profile=profile, port_range=port_range)
    execution = run_nmap(command)
    report = parse_nmap_xml(execution.xml_report)

    with session_scope() as session:
        stored = replace_scan_results(
            session,
            scan_id=identifiers.scan_id,
            tenant_id=identifiers.tenant_id,
            findings=report.hosts,
        )
        finish_scan(
            session,
            scan_id=identifiers.scan_id,
            tenant_id=identifiers.tenant_id,
            status=ScanStatus.COMPLETED,
        )

    diff = compare_scans(baseline, {host.host_ip: list(host.open_ports) for host in report.hosts})
    _log_outcome(identifiers, report=report, diff=diff, duration=execution.duration_seconds)

    return {
        "scan_id": str(identifiers.scan_id),
        "status": ScanStatus.COMPLETED.value,
        "targets_scanned": list(selection.accepted),
        "targets_rejected": [
            {"target": value, "reason": reason} for value, reason in selection.rejected
        ],
        "addresses_covered": selection.total_addresses,
        "hosts_with_open_ports": stored,
        "hosts_without_open_ports": list(report.hosts_without_open_ports),
        "open_ports_found": report.total_open_ports,
        "duration_seconds": round(execution.duration_seconds, 2),
        "diff": diff.as_dict(),
    }


def _log_outcome(
    identifiers: _Identifiers,
    *,
    report: NmapReport,
    diff: ScanDiff,
    duration: float,
) -> None:
    """Emit one structured line summarising what the scan found and changed."""
    logger.info(
        "scan.completed",
        scan_id=str(identifiers.scan_id),
        hosts=len(report.hosts),
        open_ports=report.total_open_ports,
        duration_seconds=round(duration, 2),
        has_baseline=diff.has_baseline,
        new_hosts=len(diff.new_hosts),
        disappeared_hosts=len(diff.disappeared_hosts),
        opened_ports=diff.opened_port_count,
        closed_ports=diff.closed_port_count,
    )


def _mark_failed(identifiers: _Identifiers, *, reason: str) -> None:
    """Record the failure in a transaction of its own.

    Never raises: a failure while recording a failure must not replace the
    original error in the logs.
    """
    try:
        with session_scope() as session:
            finish_scan(
                session,
                scan_id=identifiers.scan_id,
                tenant_id=identifiers.tenant_id,
                status=ScanStatus.FAILED,
            )
    # Last-resort handler: anything at all here must be swallowed.
    except Exception as exc:
        logger.error(
            "scan.failure_not_recorded",
            scan_id=str(identifiers.scan_id),
            error=str(exc),
            exc_info=True,
        )
    else:
        logger.error("scan.failed", scan_id=str(identifiers.scan_id), reason=reason)


@celery_app.task(  # type: ignore[misc]
    name=RUN_NETWORK_SCAN_TASK,
    base=TenantAwareTask,
    bind=True,
    ignore_result=False,
    # A scan is not safe to retry automatically: it is expensive, it touches a
    # customer's network, and a failure is usually a policy or configuration
    # problem that a retry will hit again. The scan is marked FAILED and an
    # operator decides.
    autoretry_for=(),
    max_retries=0,
)
def run_network_scan(
    self: Any,
    scan_id: str,
    *,
    tenant_id: str,
    profile: str = DEFAULT_SCAN_PROFILE.value,
    port_range: str | None = None,
    targets: Sequence[str] | None = None,
) -> dict[str, Any]:
    """Execute one network scan and record its findings.

    The task claims the scan, resolves the tenant's registered ranges, runs Nmap
    over them, stores one result row per responding host, compares the outcome
    against the tenant's previous completed scan, and finishes the scan as
    COMPLETED or FAILED.

    Args:
        self: The bound Celery task, used for the request id in logs.
        scan_id: UUID of the scan to run, as a string.
        tenant_id: UUID of the tenant that owns it. Required and enforced by
            :class:`~app.workers.celery_app.TenantAwareTask`: the scan row is
            never loaded by identifier alone, so a task carrying a scan id that
            belongs to another tenant finds nothing rather than running.
        profile: Scan thoroughness, one of :class:`ScanProfile`'s values. An
            unrecognised value falls back to the default rather than failing the
            scan.
        port_range: An explicit Nmap port specification overriding the profile's
            own port selection. ``None`` lets the profile choose.
        targets: Ranges to scan instead of the tenant's registered ones, for an
            ad-hoc scan. Validated again here rather than trusted.

    Returns:
        A JSON-serialisable summary including the diff against the previous scan.

    Raises:
        ScanAlreadyHandledError: The scan was not pending for this tenant.
        ValueError: An identifier was not a UUID, or no target was scannable.
        ScanExecutionError: Nmap could not be run or did not complete.
        NmapParseError: The report could not be parsed.
    """
    identifiers = _parse_identifiers(scan_id, tenant_id)

    try:
        scan_profile = ScanProfile(profile)
    except ValueError:
        # A payload from an older client, or a typo. Fall back rather than fail:
        # the scan is worth running with sensible defaults.
        logger.warning("scan.unknown_profile", profile=profile)
        scan_profile = DEFAULT_SCAN_PROFILE

    logger.info(
        "scan.started",
        scan_id=str(identifiers.scan_id),
        task_id=self.request.id,
        profile=scan_profile.value,
        port_range=port_range,
        nmap_timeout_seconds=settings.nmap_scan_timeout_seconds,
        explicit_targets=len(targets) if targets is not None else None,
    )

    try:
        return _execute_scan(
            identifiers, profile=scan_profile, port_range=port_range, targets=targets
        )
    except ScanAlreadyHandledError:
        # Not a failure of this scan: another worker owns it, or it is already
        # finished. Marking it FAILED here would undo a legitimate result.
        logger.warning("scan.skipped", scan_id=str(identifiers.scan_id))
        raise
    except SoftTimeLimitExceeded:
        _mark_failed(identifiers, reason="the task exceeded its soft time limit")
        raise
    except (
        TargetNotPermittedError,
        ScanExecutionError,
        NmapParseError,
        ValueError,
    ) as exc:
        _mark_failed(identifiers, reason=str(exc))
        raise
    # Deliberately broad: whatever went wrong, the scan must not be left in
    # RUNNING, which would block the tenant's quota and mislead the dashboard.
    except Exception as exc:
        _mark_failed(identifiers, reason=f"unexpected error: {exc}")
        raise
