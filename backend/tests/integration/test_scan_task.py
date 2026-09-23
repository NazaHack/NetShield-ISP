"""End-to-end tests for the scan task against a real database.

Nmap itself is replaced by a stub returning recorded XML: these tests are about
the task's contract, not about the scanner. What they verify is the part that
would be expensive to get wrong in production, namely that a scan reaches a
terminal state exactly once, that its findings land under the right tenant, and
that a scan belonging to another tenant cannot be run.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import delete, select, update
from sqlalchemy.orm import Session

from app.db.session import SyncSessionFactory, sync_engine
from app.models import NetworkTarget, Scan, ScanResult, ScanStatus, Tenant
from app.workers.scanning.runner import NmapExecution, ScanExecutionError
from app.workers.tasks import scanning as scanning_task

pytestmark = pytest.mark.integration

FIXTURES = Path(__file__).parent.parent / "fixtures"

#: A report describing one host with two open ports, used as the "before" state.
BASELINE_XML = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" version="7.93">
<host><status state="up"/><address addr="10.10.0.5" addrtype="ipv4"/><ports>
<port protocol="tcp" portid="22"><state state="open"/>
<service name="ssh" product="OpenSSH" version="8.4"/></port>
<port protocol="tcp" portid="80"><state state="open"/>
<service name="http" product="nginx" version="1.22"/></port>
</ports></host>
</nmaprun>"""

#: The same host later: port 80 closed, telnet opened, SSH upgraded.
CHANGED_XML = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" version="7.93">
<host><status state="up"/><address addr="10.10.0.5" addrtype="ipv4"/><ports>
<port protocol="tcp" portid="22"><state state="open"/>
<service name="ssh" product="OpenSSH" version="9.2"/></port>
<port protocol="tcp" portid="23"><state state="open"/>
<service name="telnet"/></port>
</ports></host>
<host><status state="up"/><address addr="10.10.0.9" addrtype="ipv4"/><ports>
<port protocol="tcp" portid="443"><state state="open"/>
<service name="https"/></port>
</ports></host>
</nmaprun>"""


@pytest.fixture
def db() -> Iterator[Session]:
    """A synchronous session that commits, mirroring what the task really does.

    The task manages its own transactions through ``session_scope``, so these
    tests cannot wrap it in an outer rollback. Rows are removed explicitly
    afterwards instead.
    """
    session = SyncSessionFactory()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def tenant(db: Session) -> Iterator[Tenant]:
    """A tenant with one registered range, deleted when the test ends."""
    record = Tenant(
        name="Scan task tenant",
        code_name=f"scan-{uuid.uuid4().hex[:10]}",
    )
    db.add(record)
    db.flush()
    db.add(
        NetworkTarget(
            tenant_id=record.id,
            label="Management network",
            ip_address_or_cidr="10.10.0.0/24",
        )
    )
    db.commit()

    try:
        yield record
    finally:
        # Cascades remove the targets, scans and results this tenant owns.
        db.rollback()
        db.execute(delete(Tenant).where(Tenant.id == record.id))
        db.commit()


def _new_scan(db: Session, tenant: Tenant, status: ScanStatus = ScanStatus.PENDING) -> Scan:
    """Insert a scan for the tenant and return it."""
    scan = Scan(tenant_id=tenant.id, status=status)
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan


def _stub_nmap(monkeypatch: pytest.MonkeyPatch, xml: str) -> None:
    """Replace Nmap execution with a recorded report."""

    def fake_run(*_args: Any, **_kwargs: Any) -> NmapExecution:
        return NmapExecution(xml_report=xml, stderr="", duration_seconds=0.01)

    monkeypatch.setattr(scanning_task, "run_nmap", fake_run)


def _run(scan: Scan, tenant: Tenant, **kwargs: Any) -> dict[str, Any]:
    """Invoke the task body directly, as Celery would."""
    result: dict[str, Any] = scanning_task.run_network_scan.apply(
        args=(str(scan.id),),
        kwargs={"tenant_id": str(tenant.id), **kwargs},
        throw=True,
    ).get()
    return result


# --------------------------------------------------------------------------- #
# The happy path
# --------------------------------------------------------------------------- #


def test_a_scan_completes_and_stores_its_findings(
    db: Session, tenant: Tenant, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The whole pipeline: claim, scan, parse, persist, finish."""
    _stub_nmap(monkeypatch, BASELINE_XML)
    scan = _new_scan(db, tenant)

    summary = _run(scan, tenant)

    db.expire_all()
    stored = db.get(Scan, scan.id)
    assert stored is not None
    assert stored.status is ScanStatus.COMPLETED
    assert stored.finished_at is not None

    results = db.scalars(select(ScanResult).where(ScanResult.scan_id == scan.id)).all()
    assert len(results) == 1
    assert results[0].host_ip == "10.10.0.5"
    assert results[0].tenant_id == tenant.id
    assert [port["port"] for port in results[0].open_ports] == [22, 80]
    assert results[0].raw_output

    assert summary["status"] == "COMPLETED"
    assert summary["open_ports_found"] == 2
    assert summary["targets_scanned"] == ["10.10.0.0/24"]


def test_a_first_scan_reports_no_baseline(
    db: Session, tenant: Tenant, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With nothing to compare against, the diff says so rather than inventing changes."""
    _stub_nmap(monkeypatch, BASELINE_XML)
    scan = _new_scan(db, tenant)

    summary = _run(scan, tenant)

    assert summary["diff"]["has_baseline"] is False
    assert summary["diff"]["has_changes"] is False


def test_a_second_scan_is_compared_against_the_first(
    db: Session, tenant: Tenant, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The diff names the opened port, the closed port, the new host and the upgrade."""
    _stub_nmap(monkeypatch, BASELINE_XML)
    _run(_new_scan(db, tenant), tenant)

    _stub_nmap(monkeypatch, CHANGED_XML)
    summary = _run(_new_scan(db, tenant), tenant)

    diff = summary["diff"]
    assert diff["has_baseline"] is True
    assert diff["has_changes"] is True
    assert diff["new_hosts"] == ["10.10.0.9"]
    assert diff["disappeared_hosts"] == []

    host_diff = next(entry for entry in diff["host_diffs"] if entry["host_ip"] == "10.10.0.5")
    assert [port["port"] for port in host_diff["opened_ports"]] == [23]
    assert [port["port"] for port in host_diff["closed_ports"]] == [80]
    assert host_diff["changed_ports"][0]["previous_version"] == "OpenSSH 8.4"
    assert host_diff["changed_ports"][0]["current_version"] == "OpenSSH 9.2"


def test_rerunning_a_scan_does_not_duplicate_results(
    db: Session, tenant: Tenant, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Findings are replaced, so a retried write cannot double a host's row."""
    _stub_nmap(monkeypatch, BASELINE_XML)
    scan = _new_scan(db, tenant)
    _run(scan, tenant)

    # Force the scan back to pending, as a redelivery after a crash would find it.
    db.execute(
        update(Scan).where(Scan.id == scan.id).values(status=ScanStatus.PENDING, finished_at=None)
    )
    db.commit()

    _run(scan, tenant)

    results = db.scalars(select(ScanResult).where(ScanResult.scan_id == scan.id)).all()
    assert len(results) == 1


# --------------------------------------------------------------------------- #
# Tenant isolation
# --------------------------------------------------------------------------- #


def test_a_scan_cannot_be_run_for_another_tenant(
    db: Session, tenant: Tenant, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A task carrying someone else's scan id finds nothing and does not run.

    The scan row is never loaded by identifier alone, so a mismatched tenant is
    indistinguishable from a scan that does not exist.
    """
    _stub_nmap(monkeypatch, BASELINE_XML)
    scan = _new_scan(db, tenant)
    intruder_id = uuid.uuid4()

    with pytest.raises(scanning_task.ScanAlreadyHandledError):
        scanning_task.run_network_scan.apply(
            args=(str(scan.id),),
            kwargs={"tenant_id": str(intruder_id)},
            throw=True,
        ).get()

    db.expire_all()
    untouched = db.get(Scan, scan.id)
    assert untouched is not None
    assert untouched.status is ScanStatus.PENDING


def test_the_task_refuses_to_run_without_a_tenant(db: Session, tenant: Tenant) -> None:
    """The queue-level guard rejects an unscoped invocation."""
    scan = _new_scan(db, tenant)

    with pytest.raises(ValueError, match="tenant_id"):
        scanning_task.run_network_scan.apply(args=(str(scan.id),), throw=True).get()


# --------------------------------------------------------------------------- #
# Concurrency and failure
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("status", [ScanStatus.RUNNING, ScanStatus.COMPLETED, ScanStatus.FAILED])
def test_a_scan_that_is_not_pending_is_skipped(
    db: Session, tenant: Tenant, monkeypatch: pytest.MonkeyPatch, status: ScanStatus
) -> None:
    """Late acknowledgement means a job can be redelivered; it must not re-run.

    Skipping is not treated as a failure: marking an already-completed scan
    FAILED would destroy a legitimate result.
    """
    _stub_nmap(monkeypatch, BASELINE_XML)
    scan = _new_scan(db, tenant, status=status)

    with pytest.raises(scanning_task.ScanAlreadyHandledError):
        _run(scan, tenant)

    db.expire_all()
    unchanged = db.get(Scan, scan.id)
    assert unchanged is not None
    assert unchanged.status is status


def test_a_scanner_failure_marks_the_scan_failed(
    db: Session, tenant: Tenant, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A scan must never be left stuck in RUNNING."""

    def failing_run(*_args: Any, **_kwargs: Any) -> NmapExecution:
        msg = "Nmap exited with code 1"
        raise ScanExecutionError(msg)

    monkeypatch.setattr(scanning_task, "run_nmap", failing_run)
    scan = _new_scan(db, tenant)

    with pytest.raises(ScanExecutionError):
        _run(scan, tenant)

    db.expire_all()
    failed = db.get(Scan, scan.id)
    assert failed is not None
    assert failed.status is ScanStatus.FAILED
    assert failed.finished_at is not None


def test_a_tenant_without_targets_fails_the_scan(
    db: Session, tenant: Tenant, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A scan with nothing to scan is a failure, not an empty success."""
    _stub_nmap(monkeypatch, BASELINE_XML)
    db.execute(delete(NetworkTarget).where(NetworkTarget.tenant_id == tenant.id))
    db.commit()
    scan = _new_scan(db, tenant)

    with pytest.raises(ValueError):
        _run(scan, tenant)

    db.expire_all()
    failed = db.get(Scan, scan.id)
    assert failed is not None
    assert failed.status is ScanStatus.FAILED


def test_a_malformed_identifier_is_rejected_before_any_query(db: Session, tenant: Tenant) -> None:
    """Identifiers are parsed as UUIDs first, so a bad one fails fast and clearly."""
    with pytest.raises(ValueError, match="UUID"):
        scanning_task.run_network_scan.apply(
            args=("not-a-uuid",),
            kwargs={"tenant_id": str(tenant.id)},
            throw=True,
        ).get()


def test_real_nmap_output_flows_through_the_task(
    db: Session, tenant: Tenant, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The recorded output of a genuine Nmap 7.93 run is stored end to end."""
    _stub_nmap(monkeypatch, (FIXTURES / "nmap_real_scan.xml").read_text())
    scan = _new_scan(db, tenant)

    summary = _run(scan, tenant)

    assert summary["status"] == "COMPLETED"
    assert summary["hosts_with_open_ports"] == 2

    results = db.scalars(select(ScanResult).where(ScanResult.scan_id == scan.id)).all()
    services = {port["service"] for result in results for port in result.open_ports}
    assert services == {"postgresql", "redis"}


def test_the_engine_uses_the_configured_engine_binding() -> None:
    """The worker path is synchronous, as Celery requires."""
    assert sync_engine.dialect.is_async is False
