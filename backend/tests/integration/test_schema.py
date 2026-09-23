"""Database-enforced guarantees.

These tests exist because the Python layer can be bypassed. A raw SQL statement,
a future refactor or a bug in a repository method must not be able to violate
tenant isolation, so the guarantees are asserted against PostgreSQL itself.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from sqlalchemy import delete, func, select, text
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import NetworkTarget, Scan, ScanResult, ScanStatus, Tenant

pytestmark = pytest.mark.integration


async def _make_tenant(session: AsyncSession, suffix: str | None = None) -> Tenant:
    """Create a tenant with a code name unique to this test run."""
    unique = suffix or uuid.uuid4().hex[:12]
    tenant = Tenant(name=f"Test tenant {unique}", code_name=f"t-{unique}")
    session.add(tenant)
    await session.flush()
    return tenant


async def _make_scan(session: AsyncSession, tenant: Tenant) -> Scan:
    """Create a pending scan owned by the given tenant."""
    scan = Scan(tenant_id=tenant.id, status=ScanStatus.PENDING)
    session.add(scan)
    await session.flush()
    return scan


# --------------------------------------------------------------------------- #
# Tenant isolation
# --------------------------------------------------------------------------- #


async def test_cross_tenant_scan_result_is_rejected_by_the_database(
    db_session: AsyncSession,
) -> None:
    """A result may not claim a different tenant than the scan that produced it.

    This is the single most important guarantee in the schema. The composite
    foreign key makes the row impossible to insert, so no application bug can
    attach one tenant's findings to another tenant's scan.
    """
    owner = await _make_tenant(db_session)
    intruder = await _make_tenant(db_session)
    scan = await _make_scan(db_session, owner)

    db_session.add(
        ScanResult(
            tenant_id=intruder.id,
            scan_id=scan.id,
            host_ip="10.10.0.5",
            open_ports=[],
        )
    )

    with pytest.raises(IntegrityError, match="fk_scan_results_scan_id_tenant_id_scans"):
        await db_session.flush()


async def test_matching_tenant_scan_result_is_accepted(db_session: AsyncSession) -> None:
    """The correct pairing is stored without complaint."""
    tenant = await _make_tenant(db_session)
    scan = await _make_scan(db_session, tenant)

    result = ScanResult(
        tenant_id=tenant.id,
        scan_id=scan.id,
        host_ip="10.10.0.5",
        open_ports=[{"port": 22, "protocol": "tcp", "service": "ssh", "version": None}],
    )
    db_session.add(result)
    await db_session.flush()

    assert result.id is not None


async def test_scan_result_referencing_an_unknown_scan_is_rejected(
    db_session: AsyncSession,
) -> None:
    """A dangling result cannot be created even with a valid tenant."""
    tenant = await _make_tenant(db_session)

    db_session.add(
        ScanResult(
            tenant_id=tenant.id,
            scan_id=uuid.uuid4(),
            host_ip="10.10.0.5",
            open_ports=[],
        )
    )

    with pytest.raises(IntegrityError):
        await db_session.flush()


async def test_deleting_a_tenant_cascades_to_all_owned_rows(db_session: AsyncSession) -> None:
    """Offboarding a customer removes their network map entirely."""
    tenant = await _make_tenant(db_session)
    scan = await _make_scan(db_session, tenant)
    db_session.add(
        NetworkTarget(
            tenant_id=tenant.id,
            label="Management network",
            ip_address_or_cidr="10.10.0.0/24",
        )
    )
    db_session.add(
        ScanResult(tenant_id=tenant.id, scan_id=scan.id, host_ip="10.10.0.5", open_ports=[])
    )
    await db_session.flush()

    await db_session.execute(delete(Tenant).where(Tenant.id == tenant.id))
    await db_session.flush()

    for model in (NetworkTarget, Scan, ScanResult):
        remaining = await db_session.scalar(
            select(func.count()).select_from(model).where(model.tenant_id == tenant.id)
        )
        assert remaining == 0, f"{model.__name__} rows survived the tenant deletion"


# --------------------------------------------------------------------------- #
# Uniqueness
# --------------------------------------------------------------------------- #


async def test_tenant_code_name_is_globally_unique(db_session: AsyncSession) -> None:
    """Two tenants cannot share a code name, which is used as a stable key."""
    tenant = await _make_tenant(db_session)
    db_session.add(Tenant(name="Impostor", code_name=tenant.code_name))

    with pytest.raises(IntegrityError):
        await db_session.flush()


async def test_the_same_range_twice_in_one_tenant_is_rejected(db_session: AsyncSession) -> None:
    """A duplicate range would double the tenant's scan volume silently."""
    tenant = await _make_tenant(db_session)
    db_session.add(
        NetworkTarget(tenant_id=tenant.id, label="First", ip_address_or_cidr="10.10.0.0/24")
    )
    await db_session.flush()

    db_session.add(
        NetworkTarget(tenant_id=tenant.id, label="Second", ip_address_or_cidr="10.10.0.0/24")
    )
    with pytest.raises(IntegrityError):
        await db_session.flush()


async def test_two_tenants_may_own_the_same_range(db_session: AsyncSession) -> None:
    """Uniqueness is per tenant: RFC 1918 space overlaps across customers."""
    first = await _make_tenant(db_session)
    second = await _make_tenant(db_session)

    db_session.add(
        NetworkTarget(tenant_id=first.id, label="Management", ip_address_or_cidr="10.10.0.0/24")
    )
    db_session.add(
        NetworkTarget(tenant_id=second.id, label="Management", ip_address_or_cidr="10.10.0.0/24")
    )
    await db_session.flush()


async def test_one_host_appears_at_most_once_per_scan(db_session: AsyncSession) -> None:
    """A duplicated host row would double every count in the dashboard."""
    tenant = await _make_tenant(db_session)
    scan = await _make_scan(db_session, tenant)

    db_session.add(
        ScanResult(tenant_id=tenant.id, scan_id=scan.id, host_ip="10.10.0.5", open_ports=[])
    )
    await db_session.flush()

    db_session.add(
        ScanResult(tenant_id=tenant.id, scan_id=scan.id, host_ip="10.10.0.5", open_ports=[])
    )
    with pytest.raises(IntegrityError):
        await db_session.flush()


# --------------------------------------------------------------------------- #
# Check constraints, asserted through raw SQL that bypasses the ORM validators
# --------------------------------------------------------------------------- #


async def test_check_constraint_rejects_a_non_slug_code_name(db_session: AsyncSession) -> None:
    """The Python validator is not the only thing standing between us and a bad slug."""
    with pytest.raises(DBAPIError, match="ck_tenants_code_name_is_slug"):
        await db_session.execute(
            text("INSERT INTO tenants (name, code_name) VALUES (:name, :code_name)"),
            {"name": "Hostile", "code_name": "Not A Slug"},
        )


async def test_check_constraint_rejects_a_non_cidr_target(db_session: AsyncSession) -> None:
    """A raw INSERT cannot plant a value that later reaches a command line."""
    tenant = await _make_tenant(db_session)

    with pytest.raises(DBAPIError, match="ck_network_targets_ip_address_or_cidr_is_cidr"):
        await db_session.execute(
            text(
                "INSERT INTO network_targets (tenant_id, label, ip_address_or_cidr) "
                "VALUES (:tenant_id, :label, :value)"
            ),
            {"tenant_id": tenant.id, "label": "Hostile", "value": "10.0.0.1; rm -rf /"},
        )


async def test_check_constraint_rejects_finished_at_on_a_pending_scan(
    db_session: AsyncSession,
) -> None:
    """Only a terminal scan may carry a completion time."""
    tenant = await _make_tenant(db_session)

    with pytest.raises(DBAPIError, match="ck_scans_finished_at_only_when_terminal"):
        await db_session.execute(
            text(
                "INSERT INTO scans (tenant_id, status, finished_at) "
                "VALUES (:tenant_id, 'PENDING', now())"
            ),
            {"tenant_id": tenant.id},
        )


async def test_check_constraint_rejects_a_finish_before_the_start(
    db_session: AsyncSession,
) -> None:
    """A scan cannot finish before it was created."""
    tenant = await _make_tenant(db_session)

    with pytest.raises(DBAPIError, match="ck_scans_finished_at_after_created_at"):
        await db_session.execute(
            text(
                "INSERT INTO scans (tenant_id, status, created_at, finished_at) "
                "VALUES (:tenant_id, 'COMPLETED', now(), now() - interval '1 hour')"
            ),
            {"tenant_id": tenant.id},
        )


async def test_check_constraint_rejects_non_array_open_ports(db_session: AsyncSession) -> None:
    """The JSONB column stores an array; an object would break every reader."""
    tenant = await _make_tenant(db_session)
    scan = await _make_scan(db_session, tenant)

    with pytest.raises(DBAPIError, match="ck_scan_results_open_ports_is_array"):
        await db_session.execute(
            text(
                "INSERT INTO scan_results (tenant_id, scan_id, host_ip, open_ports) "
                "VALUES (:tenant_id, :scan_id, '10.0.0.1', '{\"port\": 22}'::jsonb)"
            ),
            {"tenant_id": tenant.id, "scan_id": scan.id},
        )


# --------------------------------------------------------------------------- #
# Column behaviour
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("status", list(ScanStatus))
async def test_every_scan_status_round_trips(db_session: AsyncSession, status: ScanStatus) -> None:
    """The native PostgreSQL enum accepts and returns every declared member."""
    tenant = await _make_tenant(db_session)
    scan = Scan(tenant_id=tenant.id, status=status)
    db_session.add(scan)
    await db_session.flush()

    # `refresh` re-reads the row through the async session. Expiring the
    # instance and touching an attribute instead would attempt IO outside the
    # greenlet context that SQLAlchemy's async layer requires.
    await db_session.refresh(scan)

    assert scan.status is status


async def test_an_unknown_status_is_rejected_by_the_enum(db_session: AsyncSession) -> None:
    """Free text cannot be written into the status column."""
    tenant = await _make_tenant(db_session)

    with pytest.raises(DBAPIError):
        await db_session.execute(
            text("INSERT INTO scans (tenant_id, status) VALUES (:tenant_id, 'CANCELLED')"),
            {"tenant_id": tenant.id},
        )


async def test_open_ports_round_trip_and_containment_query(db_session: AsyncSession) -> None:
    """Findings survive the round trip and are queryable by port.

    "Which hosts expose telnet?" is the query an ISP audit actually runs, and the
    GIN index on this column is what makes it viable at scale.
    """
    tenant = await _make_tenant(db_session)
    scan = await _make_scan(db_session, tenant)

    ports: list[dict[str, Any]] = [
        {"port": 22, "protocol": "tcp", "service": "ssh", "version": "OpenSSH 9.2p1"},
        {"port": 23, "protocol": "tcp", "service": "telnet", "version": None},
    ]
    db_session.add(
        ScanResult(tenant_id=tenant.id, scan_id=scan.id, host_ip="10.10.0.7", open_ports=ports)
    )
    await db_session.flush()

    matches = (
        await db_session.scalars(
            select(ScanResult.host_ip)
            .where(ScanResult.tenant_id == tenant.id)
            .where(ScanResult.open_ports.contains([{"port": 23, "protocol": "tcp"}]))
        )
    ).all()

    assert list(matches) == ["10.10.0.7"]


async def test_defaults_are_applied_by_the_database(db_session: AsyncSession) -> None:
    """Identifiers, timestamps and the empty findings array come from the server."""
    tenant = await _make_tenant(db_session)
    scan = await _make_scan(db_session, tenant)

    assert scan.id is not None
    assert scan.created_at is not None
    assert scan.status is ScanStatus.PENDING
    assert scan.finished_at is None

    result = ScanResult(tenant_id=tenant.id, scan_id=scan.id, host_ip="10.10.0.9")
    db_session.add(result)
    await db_session.flush()
    await db_session.refresh(result)

    assert result.open_ports == []
    assert result.created_at is not None
