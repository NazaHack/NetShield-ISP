"""Scan launching, retrieval and history endpoints."""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.models import NetworkTarget, Scan, ScanResult, ScanStatus, Tenant, User, UserRole
from tests.integration.helpers import (
    admin_token,
    auth,
    make_user,
    tenant_token,
    token_for,
)

pytestmark = pytest.mark.integration


class _FakeAsyncResult:
    """Stand-in for a Celery dispatch, so tests need no live broker."""

    def __init__(self, task_id: str) -> None:
        """Record the identifier the fake dispatch should report."""
        self.id = task_id


@pytest.fixture(autouse=True)
def _stub_celery(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    """Capture dispatched tasks instead of sending them to a broker."""
    dispatched: list[dict[str, Any]] = []

    def fake_send_task(name: str, args: list[Any], kwargs: dict[str, Any]) -> _FakeAsyncResult:
        dispatched.append({"name": name, "args": args, "kwargs": kwargs})
        return _FakeAsyncResult(f"task-{len(dispatched)}")

    # Patched by dotted path: `celery_app` is imported into the endpoint
    # module rather than defined there, so it is not a public attribute of it.
    monkeypatch.setattr("app.api.v1.endpoints.scans.celery_app.send_task", fake_send_task)
    return dispatched


@pytest.fixture(autouse=True)
def _remove_adhoc_workspaces(sync_db: Session) -> Iterator[None]:
    """Delete only the ad-hoc workspaces this test provisioned.

    Celery is stubbed here, so scans queued by a test stay PENDING forever and
    would exhaust the workspace's concurrency quota for every later test. In
    production they reach a terminal state on their own.

    The set of pre-existing workspaces is recorded first and left alone. These
    tests run against a development database that also holds an operator's real
    work, and deleting every system tenant would take their ad-hoc scan history
    with it.
    """
    before = set(sync_db.scalars(select(Tenant.id).where(Tenant.is_system.is_(True))).all())
    try:
        yield
    finally:
        sync_db.rollback()
        after = set(sync_db.scalars(select(Tenant.id).where(Tenant.is_system.is_(True))).all())
        created = after - before
        if created:
            sync_db.execute(delete(Tenant).where(Tenant.id.in_(created)))
            sync_db.commit()


@pytest.fixture
def tenant_with_target(sync_db: Session, api_tenant: Tenant) -> Tenant:
    """A tenant that owns one scannable range."""
    sync_db.add(
        NetworkTarget(
            tenant_id=api_tenant.id,
            label="Management network",
            ip_address_or_cidr="10.10.0.0/24",
        )
    )
    sync_db.commit()
    return api_tenant


def _store_completed_scan(
    session: Session, tenant: Tenant, *, host_ip: str, ports: list[dict[str, Any]]
) -> Scan:
    """Insert a completed scan with findings, as the worker would have left it."""
    from datetime import UTC, datetime

    scan = Scan(tenant_id=tenant.id, status=ScanStatus.COMPLETED, finished_at=datetime.now(UTC))
    session.add(scan)
    session.flush()
    session.add(ScanResult(tenant_id=tenant.id, scan_id=scan.id, host_ip=host_ip, open_ports=ports))
    session.commit()
    session.refresh(scan)
    return scan


# --------------------------------------------------------------------------- #
# Launching
# --------------------------------------------------------------------------- #


async def test_launching_creates_a_scan_and_dispatches_it(
    api_client: AsyncClient, tenant_with_target: Tenant, _stub_celery: list[dict[str, Any]]
) -> None:
    """The endpoint returns 202 and hands the job to a worker."""
    response = await api_client.post(
        "/api/v1/scans/launch",
        headers=auth(tenant_token(tenant_with_target.id)),
        json={"tenant_id": str(tenant_with_target.id)},
    )

    assert response.status_code == 202
    body = response.json()
    assert body["status"] == "PENDING"
    assert body["tenant_id"] == str(tenant_with_target.id)
    assert body["task_id"]

    assert len(_stub_celery) == 1
    dispatched = _stub_celery[0]
    assert dispatched["name"] == "netshield.scans.run_network_scan"
    assert dispatched["args"] == [body["scan_id"]]
    # The task is always given its tenant explicitly; the worker refuses to run
    # without one.
    assert dispatched["kwargs"]["tenant_id"] == str(tenant_with_target.id)


async def test_a_tenant_cannot_launch_a_scan_for_another_tenant(
    api_client: AsyncClient,
    tenant_with_target: Tenant,
    other_tenant: Tenant,
    _stub_celery: list[dict[str, Any]],
) -> None:
    """The tenant in the body is checked against the token, not obeyed.

    This is the endpoint where a missing check would let one customer spend
    another's scanning budget and see their network.
    """
    response = await api_client.post(
        "/api/v1/scans/launch",
        headers=auth(tenant_token(other_tenant.id)),
        json={"tenant_id": str(tenant_with_target.id)},
    )

    assert response.status_code == 404
    assert _stub_celery == []


async def test_a_tenant_without_a_scannable_range_cannot_launch(
    api_client: AsyncClient, api_tenant: Tenant, _stub_celery: list[dict[str, Any]]
) -> None:
    """A scan that could only fail is never created."""
    response = await api_client.post(
        "/api/v1/scans/launch",
        headers=auth(tenant_token(api_tenant.id)),
        json={"tenant_id": str(api_tenant.id)},
    )

    assert response.status_code == 422
    assert _stub_celery == []


async def test_the_concurrency_quota_is_enforced(
    api_client: AsyncClient,
    tenant_with_target: Tenant,
    sync_db: Session,
    _stub_celery: list[dict[str, Any]],
) -> None:
    """One tenant cannot monopolise the shared worker pool."""
    from app.core.config import settings

    for _ in range(settings.max_concurrent_scans_per_tenant):
        sync_db.add(Scan(tenant_id=tenant_with_target.id, status=ScanStatus.PENDING))
    sync_db.commit()

    response = await api_client.post(
        "/api/v1/scans/launch",
        headers=auth(tenant_token(tenant_with_target.id)),
        json={"tenant_id": str(tenant_with_target.id)},
    )

    assert response.status_code == 409
    assert _stub_celery == []


@pytest.mark.parametrize("bad_range", ["1-10000; id", "$(id)", "--script=vuln", "abc"])
async def test_a_hostile_port_range_is_rejected(
    api_client: AsyncClient, tenant_with_target: Tenant, bad_range: str
) -> None:
    """The one free-form field on this endpoint is constrained at the edge."""
    response = await api_client.post(
        "/api/v1/scans/launch",
        headers=auth(tenant_token(tenant_with_target.id)),
        json={"tenant_id": str(tenant_with_target.id), "port_range": bad_range},
    )

    assert response.status_code == 422


async def test_a_custom_port_range_reaches_the_worker(
    api_client: AsyncClient, tenant_with_target: Tenant, _stub_celery: list[dict[str, Any]]
) -> None:
    """A valid port specification is passed through to the task."""
    response = await api_client.post(
        "/api/v1/scans/launch",
        headers=auth(tenant_token(tenant_with_target.id)),
        json={"tenant_id": str(tenant_with_target.id), "port_range": "22,80,443"},
    )

    assert response.status_code == 202
    assert _stub_celery[0]["kwargs"]["port_range"] == "22,80,443"


# --------------------------------------------------------------------------- #
# Retrieval
# --------------------------------------------------------------------------- #


async def test_a_pending_scan_reports_status_without_findings(
    api_client: AsyncClient, tenant_with_target: Tenant
) -> None:
    """A partial picture must not be mistaken for a final one."""
    launched = await api_client.post(
        "/api/v1/scans/launch",
        headers=auth(tenant_token(tenant_with_target.id)),
        json={"tenant_id": str(tenant_with_target.id)},
    )
    scan_id = launched.json()["scan_id"]

    response = await api_client.get(
        f"/api/v1/scans/{scan_id}", headers=auth(tenant_token(tenant_with_target.id))
    )

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "PENDING"
    assert body["is_finished"] is False
    assert body["results"] == []
    assert body["diff"] is None


async def test_a_completed_scan_returns_its_parsed_results(
    api_client: AsyncClient, api_tenant: Tenant, sync_db: Session
) -> None:
    """Findings come back parsed, not as raw scanner output."""
    scan = _store_completed_scan(
        sync_db,
        api_tenant,
        host_ip="10.10.0.5",
        ports=[{"port": 22, "protocol": "tcp", "service": "ssh", "version": "OpenSSH 9.2"}],
    )

    response = await api_client.get(
        f"/api/v1/scans/{scan.id}", headers=auth(tenant_token(api_tenant.id))
    )

    assert response.status_code == 200
    body = response.json()
    assert body["is_finished"] is True
    assert body["host_count"] == 1
    assert body["open_port_count"] == 1
    assert body["results"][0]["host_ip"] == "10.10.0.5"
    assert body["results"][0]["open_ports"][0]["service"] == "ssh"


async def test_a_completed_scan_carries_the_diff(
    api_client: AsyncClient, api_tenant: Tenant, sync_db: Session
) -> None:
    """The comparison against the previous completed scan is derived on read."""
    _store_completed_scan(
        sync_db,
        api_tenant,
        host_ip="10.10.0.5",
        ports=[{"port": 22, "protocol": "tcp", "service": "ssh", "version": None}],
    )
    second = _store_completed_scan(
        sync_db,
        api_tenant,
        host_ip="10.10.0.5",
        ports=[
            {"port": 22, "protocol": "tcp", "service": "ssh", "version": None},
            {"port": 23, "protocol": "tcp", "service": "telnet", "version": None},
        ],
    )

    response = await api_client.get(
        f"/api/v1/scans/{second.id}", headers=auth(tenant_token(api_tenant.id))
    )

    diff = response.json()["diff"]
    assert diff["has_baseline"] is True
    assert diff["has_changes"] is True
    assert diff["opened_port_count"] == 1
    assert diff["host_diffs"][0]["opened_ports"][0]["port"] == 23
    assert diff["previous_scan_id"] is not None


async def test_a_tenant_cannot_read_another_tenants_scan(
    api_client: AsyncClient, api_tenant: Tenant, other_tenant: Tenant, sync_db: Session
) -> None:
    """Knowing a scan identifier is not enough to read its findings.

    The scan endpoint is unnested, so the tenant filter in the repository is the
    only thing standing between the caller and another customer's network map.
    """
    victim_scan = _store_completed_scan(
        sync_db,
        other_tenant,
        host_ip="10.99.0.5",
        ports=[{"port": 3389, "protocol": "tcp", "service": "ms-wbt-server", "version": None}],
    )

    response = await api_client.get(
        f"/api/v1/scans/{victim_scan.id}", headers=auth(tenant_token(api_tenant.id))
    )

    assert response.status_code == 404


async def test_an_administrator_may_read_any_scan(
    api_client: AsyncClient, api_tenant: Tenant, sync_db: Session
) -> None:
    """Operator access is allowed and recorded."""
    scan = _store_completed_scan(
        sync_db,
        api_tenant,
        host_ip="10.10.0.5",
        ports=[{"port": 22, "protocol": "tcp", "service": "ssh", "version": None}],
    )

    response = await api_client.get(f"/api/v1/scans/{scan.id}", headers=auth(admin_token()))

    assert response.status_code == 200


async def test_an_unknown_scan_is_not_found(api_client: AsyncClient, api_tenant: Tenant) -> None:
    """An absent scan is indistinguishable from a forbidden one."""
    response = await api_client.get(
        f"/api/v1/scans/{uuid.uuid4()}", headers=auth(tenant_token(api_tenant.id))
    )

    assert response.status_code == 404


# --------------------------------------------------------------------------- #
# History
# --------------------------------------------------------------------------- #


async def test_history_returns_only_the_tenants_scans(
    api_client: AsyncClient, api_tenant: Tenant, other_tenant: Tenant, sync_db: Session
) -> None:
    """A list endpoint is where a missing filter leaks everything at once."""
    _store_completed_scan(sync_db, api_tenant, host_ip="10.10.0.5", ports=[])
    _store_completed_scan(sync_db, other_tenant, host_ip="10.99.0.5", ports=[])

    response = await api_client.get(
        f"/api/v1/tenants/{api_tenant.id}/scans/history",
        headers=auth(tenant_token(api_tenant.id)),
    )

    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 1
    assert body["items"][0]["tenant_id"] == str(api_tenant.id)


async def test_history_is_newest_first(
    api_client: AsyncClient, api_tenant: Tenant, sync_db: Session
) -> None:
    """Ordering matches what an operator expects to read."""
    first = _store_completed_scan(sync_db, api_tenant, host_ip="10.10.0.5", ports=[])
    second = _store_completed_scan(sync_db, api_tenant, host_ip="10.10.0.6", ports=[])

    response = await api_client.get(
        f"/api/v1/tenants/{api_tenant.id}/scans/history",
        headers=auth(tenant_token(api_tenant.id)),
    )

    identifiers = [item["id"] for item in response.json()["items"]]
    assert identifiers[0] == str(second.id)
    assert str(first.id) in identifiers


async def test_history_can_be_filtered_by_status(
    api_client: AsyncClient, api_tenant: Tenant, sync_db: Session
) -> None:
    """An operator can ask only for failures."""
    _store_completed_scan(sync_db, api_tenant, host_ip="10.10.0.5", ports=[])
    sync_db.add(Scan(tenant_id=api_tenant.id, status=ScanStatus.FAILED))
    sync_db.commit()

    response = await api_client.get(
        f"/api/v1/tenants/{api_tenant.id}/scans/history?status=FAILED",
        headers=auth(tenant_token(api_tenant.id)),
    )

    body = response.json()
    assert body["total"] == 1
    assert body["items"][0]["status"] == "FAILED"


async def test_a_tenant_cannot_read_another_tenants_history(
    api_client: AsyncClient, api_tenant: Tenant, other_tenant: Tenant
) -> None:
    """The nested tenant path is checked against the token."""
    response = await api_client.get(
        f"/api/v1/tenants/{other_tenant.id}/scans/history",
        headers=auth(tenant_token(api_tenant.id)),
    )

    assert response.status_code == 404


# --------------------------------------------------------------------------- #
# Ad-hoc scans: no client required
# --------------------------------------------------------------------------- #


async def test_an_administrator_can_scan_a_range_with_no_client(
    api_client: AsyncClient, sync_db: Session, _stub_celery: list[dict[str, Any]]
) -> None:
    """The shortest path through the product: a range, and nothing else.

    The scan still belongs to a tenant, because every scan in the platform does,
    but the operator never names or manages one.
    """
    response = await api_client.post(
        "/api/v1/scans/launch",
        headers=auth(admin_token()),
        json={"targets": ["192.0.2.0/24"]},
    )

    assert response.status_code == 202
    body = response.json()
    assert body["is_adhoc"] is True
    assert body["targets"] == ["192.0.2.0/24"]
    assert body["tenant_id"]

    assert _stub_celery[0]["kwargs"]["targets"] == ["192.0.2.0/24"]


async def test_the_adhoc_workspace_is_hidden_from_the_client_list(
    api_client: AsyncClient, _stub_celery: list[dict[str, Any]]
) -> None:
    """An operator who never created it should not have to wonder what it is."""
    await api_client.post(
        "/api/v1/scans/launch",
        headers=auth(admin_token()),
        json={"targets": ["192.0.2.0/24"]},
    )

    listed = await api_client.get("/api/v1/tenants?limit=200", headers=auth(admin_token()))

    assert listed.status_code == 200
    assert all(item["is_system"] is False for item in listed.json()["items"])


async def test_repeated_adhoc_scans_reuse_one_workspace(
    api_client: AsyncClient, _stub_celery: list[dict[str, Any]]
) -> None:
    """One operator's ad-hoc scans share their workspace, provisioned once."""
    first = await api_client.post(
        "/api/v1/scans/launch",
        headers=auth(admin_token()),
        json={"targets": ["192.0.2.0/24"]},
    )
    second = await api_client.post(
        "/api/v1/scans/launch",
        headers=auth(admin_token()),
        json={"targets": ["198.51.100.0/24"]},
    )

    assert first.json()["tenant_id"] == second.json()["tenant_id"]


async def test_inline_targets_are_normalised(
    api_client: AsyncClient, _stub_celery: list[dict[str, Any]]
) -> None:
    """A bare address becomes an explicit single-host network."""
    response = await api_client.post(
        "/api/v1/scans/launch",
        headers=auth(admin_token()),
        json={"targets": ["192.0.2.5"]},
    )

    assert response.json()["targets"] == ["192.0.2.5/32"]


@pytest.mark.parametrize(
    "hostile",
    ["10.0.0.1; rm -rf /", "--script=http-shellshock", "attacker.test", "10.0.0.1-254"],
)
async def test_hostile_inline_targets_are_refused(
    api_client: AsyncClient, hostile: str, _stub_celery: list[dict[str, Any]]
) -> None:
    """The field that reaches Nmap is validated before a scan row exists."""
    response = await api_client.post(
        "/api/v1/scans/launch", headers=auth(admin_token()), json={"targets": [hostile]}
    )

    assert response.status_code == 422
    assert _stub_celery == []


async def test_a_forbidden_inline_target_is_refused(
    api_client: AsyncClient, _stub_celery: list[dict[str, Any]]
) -> None:
    """Platform policy applies to an ad-hoc range exactly as to a registered one."""
    response = await api_client.post(
        "/api/v1/scans/launch",
        headers=auth(admin_token()),
        json={"targets": ["169.254.169.254"]},
    )

    assert response.status_code == 422
    assert _stub_celery == []


async def test_an_empty_target_list_is_refused(
    api_client: AsyncClient, _stub_celery: list[dict[str, Any]]
) -> None:
    """An empty list is a mistake, not a request to use the client's ranges."""
    response = await api_client.post(
        "/api/v1/scans/launch", headers=auth(admin_token()), json={"targets": []}
    )

    assert response.status_code == 422


async def test_a_client_user_cannot_scan_outside_their_registered_ranges(
    api_client: AsyncClient, tenant_with_target: Tenant, _stub_celery: list[dict[str, Any]]
) -> None:
    """Registration is how a customer declares what they may audit.

    Letting them type any address would make that declaration meaningless, so an
    inline target must fall inside a range already registered to them.
    """
    response = await api_client.post(
        "/api/v1/scans/launch",
        headers=auth(tenant_token(tenant_with_target.id)),
        json={"targets": ["8.8.8.0/24"]},
    )

    assert response.status_code == 422
    assert "not inside any range registered" in response.text
    assert _stub_celery == []


async def test_a_client_user_may_scan_a_host_inside_their_range(
    api_client: AsyncClient, tenant_with_target: Tenant, _stub_celery: list[dict[str, Any]]
) -> None:
    """Containment, not equality: a single host inside an owned block is fine."""
    response = await api_client.post(
        "/api/v1/scans/launch",
        headers=auth(tenant_token(tenant_with_target.id)),
        json={"targets": ["10.10.0.5"]},
    )

    assert response.status_code == 202
    assert response.json()["targets"] == ["10.10.0.5/32"]
    assert response.json()["is_adhoc"] is False


async def test_a_client_user_omitting_the_client_uses_their_own(
    api_client: AsyncClient, tenant_with_target: Tenant, _stub_celery: list[dict[str, Any]]
) -> None:
    """A tenant user has exactly one client, so naming it is optional."""
    response = await api_client.post(
        "/api/v1/scans/launch",
        headers=auth(tenant_token(tenant_with_target.id)),
        json={},
    )

    assert response.status_code == 202
    assert response.json()["tenant_id"] == str(tenant_with_target.id)
    assert response.json()["is_adhoc"] is False


async def test_each_operator_gets_their_own_adhoc_workspace(
    api_client: AsyncClient, sync_db: Session, _stub_celery: list[dict[str, Any]]
) -> None:
    """The concurrency quota bounds each operator, not the platform as a whole.

    A shared workspace would make every operator compete for the same three
    slots, so one running a wide sweep would block everyone else's quick checks.
    """
    other_admin = make_user(sync_db, role=UserRole.PLATFORM_ADMIN)

    mine = await api_client.post(
        "/api/v1/scans/launch",
        headers=auth(admin_token()),
        json={"targets": ["192.0.2.0/24"]},
    )
    theirs = await api_client.post(
        "/api/v1/scans/launch",
        headers=auth(token_for(other_admin)),
        json={"targets": ["192.0.2.0/24"]},
    )

    assert mine.json()["tenant_id"] != theirs.json()["tenant_id"]

    sync_db.execute(delete(User).where(User.id == other_admin.id))
    sync_db.commit()


# --------------------------------------------------------------------------- #
# The caller's own scan history
# --------------------------------------------------------------------------- #


async def test_an_operator_sees_their_own_adhoc_scans(
    api_client: AsyncClient, _stub_celery: list[dict[str, Any]]
) -> None:
    """Without this list an ad-hoc report is unreachable once you navigate away.

    The workspace owning it is hidden from the customer list by design, so it
    has no history page of its own.
    """
    token = admin_token()
    launched = await api_client.post(
        "/api/v1/scans/launch", headers=auth(token), json={"targets": ["192.0.2.0/24"]}
    )
    scan_id = launched.json()["scan_id"]

    listed = await api_client.get("/api/v1/scans", headers=auth(token))

    assert listed.status_code == 200
    assert scan_id in [item["id"] for item in listed.json()["items"]]


async def test_listing_scans_does_not_create_a_workspace(
    api_client: AsyncClient, sync_db: Session
) -> None:
    """Looking at an empty page must not bring a tenant row into existence."""
    fresh_admin = make_user(sync_db, role=UserRole.PLATFORM_ADMIN)

    listed = await api_client.get("/api/v1/scans", headers=auth(token_for(fresh_admin)))

    assert listed.status_code == 200
    assert listed.json()["total"] == 0

    workspaces = sync_db.scalars(select(Tenant).where(Tenant.is_system.is_(True))).all()
    assert all(fresh_admin.id.hex not in workspace.code_name for workspace in workspaces)

    sync_db.execute(delete(User).where(User.id == fresh_admin.id))
    sync_db.commit()


async def test_an_operator_does_not_see_another_operators_adhoc_scans(
    api_client: AsyncClient, sync_db: Session, _stub_celery: list[dict[str, Any]]
) -> None:
    """Each operator's workspace is their own, so their histories are separate."""
    other_admin = make_user(sync_db, role=UserRole.PLATFORM_ADMIN)

    mine = await api_client.post(
        "/api/v1/scans/launch",
        headers=auth(admin_token()),
        json={"targets": ["192.0.2.0/24"]},
    )
    my_scan_id = mine.json()["scan_id"]

    theirs = await api_client.get("/api/v1/scans", headers=auth(token_for(other_admin)))

    assert my_scan_id not in [item["id"] for item in theirs.json()["items"]]

    sync_db.execute(delete(User).where(User.id == other_admin.id))
    sync_db.commit()


async def test_a_client_user_sees_their_clients_scans(
    api_client: AsyncClient, api_tenant: Tenant, sync_db: Session
) -> None:
    """For a tenant user, "my scans" means their client's."""
    scan = _store_completed_scan(sync_db, api_tenant, host_ip="10.10.0.5", ports=[])

    listed = await api_client.get("/api/v1/scans", headers=auth(tenant_token(api_tenant.id)))

    assert listed.status_code == 200
    assert str(scan.id) in [item["id"] for item in listed.json()["items"]]


async def test_own_scans_require_authentication(api_client: AsyncClient) -> None:
    """The history is per account, so it is never anonymous."""
    assert (await api_client.get("/api/v1/scans")).status_code == 401
