"""The audit trail.

The trail is the durable record of who did what. These tests confirm that the
security-relevant actions land in it, that it survives the deletion of what it
describes, and that only administrators can read it.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import delete
from sqlalchemy.orm import Session

from app.models import Tenant, User, UserRole
from tests.integration.helpers import TEST_PASSWORD, admin_token, auth, make_user, tenant_token

pytestmark = pytest.mark.integration


async def _events(client: AsyncClient, query: str = "") -> list[dict[str, object]]:
    """Read the audit trail as an administrator."""
    response = await client.get(f"/api/v1/audit/events{query}", headers=auth(admin_token()))
    assert response.status_code == 200
    items: list[dict[str, object]] = response.json()["items"]
    return items


# --------------------------------------------------------------------------- #
# Events are recorded
# --------------------------------------------------------------------------- #


async def test_a_failed_login_is_recorded(api_client: AsyncClient) -> None:
    """A wrong password leaves a trail entry, even with no account behind it."""
    email = f"ghost-{uuid.uuid4().hex[:8]}@netshield.test"
    await api_client.post("/api/v1/auth/login", json={"email": email, "password": "wrong"})

    events = await _events(api_client, f"?action=login.failed&actor_email={email}")
    assert len(events) == 1
    assert events[0]["actor_email"] == email
    assert events[0]["actor_user_id"] is None


async def test_a_successful_login_is_recorded(api_client: AsyncClient, sync_db: Session) -> None:
    """A good sign-in names the actor and their role."""
    user = make_user(sync_db, role=UserRole.PLATFORM_ADMIN)
    await api_client.post(
        "/api/v1/auth/login", json={"email": user.email, "password": TEST_PASSWORD}
    )

    events = await _events(api_client, f"?action=login.succeeded&actor_email={user.email}")
    assert len(events) == 1
    assert events[0]["actor_user_id"] == str(user.id)
    assert events[0]["actor_role"] == "PLATFORM_ADMIN"

    sync_db.query(User).filter_by(id=user.id).delete()
    sync_db.commit()


async def test_tenant_creation_is_recorded(api_client: AsyncClient, sync_db: Session) -> None:
    """Creating a client records the action against that client."""
    code_name = f"audited-{uuid.uuid4().hex[:8]}"
    created = await api_client.post(
        "/api/v1/tenants",
        headers=auth(admin_token()),
        json={"name": "Audited ISP", "code_name": code_name},
    )
    tenant_id = created.json()["id"]

    events = await _events(api_client, f"?action=tenant.created&tenant_id={tenant_id}")
    assert len(events) == 1
    assert events[0]["tenant_code_name"] == code_name
    assert events[0]["actor_role"] == "PLATFORM_ADMIN"

    sync_db.execute(delete(Tenant).where(Tenant.id == uuid.UUID(tenant_id)))
    sync_db.commit()


async def test_a_scan_launch_is_recorded(
    api_client: AsyncClient,
    api_tenant: Tenant,
    sync_db: Session,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Launching a scan records who launched it and what it covered."""

    class _Result:
        id = "task-audit"

    def _fake(*_a: object, **_k: object) -> object:
        return _Result()

    # Avoid a live broker; the audit event is written regardless of dispatch.
    # Patched through monkeypatch so it is restored after this test.
    monkeypatch.setattr("app.api.v1.endpoints.scans.celery_app.send_task", _fake)

    launched = await api_client.post(
        "/api/v1/scans/launch",
        headers=auth(admin_token()),
        json={"targets": ["192.0.2.0/24"]},
    )
    scan_id = launched.json()["scan_id"]

    events = await _events(api_client, "?action=scan.launched")
    assert any(event["target"] == scan_id for event in events)

    sync_db.execute(delete(Tenant).where(Tenant.is_system.is_(True)))
    sync_db.commit()


# --------------------------------------------------------------------------- #
# Durability and access
# --------------------------------------------------------------------------- #


async def test_the_trail_survives_tenant_deletion(
    api_client: AsyncClient, sync_db: Session
) -> None:
    """The record of a deletion outlives the thing deleted.

    A foreign key with cascade would take the audit entry with the tenant; the
    audit table deliberately has none.
    """
    code_name = f"doomed-{uuid.uuid4().hex[:8]}"
    created = await api_client.post(
        "/api/v1/tenants",
        headers=auth(admin_token()),
        json={"name": "Doomed", "code_name": code_name},
    )
    tenant_id = created.json()["id"]

    await api_client.delete(f"/api/v1/tenants/{tenant_id}", headers=auth(admin_token()))

    created_events = await _events(api_client, f"?action=tenant.created&tenant_id={tenant_id}")
    deleted_events = await _events(api_client, f"?action=tenant.deleted&tenant_id={tenant_id}")
    assert len(created_events) == 1
    assert len(deleted_events) == 1
    # The tenant row is gone, but its code name is still legible on the trail.
    assert deleted_events[0]["tenant_code_name"] == code_name


async def test_a_tenant_user_cannot_read_the_trail(
    api_client: AsyncClient, api_tenant: Tenant
) -> None:
    """The platform-wide trail is administrator only."""
    response = await api_client.get(
        "/api/v1/audit/events", headers=auth(tenant_token(api_tenant.id))
    )
    assert response.status_code == 403


async def test_the_trail_requires_authentication(api_client: AsyncClient) -> None:
    """It is never anonymous."""
    assert (await api_client.get("/api/v1/audit/events")).status_code == 401


async def test_the_trail_can_be_filtered_by_action(api_client: AsyncClient) -> None:
    """A filter narrows the trail to one kind of event."""
    email = f"filtered-{uuid.uuid4().hex[:8]}@netshield.test"
    await api_client.post("/api/v1/auth/login", json={"email": email, "password": "wrong"})

    events = await _events(api_client, "?action=login.failed")
    assert events
    assert all(event["action"] == "login.failed" for event in events)
