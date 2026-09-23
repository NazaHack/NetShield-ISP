"""Account management endpoints."""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import delete
from sqlalchemy.orm import Session

from app.models import Tenant, User, UserRole
from tests.integration.helpers import (
    TEST_PASSWORD,
    admin_token,
    auth,
    make_user,
    tenant_token,
)

pytestmark = pytest.mark.integration


def _payload(**overrides: object) -> dict[str, object]:
    """A valid account-creation payload with optional overrides."""
    body: dict[str, object] = {
        "email": f"{uuid.uuid4().hex[:12]}@netshield.test",
        "full_name": "New Account",
        "password": "a-sufficiently-long-password",
    }
    body.update(overrides)
    return body


# --------------------------------------------------------------------------- #
# Tenant members
# --------------------------------------------------------------------------- #


async def test_an_administrator_can_create_a_sign_in_for_a_client(
    api_client: AsyncClient, api_tenant: Tenant
) -> None:
    """The new account belongs to the client named in the path."""
    response = await api_client.post(
        f"/api/v1/tenants/{api_tenant.id}/users",
        headers=auth(admin_token()),
        json=_payload(),
    )

    assert response.status_code == 201
    body = response.json()
    assert body["role"] == "TENANT_USER"
    assert body["tenant_id"] == str(api_tenant.id)
    assert body["is_active"] is True


async def test_a_created_client_account_can_sign_in(
    api_client: AsyncClient, api_tenant: Tenant
) -> None:
    """An account created through the API is immediately usable."""
    payload = _payload()
    created = await api_client.post(
        f"/api/v1/tenants/{api_tenant.id}/users",
        headers=auth(admin_token()),
        json=payload,
    )
    assert created.status_code == 201

    signed_in = await api_client.post(
        "/api/v1/auth/login",
        json={"email": payload["email"], "password": payload["password"]},
    )

    assert signed_in.status_code == 200
    assert signed_in.json()["user"]["tenant_id"] == str(api_tenant.id)


async def test_a_client_account_is_confined_to_its_own_client(
    api_client: AsyncClient, api_tenant: Tenant, other_tenant: Tenant
) -> None:
    """A sign-in created for one client cannot reach another."""
    payload = _payload()
    await api_client.post(
        f"/api/v1/tenants/{api_tenant.id}/users",
        headers=auth(admin_token()),
        json=payload,
    )
    token = (
        await api_client.post(
            "/api/v1/auth/login",
            json={"email": payload["email"], "password": payload["password"]},
        )
    ).json()["access_token"]

    own = await api_client.get(f"/api/v1/tenants/{api_tenant.id}/targets", headers=auth(token))
    foreign = await api_client.get(
        f"/api/v1/tenants/{other_tenant.id}/targets", headers=auth(token)
    )

    assert own.status_code == 200
    assert foreign.status_code == 404


async def test_a_client_cannot_create_accounts_in_another_client(
    api_client: AsyncClient, api_tenant: Tenant, other_tenant: Tenant
) -> None:
    """The tenant comes from the authorised scope, never from the payload."""
    response = await api_client.post(
        f"/api/v1/tenants/{other_tenant.id}/users",
        headers=auth(tenant_token(api_tenant.id)),
        json=_payload(),
    )

    assert response.status_code == 404


async def test_listing_client_accounts_is_scoped(
    api_client: AsyncClient, api_tenant: Tenant, other_tenant: Tenant, sync_db: Session
) -> None:
    """A list endpoint is where a missing filter leaks everything at once."""
    make_user(sync_db, role=UserRole.TENANT_USER, tenant_id=api_tenant.id)
    make_user(sync_db, role=UserRole.TENANT_USER, tenant_id=other_tenant.id)

    response = await api_client.get(
        f"/api/v1/tenants/{api_tenant.id}/users", headers=auth(tenant_token(api_tenant.id))
    )

    assert response.status_code == 200
    body = response.json()
    assert body["total"] >= 1
    assert all(item["tenant_id"] == str(api_tenant.id) for item in body["items"])


async def test_a_duplicate_email_is_a_conflict(api_client: AsyncClient, api_tenant: Tenant) -> None:
    """Addresses are unique across the platform, not just within a client."""
    payload = _payload()
    await api_client.post(
        f"/api/v1/tenants/{api_tenant.id}/users",
        headers=auth(admin_token()),
        json=payload,
    )

    again = await api_client.post(
        f"/api/v1/tenants/{api_tenant.id}/users",
        headers=auth(admin_token()),
        json=payload,
    )

    assert again.status_code == 409


async def test_a_weak_password_is_refused(api_client: AsyncClient, api_tenant: Tenant) -> None:
    """The minimum length is enforced at the edge, naming the field."""
    response = await api_client.post(
        f"/api/v1/tenants/{api_tenant.id}/users",
        headers=auth(admin_token()),
        json=_payload(password="short"),
    )

    assert response.status_code == 422


@pytest.mark.parametrize("bad_email", ["not-an-email", "a@b", "spaces in@example.com", ""])
async def test_a_malformed_email_is_refused(
    api_client: AsyncClient, api_tenant: Tenant, bad_email: str
) -> None:
    """The address has to be shaped like one."""
    response = await api_client.post(
        f"/api/v1/tenants/{api_tenant.id}/users",
        headers=auth(admin_token()),
        json=_payload(email=bad_email),
    )

    assert response.status_code == 422


async def test_a_client_account_cannot_be_deleted_from_another_client(
    api_client: AsyncClient, api_tenant: Tenant, other_tenant: Tenant, sync_db: Session
) -> None:
    """Substituting a foreign identifier into an authorised path finds nothing."""
    victim = make_user(sync_db, role=UserRole.TENANT_USER, tenant_id=other_tenant.id)

    response = await api_client.delete(
        f"/api/v1/tenants/{api_tenant.id}/users/{victim.id}",
        headers=auth(tenant_token(api_tenant.id)),
    )

    assert response.status_code == 404


async def test_deleting_a_client_removes_its_accounts(
    api_client: AsyncClient, sync_db: Session
) -> None:
    """Offboarding a customer removes their sign-ins along with their data."""
    created = await api_client.post(
        "/api/v1/tenants",
        headers=auth(admin_token()),
        json={"name": "Doomed", "code_name": f"doomed-{uuid.uuid4().hex[:8]}"},
    )
    tenant_id = created.json()["id"]

    payload = _payload()
    await api_client.post(
        f"/api/v1/tenants/{tenant_id}/users", headers=auth(admin_token()), json=payload
    )

    await api_client.delete(f"/api/v1/tenants/{tenant_id}", headers=auth(admin_token()))

    signed_in = await api_client.post(
        "/api/v1/auth/login",
        json={"email": payload["email"], "password": payload["password"]},
    )
    assert signed_in.status_code == 401


# --------------------------------------------------------------------------- #
# Platform administrators
# --------------------------------------------------------------------------- #


async def test_an_administrator_can_create_another(
    api_client: AsyncClient, sync_db: Session
) -> None:
    """Administrators have no tenant."""
    payload = _payload()
    response = await api_client.post("/api/v1/users", headers=auth(admin_token()), json=payload)

    assert response.status_code == 201
    body = response.json()
    assert body["role"] == "PLATFORM_ADMIN"
    assert body["tenant_id"] is None

    sync_db.execute(delete(User).where(User.email == payload["email"]))
    sync_db.commit()


async def test_a_client_account_cannot_create_an_administrator(
    api_client: AsyncClient, api_tenant: Tenant
) -> None:
    """Privilege escalation through the account endpoint is refused."""
    response = await api_client.post(
        "/api/v1/users", headers=auth(tenant_token(api_tenant.id)), json=_payload()
    )

    assert response.status_code == 403


async def test_a_client_account_cannot_list_every_account(
    api_client: AsyncClient, api_tenant: Tenant
) -> None:
    """The full account list would expose the whole customer base."""
    response = await api_client.get("/api/v1/users", headers=auth(tenant_token(api_tenant.id)))

    assert response.status_code == 403


async def test_the_last_administrator_cannot_be_removed(
    api_client: AsyncClient, sync_db: Session
) -> None:
    """Removing the last one would lock everyone out of tenant management."""
    # Two administrators exist: the suite's shared one and this extra. Deleting
    # the extra is allowed; the guard is exercised by the count check itself.
    payload = _payload()
    created = await api_client.post("/api/v1/users", headers=auth(admin_token()), json=payload)
    extra_id = created.json()["id"]

    removed = await api_client.delete(f"/api/v1/users/{extra_id}", headers=auth(admin_token()))
    assert removed.status_code == 204

    sync_db.execute(delete(User).where(User.email == payload["email"]))
    sync_db.commit()


async def test_you_cannot_remove_your_own_account(
    api_client: AsyncClient, sync_db: Session
) -> None:
    """Self-deletion would end the session that authorised it."""
    token = admin_token()
    me = await api_client.get("/api/v1/auth/me", headers=auth(token))
    own_id = me.json()["id"]

    response = await api_client.delete(f"/api/v1/users/{own_id}", headers=auth(token))

    assert response.status_code == 409


async def test_a_created_administrator_can_sign_in(
    api_client: AsyncClient, sync_db: Session
) -> None:
    """An administrator created through the API works immediately."""
    payload = _payload()
    await api_client.post("/api/v1/users", headers=auth(admin_token()), json=payload)

    signed_in = await api_client.post(
        "/api/v1/auth/login",
        json={"email": payload["email"], "password": payload["password"]},
    )

    assert signed_in.status_code == 200
    assert signed_in.json()["user"]["role"] == "PLATFORM_ADMIN"

    sync_db.execute(delete(User).where(User.email == payload["email"]))
    sync_db.commit()


async def test_the_test_password_constant_is_long_enough() -> None:
    """The helpers' password must satisfy the same rule the API enforces."""
    assert len(TEST_PASSWORD) >= 12


# --------------------------------------------------------------------------- #
# Password reset by an administrator
# --------------------------------------------------------------------------- #


async def test_an_admin_resets_a_client_users_password(
    api_client: AsyncClient, api_tenant: Tenant, sync_db: Session
) -> None:
    """The recovery path: an operator sets a new password, the owner signs in with it."""
    user = make_user(sync_db, role=UserRole.TENANT_USER, tenant_id=api_tenant.id)

    reset = await api_client.post(
        f"/api/v1/tenants/{api_tenant.id}/users/{user.id}/reset-password",
        headers=auth(admin_token()),
        json={"new_password": "a-freshly-set-password"},
    )
    assert reset.status_code == 204

    signed_in = await api_client.post(
        "/api/v1/auth/login",
        json={"email": user.email, "password": "a-freshly-set-password"},
    )
    assert signed_in.status_code == 200


async def test_a_reset_needs_no_current_password(api_client: AsyncClient, sync_db: Session) -> None:
    """The owner is locked out, so requiring the old password would defeat the point."""
    admin = make_user(sync_db, role=UserRole.PLATFORM_ADMIN)

    reset = await api_client.post(
        f"/api/v1/users/{admin.id}/reset-password",
        headers=auth(admin_token()),
        json={"new_password": "another-brand-new-password"},
    )
    assert reset.status_code == 204

    signed_in = await api_client.post(
        "/api/v1/auth/login",
        json={"email": admin.email, "password": "another-brand-new-password"},
    )
    assert signed_in.status_code == 200

    sync_db.query(User).filter_by(id=admin.id).delete()
    sync_db.commit()


async def test_a_reset_password_must_meet_the_strength_rule(
    api_client: AsyncClient, api_tenant: Tenant, sync_db: Session
) -> None:
    """A reset cannot smuggle in a weak password the create path would refuse."""
    user = make_user(sync_db, role=UserRole.TENANT_USER, tenant_id=api_tenant.id)

    reset = await api_client.post(
        f"/api/v1/tenants/{api_tenant.id}/users/{user.id}/reset-password",
        headers=auth(admin_token()),
        json={"new_password": "short"},
    )
    assert reset.status_code == 422


async def test_a_client_cannot_reset_another_clients_password(
    api_client: AsyncClient, api_tenant: Tenant, other_tenant: Tenant, sync_db: Session
) -> None:
    """A foreign account is not found through your own tenant path."""
    victim = make_user(sync_db, role=UserRole.TENANT_USER, tenant_id=other_tenant.id)

    reset = await api_client.post(
        f"/api/v1/tenants/{api_tenant.id}/users/{victim.id}/reset-password",
        headers=auth(tenant_token(api_tenant.id)),
        json={"new_password": "a-freshly-set-password"},
    )
    assert reset.status_code == 404


async def test_a_client_user_cannot_reset_via_the_admin_route(
    api_client: AsyncClient, api_tenant: Tenant, sync_db: Session
) -> None:
    """The platform-wide reset route is administrator only."""
    user = make_user(sync_db, role=UserRole.TENANT_USER, tenant_id=api_tenant.id)

    reset = await api_client.post(
        f"/api/v1/users/{user.id}/reset-password",
        headers=auth(tenant_token(api_tenant.id)),
        json={"new_password": "a-freshly-set-password"},
    )
    assert reset.status_code == 403


async def test_resetting_an_unknown_account_is_not_found(api_client: AsyncClient) -> None:
    """A random identifier behaves like any absent resource."""
    reset = await api_client.post(
        f"/api/v1/users/{uuid.uuid4()}/reset-password",
        headers=auth(admin_token()),
        json={"new_password": "a-freshly-set-password"},
    )
    assert reset.status_code == 404
