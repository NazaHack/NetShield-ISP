"""Tenant management endpoints."""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import delete
from sqlalchemy.orm import Session

from app.models import Tenant
from tests.integration.helpers import admin_token, auth, tenant_token

pytestmark = pytest.mark.integration


async def test_an_administrator_can_register_a_tenant(
    api_client: AsyncClient, sync_db: Session
) -> None:
    """The create endpoint returns the stored record with its generated id."""
    code_name = f"created-{uuid.uuid4().hex[:8]}"
    response = await api_client.post(
        "/api/v1/tenants",
        headers=auth(admin_token()),
        json={"name": "Created ISP", "code_name": code_name},
    )

    assert response.status_code == 201
    body = response.json()
    assert body["code_name"] == code_name
    assert body["name"] == "Created ISP"
    assert uuid.UUID(body["id"])

    sync_db.execute(delete(Tenant).where(Tenant.code_name == code_name))
    sync_db.commit()


async def test_a_duplicate_code_name_is_a_conflict(
    api_client: AsyncClient, api_tenant: Tenant
) -> None:
    """The caller gets a clear 409 rather than a 500 from the unique constraint."""
    response = await api_client.post(
        "/api/v1/tenants",
        headers=auth(admin_token()),
        json={"name": "Impostor", "code_name": api_tenant.code_name},
    )

    assert response.status_code == 409


@pytest.mark.parametrize(
    "bad_code_name",
    ["Not A Slug", "-leading", "trailing-", "has_underscore", "has.dot", "has/slash"],
)
async def test_an_invalid_code_name_is_rejected(
    api_client: AsyncClient, bad_code_name: str
) -> None:
    """The slug grammar is enforced at the edge, naming the offending field."""
    response = await api_client.post(
        "/api/v1/tenants",
        headers=auth(admin_token()),
        json={"name": "Hostile", "code_name": bad_code_name},
    )

    assert response.status_code == 422


async def test_unknown_fields_are_rejected(api_client: AsyncClient) -> None:
    """`extra="forbid"` stops a caller smuggling a field the model ignores."""
    response = await api_client.post(
        "/api/v1/tenants",
        headers=auth(admin_token()),
        json={"name": "X", "code_name": "x-isp", "id": str(uuid.uuid4())},
    )

    assert response.status_code == 422


async def test_listing_tenants_is_paginated(api_client: AsyncClient, api_tenant: Tenant) -> None:
    """The list endpoint returns a bounded page with a total."""
    response = await api_client.get("/api/v1/tenants?limit=1&offset=0", headers=auth(admin_token()))

    assert response.status_code == 200
    body = response.json()
    assert len(body["items"]) <= 1
    assert body["limit"] == 1
    assert body["total"] >= 1


async def test_an_oversized_page_is_rejected(api_client: AsyncClient) -> None:
    """A caller cannot ask for an unbounded result set."""
    response = await api_client.get("/api/v1/tenants?limit=10000", headers=auth(admin_token()))

    assert response.status_code == 422


async def test_a_tenant_may_read_its_own_record(
    api_client: AsyncClient, api_tenant: Tenant
) -> None:
    """Reading one's own tenant is allowed, unlike listing them all."""
    response = await api_client.get(
        f"/api/v1/tenants/{api_tenant.id}", headers=auth(tenant_token(api_tenant.id))
    )

    assert response.status_code == 200
    assert response.json()["code_name"] == api_tenant.code_name


async def test_a_tenant_cannot_read_another_tenant(
    api_client: AsyncClient, api_tenant: Tenant, other_tenant: Tenant
) -> None:
    """Cross-tenant reads are answered 404, not 403.

    A 403 would confirm the other tenant exists, which is exactly what the
    platform promises never to reveal.
    """
    response = await api_client.get(
        f"/api/v1/tenants/{other_tenant.id}", headers=auth(tenant_token(api_tenant.id))
    )

    assert response.status_code == 404


async def test_a_nonexistent_tenant_is_indistinguishable_from_a_forbidden_one(
    api_client: AsyncClient, api_tenant: Tenant, other_tenant: Tenant
) -> None:
    """Both cases return the same body, so tenants cannot be enumerated."""
    forbidden = await api_client.get(
        f"/api/v1/tenants/{other_tenant.id}", headers=auth(tenant_token(api_tenant.id))
    )
    absent = await api_client.get(
        f"/api/v1/tenants/{uuid.uuid4()}", headers=auth(tenant_token(api_tenant.id))
    )

    assert forbidden.status_code == absent.status_code == 404
    assert forbidden.json()["detail"] == absent.json()["detail"]


async def test_an_administrator_can_rename_a_tenant(
    api_client: AsyncClient, api_tenant: Tenant
) -> None:
    """The display name is editable."""
    response = await api_client.patch(
        f"/api/v1/tenants/{api_tenant.id}",
        headers=auth(admin_token()),
        json={"name": "Renamed ISP"},
    )

    assert response.status_code == 200
    assert response.json()["name"] == "Renamed ISP"


async def test_the_code_name_cannot_be_changed(api_client: AsyncClient, api_tenant: Tenant) -> None:
    """The stable identifier other systems key on is not editable."""
    response = await api_client.patch(
        f"/api/v1/tenants/{api_tenant.id}",
        headers=auth(admin_token()),
        json={"name": "Renamed", "code_name": "something-else"},
    )

    assert response.status_code == 422


async def test_a_tenant_cannot_rename_itself(api_client: AsyncClient, api_tenant: Tenant) -> None:
    """Editing a tenant record is an administrator operation."""
    response = await api_client.patch(
        f"/api/v1/tenants/{api_tenant.id}",
        headers=auth(tenant_token(api_tenant.id)),
        json={"name": "Self-renamed"},
    )

    assert response.status_code == 403


async def test_deleting_a_tenant_removes_it(api_client: AsyncClient, sync_db: Session) -> None:
    """Deletion is complete: the record is gone afterwards."""
    code_name = f"doomed-{uuid.uuid4().hex[:8]}"
    created = await api_client.post(
        "/api/v1/tenants",
        headers=auth(admin_token()),
        json={"name": "Doomed ISP", "code_name": code_name},
    )
    tenant_id = created.json()["id"]

    deleted = await api_client.delete(f"/api/v1/tenants/{tenant_id}", headers=auth(admin_token()))
    assert deleted.status_code == 204

    follow_up = await api_client.get(f"/api/v1/tenants/{tenant_id}", headers=auth(admin_token()))
    assert follow_up.status_code == 404


async def test_a_tenant_cannot_delete_itself(api_client: AsyncClient, api_tenant: Tenant) -> None:
    """Deletion is an administrator operation."""
    response = await api_client.delete(
        f"/api/v1/tenants/{api_tenant.id}", headers=auth(tenant_token(api_tenant.id))
    )

    assert response.status_code == 403
