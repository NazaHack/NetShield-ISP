"""Network target endpoints, nested under a tenant."""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient

from app.models import Tenant
from tests.integration.helpers import admin_token, auth, tenant_token

pytestmark = pytest.mark.integration


async def _create_target(
    client: AsyncClient,
    tenant: Tenant,
    *,
    label: str = "Management network",
    network: str = "10.10.0.0/24",
) -> dict[str, object]:
    """Register a target and return the created record."""
    response = await client.post(
        f"/api/v1/tenants/{tenant.id}/targets",
        headers=auth(tenant_token(tenant.id)),
        json={"label": label, "ip_address_or_cidr": network, "description": "Test range"},
    )
    assert response.status_code == 201, response.text
    body: dict[str, object] = response.json()
    return body


# --------------------------------------------------------------------------- #
# Creation and validation
# --------------------------------------------------------------------------- #


async def test_a_tenant_can_register_a_range(api_client: AsyncClient, api_tenant: Tenant) -> None:
    """The created record carries the owning tenant."""
    target = await _create_target(api_client, api_tenant)

    assert target["ip_address_or_cidr"] == "10.10.0.0/24"
    assert target["tenant_id"] == str(api_tenant.id)


async def test_a_bare_address_is_stored_as_a_single_host_network(
    api_client: AsyncClient, api_tenant: Tenant
) -> None:
    """Ranges are canonicalised so every row has the same shape."""
    target = await _create_target(api_client, api_tenant, label="Jump host", network="10.10.0.5")

    assert target["ip_address_or_cidr"] == "10.10.0.5/32"


@pytest.mark.parametrize(
    "hostile",
    [
        "10.0.0.1; rm -rf /",
        "--script=http-shellshock",
        "-iL /etc/passwd",
        "$(id)",
        "attacker.test",
        "10.0.0.1-254",
        "999.999.999.999",
    ],
)
async def test_hostile_ranges_are_rejected_at_the_edge(
    api_client: AsyncClient, api_tenant: Tenant, hostile: str
) -> None:
    """The field that eventually reaches Nmap is validated before it is stored."""
    response = await api_client.post(
        f"/api/v1/tenants/{api_tenant.id}/targets",
        headers=auth(tenant_token(api_tenant.id)),
        json={"label": "Hostile", "ip_address_or_cidr": hostile},
    )

    assert response.status_code == 422


async def test_host_bits_set_is_rejected_rather_than_widened(
    api_client: AsyncClient, api_tenant: Tenant
) -> None:
    """Accepting 192.168.1.5/24 would turn one host into 256."""
    response = await api_client.post(
        f"/api/v1/tenants/{api_tenant.id}/targets",
        headers=auth(tenant_token(api_tenant.id)),
        json={"label": "Ambiguous", "ip_address_or_cidr": "192.168.1.5/24"},
    )

    assert response.status_code == 422


@pytest.mark.parametrize("forbidden", ["127.0.0.0/8", "169.254.169.254", "224.0.0.0/4"])
async def test_a_range_policy_will_never_scan_is_refused(
    api_client: AsyncClient, api_tenant: Tenant, forbidden: str
) -> None:
    """Storing a range the engine would skip is a trap, so it is refused now.

    The target would otherwise look registered in the dashboard while silently
    contributing nothing to every scan.
    """
    response = await api_client.post(
        f"/api/v1/tenants/{api_tenant.id}/targets",
        headers=auth(tenant_token(api_tenant.id)),
        json={"label": "Forbidden", "ip_address_or_cidr": forbidden},
    )

    assert response.status_code == 422
    assert "not_permitted" in response.text


async def test_a_duplicate_label_is_a_conflict(api_client: AsyncClient, api_tenant: Tenant) -> None:
    """Two ranges sharing a label inside one tenant would be misleading."""
    await _create_target(api_client, api_tenant)

    response = await api_client.post(
        f"/api/v1/tenants/{api_tenant.id}/targets",
        headers=auth(tenant_token(api_tenant.id)),
        json={"label": "Management network", "ip_address_or_cidr": "10.20.0.0/24"},
    )

    assert response.status_code == 409


async def test_a_duplicate_range_is_a_conflict(api_client: AsyncClient, api_tenant: Tenant) -> None:
    """The same range twice would double the tenant's scan volume."""
    await _create_target(api_client, api_tenant)

    response = await api_client.post(
        f"/api/v1/tenants/{api_tenant.id}/targets",
        headers=auth(tenant_token(api_tenant.id)),
        json={"label": "Second name", "ip_address_or_cidr": "10.10.0.0/24"},
    )

    assert response.status_code == 409


async def test_two_tenants_may_register_the_same_range(
    api_client: AsyncClient, api_tenant: Tenant, other_tenant: Tenant
) -> None:
    """RFC 1918 space overlaps across customers, so uniqueness is per tenant."""
    await _create_target(api_client, api_tenant)
    await _create_target(api_client, other_tenant)


# --------------------------------------------------------------------------- #
# Isolation
# --------------------------------------------------------------------------- #


async def test_a_tenant_cannot_list_another_tenants_ranges(
    api_client: AsyncClient, api_tenant: Tenant, other_tenant: Tenant
) -> None:
    """The nested path is checked against the token, not obeyed."""
    await _create_target(api_client, other_tenant)

    response = await api_client.get(
        f"/api/v1/tenants/{other_tenant.id}/targets",
        headers=auth(tenant_token(api_tenant.id)),
    )

    assert response.status_code == 404


async def test_a_tenant_cannot_read_another_tenants_range_by_id(
    api_client: AsyncClient, api_tenant: Tenant, other_tenant: Tenant
) -> None:
    """Knowing a target's identifier is not enough to read it.

    The attempt uses the victim's own tenant path, so only the token stands
    between the caller and the data.
    """
    victim_target = await _create_target(api_client, other_tenant)

    response = await api_client.get(
        f"/api/v1/tenants/{other_tenant.id}/targets/{victim_target['id']}",
        headers=auth(tenant_token(api_tenant.id)),
    )

    assert response.status_code == 404


async def test_a_target_id_from_another_tenant_is_not_found_under_your_own_path(
    api_client: AsyncClient, api_tenant: Tenant, other_tenant: Tenant
) -> None:
    """Substituting a foreign identifier into an authorised path finds nothing.

    This is the attack the repository's tenant filter exists to stop: the caller
    is legitimately authorised for the path, and only the query scoping prevents
    the read.
    """
    victim_target = await _create_target(api_client, other_tenant)

    response = await api_client.get(
        f"/api/v1/tenants/{api_tenant.id}/targets/{victim_target['id']}",
        headers=auth(tenant_token(api_tenant.id)),
    )

    assert response.status_code == 404


async def test_a_tenant_cannot_delete_another_tenants_range(
    api_client: AsyncClient, api_tenant: Tenant, other_tenant: Tenant
) -> None:
    """A write across the boundary fails exactly like a read."""
    victim_target = await _create_target(api_client, other_tenant)

    response = await api_client.delete(
        f"/api/v1/tenants/{api_tenant.id}/targets/{victim_target['id']}",
        headers=auth(tenant_token(api_tenant.id)),
    )
    assert response.status_code == 404

    still_there = await api_client.get(
        f"/api/v1/tenants/{other_tenant.id}/targets/{victim_target['id']}",
        headers=auth(tenant_token(other_tenant.id)),
    )
    assert still_there.status_code == 200


async def test_listing_returns_only_the_callers_ranges(
    api_client: AsyncClient, api_tenant: Tenant, other_tenant: Tenant
) -> None:
    """A list endpoint is where a missing filter leaks everything at once."""
    await _create_target(api_client, api_tenant, label="Mine", network="10.1.0.0/24")
    await _create_target(api_client, other_tenant, label="Theirs", network="10.2.0.0/24")

    response = await api_client.get(
        f"/api/v1/tenants/{api_tenant.id}/targets",
        headers=auth(tenant_token(api_tenant.id)),
    )

    assert response.status_code == 200
    body = response.json()
    assert [item["label"] for item in body["items"]] == ["Mine"]
    assert body["total"] == 1


async def test_an_administrator_may_act_for_a_tenant(
    api_client: AsyncClient, api_tenant: Tenant
) -> None:
    """Operator support access is permitted, and is logged as impersonation."""
    await _create_target(api_client, api_tenant)

    response = await api_client.get(
        f"/api/v1/tenants/{api_tenant.id}/targets", headers=auth(admin_token())
    )

    assert response.status_code == 200
    assert response.json()["total"] == 1


# --------------------------------------------------------------------------- #
# Editing
# --------------------------------------------------------------------------- #


async def test_a_partial_update_leaves_other_fields_alone(
    api_client: AsyncClient, api_tenant: Tenant
) -> None:
    """Fields omitted from the payload are not cleared."""
    target = await _create_target(api_client, api_tenant)

    response = await api_client.patch(
        f"/api/v1/tenants/{api_tenant.id}/targets/{target['id']}",
        headers=auth(tenant_token(api_tenant.id)),
        json={"label": "Renamed network"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["label"] == "Renamed network"
    assert body["ip_address_or_cidr"] == "10.10.0.0/24"


async def test_an_update_cannot_smuggle_a_hostile_range(
    api_client: AsyncClient, api_tenant: Tenant
) -> None:
    """Edits are validated exactly like creations."""
    target = await _create_target(api_client, api_tenant)

    response = await api_client.patch(
        f"/api/v1/tenants/{api_tenant.id}/targets/{target['id']}",
        headers=auth(tenant_token(api_tenant.id)),
        json={"ip_address_or_cidr": "10.0.0.1; id"},
    )

    assert response.status_code == 422


async def test_a_deleted_range_is_gone(api_client: AsyncClient, api_tenant: Tenant) -> None:
    """Deletion removes the record."""
    target = await _create_target(api_client, api_tenant)

    deleted = await api_client.delete(
        f"/api/v1/tenants/{api_tenant.id}/targets/{target['id']}",
        headers=auth(tenant_token(api_tenant.id)),
    )
    assert deleted.status_code == 204

    follow_up = await api_client.get(
        f"/api/v1/tenants/{api_tenant.id}/targets/{target['id']}",
        headers=auth(tenant_token(api_tenant.id)),
    )
    assert follow_up.status_code == 404


async def test_an_unknown_target_is_not_found(api_client: AsyncClient, api_tenant: Tenant) -> None:
    """A random identifier behaves the same as a foreign one."""
    response = await api_client.get(
        f"/api/v1/tenants/{api_tenant.id}/targets/{uuid.uuid4()}",
        headers=auth(tenant_token(api_tenant.id)),
    )

    assert response.status_code == 404
