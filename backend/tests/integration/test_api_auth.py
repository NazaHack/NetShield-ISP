"""Authentication: sign-in, token handling and role separation.

Tenant isolation rests entirely on the credential: if a caller can forge, alter
or sidestep it, every filter downstream is decoration. These tests attack that
assumption directly.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import jwt
import pytest
from httpx import AsyncClient
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.passwords import MIN_PASSWORD_LENGTH, hash_password, verify_password
from app.core.security import (
    JWT_AUDIENCE,
    JWT_ISSUER,
    AuthenticationError,
    PrincipalScope,
    create_access_token,
    decode_access_token,
)
from app.models import Tenant, User, UserRole
from tests.integration.helpers import (
    TEST_PASSWORD,
    admin_token,
    auth,
    make_user,
    tenant_token,
    token_for,
)

pytestmark = pytest.mark.integration


def _forge(claims: dict[str, object], *, key: str | None = None, algorithm: str = "HS256") -> str:
    """Encode arbitrary claims, standing in for an attacker with a key guess."""
    secret = key if key is not None else settings.secret_key.get_secret_value()
    return jwt.encode(claims, secret, algorithm=algorithm)


def _base_claims(**overrides: object) -> dict[str, object]:
    """A claim set that would otherwise decode successfully."""
    now = datetime.now(UTC)
    claims: dict[str, object] = {
        "sub": str(uuid.uuid4()),
        "scope": "admin",
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
        "iat": now,
        "exp": now + timedelta(minutes=5),
        "jti": uuid.uuid4().hex,
    }
    claims.update(overrides)
    return claims


# --------------------------------------------------------------------------- #
# Passwords
# --------------------------------------------------------------------------- #


def test_a_password_hash_is_salted_per_account() -> None:
    """Two accounts with the same password must not share a hash."""
    first = hash_password("the-same-password-twice")
    second = hash_password("the-same-password-twice")

    assert first != second
    assert verify_password("the-same-password-twice", first)
    assert verify_password("the-same-password-twice", second)


def test_a_short_password_is_refused() -> None:
    """Length is the requirement that actually matters."""
    with pytest.raises(ValueError, match=str(MIN_PASSWORD_LENGTH)):
        hash_password("short")


def test_verification_against_a_missing_account_is_false() -> None:
    """An unknown email still runs a verification, so timing does not differ."""
    assert verify_password("anything", None) is False


# --------------------------------------------------------------------------- #
# Token decoding
# --------------------------------------------------------------------------- #


def test_a_tenant_token_decodes_to_its_account_and_tenant(
    sync_db: Session, api_tenant: Tenant
) -> None:
    """The tenant is a claim inside the signature, not something the caller sends."""
    user = make_user(sync_db, role=UserRole.TENANT_USER, tenant_id=api_tenant.id)
    claims = decode_access_token(token_for(user))

    assert claims.scope is PrincipalScope.TENANT
    assert claims.tenant_id == api_tenant.id
    assert claims.user_id == user.id


def test_an_admin_token_carries_no_tenant(sync_db: Session) -> None:
    """An administrator belongs to no tenant."""
    claims = decode_access_token(admin_token())

    assert claims.scope is PrincipalScope.ADMIN
    assert claims.tenant_id is None


def test_a_token_signed_with_another_key_is_refused() -> None:
    """Without the signing key a token cannot be minted."""
    with pytest.raises(AuthenticationError):
        decode_access_token(_forge(_base_claims(), key="a-different-key-entirely-long-enough"))


def test_an_unsigned_token_is_refused() -> None:
    """The classic `alg: none` downgrade must not be accepted.

    The decoder pins the algorithm rather than trusting the token header, so an
    attacker cannot choose how their own token is verified.
    """
    with pytest.raises(AuthenticationError):
        decode_access_token(jwt.encode(_base_claims(), key="", algorithm="none"))


def test_an_expired_token_is_refused() -> None:
    """Expiry is enforced, so a leaked credential has a bounded life."""
    past = datetime.now(UTC) - timedelta(hours=2)
    with pytest.raises(AuthenticationError):
        decode_access_token(_forge(_base_claims(iat=past, exp=past + timedelta(minutes=5))))


def test_a_token_for_another_audience_is_refused() -> None:
    """A credential minted for a sibling service is not valid here."""
    with pytest.raises(AuthenticationError):
        decode_access_token(_forge(_base_claims(aud="some-other-service")))


def test_a_token_from_another_issuer_is_refused() -> None:
    """The issuer claim is verified as well as the audience."""
    with pytest.raises(AuthenticationError):
        decode_access_token(_forge(_base_claims(iss="somebody-else")))


def test_an_admin_token_that_also_names_a_tenant_is_refused() -> None:
    """Incoherent claims are rejected rather than resolved by guessing."""
    with pytest.raises(AuthenticationError):
        decode_access_token(_forge(_base_claims(tenant_id=str(uuid.uuid4()))))


def test_a_tenant_token_without_a_tenant_is_refused() -> None:
    """Tenant scope without a tenant is not an identity."""
    with pytest.raises(AuthenticationError):
        decode_access_token(_forge(_base_claims(scope="tenant")))


@pytest.mark.parametrize("bad_scope", ["superuser", "", "TENANT", "root"])
def test_an_unknown_scope_is_refused(bad_scope: str) -> None:
    """Only the two declared scopes exist."""
    with pytest.raises(AuthenticationError):
        decode_access_token(_forge(_base_claims(scope=bad_scope)))


def test_a_token_missing_required_claims_is_refused() -> None:
    """Every claim the decoder relies on is required, not optional."""
    with pytest.raises(AuthenticationError):
        decode_access_token(_forge({"sub": str(uuid.uuid4()), "scope": "admin"}))


def test_minting_rejects_incoherent_arguments() -> None:
    """The issuer refuses to create the tokens the decoder would reject."""
    with pytest.raises(ValueError, match="requires a tenant_id"):
        create_access_token(user_id=uuid.uuid4(), role=UserRole.TENANT_USER)
    with pytest.raises(ValueError, match="must not carry a tenant_id"):
        create_access_token(
            user_id=uuid.uuid4(), role=UserRole.PLATFORM_ADMIN, tenant_id=uuid.uuid4()
        )


# --------------------------------------------------------------------------- #
# Sign-in
# --------------------------------------------------------------------------- #


async def test_signing_in_returns_a_usable_token(api_client: AsyncClient, sync_db: Session) -> None:
    """The happy path: credentials in, token and account out."""
    user = make_user(sync_db, role=UserRole.PLATFORM_ADMIN)

    response = await api_client.post(
        "/api/v1/auth/login", json={"email": user.email, "password": TEST_PASSWORD}
    )

    assert response.status_code == 200
    body = response.json()
    assert body["token_type"] == "bearer"
    assert body["user"]["email"] == user.email
    assert body["user"]["role"] == "PLATFORM_ADMIN"

    me = await api_client.get("/api/v1/auth/me", headers=auth(body["access_token"]))
    assert me.status_code == 200
    assert me.json()["id"] == str(user.id)

    sync_db.query(User).filter(User.id == user.id).delete()
    sync_db.commit()


async def test_the_password_hash_is_never_returned(
    api_client: AsyncClient, sync_db: Session
) -> None:
    """The response model has no field for it, so it cannot leak by accident."""
    user = make_user(sync_db, role=UserRole.PLATFORM_ADMIN)

    response = await api_client.post(
        "/api/v1/auth/login", json={"email": user.email, "password": TEST_PASSWORD}
    )

    assert "password_hash" not in response.text
    assert user.password_hash not in response.text

    sync_db.query(User).filter(User.id == user.id).delete()
    sync_db.commit()


async def test_signing_in_is_case_insensitive(api_client: AsyncClient, sync_db: Session) -> None:
    """An address typed in capitals still matches the stored account."""
    user = make_user(sync_db, role=UserRole.PLATFORM_ADMIN)

    response = await api_client.post(
        "/api/v1/auth/login",
        json={"email": user.email.upper(), "password": TEST_PASSWORD},
    )

    assert response.status_code == 200

    sync_db.query(User).filter(User.id == user.id).delete()
    sync_db.commit()


async def test_a_wrong_password_and_an_unknown_account_are_indistinguishable(
    api_client: AsyncClient, sync_db: Session
) -> None:
    """Otherwise the login form becomes a way to enumerate registered addresses."""
    user = make_user(sync_db, role=UserRole.PLATFORM_ADMIN)

    wrong = await api_client.post(
        "/api/v1/auth/login", json={"email": user.email, "password": "not-the-password"}
    )
    unknown = await api_client.post(
        "/api/v1/auth/login",
        json={"email": "nobody@netshield.test", "password": "not-the-password"},
    )

    assert wrong.status_code == unknown.status_code == 401
    assert wrong.json()["detail"] == unknown.json()["detail"]

    sync_db.query(User).filter(User.id == user.id).delete()
    sync_db.commit()


async def test_a_disabled_account_cannot_sign_in(api_client: AsyncClient, sync_db: Session) -> None:
    """Deactivating an account takes effect at the next sign-in attempt."""
    user = make_user(sync_db, role=UserRole.PLATFORM_ADMIN, is_active=False)

    response = await api_client.post(
        "/api/v1/auth/login", json={"email": user.email, "password": TEST_PASSWORD}
    )

    assert response.status_code == 401

    sync_db.query(User).filter(User.id == user.id).delete()
    sync_db.commit()


async def test_disabling_an_account_revokes_its_existing_token(
    api_client: AsyncClient, sync_db: Session
) -> None:
    """A live token stops working the moment the account is disabled.

    The account is re-read on every request rather than trusted from the token,
    which is what makes deactivation immediate instead of waiting for expiry.
    """
    user = make_user(sync_db, role=UserRole.PLATFORM_ADMIN)
    token = token_for(user)

    assert (await api_client.get("/api/v1/auth/me", headers=auth(token))).status_code == 200

    user.is_active = False
    sync_db.commit()

    assert (await api_client.get("/api/v1/auth/me", headers=auth(token))).status_code == 401

    sync_db.query(User).filter(User.id == user.id).delete()
    sync_db.commit()


async def test_a_token_naming_a_deleted_account_is_refused(
    api_client: AsyncClient, sync_db: Session
) -> None:
    """Deleting the account invalidates its credentials at once."""
    user = make_user(sync_db, role=UserRole.PLATFORM_ADMIN)
    token = token_for(user)

    sync_db.query(User).filter(User.id == user.id).delete()
    sync_db.commit()

    response = await api_client.get("/api/v1/auth/me", headers=auth(token))
    assert response.status_code == 401


async def test_changing_a_password_requires_the_current_one(
    api_client: AsyncClient, sync_db: Session
) -> None:
    """A stolen token alone cannot be used to take over the account."""
    user = make_user(sync_db, role=UserRole.PLATFORM_ADMIN)
    token = token_for(user)

    refused = await api_client.post(
        "/api/v1/auth/password",
        headers=auth(token),
        json={"current_password": "wrong", "new_password": "a-brand-new-password"},
    )
    assert refused.status_code == 401

    accepted = await api_client.post(
        "/api/v1/auth/password",
        headers=auth(token),
        json={"current_password": TEST_PASSWORD, "new_password": "a-brand-new-password"},
    )
    assert accepted.status_code == 204

    signed_in = await api_client.post(
        "/api/v1/auth/login",
        json={"email": user.email, "password": "a-brand-new-password"},
    )
    assert signed_in.status_code == 200

    sync_db.query(User).filter(User.id == user.id).delete()
    sync_db.commit()


# --------------------------------------------------------------------------- #
# The API surface
# --------------------------------------------------------------------------- #


async def test_an_unauthenticated_request_is_rejected(api_client: AsyncClient) -> None:
    """No token, no access, and the response says how to authenticate."""
    response = await api_client.get("/api/v1/tenants")

    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == "Bearer"


@pytest.mark.parametrize(
    "header",
    [
        {"Authorization": "Bearer "},
        {"Authorization": "Bearer not-a-jwt"},
        {"Authorization": "Basic dXNlcjpwYXNz"},
        {"Authorization": "eyJhbGciOiJIUzI1NiJ9.e30.x"},
    ],
)
async def test_malformed_credentials_are_rejected(
    api_client: AsyncClient, header: dict[str, str]
) -> None:
    """Anything that is not a valid bearer token gets the same 401."""
    response = await api_client.get("/api/v1/tenants", headers=header)

    assert response.status_code == 401


async def test_a_tenant_token_cannot_reach_tenant_administration(
    api_client: AsyncClient, api_tenant: Tenant
) -> None:
    """Listing tenants would expose the customer base, so it is admin only."""
    response = await api_client.get("/api/v1/tenants", headers=auth(tenant_token(api_tenant.id)))

    assert response.status_code == 403


async def test_health_and_login_stay_anonymous(api_client: AsyncClient) -> None:
    """Orchestrator probes and the sign-in form must not need a credential."""
    assert (await api_client.get("/api/v1/health/live")).status_code == 200

    # Wrong credentials, but reached without one: a 401 rather than a redirect.
    login = await api_client.post(
        "/api/v1/auth/login", json={"email": "nobody@netshield.test", "password": "x"}
    )
    assert login.status_code == 401
