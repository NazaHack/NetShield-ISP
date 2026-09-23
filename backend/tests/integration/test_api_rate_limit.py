"""Login rate limiting.

The sign-in endpoint is the only place credentials can be guessed, so it must
refuse a caller who keeps trying. These tests drive the endpoint the way an
attacker would and confirm it stops answering.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models import UserRole
from tests.integration.helpers import TEST_PASSWORD, make_user

pytestmark = pytest.mark.integration


async def _attempt(client: AsyncClient, email: str, password: str) -> int:
    """Make one sign-in attempt and return its status code."""
    response = await client.post("/api/v1/auth/login", json={"email": email, "password": password})
    return response.status_code


async def test_repeated_failures_are_eventually_refused(api_client: AsyncClient) -> None:
    """After the configured number of failures the endpoint returns 429."""
    email = f"nobody-{uuid.uuid4().hex[:8]}@netshield.test"

    # The limit's worth of failures are all answered 401.
    for _ in range(settings.login_max_attempts):
        assert await _attempt(api_client, email, "wrong") == 401

    # The next one is refused outright.
    response = await api_client.post(
        "/api/v1/auth/login", json={"email": email, "password": "wrong"}
    )
    assert response.status_code == 429
    assert response.headers.get("Retry-After")


async def test_a_correct_password_still_works_below_the_limit(
    api_client: AsyncClient, sync_db: Session
) -> None:
    """A few typos followed by the right password sign in cleanly.

    The limit is not reached, and the successful attempt clears the counters, so
    an operator who fumbles their password is never locked out.
    """
    user = make_user(sync_db, role=UserRole.PLATFORM_ADMIN)

    assert await _attempt(api_client, user.email, "wrong") == 401
    assert await _attempt(api_client, user.email, "wrong") == 401
    assert await _attempt(api_client, user.email, TEST_PASSWORD) == 200

    # The counter was cleared, so further failures start from zero rather than
    # from where the earlier typos left off.
    for _ in range(settings.login_max_attempts - 1):
        assert await _attempt(api_client, user.email, "wrong") == 401
    # Still one attempt short of the limit, so this is 401 rather than 429.
    assert await _attempt(api_client, user.email, "wrong") == 401

    sync_db.query(type(user)).filter_by(id=user.id).delete()
    sync_db.commit()


async def test_the_lockout_hides_a_valid_password_too(
    api_client: AsyncClient, sync_db: Session
) -> None:
    """Once locked out, even the correct password is refused with 429.

    That is the point: an attacker who has exhausted their guesses cannot keep
    going even if the next guess would have been right.
    """
    user = make_user(sync_db, role=UserRole.PLATFORM_ADMIN)

    for _ in range(settings.login_max_attempts):
        assert await _attempt(api_client, user.email, "wrong") == 401

    assert await _attempt(api_client, user.email, TEST_PASSWORD) == 429

    sync_db.query(type(user)).filter_by(id=user.id).delete()
    sync_db.commit()


async def test_the_limit_matches_the_configured_value(api_client: AsyncClient) -> None:
    """Exactly `login_max_attempts` failures are allowed before the block."""
    email = f"count-{uuid.uuid4().hex[:8]}@netshield.test"

    allowed = 0
    for _ in range(settings.login_max_attempts + 5):
        if await _attempt(api_client, email, "wrong") == 401:
            allowed += 1
        else:
            break

    assert allowed == settings.login_max_attempts
