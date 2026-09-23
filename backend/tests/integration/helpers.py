"""Helpers shared by the API integration tests.

Kept out of ``conftest.py`` so that test modules can import them by absolute
path, which is what the project's import rules require.

Tokens now name a real account, so these helpers create one. A tenant member is
removed by the cascade when its tenant is deleted; the administrator is a single
well-known row reused across the suite and cleaned up at the end of the session.
"""

from __future__ import annotations

import uuid
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.passwords import hash_password
from app.core.security import create_access_token
from app.db.session import SyncSessionFactory
from app.models import User, UserRole

#: Password given to every account these tests create.
TEST_PASSWORD = "integration-test-password"

#: The single administrator account the suite reuses.
INTEGRATION_ADMIN_EMAIL = "integration-admin@netshield.test"


def make_user(
    session: Session,
    *,
    role: UserRole,
    tenant_id: uuid.UUID | None = None,
    email: str | None = None,
    is_active: bool = True,
) -> User:
    """Create and commit an account for a test to authenticate as."""
    user = User(
        email=email or f"{uuid.uuid4().hex[:12]}@netshield.test",
        full_name="Integration Test User",
        password_hash=hash_password(TEST_PASSWORD),
        role=role,
        tenant_id=tenant_id,
        is_active=is_active,
    )
    session.add(user)
    session.commit()
    session.refresh(user)
    return user


def token_for(user: User, *, minutes: int = 30) -> str:
    """Mint a bearer token naming an existing account."""
    return create_access_token(
        user_id=user.id,
        role=user.role,
        tenant_id=user.tenant_id,
        expires_in=timedelta(minutes=minutes),
    )


def admin_token(*, minutes: int = 30) -> str:
    """Return a token for the suite's platform administrator, creating it once."""
    with SyncSessionFactory() as session:
        user = session.scalar(select(User).where(User.email == INTEGRATION_ADMIN_EMAIL))
        if user is None:
            user = make_user(session, role=UserRole.PLATFORM_ADMIN, email=INTEGRATION_ADMIN_EMAIL)
        return token_for(user, minutes=minutes)


def tenant_token(tenant_id: uuid.UUID, *, minutes: int = 30) -> str:
    """Create a member of the tenant and return a token for them.

    The account is removed by the cascade when the tenant fixture tears down.
    """
    with SyncSessionFactory() as session:
        user = make_user(session, role=UserRole.TENANT_USER, tenant_id=tenant_id)
        return token_for(user, minutes=minutes)


def auth(token: str) -> dict[str, str]:
    """Build the Authorization header for a token."""
    return {"Authorization": f"Bearer {token}"}
