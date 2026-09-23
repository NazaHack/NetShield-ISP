"""User account persistence.

Users are the one entity whose tenant may legitimately be ``NULL``, so the
functions here take the tenant filter explicitly where it applies rather than
receiving it from a mixin.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import User, UserRole


async def get_user_by_id(session: AsyncSession, *, user_id: uuid.UUID) -> User | None:
    """Return one account, or ``None`` when it does not exist."""
    user: User | None = await session.get(User, user_id)
    return user


async def get_user_by_email(session: AsyncSession, *, email: str) -> User | None:
    """Return one account by sign-in address, or ``None``.

    The address is lowercased here so a login is case-insensitive without
    relying on the caller to normalise first.
    """
    user: User | None = await session.scalar(
        select(User).where(User.email == email.strip().lower())
    )
    return user


async def list_users(
    session: AsyncSession, *, tenant_id: uuid.UUID | None, limit: int, offset: int
) -> tuple[Sequence[User], int]:
    """Return a page of accounts.

    Args:
        session: An open session.
        tenant_id: Restrict to one tenant's members, or ``None`` for every
            account on the platform. Only an administrator reaches the latter.
        limit: Rows per page.
        offset: Rows to skip.
    """
    filters = [] if tenant_id is None else [User.tenant_id == tenant_id]

    total = await session.scalar(select(func.count()).select_from(User).where(*filters)) or 0
    rows = await session.scalars(
        select(User).where(*filters).order_by(User.email).limit(limit).offset(offset)
    )
    return rows.all(), total


async def count_platform_admins(session: AsyncSession) -> int:
    """How many active platform administrators exist.

    Used to refuse the removal of the last one, which would lock every operator
    out of tenant management with no way back in through the API.
    """
    return (
        await session.scalar(
            select(func.count())
            .select_from(User)
            .where(User.role == UserRole.PLATFORM_ADMIN, User.is_active.is_(True))
        )
        or 0
    )


async def create_user(
    session: AsyncSession,
    *,
    email: str,
    full_name: str,
    password_hash: str,
    role: UserRole,
    tenant_id: uuid.UUID | None,
) -> User:
    """Insert an account and return it with its generated identifier."""
    user = User(
        email=email,
        full_name=full_name,
        password_hash=password_hash,
        role=role,
        tenant_id=tenant_id,
    )
    session.add(user)
    await session.flush()
    await session.refresh(user)
    return user


async def record_successful_login(session: AsyncSession, *, user: User) -> None:
    """Stamp the moment an account last signed in."""
    user.last_login_at = datetime.now(UTC)
    await session.flush()


async def delete_user(session: AsyncSession, *, user: User) -> None:
    """Remove an account outright.

    Deactivation is usually preferable, since it keeps the audit trail of who
    ran which scan attributable. This exists for accounts created in error.
    """
    await session.delete(user)
    await session.flush()
