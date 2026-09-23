"""Fixtures for database-backed tests.

Each test runs inside a transaction that is rolled back afterwards, so the suite
can be pointed at a development database without disturbing seeded data and
without needing to create and drop a database per run.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator, Iterator

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import Session
from sqlalchemy.pool import NullPool

from app.core.config import settings
from app.db.session import SyncSessionFactory, get_async_session, sync_engine
from app.main import create_app
from app.models import Tenant, User
from tests.integration.helpers import INTEGRATION_ADMIN_EMAIL


def _database_is_reachable() -> bool:
    """Probe PostgreSQL synchronously, before any async fixture is set up."""
    try:
        with sync_engine.connect() as connection:
            connection.execute(text("SELECT 1"))
    except (SQLAlchemyError, OSError):
        return False
    return True


@pytest.fixture(scope="session", autouse=True)
def _require_database() -> None:
    """Skip this package when no database is available."""
    if not _database_is_reachable():
        pytest.skip(
            "PostgreSQL is not reachable. Start the stack with `make up`, or run "
            "these tests inside the backend container with `make test`.",
            allow_module_level=True,
        )


@pytest.fixture(autouse=True)
async def _reset_rate_limiter() -> AsyncIterator[None]:
    """Clear login rate-limit counters around every test.

    Two reasons this is needed. The counters live in Redis and would otherwise
    carry between tests: the test client presents a fixed source address, so
    failed-login tests share one IP bucket and would trip the limit for
    unrelated tests. And the limiter caches its Redis client at module level;
    pytest-asyncio gives each test its own event loop, so the cached client must
    be dropped between tests or it ends up bound to a closed loop.
    """
    import redis.asyncio as aioredis

    from app.core import ratelimit

    async def _flush() -> None:
        await ratelimit.close_ratelimit_client()
        client = aioredis.from_url(settings.redis_ratelimit_uri)  # type: ignore[no-untyped-call]
        try:
            await client.flushdb()
        finally:
            await client.aclose()

    await _flush()
    yield
    await _flush()


@pytest.fixture
async def db_engine() -> AsyncIterator[AsyncEngine]:
    """Yield an engine that never reuses a connection across tests.

    The application engine pools connections, and pytest-asyncio gives each test
    its own event loop. A pooled connection created in one loop and handed to the
    next test fails with `MissingGreenlet`, so the test engine uses `NullPool`
    and is disposed per test.
    """
    engine = create_async_engine(settings.async_database_uri, poolclass=NullPool)
    try:
        yield engine
    finally:
        await engine.dispose()


@pytest.fixture
async def db_session(db_engine: AsyncEngine) -> AsyncIterator[AsyncSession]:
    """Yield a session whose writes are discarded when the test ends.

    The session joins an outer transaction owned by this fixture. With
    ``join_transaction_mode="create_savepoint"`` a test may call ``commit()`` and
    observe its own writes, while the outer rollback still removes everything.
    """
    async with db_engine.connect() as connection:
        transaction = await connection.begin()
        session = AsyncSession(
            bind=connection,
            expire_on_commit=False,
            join_transaction_mode="create_savepoint",
        )
        try:
            yield session
        finally:
            await session.close()
            if transaction.is_active:
                await transaction.rollback()


# --------------------------------------------------------------------------- #
# HTTP API fixtures
# --------------------------------------------------------------------------- #


@pytest.fixture
async def api_client(db_engine: AsyncEngine) -> AsyncIterator[AsyncClient]:
    """An HTTP client bound to the application, backed by the test engine.

    The session dependency is overridden so that requests use the per-test
    `NullPool` engine. The application's own pooled engine would hand a
    connection created in one event loop to the next test and fail.
    """
    app = create_app()
    factory = async_sessionmaker(bind=db_engine, expire_on_commit=False, autoflush=False)

    async def _session_override() -> AsyncIterator[AsyncSession]:
        async with factory() as session:
            yield session

    app.dependency_overrides[get_async_session] = _session_override

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://netshield.test") as client:
        yield client

    app.dependency_overrides.clear()


@pytest.fixture
def sync_db() -> Iterator[Session]:
    """A synchronous session for arranging and cleaning up committed test data.

    API endpoints commit, so these tests cannot run inside a rolled-back
    transaction. Rows are created and removed explicitly instead.
    """
    session = SyncSessionFactory()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def api_tenant(sync_db: Session) -> Iterator[Tenant]:
    """A committed tenant, removed with everything it owns when the test ends."""
    record = Tenant(name="API test tenant", code_name=f"api-{uuid.uuid4().hex[:10]}")
    sync_db.add(record)
    sync_db.commit()
    sync_db.refresh(record)

    try:
        yield record
    finally:
        sync_db.rollback()
        sync_db.execute(delete(Tenant).where(Tenant.id == record.id))
        sync_db.commit()


@pytest.fixture
def other_tenant(sync_db: Session) -> Iterator[Tenant]:
    """A second committed tenant, used to prove isolation between them."""
    record = Tenant(name="Other API tenant", code_name=f"other-{uuid.uuid4().hex[:10]}")
    sync_db.add(record)
    sync_db.commit()
    sync_db.refresh(record)

    try:
        yield record
    finally:
        sync_db.rollback()
        sync_db.execute(delete(Tenant).where(Tenant.id == record.id))
        sync_db.commit()


# --------------------------------------------------------------------------- #
# Accounts
# --------------------------------------------------------------------------- #


@pytest.fixture(scope="session", autouse=True)
def _remove_integration_accounts() -> Iterator[None]:
    """Delete the suite's shared administrator account once everything is done."""
    yield
    with SyncSessionFactory() as session:
        session.execute(delete(User).where(User.email == INTEGRATION_ADMIN_EMAIL))
        session.commit()
