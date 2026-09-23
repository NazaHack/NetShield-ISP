"""Engine and session management.

NetShield-ISP runs two database access paths against the same schema:

* **Async** (``asyncpg``) for the FastAPI request path, where concurrency comes
  from the event loop.
* **Sync** (``psycopg``) for Celery tasks and Alembic, which are synchronous by
  nature. Driving an async engine from a Celery worker would mean one private
  event loop per task and no usable pooling.

Both engines use ``pool_pre_ping`` so that connections killed by a PostgreSQL
restart or an idle-timeout proxy are transparently recycled instead of
surfacing as a failed scan.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterator
from contextlib import contextmanager

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import settings

# -----------------------------------------------------------------------------
# Async stack — FastAPI
# -----------------------------------------------------------------------------

async_engine: AsyncEngine = create_async_engine(
    settings.async_database_uri,
    echo=settings.db_echo_sql,
    pool_size=settings.db_pool_size,
    max_overflow=settings.db_max_overflow,
    pool_recycle=settings.db_pool_recycle_seconds,
    pool_pre_ping=True,
    future=True,
)

AsyncSessionFactory: async_sessionmaker[AsyncSession] = async_sessionmaker(
    bind=async_engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
)

# -----------------------------------------------------------------------------
# Sync stack — Celery workers and Alembic
# -----------------------------------------------------------------------------

sync_engine: Engine = create_engine(
    settings.sync_database_uri,
    echo=settings.db_echo_sql,
    pool_size=settings.db_pool_size,
    max_overflow=settings.db_max_overflow,
    pool_recycle=settings.db_pool_recycle_seconds,
    pool_pre_ping=True,
    future=True,
)

SyncSessionFactory: sessionmaker[Session] = sessionmaker(
    bind=sync_engine,
    expire_on_commit=False,
    autoflush=False,
)


async def get_async_session() -> AsyncIterator[AsyncSession]:
    """FastAPI dependency yielding a transactional async session.

    The session is rolled back on any exception and always closed, so a failing
    request can never leave a half-applied write visible to another tenant's
    subsequent request on the same pooled connection.
    """
    async with AsyncSessionFactory() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


@contextmanager
def session_scope() -> Iterator[Session]:
    """Transactional scope for synchronous callers such as Celery tasks.

    Commits on clean exit, rolls back on exception, and always closes.
    """
    session = SyncSessionFactory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


async def dispose_engines() -> None:
    """Release all pooled connections. Called during application shutdown."""
    await async_engine.dispose()
    sync_engine.dispose()
