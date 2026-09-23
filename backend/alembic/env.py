"""Alembic migration environment.

Migrations run against the synchronous psycopg driver. Schema changes are a
sequential, transactional operation, so the async engine would add complexity
with no benefit.

The URL is pulled from the validated application settings rather than from
``alembic.ini``, which keeps database credentials out of version control and
guarantees migrations target the same database the application uses.
"""

from __future__ import annotations

from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

# Importing ``app.models`` registers every table on ``Base.metadata``, which is
# what makes `alembic revision --autogenerate` able to see them.
import app.models  # noqa: F401
from app.core.config import settings
from app.db.base import Base

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Injected at runtime; never written back to alembic.ini.
config.set_main_option("sqlalchemy.url", settings.sync_database_uri)

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """Emit SQL to stdout without connecting to a database.

    Used to hand a reviewable DDL script to a DBA before a production change.
    """
    context.configure(
        url=settings.sync_database_uri,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
        compare_server_default=True,
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Apply migrations against a live database connection."""
    configuration = config.get_section(config.config_ini_section, {})
    configuration["sqlalchemy.url"] = settings.sync_database_uri

    connectable = engine_from_config(
        configuration,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
            compare_server_default=True,
            # Every NetShield-ISP table lives in the default schema; multi-tenancy
            # is row-level via tenant_id, not schema-per-tenant.
            include_schemas=False,
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
