#!/usr/bin/env python3
"""Seed the database with a development tenant and two network ranges.

Run from the backend directory, or inside the API container:

    python seed.py

The script is idempotent: re-running it leaves the database unchanged rather
than raising on the unique constraints. That matters because a seed is typically
wired into a container start-up or a CI job, where "already applied" has to be a
success rather than a crash.

It refuses to run against a production environment. Seed data is fictional and
has no place in a real tenant list.
"""

from __future__ import annotations

import asyncio
import sys
import uuid
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.logging import configure_logging, get_logger
from app.core.passwords import hash_password
from app.db.session import AsyncSessionFactory, dispose_engines
from app.models import NetworkTarget, Tenant, User, UserRole

logger = get_logger(__name__)


@dataclass(frozen=True, slots=True)
class TargetSeed:
    """One network range to create for the demonstration tenant."""

    label: str
    ip_address_or_cidr: str
    description: str


#: The demonstration tenant. `code_name` is the idempotency key.
TENANT_CODE_NAME = "acme-isp"
TENANT_NAME = "Acme ISP (development)"

#: Development sign-ins. These credentials are published in the repository and
#: are useless anywhere the seed refuses to run, which is any environment marked
#: production. They exist so a fresh checkout is usable within one command.
ADMIN_EMAIL = "admin@netshield.local"
ADMIN_NAME = "Platform Administrator"
TENANT_USER_EMAIL = "operator@acme-isp.local"
TENANT_USER_NAME = "Acme Network Operator"
# A hardcoded credential, deliberately. This whole module refuses to run when
# ENVIRONMENT is production, and the value is published in the repository, so
# it grants nothing an attacker could not already read.
DEVELOPMENT_PASSWORD = "netshield-dev-2026"  # noqa: S105

#: Two ranges that exercise both halves of the target model: a small management
#: network and a larger customer-facing block. Both are documentation or private
#: ranges, so a seeded environment can never scan somebody else's addresses.
TARGET_SEEDS: tuple[TargetSeed, ...] = (
    TargetSeed(
        label="Management network",
        ip_address_or_cidr="10.10.0.0/24",
        description=(
            "RFC 1918 range hosting routers, switches and the NOC jump hosts. "
            "Expected to expose SSH and SNMP only."
        ),
    ),
    TargetSeed(
        label="CGNAT customer pool",
        ip_address_or_cidr="100.64.0.0/22",
        description=(
            "RFC 6598 shared address space handed out to residential customers. "
            "Audited for exposed management interfaces on customer equipment."
        ),
    ),
)


async def _get_or_create_tenant(session: AsyncSession) -> tuple[Tenant, bool]:
    """Return the demonstration tenant, creating it when absent.

    Returns:
        The tenant and whether this call created it.
    """
    existing = await session.scalar(select(Tenant).where(Tenant.code_name == TENANT_CODE_NAME))
    if existing is not None:
        return existing, False

    tenant = Tenant(name=TENANT_NAME, code_name=TENANT_CODE_NAME)
    session.add(tenant)
    # Flush rather than commit: the targets created next need the generated
    # primary key, and the whole seed should still succeed or fail as one unit.
    await session.flush()
    return tenant, True


async def _create_missing_targets(session: AsyncSession, tenant: Tenant) -> int:
    """Create any seed range the tenant does not already own.

    Returns:
        How many ranges were created.
    """
    existing_ranges = set(
        (
            await session.scalars(
                select(NetworkTarget.ip_address_or_cidr).where(NetworkTarget.tenant_id == tenant.id)
            )
        ).all()
    )

    created = 0
    for seed in TARGET_SEEDS:
        if seed.ip_address_or_cidr in existing_ranges:
            continue
        session.add(
            NetworkTarget(
                tenant_id=tenant.id,
                label=seed.label,
                ip_address_or_cidr=seed.ip_address_or_cidr,
                description=seed.description,
            )
        )
        created += 1
    return created


async def _get_or_create_user(
    session: AsyncSession,
    *,
    email: str,
    full_name: str,
    role: UserRole,
    tenant_id: uuid.UUID | None,
) -> bool:
    """Create a development sign-in when it is absent.

    Returns:
        Whether this call created the account.
    """
    existing = await session.scalar(select(User).where(User.email == email))
    if existing is not None:
        return False

    session.add(
        User(
            email=email,
            full_name=full_name,
            password_hash=hash_password(DEVELOPMENT_PASSWORD),
            role=role,
            tenant_id=tenant_id,
        )
    )
    return True


async def seed() -> int:
    """Apply the seed data. Returns a process exit code."""
    if settings.is_production:
        logger.error("seed.refused", environment=settings.environment.value)
        print(
            "Refusing to seed a production database. Seed data is fictional.",
            file=sys.stderr,
        )
        return 1

    async with AsyncSessionFactory() as session, session.begin():
        tenant, tenant_created = await _get_or_create_tenant(session)
        targets_created = await _create_missing_targets(session, tenant)

        admin_created = await _get_or_create_user(
            session,
            email=ADMIN_EMAIL,
            full_name=ADMIN_NAME,
            role=UserRole.PLATFORM_ADMIN,
            tenant_id=None,
        )
        operator_created = await _get_or_create_user(
            session,
            email=TENANT_USER_EMAIL,
            full_name=TENANT_USER_NAME,
            role=UserRole.TENANT_USER,
            tenant_id=tenant.id,
        )

    logger.info(
        "seed.applied",
        tenant_code_name=TENANT_CODE_NAME,
        tenant_created=tenant_created,
        targets_created=targets_created,
        admin_created=admin_created,
        operator_created=operator_created,
    )
    print(
        f"tenant {TENANT_CODE_NAME!r}: {'created' if tenant_created else 'already present'}\n"
        f"network targets created: {targets_created} of {len(TARGET_SEEDS)}\n"
        f"\nDevelopment sign-ins (password: {DEVELOPMENT_PASSWORD}):\n"
        f"  platform admin : {ADMIN_EMAIL}\n"
        f"  tenant operator: {TENANT_USER_EMAIL}"
    )
    return 0


async def _main() -> int:
    """Configure logging, run the seed and release the connection pools."""
    configure_logging()
    try:
        return await seed()
    finally:
        await dispose_engines()


if __name__ == "__main__":
    raise SystemExit(asyncio.run(_main()))
