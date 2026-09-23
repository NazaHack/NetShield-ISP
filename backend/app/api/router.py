"""Aggregate API router.

Every versioned router is mounted here so that ``main`` has a single include
point and route ownership stays visible in one file.

Authorisation is declared per router rather than globally: health probes are
deliberately anonymous, tenant management requires an administrator, and
everything else is tenant-scoped through ``resolve_tenant_scope``. Making that
explicit here means a new router cannot be added without someone deciding which
of the three it is.
"""

from __future__ import annotations

from fastapi import APIRouter

from app.api.v1.endpoints import audit, auth, health, scans, targets, tenants, users

api_router = APIRouter()

# Unauthenticated: orchestrator probes and sign-in.
api_router.include_router(health.router)
api_router.include_router(auth.router)

# Administrator only.
api_router.include_router(tenants.router)
api_router.include_router(users.admin_users_router)
api_router.include_router(audit.router)

# Tenant-scoped.
api_router.include_router(targets.router)
api_router.include_router(scans.scans_router)
api_router.include_router(scans.tenant_scans_router)
api_router.include_router(users.tenant_users_router)
