"""Liveness and readiness endpoints.

These are the only unauthenticated endpoints in the platform. They are written
so that a failing probe is diagnostic for an operator without disclosing
infrastructure detail to an anonymous caller: connection strings, hostnames and
driver stack traces are logged, never returned.
"""

from __future__ import annotations

import time
from datetime import UTC, datetime

import redis.asyncio as aioredis
from fastapi import APIRouter, Response, status
from sqlalchemy import text

from app import __version__
from app.core.config import settings
from app.core.logging import get_logger
from app.db.session import AsyncSessionFactory
from app.schemas.health import (
    ComponentStatus,
    DependencyHealth,
    LivenessResponse,
    ReadinessResponse,
)

router = APIRouter(tags=["health"])
logger = get_logger(__name__)

#: Probes are capped so an unhealthy dependency cannot stall the readiness gate.
_PROBE_TIMEOUT_SECONDS = 3.0

#: Generic message returned to callers; the real error only goes to the logs.
_OPAQUE_FAILURE = "dependency probe failed"


async def _probe_postgres() -> DependencyHealth:
    """Execute a trivial round-trip against PostgreSQL."""
    started = time.perf_counter()
    try:
        async with AsyncSessionFactory() as session:
            await session.execute(text("SELECT 1"))
        elapsed_ms = (time.perf_counter() - started) * 1000
        return DependencyHealth(
            name="postgresql", status=ComponentStatus.UP, latency_ms=round(elapsed_ms, 2)
        )
    # A probe classifies any failure as `down`; letting the exception escape
    # would turn a degraded dependency into a 500 on the readiness endpoint.
    except Exception as exc:
        elapsed_ms = (time.perf_counter() - started) * 1000
        logger.error("health.postgres_probe_failed", error=str(exc), exc_info=True)
        return DependencyHealth(
            name="postgresql",
            status=ComponentStatus.DOWN,
            latency_ms=round(elapsed_ms, 2),
            detail=_OPAQUE_FAILURE,
        )


async def _probe_redis() -> DependencyHealth:
    """Ping the Redis instance backing the Celery broker."""
    started = time.perf_counter()
    try:
        client = aioredis.from_url(  # type: ignore[no-untyped-call]
            settings.celery_broker_uri,
            socket_connect_timeout=_PROBE_TIMEOUT_SECONDS,
            socket_timeout=_PROBE_TIMEOUT_SECONDS,
        )
        try:
            await client.ping()
        finally:
            # Always returned to the pool, including when the ping itself fails.
            await client.aclose()

        elapsed_ms = (time.perf_counter() - started) * 1000
        return DependencyHealth(
            name="redis", status=ComponentStatus.UP, latency_ms=round(elapsed_ms, 2)
        )
    # A probe classifies any failure as `down`; letting the exception escape
    # would turn a degraded dependency into a 500 on the readiness endpoint.
    except Exception as exc:
        elapsed_ms = (time.perf_counter() - started) * 1000
        logger.error("health.redis_probe_failed", error=str(exc), exc_info=True)
        return DependencyHealth(
            name="redis",
            status=ComponentStatus.DOWN,
            latency_ms=round(elapsed_ms, 2),
            detail=_OPAQUE_FAILURE,
        )


@router.get(
    "/health/live",
    response_model=LivenessResponse,
    summary="Liveness probe",
    description="Returns 200 while the process is running. Probes no dependencies.",
)
async def liveness() -> LivenessResponse:
    """Report that the process itself is up."""
    return LivenessResponse(
        status=ComponentStatus.UP,
        service=settings.service_name,
        version=__version__,
        timestamp=datetime.now(UTC),
    )


@router.get(
    "/health/ready",
    response_model=ReadinessResponse,
    summary="Readiness probe",
    description=(
        "Probes PostgreSQL and Redis. Returns 503 when any dependency is "
        "unreachable, so orchestrators stop routing traffic to this instance."
    ),
    responses={status.HTTP_503_SERVICE_UNAVAILABLE: {"model": ReadinessResponse}},
)
async def readiness(response: Response) -> ReadinessResponse:
    """Report whether every dependency required to serve traffic is reachable."""
    dependencies = [await _probe_postgres(), await _probe_redis()]
    healthy = all(dep.status is ComponentStatus.UP for dep in dependencies)

    if not healthy:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE

    return ReadinessResponse(
        status=ComponentStatus.UP if healthy else ComponentStatus.DOWN,
        service=settings.service_name,
        version=__version__,
        environment=settings.environment.value,
        timestamp=datetime.now(UTC),
        dependencies=dependencies,
    )
