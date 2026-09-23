"""Login rate limiting, backed by Redis.

The sign-in endpoint is the one place an attacker can guess credentials, and
Argon2's cost slows each guess but does not bound how many they may make. This
module bounds them: failed attempts are counted per email and per source IP over
a fixed window, and once a scope reaches the limit its attempts are refused
until the window expires.

Two design choices worth stating:

* **Counts only failures, and a success clears them.** An operator who mistypes
  their password twice and then gets it right is never penalised.
* **Fails open.** If Redis is unreachable the limiter allows the attempt rather
  than locking every operator out of the platform. Redis being down already
  breaks scanning, so the platform is degraded regardless, and an availability
  failure here should not compound into a lockout. The event is logged.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

import redis.asyncio as aioredis
from redis.exceptions import RedisError

from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger(__name__)

#: Prefixes keep the two scopes' keys distinct and easy to recognise in Redis.
_EMAIL_PREFIX: Final[str] = "ratelimit:login:email:"
_IP_PREFIX: Final[str] = "ratelimit:login:ip:"

#: Short socket timeouts so a slow or wedged Redis degrades to "allow" quickly
#: rather than adding latency to every login.
_SOCKET_TIMEOUT_SECONDS: Final[float] = 2.0

_client: aioredis.Redis | None = None


def _redis() -> aioredis.Redis:
    """Return the shared async Redis client, creating it on first use."""
    global _client
    if _client is None:
        _client = aioredis.from_url(  # type: ignore[no-untyped-call]
            settings.redis_ratelimit_uri,
            socket_connect_timeout=_SOCKET_TIMEOUT_SECONDS,
            socket_timeout=_SOCKET_TIMEOUT_SECONDS,
            decode_responses=True,
        )
    return _client


async def close_ratelimit_client() -> None:
    """Release the Redis client. Called during application shutdown."""
    global _client
    if _client is not None:
        await _client.aclose()
        _client = None


def _keys(email: str, ip: str) -> tuple[str, str]:
    """Build the two counter keys for one login attempt."""
    return (f"{_EMAIL_PREFIX}{email.strip().lower()}", f"{_IP_PREFIX}{ip}")


@dataclass(frozen=True, slots=True)
class RateLimitDecision:
    """Whether a login may proceed, and if not, how long to wait."""

    allowed: bool
    retry_after_seconds: int = 0


async def check_login_allowed(*, email: str, ip: str) -> RateLimitDecision:
    """Decide whether a sign-in attempt may proceed.

    Reads the current failure counts without changing them. When either scope is
    at or over the limit, returns a decision carrying the longest remaining
    window so the caller can tell the client when to try again.
    """
    email_key, ip_key = _keys(email, ip)
    limit = settings.login_max_attempts

    try:
        client = _redis()
        async with client.pipeline(transaction=False) as pipe:
            pipe.get(email_key)
            pipe.ttl(email_key)
            pipe.get(ip_key)
            pipe.ttl(ip_key)
            email_count, email_ttl, ip_count, ip_ttl = await pipe.execute()
    except RedisError as exc:
        # Fail open: an availability problem must not become a lockout.
        logger.warning("ratelimit.unavailable", operation="check", error=str(exc))
        return RateLimitDecision(allowed=True)

    retry_after = 0
    if int(email_count or 0) >= limit:
        retry_after = max(retry_after, int(email_ttl or 0))
    if int(ip_count or 0) >= limit:
        retry_after = max(retry_after, int(ip_ttl or 0))

    if retry_after > 0:
        return RateLimitDecision(allowed=False, retry_after_seconds=retry_after)
    return RateLimitDecision(allowed=True)


async def record_failed_login(*, email: str, ip: str) -> None:
    """Count one failed attempt against both scopes.

    Each key is incremented and, on its first increment, given the window as its
    expiry, so the counter clears itself once the window passes with no further
    failures.
    """
    email_key, ip_key = _keys(email, ip)
    window = settings.login_attempt_window_seconds

    try:
        client = _redis()
        for key in (email_key, ip_key):
            count = await client.incr(key)
            if count == 1:
                await client.expire(key, window)
    except RedisError as exc:
        # A failure to record simply means this attempt is not counted.
        logger.warning("ratelimit.unavailable", operation="record", error=str(exc))


async def reset_login_counters(*, email: str, ip: str) -> None:
    """Clear both scopes after a successful sign-in."""
    email_key, ip_key = _keys(email, ip)
    try:
        await _redis().delete(email_key, ip_key)
    except RedisError as exc:
        logger.warning("ratelimit.unavailable", operation="reset", error=str(exc))
