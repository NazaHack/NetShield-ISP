"""Shared pytest fixtures.

A complete, valid environment is installed before ``app.core.config`` is ever
imported, so the settings singleton validates against known-good values rather
than whatever happens to be exported on the developer's machine.
"""

from __future__ import annotations

import os
from collections.abc import Iterator

import pytest

#: Minimal environment required for `Settings` to validate.
_TEST_ENVIRONMENT: dict[str, str] = {
    "ENVIRONMENT": "development",
    # INFO rather than WARNING on purpose. `make_filtering_bound_logger` turns
    # calls below the configured level into no-ops that never reach the
    # processor chain, so a WARNING default would leave every INFO-level log
    # path in the application untested.
    "LOG_LEVEL": "INFO",
    "LOG_FORMAT": "json",
    "SECRET_KEY": "test-secret-key-with-more-than-thirty-two-characters",
    "POSTGRES_HOST": "localhost",
    "POSTGRES_PORT": "5432",
    "POSTGRES_USER": "netshield_test",
    "POSTGRES_PASSWORD": "netshield_test_password",
    "POSTGRES_DB": "netshield_test",
    "REDIS_HOST": "localhost",
    "REDIS_PORT": "6379",
    "REDIS_PASSWORD": "netshield_test_redis",
    "CORS_ORIGINS": "http://localhost:3000",
}

for _key, _value in _TEST_ENVIRONMENT.items():
    os.environ.setdefault(_key, _value)


@pytest.fixture
def clean_settings_cache() -> Iterator[None]:
    """Clear the cached settings singleton around a test that mutates the env."""
    from app.core.config import get_settings

    get_settings.cache_clear()
    yield
    get_settings.cache_clear()
