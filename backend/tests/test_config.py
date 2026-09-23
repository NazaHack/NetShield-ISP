"""Tests for configuration validation.

These guard the two settings that carry security weight: the JWT signing key
and the scan denylist.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.core.config import Settings


def _base_kwargs(**overrides: str) -> dict[str, str]:
    """Return a complete settings payload with optional field overrides."""
    payload = {
        "secret_key": "a-sufficiently-long-secret-key-for-tests-12345",
        "postgres_password": "database-password",
        "redis_password": "redis-password",
    }
    payload.update(overrides)
    return payload


def test_short_secret_key_is_rejected() -> None:
    """A signing key below the minimum length must fail validation."""
    with pytest.raises(ValidationError, match="at least 32 characters"):
        Settings.model_validate(_base_kwargs(secret_key="too-short"))


def test_placeholder_secret_key_is_rejected() -> None:
    """The .env.example placeholder must never reach a running process."""
    placeholder = "CHANGE_ME_generate_with_secrets_token_urlsafe_64"
    with pytest.raises(ValidationError, match="placeholder"):
        Settings.model_validate(_base_kwargs(secret_key=placeholder))


def test_invalid_denylist_cidr_is_rejected() -> None:
    """A malformed denylist entry must fail at start-up, not at scan time."""
    with pytest.raises(ValidationError):
        Settings.model_validate(_base_kwargs(scan_denylist_cidrs="not-a-network"))


def test_denylist_is_parsed_into_networks() -> None:
    """Denylist entries are exposed as parsed network objects."""
    settings = Settings.model_validate(_base_kwargs(scan_denylist_cidrs="10.0.0.0/8, 127.0.0.0/8"))
    networks = settings.scan_denylist_networks
    assert len(networks) == 2
    assert str(networks[0]) == "10.0.0.0/8"


def test_cors_origins_are_split_on_commas() -> None:
    """Comma-separated origins become a list without JSON decoding."""
    settings = Settings.model_validate(_base_kwargs(cors_origins="http://a.test, http://b.test"))
    assert settings.cors_origin_list == ["http://a.test", "http://b.test"]


def test_database_uris_select_the_right_drivers() -> None:
    """The async path uses asyncpg and the sync path uses psycopg."""
    settings = Settings.model_validate(_base_kwargs())
    assert settings.async_database_uri.startswith("postgresql+asyncpg://")
    assert settings.sync_database_uri.startswith("postgresql+psycopg://")


def test_api_prefix_is_normalised() -> None:
    """Prefixes are stored with a leading slash and no trailing slash."""
    settings = Settings.model_validate(_base_kwargs(api_v1_prefix="api/v1/"))
    assert settings.api_v1_prefix == "/api/v1"


def test_secret_is_not_exposed_in_repr() -> None:
    """Secrets must not leak through logging or debugger output."""
    settings = Settings.model_validate(_base_kwargs())
    assert "a-sufficiently-long-secret-key" not in repr(settings)
