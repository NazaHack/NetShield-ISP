"""Application configuration.

Every runtime knob of NetShield-ISP is declared here and sourced from the
environment, so the same image can be promoted from development to production
without a rebuild. Settings are validated once at import time and cached, which
means a malformed environment fails the container start rather than the first
request.
"""

from __future__ import annotations

import ipaddress
from enum import StrEnum
from functools import lru_cache
from typing import Final, Literal

from pydantic import Field, SecretStr, computed_field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

#: Secrets shorter than this are rejected outright; 32 bytes is the floor for
#: HS256 signing material to resist offline brute force.
MIN_SECRET_KEY_LENGTH: Final[int] = 32


class Environment(StrEnum):
    """Deployment environment the process believes it is running in."""

    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"


class Settings(BaseSettings):
    """Validated, immutable view of the process environment."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
        frozen=True,
    )

    # -- Runtime --------------------------------------------------------------
    service_name: str = Field(default="netshield-api")
    environment: Environment = Field(default=Environment.DEVELOPMENT)
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    log_format: Literal["console", "json"] = "console"
    api_v1_prefix: str = Field(default="/api/v1")

    # -- Cryptography ---------------------------------------------------------
    secret_key: SecretStr = Field(...)
    jwt_algorithm: Literal["HS256", "HS512"] = "HS256"
    access_token_expire_minutes: int = Field(default=720, ge=1, le=1440)
    refresh_token_expire_days: int = Field(default=7, ge=1, le=90)

    # -- PostgreSQL -----------------------------------------------------------
    postgres_host: str = Field(default="db")
    postgres_port: int = Field(default=5432, ge=1, le=65535)
    postgres_user: str = Field(default="netshield")
    postgres_password: SecretStr = Field(...)
    postgres_db: str = Field(default="netshield")
    db_pool_size: int = Field(default=10, ge=1, le=100)
    db_max_overflow: int = Field(default=20, ge=0, le=200)
    db_pool_recycle_seconds: int = Field(default=1800, ge=60)
    db_echo_sql: bool = Field(default=False)

    # -- Redis / Celery -------------------------------------------------------
    redis_host: str = Field(default="redis")
    redis_port: int = Field(default=6379, ge=1, le=65535)
    redis_password: SecretStr = Field(...)
    redis_broker_db: int = Field(default=0, ge=0, le=15)
    redis_result_db: int = Field(default=1, ge=0, le=15)
    # A separate logical database so rate-limit keys never collide with Celery's
    # broker or result data.
    redis_ratelimit_db: int = Field(default=2, ge=0, le=15)

    # -- Login rate limiting --------------------------------------------------
    # Failed sign-ins are counted per email and per source IP over a fixed
    # window. Once the count reaches the limit, further attempts for that scope
    # are refused with 429 until the window expires. A successful sign-in clears
    # the counters, so an operator typing their password correctly is never
    # penalised for earlier typos.
    login_max_attempts: int = Field(default=5, ge=1, le=100)
    login_attempt_window_seconds: int = Field(default=900, ge=30, le=86400)

    # -- HTTP surface ---------------------------------------------------------
    # Stored as raw strings because pydantic-settings would otherwise attempt a
    # JSON decode of list-typed fields, which breaks the ergonomic
    # `A,B,C` form used in .env files and Compose.
    cors_origins: str = Field(default="http://localhost:3000")
    allowed_hosts: str = Field(default="*")

    # -- Scanning engine ------------------------------------------------------
    nmap_binary_path: str = Field(default="/usr/bin/nmap")
    nmap_max_targets_per_scan: int = Field(default=4096, ge=1, le=65536)
    nmap_scan_timeout_seconds: int = Field(default=3600, ge=30, le=86400)
    scan_artifact_dir: str = Field(default="/var/lib/netshield/scans")
    scan_allow_private_ranges: bool = Field(default=True)
    scan_denylist_cidrs: str = Field(default="169.254.0.0/16,127.0.0.0/8")
    max_concurrent_scans_per_tenant: int = Field(default=3, ge=1, le=100)

    # -- Validators -----------------------------------------------------------

    @field_validator("secret_key")
    @classmethod
    def _validate_secret_key(cls, value: SecretStr) -> SecretStr:
        """Reject placeholder or short signing keys before they reach production."""
        raw = value.get_secret_value()
        if len(raw) < MIN_SECRET_KEY_LENGTH:
            msg = (
                f"SECRET_KEY must be at least {MIN_SECRET_KEY_LENGTH} characters; "
                f"got {len(raw)}."
            )
            raise ValueError(msg)
        if "CHANGE_ME" in raw.upper():
            msg = "SECRET_KEY still contains the .env.example placeholder value."
            raise ValueError(msg)
        return value

    @field_validator("scan_denylist_cidrs")
    @classmethod
    def _validate_denylist(cls, value: str) -> str:
        """Ensure every denylist entry is a parseable network before start-up."""
        for entry in (item.strip() for item in value.split(",") if item.strip()):
            ipaddress.ip_network(entry, strict=False)
        return value

    @field_validator("api_v1_prefix")
    @classmethod
    def _validate_prefix(cls, value: str) -> str:
        """Normalise the API prefix to a leading-slash, no-trailing-slash form."""
        normalised = "/" + value.strip("/")
        return "" if normalised == "/" else normalised

    # -- Derived values -------------------------------------------------------

    @computed_field  # type: ignore[prop-decorator]
    @property
    def is_production(self) -> bool:
        """True when the process must apply production-grade hardening."""
        return self.environment is Environment.PRODUCTION

    @computed_field  # type: ignore[prop-decorator]
    @property
    def cors_origin_list(self) -> list[str]:
        """CORS origins as a list, parsed from the comma-separated env value."""
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]

    @computed_field  # type: ignore[prop-decorator]
    @property
    def allowed_host_list(self) -> list[str]:
        """Accepted Host header values, parsed from the comma-separated env value."""
        return [host.strip() for host in self.allowed_hosts.split(",") if host.strip()]

    @property
    def scan_denylist_networks(self) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
        """Networks that no tenant may ever scan, as parsed network objects."""
        return tuple(
            ipaddress.ip_network(entry.strip(), strict=False)
            for entry in self.scan_denylist_cidrs.split(",")
            if entry.strip()
        )

    @property
    def async_database_uri(self) -> str:
        """SQLAlchemy DSN for the asyncpg driver, used by the FastAPI process."""
        return (
            f"postgresql+asyncpg://{self.postgres_user}:"
            f"{self.postgres_password.get_secret_value()}@"
            f"{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    @property
    def sync_database_uri(self) -> str:
        """SQLAlchemy DSN for psycopg, used by Celery workers and Alembic.

        Celery tasks are synchronous; driving an async engine from them would
        require a private event loop per task and defeats connection pooling.
        """
        return (
            f"postgresql+psycopg://{self.postgres_user}:"
            f"{self.postgres_password.get_secret_value()}@"
            f"{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    @property
    def celery_broker_uri(self) -> str:
        """Redis DSN used as the Celery broker."""
        return (
            f"redis://:{self.redis_password.get_secret_value()}@"
            f"{self.redis_host}:{self.redis_port}/{self.redis_broker_db}"
        )

    @property
    def celery_result_backend_uri(self) -> str:
        """Redis DSN used as the Celery result backend."""
        return (
            f"redis://:{self.redis_password.get_secret_value()}@"
            f"{self.redis_host}:{self.redis_port}/{self.redis_result_db}"
        )

    @property
    def redis_ratelimit_uri(self) -> str:
        """Redis DSN used for login rate-limit counters."""
        return (
            f"redis://:{self.redis_password.get_secret_value()}@"
            f"{self.redis_host}:{self.redis_port}/{self.redis_ratelimit_db}"
        )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the process-wide settings singleton.

    Cached so that importing modules, FastAPI dependencies and Celery tasks all
    observe exactly one validated configuration object.
    """
    return Settings()


settings: Settings = get_settings()
