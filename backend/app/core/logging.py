"""Structured logging.

Two properties matter for a multi-tenant auditing platform:

1. Every log line must be attributable to a tenant and a request, so that an
   incident can be reconstructed without cross-tenant guesswork.
2. Secrets must never be serialised. Settings hold credentials in ``SecretStr``
   and this module never logs the settings object itself.

``structlog`` context variables carry ``tenant_id``/``request_id`` across await
boundaries and Celery task bodies without threading them through every call.
"""

from __future__ import annotations

import logging
import sys
from collections.abc import MutableMapping
from typing import Any, cast

import structlog
from structlog.contextvars import bind_contextvars, clear_contextvars
from structlog.types import FilteringBoundLogger, Processor

from app.core.config import settings

#: Keys that are redacted if they ever reach a log event.
_SENSITIVE_KEYS: frozenset[str] = frozenset(
    {
        "password",
        "secret",
        "secret_key",
        "token",
        "access_token",
        "refresh_token",
        "authorization",
        "api_key",
        "postgres_password",
        "redis_password",
    }
)

_REDACTED = "***redacted***"


def _redact_sensitive(
    _logger: Any, _method_name: str, event_dict: MutableMapping[str, Any]
) -> MutableMapping[str, Any]:
    """Replace the value of any sensitive-looking key with a redaction marker."""
    for key in list(event_dict):
        if key.lower() in _SENSITIVE_KEYS:
            event_dict[key] = _REDACTED
    return event_dict


def _build_processor_chain() -> list[Processor]:
    """Assemble the shared structlog processor chain."""
    return [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        # `structlog.stdlib.add_logger_name` is deliberately absent: it reads
        # `logger.name`, which only exists on a stdlib logger. This process uses
        # `PrintLoggerFactory` to avoid a stdlib round-trip per line, so the
        # logger name is bound explicitly in `get_logger` instead.
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.UnicodeDecoder(),
        _redact_sensitive,
    ]


def configure_logging() -> None:
    """Install the structlog + stdlib logging configuration for this process.

    Safe to call more than once; later calls replace the previous configuration.
    """
    level = getattr(logging, settings.log_level)

    shared_processors = _build_processor_chain()

    renderer: Processor = (
        structlog.processors.JSONRenderer()
        if settings.log_format == "json"
        else structlog.dev.ConsoleRenderer(colors=sys.stderr.isatty())
    )

    structlog.configure(
        processors=[
            *shared_processors,
            structlog.processors.format_exc_info,
            renderer,
        ],
        wrapper_class=structlog.make_filtering_bound_logger(level),
        logger_factory=structlog.PrintLoggerFactory(file=sys.stdout),
        cache_logger_on_first_use=True,
    )

    # Route stdlib loggers (uvicorn, sqlalchemy, celery) through the same sink.
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=level,
        force=True,
    )
    for noisy in ("uvicorn.access", "uvicorn.error", "sqlalchemy.engine", "celery"):
        logging.getLogger(noisy).handlers.clear()
        logging.getLogger(noisy).propagate = True


def get_logger(name: str | None = None) -> FilteringBoundLogger:
    """Return a bound logger carrying its namespace under the ``logger`` key.

    Args:
        name: Logger name, conventionally the importing module's ``__name__``.
    """
    return cast(
        "FilteringBoundLogger",
        structlog.get_logger().bind(logger=name or settings.service_name),
    )


def bind_log_context(**values: Any) -> None:
    """Bind values onto the ambient log context for the current task/request.

    Typical use is ``bind_log_context(tenant_id=..., request_id=...)`` at the
    edge of a request or Celery task so that every downstream log line is
    attributable without passing identifiers around.
    """
    bind_contextvars(**values)


def clear_log_context() -> None:
    """Drop all ambient log context.

    Must be called when a request or task finishes, otherwise a pooled worker
    thread could leak one tenant's identifiers into the next tenant's logs.
    """
    clear_contextvars()
