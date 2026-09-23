"""Tests for the structured logging pipeline.

These exercise the processor chain end to end. A misconfigured processor only
fails when a record actually flows through it, and a filtering logger silences
calls below the configured level, so the suite must emit at the level the
application really uses.
"""

from __future__ import annotations

import json
from collections.abc import Iterator

import pytest

from app.core.logging import (
    bind_log_context,
    clear_log_context,
    configure_logging,
    get_logger,
)


@pytest.fixture(autouse=True)
def _json_logging(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Force JSON rendering at INFO, independent of the ambient environment.

    These tests parse the rendered output, so they must not inherit whatever
    `LOG_FORMAT` the surrounding container or shell happens to set. Overriding
    the settings object rather than the environment avoids depending on the
    order in which the cached settings singleton was built.
    """
    from app.core.config import settings

    # Patched by dotted path: `settings` is imported into `app.core.logging`
    # rather than defined there, so it is not a public attribute of that module.
    monkeypatch.setattr(
        "app.core.logging.settings",
        settings.model_copy(update={"log_format": "json", "log_level": "INFO"}),
    )
    clear_log_context()
    yield
    clear_log_context()


def _emit_and_capture(capsys: pytest.CaptureFixture[str], **fields: object) -> dict[str, object]:
    """Emit one INFO record and return it decoded."""
    configure_logging()
    get_logger("tests.logging").info("test.event", **fields)
    captured = capsys.readouterr().out.strip().splitlines()
    assert captured, "no log line was emitted"
    record: dict[str, object] = json.loads(captured[-1])
    return record


def test_info_records_reach_the_renderer(capsys: pytest.CaptureFixture[str]) -> None:
    """An INFO call produces a rendered record rather than being filtered away."""
    record = _emit_and_capture(capsys, detail="value")

    assert record["event"] == "test.event"
    assert record["level"] == "info"
    assert record["detail"] == "value"


def test_logger_name_is_bound(capsys: pytest.CaptureFixture[str]) -> None:
    """The namespace is carried explicitly, without relying on a stdlib logger."""
    record = _emit_and_capture(capsys)

    assert record["logger"] == "tests.logging"


def test_timestamp_is_utc_iso(capsys: pytest.CaptureFixture[str]) -> None:
    """Records carry a UTC ISO-8601 timestamp, never a naive local one."""
    record = _emit_and_capture(capsys)

    assert isinstance(record["timestamp"], str)
    assert record["timestamp"].endswith("Z")


def test_sensitive_fields_are_redacted(capsys: pytest.CaptureFixture[str]) -> None:
    """Credentials must never be serialised, whatever the caller passes."""
    record = _emit_and_capture(
        capsys,
        password="hunter2",
        access_token="secret-token",
        redis_password="redis-secret",
        safe_field="visible",
    )

    assert record["password"] == "***redacted***"
    assert record["access_token"] == "***redacted***"
    assert record["redis_password"] == "***redacted***"
    assert record["safe_field"] == "visible"


def test_bound_context_appears_on_records(capsys: pytest.CaptureFixture[str]) -> None:
    """Tenant and request identifiers flow from the ambient context."""
    bind_log_context(tenant_id="tenant-1", request_id="request-1")
    record = _emit_and_capture(capsys)

    assert record["tenant_id"] == "tenant-1"
    assert record["request_id"] == "request-1"


def test_cleared_context_does_not_leak(capsys: pytest.CaptureFixture[str]) -> None:
    """Clearing the context prevents one caller's identifiers reaching the next."""
    bind_log_context(tenant_id="tenant-1")
    clear_log_context()
    record = _emit_and_capture(capsys)

    assert "tenant_id" not in record
