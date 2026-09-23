"""Tests for the liveness endpoint and the security response headers.

The readiness probe is exercised separately as an integration test, because it
requires a live PostgreSQL and Redis.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import create_app


def test_liveness_reports_up() -> None:
    """The liveness probe answers without touching any dependency."""
    with TestClient(create_app()) as client:
        response = client.get("/health/live")

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "up"
    assert payload["service"]
    assert payload["version"]


def test_security_headers_are_applied() -> None:
    """Every response carries the OWASP baseline headers."""
    with TestClient(create_app()) as client:
        response = client.get("/health/live")

    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]


def test_request_id_is_echoed_back() -> None:
    """A caller-supplied correlation id is sanitised and returned."""
    with TestClient(create_app()) as client:
        response = client.get("/health/live", headers={"X-Request-ID": "abc-123"})

    assert response.headers["X-Request-ID"] == "abc-123"


def test_hostile_request_id_is_replaced() -> None:
    """A correlation id containing control characters is discarded."""
    with TestClient(create_app()) as client:
        response = client.get("/health/live", headers={"X-Request-ID": "bad<id>value"})

    assert response.headers["X-Request-ID"] == "badidvalue"


def test_unknown_route_returns_uniform_error_envelope() -> None:
    """404s use the platform error envelope and include the request id."""
    with TestClient(create_app()) as client:
        response = client.get("/does-not-exist")

    assert response.status_code == 404
    payload = response.json()
    assert "detail" in payload
    assert payload["request_id"]
