"""HTTP middleware: request correlation and security response headers."""

from __future__ import annotations

import time
import uuid
from collections.abc import Awaitable, Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp

from app.core.config import settings
from app.core.logging import bind_log_context, clear_log_context, get_logger

logger = get_logger(__name__)

#: Header used to accept and propagate a correlation identifier.
REQUEST_ID_HEADER = "X-Request-ID"

#: Maximum accepted length of an inbound request id. Anything longer is replaced
#: rather than echoed, so the header cannot be used to smuggle payloads into logs.
_MAX_REQUEST_ID_LENGTH = 64

_RequestHandler = Callable[[Request], Awaitable[Response]]


def _sanitise_request_id(raw: str | None) -> str:
    """Return a safe correlation id, generating one when the input is unusable.

    Only hyphens and alphanumerics survive, which keeps the value safe to embed
    in structured logs and to echo back in a response header.
    """
    if not raw or len(raw) > _MAX_REQUEST_ID_LENGTH:
        return str(uuid.uuid4())
    cleaned = "".join(char for char in raw if char.isalnum() or char == "-")
    return cleaned or str(uuid.uuid4())


class RequestContextMiddleware(BaseHTTPMiddleware):
    """Assign a correlation id to every request and log its outcome.

    The id is bound to the ambient log context, so any log line emitted while
    handling the request carries it, and cleared afterwards so that a pooled
    worker never leaks one caller's context into the next request.
    """

    async def dispatch(self, request: Request, call_next: _RequestHandler) -> Response:
        """Wrap the downstream handler with correlation and timing."""
        request_id = _sanitise_request_id(request.headers.get(REQUEST_ID_HEADER))
        request.state.request_id = request_id

        clear_log_context()
        bind_log_context(request_id=request_id)

        started = time.perf_counter()
        try:
            response = await call_next(request)
        except Exception:
            duration_ms = (time.perf_counter() - started) * 1000
            logger.exception(
                "http.request_failed",
                method=request.method,
                path=request.url.path,
                duration_ms=round(duration_ms, 2),
            )
            raise
        else:
            duration_ms = (time.perf_counter() - started) * 1000
            logger.info(
                "http.request_completed",
                method=request.method,
                path=request.url.path,
                status_code=response.status_code,
                duration_ms=round(duration_ms, 2),
            )
            response.headers[REQUEST_ID_HEADER] = request_id
            return response
        finally:
            clear_log_context()


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Apply OWASP-recommended response headers to every response.

    The API returns JSON only, so the content security policy is maximally
    restrictive: nothing may be loaded, framed or embedded from an API response.
    Strict-Transport-Security is emitted in production only, because sending it
    over plain HTTP in development would pin developers' browsers to HTTPS.
    """

    #: Interactive documentation routes. Swagger UI and ReDoc pull assets from a
    #: CDN, which the API's `default-src 'none'` policy would block outright.
    _DOCS_PATHS: frozenset[str] = frozenset(
        {"/docs", "/redoc", "/docs/oauth2-redirect", "/openapi.json"}
    )

    #: Policy applied to the documentation routes. Still forbids framing and
    #: form submission, and is never served in production because the docs
    #: routes are disabled there.
    _DOCS_CSP: str = (
        "default-src 'none'; "
        "script-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; "
        "style-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; "
        "img-src 'self' https://fastapi.tiangolo.com data:; "
        "font-src 'self' https://cdn.jsdelivr.net; "
        "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; "
        "form-action 'none'"
    )

    def __init__(self, app: ASGIApp) -> None:
        """Precompute the static header set once per process."""
        super().__init__(app)
        self._headers: dict[str, str] = {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "no-referrer",
            "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
            "Content-Security-Policy": (
                "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; " "form-action 'none'"
            ),
            "Cross-Origin-Opener-Policy": "same-origin",
            "Cross-Origin-Resource-Policy": "same-site",
            "Cache-Control": "no-store",
        }
        if settings.is_production:
            self._headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains; preload"
            )

    async def dispatch(self, request: Request, call_next: _RequestHandler) -> Response:
        """Attach the security headers to the downstream response."""
        response = await call_next(request)
        for header, value in self._headers.items():
            response.headers.setdefault(header, value)

        if not settings.is_production and request.url.path in self._DOCS_PATHS:
            response.headers["Content-Security-Policy"] = self._DOCS_CSP
            response.headers["Cache-Control"] = "no-cache"

        return response
