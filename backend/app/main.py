"""FastAPI application factory and process lifecycle.

The API process is intentionally the least privileged component of the
platform: it validates and authorises input, then hands work to Celery. It has
no scanner installed and no raw-socket capability.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.gzip import GZipMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app import __version__
from app.api.router import api_router
from app.api.v1.endpoints import health as health_endpoints
from app.core.config import settings
from app.core.logging import configure_logging, get_logger
from app.core.middleware import (
    REQUEST_ID_HEADER,
    RequestContextMiddleware,
    SecurityHeadersMiddleware,
)
from app.db.session import dispose_engines

logger = get_logger(__name__)

API_TITLE = "NetShield-ISP API"
API_DESCRIPTION = (
    "Multi-tenant network audit and port scanning platform for Internet "
    "Service Providers. Every resource in this API is scoped to the "
    "authenticated caller's tenant."
)


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    """Configure logging on start-up and release pooled connections on shutdown."""
    configure_logging()
    logger.info(
        "api.startup",
        service=settings.service_name,
        version=__version__,
        environment=settings.environment.value,
    )
    try:
        yield
    finally:
        await dispose_engines()
        logger.info("api.shutdown", service=settings.service_name)


def _register_middleware(app: FastAPI) -> None:
    """Install the middleware stack.

    Starlette executes middleware in reverse registration order, so the entries
    below run outermost-last: security headers wrap every response, and request
    correlation wraps everything including error handling.
    """
    app.add_middleware(GZipMiddleware, minimum_size=1024)

    app.add_middleware(
        CORSMiddleware,
        # Explicit origins only. A wildcard here combined with credentials would
        # let any site drive the API with a victim's session.
        allow_origins=settings.cors_origin_list,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", REQUEST_ID_HEADER],
        expose_headers=[REQUEST_ID_HEADER],
        max_age=600,
    )

    if settings.allowed_host_list != ["*"]:
        app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.allowed_host_list)

    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(RequestContextMiddleware)


def _register_exception_handlers(app: FastAPI) -> None:
    """Install handlers that keep error responses uniform and non-revealing."""

    def _request_id(request: Request) -> str | None:
        return getattr(request.state, "request_id", None)

    @app.exception_handler(RequestValidationError)
    async def _validation_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
        """Return field-level validation errors without echoing raw input.

        The submitted value is dropped from each error entry: it may contain a
        password or a token that would otherwise be reflected back and logged.
        """
        errors: list[dict[str, Any]] = [
            {
                "field": ".".join(str(part) for part in error.get("loc", ())),
                "message": error.get("msg", "invalid value"),
                "type": error.get("type", "validation_error"),
            }
            for error in exc.errors()
        ]
        logger.warning(
            "http.validation_failed",
            path=request.url.path,
            error_count=len(errors),
        )
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={
                "detail": "Request validation failed.",
                "errors": errors,
                "request_id": _request_id(request),
            },
        )

    @app.exception_handler(StarletteHTTPException)
    async def _http_exception_handler(
        request: Request, exc: StarletteHTTPException
    ) -> JSONResponse:
        """Render HTTP exceptions in the platform's uniform error envelope."""
        return JSONResponse(
            status_code=exc.status_code,
            content={"detail": exc.detail, "request_id": _request_id(request)},
            headers=getattr(exc, "headers", None),
        )

    @app.exception_handler(Exception)
    async def _unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        """Log the full failure internally and return an opaque 500 to the caller.

        Stack traces and driver messages routinely contain hostnames, SQL and
        occasionally credentials; none of that crosses the tenant boundary.
        """
        logger.error(
            "http.unhandled_exception",
            path=request.url.path,
            error=str(exc),
            exc_info=True,
        )
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "detail": "Internal server error.",
                "request_id": _request_id(request),
            },
        )


def create_app() -> FastAPI:
    """Build and configure the FastAPI application."""
    configure_logging()

    # Interactive docs describe the full attack surface; they stay off in production.
    docs_enabled = not settings.is_production

    app = FastAPI(
        title=API_TITLE,
        description=API_DESCRIPTION,
        version=__version__,
        lifespan=lifespan,
        docs_url="/docs" if docs_enabled else None,
        redoc_url="/redoc" if docs_enabled else None,
        openapi_url="/openapi.json" if docs_enabled else None,
        swagger_ui_parameters={"persistAuthorization": True},
    )

    _register_middleware(app)
    _register_exception_handlers(app)

    # Versioned business API.
    app.include_router(api_router, prefix=settings.api_v1_prefix)

    # Unversioned probes for orchestrators (Docker, Kubernetes, load balancers).
    # Hidden from the schema so the operation ids stay unique.
    app.include_router(health_endpoints.router, include_in_schema=False)

    return app


app = create_app()
