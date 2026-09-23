# =============================================================================
#  NetShield-ISP — FastAPI API image
#
#  Targets:
#    base         shared runtime + virtualenv with production dependencies
#    development  adds dev tooling, runs Uvicorn with hot reload
#    production   hardened, read-only-friendly, multi-worker Uvicorn
#
#  This image deliberately does NOT contain Nmap. The API never executes
#  scanners; it only validates input and enqueues Celery jobs. Keeping the
#  scanner out of the internet-facing container removes it as a post-exploitation
#  primitive if the API is ever compromised.
# =============================================================================

ARG PYTHON_VERSION=3.12

# -----------------------------------------------------------------------------
FROM python:${PYTHON_VERSION}-slim-bookworm AS base
# -----------------------------------------------------------------------------

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONFAULTHANDLER=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_ROOT_USER_ACTION=ignore \
    VIRTUAL_ENV=/opt/venv \
    PATH="/opt/venv/bin:${PATH}"

# Runtime libraries only. Build toolchains are installed and removed inside the
# dependency layer so they never reach the final filesystem.
RUN set -eux; \
    apt-get update; \
    apt-get install --no-install-recommends -y \
        libpq5 \
        ca-certificates \
        tini; \
    apt-get clean; \
    rm -rf /var/lib/apt/lists/*

# Unprivileged runtime identity. Fixed UID/GID keeps bind-mounted volumes
# predictable across developer machines and CI.
ARG APP_UID=10001
ARG APP_GID=10001
RUN set -eux; \
    groupadd --gid "${APP_GID}" netshield; \
    useradd --uid "${APP_UID}" --gid "${APP_GID}" --create-home --shell /usr/sbin/nologin netshield

WORKDIR /app

# Dependency layer: cached independently of application source.
# The virtualenv lives at /opt/venv rather than inside /app so that a
# bind-mounted source tree in development cannot shadow it, and so that a
# rebuild after changing requirements.txt takes effect immediately instead
# of being masked by a stale named volume.
COPY --chown=netshield:netshield requirements.txt ./
RUN set -eux; \
    apt-get update; \
    apt-get install --no-install-recommends -y build-essential libpq-dev; \
    python -m venv "${VIRTUAL_ENV}"; \
    "${VIRTUAL_ENV}/bin/pip" install --upgrade pip setuptools wheel; \
    "${VIRTUAL_ENV}/bin/pip" install -r requirements.txt; \
    apt-get purge -y --auto-remove build-essential libpq-dev; \
    apt-get clean; \
    rm -rf /var/lib/apt/lists/*; \
    chown -R netshield:netshield "${VIRTUAL_ENV}"

COPY --chown=netshield:netshield . .

EXPOSE 8000
ENTRYPOINT ["/usr/bin/tini", "--"]

# -----------------------------------------------------------------------------
FROM base AS development
# -----------------------------------------------------------------------------

ENV ENVIRONMENT=development

# Development tooling writes caches next to the sources by default. The source
# tree is a bind mount owned by the host user, so the container user cannot
# write to it; redirect every cache to a writable path instead.
ENV RUFF_CACHE_DIR=/tmp/netshield-cache/ruff \
    MYPY_CACHE_DIR=/tmp/netshield-cache/mypy \
    PYTEST_ADDOPTS="-o cache_dir=/tmp/netshield-cache/pytest"

COPY --chown=netshield:netshield requirements-dev.txt ./
RUN set -eux; \
    "${VIRTUAL_ENV}/bin/pip" install -r requirements-dev.txt; \
    chown -R netshield:netshield "${VIRTUAL_ENV}"

USER netshield

# `--reload-dir app` prevents the reloader from watching the virtualenv.
CMD ["uvicorn", "app.main:app", \
     "--host", "0.0.0.0", \
     "--port", "8000", \
     "--reload", \
     "--reload-dir", "app", \
     "--log-config", "app/core/uvicorn_logging.json"]

# -----------------------------------------------------------------------------
FROM base AS production
# -----------------------------------------------------------------------------

ENV ENVIRONMENT=production \
    UVICORN_WORKERS=4

USER netshield

# Uvicorn's own process manager: no root, no extra supervisor in the container.
CMD ["sh", "-c", "exec uvicorn app.main:app \
     --host 0.0.0.0 \
     --port 8000 \
     --workers ${UVICORN_WORKERS} \
     --proxy-headers \
     --forwarded-allow-ips '*' \
     --no-server-header \
     --log-config app/core/uvicorn_logging.json"]
