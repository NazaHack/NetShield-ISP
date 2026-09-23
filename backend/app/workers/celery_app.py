"""Celery application.

Configuration decisions worth stating explicitly:

* **JSON only.** ``pickle`` is refused as a serializer in both directions. A
  broker that accepts pickled payloads turns any Redis foothold into remote
  code execution on every worker.
* **Late acknowledgement.** Scans are long-running and idempotent at the job
  level, so a task is acknowledged after completion. A worker killed mid-scan
  returns the job to the queue instead of silently losing it.
* **Prefetch of one.** Port scans have wildly uneven durations; prefetching
  would let one worker sit on queued jobs it cannot start for minutes.
* **Hard and soft time limits.** Every task inherits the configured Nmap
  timeout, so a wedged scan cannot occupy a worker slot indefinitely.
"""

from __future__ import annotations

from typing import Any

from celery import Celery, Task
from celery.signals import setup_logging, task_postrun, task_prerun

from app.core.config import settings
from app.core.logging import bind_log_context, clear_log_context, configure_logging, get_logger

logger = get_logger(__name__)

#: Queue that carries scan execution work.
SCAN_QUEUE = "scans"

#: Queue for everything else (notifications, maintenance, reporting).
DEFAULT_QUEUE = "default"

#: Grace period between the soft and hard time limit, giving a task the chance
#: to terminate its Nmap child process and persist partial results.
_SOFT_LIMIT_GRACE_SECONDS = 60


# Celery ships no type information, so `Task` resolves to `Any` under mypy's
# strict mode. The subclass is intentional and the ignore is scoped to it.
class TenantAwareTask(Task):  # type: ignore[misc]
    """Base class for tasks that operate on a single tenant's data.

    Enforces the platform's central invariant at the queue boundary: a task
    body may not run unless it was given the tenant it belongs to. Without this
    check, a task whose ``tenant_id`` was lost during a refactor would silently
    execute against the whole table.

    Subclasses must be invoked with an explicit ``tenant_id`` keyword argument.
    """

    #: Retry transport-level failures without burying the error.
    autoretry_for = (ConnectionError, TimeoutError)
    retry_backoff = True
    retry_backoff_max = 600
    retry_jitter = True
    max_retries = 3

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        """Validate tenant scoping, then delegate to the task body."""
        tenant_id = kwargs.get("tenant_id")
        if not tenant_id:
            msg = (
                f"Task {self.name!r} inherits TenantAwareTask and must be called "
                "with an explicit 'tenant_id' keyword argument."
            )
            raise ValueError(msg)
        return super().__call__(*args, **kwargs)


#: Modules containing task definitions, imported lazily by Celery when the
#: application is finalised. The list is explicit rather than autodiscovered:
#: autodiscovery runs at import time and would form a circular import with the
#: task modules, and in a security product an explicit registry of everything a
#: worker can be asked to execute is worth the small maintenance cost.
TASK_MODULES: tuple[str, ...] = (
    "app.workers.tasks.system",
    "app.workers.tasks.scanning",
)


def _build_celery_app() -> Celery:
    """Construct and configure the Celery application."""
    app = Celery("netshield", include=TASK_MODULES)

    app.conf.update(
        broker_url=settings.celery_broker_uri,
        result_backend=settings.celery_result_backend_uri,
        # --- Serialization: JSON only, never pickle ---------------------------
        task_serializer="json",
        result_serializer="json",
        accept_content=["json"],
        result_accept_content=["json"],
        # --- Time and timezone -----------------------------------------------
        timezone="UTC",
        enable_utc=True,
        # --- Reliability ------------------------------------------------------
        task_acks_late=True,
        task_reject_on_worker_lost=True,
        task_track_started=True,
        worker_prefetch_multiplier=1,
        broker_connection_retry_on_startup=True,
        result_expires=60 * 60 * 24 * 7,
        # --- Limits -----------------------------------------------------------
        task_time_limit=settings.nmap_scan_timeout_seconds + _SOFT_LIMIT_GRACE_SECONDS,
        task_soft_time_limit=settings.nmap_scan_timeout_seconds,
        # --- Routing ----------------------------------------------------------
        task_default_queue=DEFAULT_QUEUE,
        task_routes={
            "netshield.scans.*": {"queue": SCAN_QUEUE},
            "netshield.system.*": {"queue": DEFAULT_QUEUE},
        },
        # --- Observability ----------------------------------------------------
        worker_send_task_events=True,
        task_send_sent_event=True,
        worker_hijack_root_logger=False,
    )

    return app


celery_app: Celery = _build_celery_app()


@setup_logging.connect  # type: ignore[misc]
def _configure_worker_logging(**_kwargs: Any) -> None:
    """Use the platform's structlog configuration instead of Celery's default."""
    configure_logging()


@task_prerun.connect  # type: ignore[misc]
def _bind_task_context(
    task_id: str | None = None,
    task: Task | None = None,
    kwargs: dict[str, Any] | None = None,
    **_extra: Any,
) -> None:
    """Bind task and tenant identifiers onto the ambient log context."""
    context: dict[str, Any] = {"task_id": task_id, "task_name": getattr(task, "name", None)}
    tenant_id = (kwargs or {}).get("tenant_id")
    if tenant_id:
        context["tenant_id"] = str(tenant_id)
    bind_log_context(**context)


@task_postrun.connect  # type: ignore[misc]
def _clear_task_context(**_kwargs: Any) -> None:
    """Clear the log context so a pooled worker process cannot leak it forward."""
    clear_log_context()
