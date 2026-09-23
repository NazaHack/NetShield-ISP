"""Dispatch the worker health check and print its report.

Run from the API container so the round trip exercises the real path a scan
takes: FastAPI enqueues onto Redis, a Celery worker consumes the job, and the
result returns through the Redis result backend.

    python -m app.diagnostics.worker_ping

Exit codes: ``0`` the worker is ready, ``1`` it is not or did not answer.
"""

from __future__ import annotations

import json
import sys
from typing import Any

from celery.exceptions import CeleryError

from app.workers.celery_app import celery_app

#: How long to wait for a worker to pick up the job and answer.
RESULT_TIMEOUT_SECONDS = 60

#: Task dispatched by this diagnostic.
HEALTH_CHECK_TASK = "netshield.system.health_check"


def main() -> int:
    """Dispatch the health check and render the worker's report."""
    try:
        async_result = celery_app.send_task(HEALTH_CHECK_TASK)
    except (CeleryError, OSError) as exc:
        print(f"could not reach the broker: {exc}", file=sys.stderr)
        return 1

    print(f"dispatched {HEALTH_CHECK_TASK} as {async_result.id}")

    # Any failure here, from a timeout to a task exception, means the same thing
    # to an operator: the worker is not ready.
    try:
        report: dict[str, Any] = async_result.get(timeout=RESULT_TIMEOUT_SECONDS)
    except Exception as exc:
        print(f"no worker answered within {RESULT_TIMEOUT_SECONDS}s: {exc}", file=sys.stderr)
        return 1

    print(json.dumps(report, indent=2))
    return 0 if report.get("status") == "up" else 1


if __name__ == "__main__":
    raise SystemExit(main())
