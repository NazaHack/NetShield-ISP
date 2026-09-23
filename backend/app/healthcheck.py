"""Container health probe.

Executed by the Docker ``HEALTHCHECK`` for the API container. Uses only the
standard library so the probe keeps working even if an application dependency
is the thing that is broken.

Exit codes: ``0`` healthy, ``1`` unhealthy.
"""

from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request

PROBE_URL = "http://127.0.0.1:8000/health/live"
TIMEOUT_SECONDS = 5.0


def main() -> int:
    """Probe the local liveness endpoint and translate it into an exit code."""
    # Scheme-check suppressed below: PROBE_URL is a module-level constant pointing
    # at the loopback interface, and no caller-supplied data reaches this request.
    request = urllib.request.Request(  # noqa: S310  # nosec B310
        PROBE_URL,
        method="GET",
        headers={"User-Agent": "netshield-healthcheck/1.0"},
    )
    try:
        with urllib.request.urlopen(  # noqa: S310  # nosec B310
            request, timeout=TIMEOUT_SECONDS
        ) as response:
            if response.status != 200:
                print(f"unhealthy: HTTP {response.status}", file=sys.stderr)
                return 1
            payload = json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError) as exc:
        print(f"unhealthy: {exc}", file=sys.stderr)
        return 1

    if payload.get("status") != "up":
        print(f"unhealthy: status={payload.get('status')!r}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
