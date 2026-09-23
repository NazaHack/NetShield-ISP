"""System maintenance and diagnostic tasks.

These tasks are deliberately tenant-agnostic: they report on the worker itself,
not on any customer's data, and therefore do not inherit ``TenantAwareTask``.
"""

from __future__ import annotations

import os
import shutil

# Used exclusively with a fixed argument vector and shell=False; see _probe_nmap.
import subprocess  # nosec B404
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final

from sqlalchemy import text

from app.core.config import settings
from app.core.logging import get_logger
from app.db.session import session_scope
from app.workers.celery_app import celery_app

logger = get_logger(__name__)

#: Upper bound on the `nmap --version` probe. A scanner that cannot answer in
#: this window is treated as unavailable.
_VERSION_PROBE_TIMEOUT_SECONDS = 10

#: Upper bound on the loopback SYN scan used to verify raw-socket access.
_SCAN_PROBE_TIMEOUT_SECONDS = 20

#: Linux capability bit numbers. Raw-socket scanning (-sS, -sU, -O) needs
#: CAP_NET_RAW. CAP_NET_BIND_SERVICE allows low source ports such as
#: `--source-port 53`; it is reported for diagnostics but is not required.
_CAP_NET_BIND_SERVICE_BIT: Final[int] = 10
_CAP_NET_RAW_BIT: Final[int] = 13

#: Extended attribute that carries a binary's file capabilities.
_FILE_CAPABILITY_XATTR: Final[str] = "security.capability"

#: Where the kernel exposes this process's capability sets.
_PROC_STATUS_PATH: Final[Path] = Path("/proc/self/status")


def _read_proc_status() -> dict[str, str]:
    """Parse ``/proc/self/status`` into a field/value mapping.

    Returns an empty mapping on a kernel or platform that does not expose it,
    so callers degrade to "unknown" rather than crashing.
    """
    try:
        raw = _PROC_STATUS_PATH.read_text(encoding="utf-8")
    except OSError:
        return {}

    fields: dict[str, str] = {}
    for line in raw.splitlines():
        key, separator, value = line.partition(":")
        if separator:
            fields[key.strip()] = value.strip()
    return fields


def _has_capability(mask_hex: str, bit: int) -> bool:
    """Return whether a capability bit is set in a hexadecimal capability mask."""
    try:
        return bool(int(mask_hex, 16) & (1 << bit))
    except ValueError:
        return False


def _explain_missing_privileges(
    *,
    raw_in_bounding_set: bool,
    raw_already_effective: bool,
    binary_has_file_capabilities: bool,
    no_new_privs: bool,
    nmap_privileged_env: bool,
) -> str:
    """Name the most likely reason raw-socket scanning is unavailable.

    Four independent things have to line up, and each one fails silently in its
    own way, so the diagnosis walks them in the order a misconfiguration is most
    likely to occur.
    """
    if not raw_in_bounding_set:
        return "CAP_NET_RAW is absent from the container bounding set"
    if not raw_already_effective and not binary_has_file_capabilities:
        return "the scanner binary carries no file capabilities"
    if not raw_already_effective and no_new_privs:
        return "no_new_privs is set, which suppresses the scanner's file capabilities"
    if not nmap_privileged_env:
        return (
            "NMAP_PRIVILEGED is unset, so Nmap refuses raw scans for a non-root "
            "user even though the capabilities are present"
        )
    return "the scanner rejected the privileged scan for an unrecognised reason"


def _verify_raw_socket_scan() -> tuple[bool, str]:
    """Prove raw-socket scanning works by performing one against the loopback.

    Modelling the kernel's capability rules is error-prone, so readiness is
    decided by actually opening a raw socket rather than by inference. A
    single-port SYN scan of the loopback interface costs milliseconds and needs
    no external network.

    The loopback address is hard-coded here and is not subject to the tenant
    scan denylist: this is the worker probing itself, not auditing a customer.
    """
    binary = settings.nmap_binary_path
    command = [
        binary,
        "--privileged",
        "-sS",
        "-Pn",
        "-n",
        "-p",
        "1",
        "--max-retries",
        "0",
        "--host-timeout",
        "5s",
        "127.0.0.1",
    ]
    try:
        # Untrusted-input warning suppressed: every element of this argument
        # vector is a literal or the operator-configured binary path, and
        # `shell=False` is explicit.
        completed = subprocess.run(  # noqa: S603  # nosec B603
            command,
            capture_output=True,
            text=True,
            timeout=_SCAN_PROBE_TIMEOUT_SECONDS,
            check=False,
            shell=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        logger.error("system.scan_probe_failed", error=str(exc))
        return False, "the scan probe could not be executed"

    output = f"{completed.stdout}\n{completed.stderr}"
    if "requires root privileges" in output:
        return False, "Nmap refused the scan type as unprivileged"
    if completed.returncode != 0:
        return False, f"the scan probe exited with code {completed.returncode}"
    return True, "verified by a loopback SYN scan"


def _probe_scan_privileges() -> dict[str, Any]:
    """Report whether this worker can actually open raw sockets for scanning.

    Readiness is established empirically, by running a real SYN scan. The
    capability fields alongside it are diagnostic: when the scan fails they say
    which of the four preconditions is missing.

    1. The container's **capability bounding set** must contain CAP_NET_RAW,
       which comes from `cap_add` in the orchestrator configuration.
    2. Either the process already holds CAP_NET_RAW, or the **Nmap binary must
       carry file capabilities**, because a non-root process gains capabilities
       on exec only through them.
    3. **NoNewPrivs must be clear** when relying on file capabilities: the kernel
       refuses to let an exec grant privileges the caller did not already hold.
    4. **NMAP_PRIVILEGED must be set**, because Nmap gates raw scans on
       `geteuid()` rather than on its own capabilities.
    """
    status = _read_proc_status()
    bounding = status.get("CapBnd", "")
    effective = status.get("CapEff", "")
    no_new_privs = status.get("NoNewPrivs") == "1"

    binary = settings.nmap_binary_path
    try:
        os.getxattr(binary, _FILE_CAPABILITY_XATTR)
        binary_has_file_capabilities = True
    except OSError:
        # Missing attribute, missing file or a filesystem without xattr support.
        binary_has_file_capabilities = False

    raw_in_bounding_set = _has_capability(bounding, _CAP_NET_RAW_BIT)
    raw_already_effective = _has_capability(effective, _CAP_NET_RAW_BIT)
    nmap_privileged_env = os.environ.get("NMAP_PRIVILEGED", "") not in ("", "0")

    available, detail = _verify_raw_socket_scan()
    reason = (
        detail
        if available
        else _explain_missing_privileges(
            raw_in_bounding_set=raw_in_bounding_set,
            raw_already_effective=raw_already_effective,
            binary_has_file_capabilities=binary_has_file_capabilities,
            no_new_privs=no_new_privs,
            nmap_privileged_env=nmap_privileged_env,
        )
    )

    return {
        "raw_socket_scanning": available,
        "reason": reason,
        "cap_net_raw_in_bounding_set": raw_in_bounding_set,
        "cap_net_bind_service_in_bounding_set": _has_capability(
            bounding, _CAP_NET_BIND_SERVICE_BIT
        ),
        "binary_has_file_capabilities": binary_has_file_capabilities,
        "no_new_privs": no_new_privs,
        "nmap_privileged_env": nmap_privileged_env,
        "effective_uid": os.geteuid(),
    }


def _probe_nmap() -> dict[str, Any]:
    """Report whether the Nmap binary is present, executable and privileged.

    The command line is a fixed argument vector with no shell and no
    interpolated input, so there is no injection surface here.
    """
    binary = settings.nmap_binary_path
    if not shutil.which(binary) and not os.access(binary, os.X_OK):
        return {"available": False, "reason": "binary not found or not executable"}

    try:
        # Untrusted-input warning suppressed below: the argument vector is exactly
        # `[<configured binary>, "--version"]`. Nothing is caller-controlled and
        # `shell=False` is explicit, so there is no command-injection surface here.
        # Scan argument construction, which does handle tenant input, is validated
        # separately in the scanning module.
        completed = subprocess.run(  # noqa: S603  # nosec B603
            [binary, "--version"],
            capture_output=True,
            text=True,
            timeout=_VERSION_PROBE_TIMEOUT_SECONDS,
            check=False,
            shell=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        logger.error("system.nmap_probe_failed", error=str(exc))
        return {"available": False, "reason": "probe failed"}

    if completed.returncode != 0:
        return {"available": False, "reason": f"exit code {completed.returncode}"}

    first_line = completed.stdout.splitlines()[0].strip() if completed.stdout else ""
    return {"available": True, "version": first_line}


def _probe_database() -> dict[str, Any]:
    """Confirm the worker can reach PostgreSQL through the synchronous engine."""
    try:
        with session_scope() as session:
            session.execute(text("SELECT 1"))
    # A diagnostic probe must classify every failure rather than propagate it:
    # an unreachable database is a result to report, not a crash.
    except Exception as exc:
        logger.error("system.database_probe_failed", error=str(exc), exc_info=True)
        return {"available": False, "reason": "probe failed"}
    return {"available": True}


@celery_app.task(  # type: ignore[misc]
    name="netshield.system.health_check",
    bind=True,
    ignore_result=False,
)
def health_check(self: Any) -> dict[str, Any]:
    """Report worker readiness: database, scanner and raw-socket privileges.

    A worker counts as healthy only when all three hold. A scanner that is
    installed but cannot open raw sockets would accept jobs and fail every one
    of them, so the privilege check is part of readiness rather than a separate
    diagnostic.

    Returns:
        A JSON-serialisable report naming the worker, its database status, the
        detected Nmap version and the three factors governing raw-socket access.
    """
    database = _probe_database()
    nmap = _probe_nmap()
    privileges = _probe_scan_privileges()
    healthy = bool(
        database["available"] and nmap["available"] and privileges["raw_socket_scanning"]
    )

    report: dict[str, Any] = {
        "status": "up" if healthy else "down",
        "worker": self.request.hostname,
        "environment": settings.environment.value,
        "timestamp": datetime.now(UTC).isoformat(),
        "database": database,
        "nmap": nmap,
        "privileges": privileges,
    }
    logger.info(
        "system.health_check",
        healthy=healthy,
        nmap=nmap.get("version"),
        raw_socket_scanning=privileges["raw_socket_scanning"],
        privilege_reason=privileges["reason"],
    )
    return report
