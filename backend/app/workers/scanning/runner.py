"""Execution of the Nmap subprocess.

The runner exists to bound what a scan can consume. Nmap is a well-behaved tool,
but it is pointed at networks the platform does not control, and an unresponsive
or hostile range can keep it running far longer than expected.
"""

from __future__ import annotations

import subprocess  # nosec B404
import time
from dataclasses import dataclass
from typing import Final

from app.core.config import settings
from app.core.logging import get_logger
from app.workers.scanning.command import ScanCommand

logger = get_logger(__name__)

#: Upper bound on the XML report accepted from Nmap, in bytes.
#:
#: A scan is already bounded by the per-scan address ceiling and the port range,
#: so a report beyond this size means something is wrong rather than merely
#: large. Refusing it keeps a worker from being pushed into swap by one job.
MAX_REPORT_BYTES: Final[int] = 64 * 1024 * 1024

#: Nmap exit codes. Anything else is treated as a failure.
_SUCCESS_RETURN_CODE: Final[int] = 0

#: Signals worth naming when Nmap is killed rather than exiting on its own.
_SIGNAL_NAMES: Final[dict[int, str]] = {
    2: "SIGINT (interrupt)",
    9: "SIGKILL (killed, often the out-of-memory killer)",
    15: "SIGTERM (shutdown)",
}


class ScanExecutionError(RuntimeError):
    """Raised when Nmap could not be run or did not complete successfully."""


class ScanTimeoutError(ScanExecutionError):
    """Raised when Nmap exceeded the configured wall-clock budget."""


@dataclass(frozen=True, slots=True)
class NmapExecution:
    """The outcome of one Nmap invocation."""

    #: The XML report, as written to standard output by ``-oX -``.
    xml_report: str

    #: Whatever Nmap wrote to standard error. Warnings are normal here.
    stderr: str

    #: Wall-clock duration in seconds.
    duration_seconds: float


def run_nmap(command: ScanCommand, *, timeout_seconds: int | None = None) -> NmapExecution:
    """Execute a prepared scan command and return its XML report.

    Args:
        command: A vector produced by
            :func:`app.workers.scanning.command.build_scan_command`.
        timeout_seconds: Wall-clock budget. Defaults to the configured scan
            timeout.

    Returns:
        The captured report and timing.

    Raises:
        ScanTimeoutError: The budget elapsed. Nmap is killed before this raises.
        ScanExecutionError: Nmap could not be started, exited non-zero, or
            produced a report larger than :data:`MAX_REPORT_BYTES`.
    """
    budget = timeout_seconds if timeout_seconds is not None else settings.nmap_scan_timeout_seconds

    logger.info(
        "scan.nmap_started",
        command=command.redacted(),
        target_count=len(command.targets),
        address_count=command.total_addresses,
        timeout_seconds=budget,
    )

    started = time.perf_counter()
    try:
        # Untrusted-input warning suppressed: `argv` is built from a fixed flag
        # list plus targets that were each validated as IP networks, and
        # `shell=False` is explicit. There is no command line to break out of.
        completed = subprocess.run(  # noqa: S603  # nosec B603
            command.argv,
            capture_output=True,
            text=True,
            timeout=budget,
            check=False,
            shell=False,
        )
    except subprocess.TimeoutExpired as exc:
        duration = time.perf_counter() - started
        logger.warning(
            "scan.nmap_timed_out", duration_seconds=round(duration, 2), timeout_seconds=budget
        )
        msg = f"Nmap exceeded its {budget}s budget and was terminated."
        raise ScanTimeoutError(msg) from exc
    except OSError as exc:
        # A missing binary, a permissions problem or a resource limit.
        logger.error("scan.nmap_not_executable", error=str(exc))
        msg = f"Could not execute {settings.nmap_binary_path!r}."
        raise ScanExecutionError(msg) from exc

    duration = time.perf_counter() - started
    stdout = completed.stdout or ""
    stderr = (completed.stderr or "").strip()

    if completed.returncode != _SUCCESS_RETURN_CODE:
        logger.error(
            "scan.nmap_failed",
            return_code=completed.returncode,
            stderr=_first_line(stderr),
            duration_seconds=round(duration, 2),
        )
        # The exit code and the first line of stderr are enough to diagnose;
        # the full stderr may quote target addresses.
        raise ScanExecutionError(_describe_failure(completed.returncode, stderr))

    report_size = len(stdout.encode("utf-8"))
    if report_size > MAX_REPORT_BYTES:
        logger.error("scan.nmap_report_too_large", report_bytes=report_size)
        msg = f"Nmap report of {report_size} bytes exceeds the {MAX_REPORT_BYTES} byte limit."
        raise ScanExecutionError(msg)

    logger.info(
        "scan.nmap_completed",
        duration_seconds=round(duration, 2),
        report_bytes=report_size,
    )

    return NmapExecution(xml_report=stdout, stderr=stderr, duration_seconds=duration)


def _describe_failure(return_code: int, stderr: str) -> str:
    """Turn an Nmap exit status into something an operator can act on.

    A negative return code means the process was killed by a signal rather than
    exiting on its own, and reporting it as "exited with code -2" sends people
    looking through Nmap's documentation for an exit code that does not exist.

    The common cause in development is the worker restarting: it runs under
    `watchmedo auto-restart`, which signals the whole process group when a
    source file changes, taking any scan in flight with it.
    """
    if return_code < 0:
        signal_number = -return_code
        name = _SIGNAL_NAMES.get(signal_number, f"signal {signal_number}")
        return (
            f"Nmap was terminated by {name} after starting. The worker was most "
            f"likely restarted mid-scan, which in development happens whenever a "
            f"backend source file changes."
        )

    detail = _first_line(stderr)
    suffix = f": {detail}" if detail else "."
    return f"Nmap exited with code {return_code}{suffix}"


def _first_line(text: str) -> str:
    """Return the first non-empty line, truncated for log safety."""
    for line in text.splitlines():
        stripped = line.strip()
        if stripped:
            return stripped[:200]
    return ""
