"""Tests for how Nmap failures are reported.

An exit status is the only thing an operator sees when a scan fails, so it has
to say something true and actionable.
"""

from __future__ import annotations

import pytest

from app.workers.scanning.runner import _describe_failure


@pytest.mark.parametrize(
    ("signal_number", "expected"),
    [(2, "SIGINT"), (9, "SIGKILL"), (15, "SIGTERM")],
)
def test_a_signalled_process_is_named_as_such(signal_number: int, expected: str) -> None:
    """A negative return code means killed, not an Nmap exit code.

    Reporting it as "exited with code -2" sends people looking through Nmap's
    documentation for an exit code that does not exist.
    """
    message = _describe_failure(-signal_number, "")

    assert expected in message
    assert "exited with code" not in message


def test_a_signalled_process_names_the_usual_cause() -> None:
    """In development the usual cause is the worker restarting mid-scan."""
    assert "restarted" in _describe_failure(-2, "")


def test_an_unknown_signal_is_still_reported() -> None:
    """A signal without a friendly name is still identified as a signal."""
    message = _describe_failure(-7, "")

    assert "signal 7" in message


def test_an_ordinary_failure_quotes_the_first_stderr_line() -> None:
    """Nmap's own diagnosis is the most useful thing to pass through."""
    message = _describe_failure(1, 'Failed to resolve "nope".\nsecond line')

    assert "exited with code 1" in message
    assert "Failed to resolve" in message
    assert "second line" not in message


def test_an_ordinary_failure_without_stderr_is_still_readable() -> None:
    """A bare exit code produces a complete sentence, not a dangling colon."""
    message = _describe_failure(2, "")

    assert message == "Nmap exited with code 2."
