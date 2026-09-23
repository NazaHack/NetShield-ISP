"""Tests for the exposure assessment.

The classifier turns a flat port list into triage, so what matters is that the
genuinely dangerous exposures rank above the mundane ones, that the port number
wins over Nmap's service guess, and that an unknown port is noted rather than
alarmed.
"""

from __future__ import annotations

import pytest

from app.core.risk import Severity, assess_port
from app.models.scan_result import OpenPort


def _port(number: int, service: str | None = None) -> OpenPort:
    """Build an open port for assessment."""
    return OpenPort(port=number, protocol="tcp", service=service, version=None)


@pytest.mark.parametrize(
    ("number", "expected"),
    [
        (23, Severity.CRITICAL),  # telnet
        (445, Severity.CRITICAL),  # SMB
        (3389, Severity.CRITICAL),  # RDP
        (5432, Severity.CRITICAL),  # PostgreSQL
        (6379, Severity.CRITICAL),  # Redis
        (21, Severity.HIGH),  # FTP
        (1723, Severity.HIGH),  # PPTP
        (161, Severity.HIGH),  # SNMP
        (22, Severity.MEDIUM),  # SSH
        (8000, Severity.MEDIUM),  # alt HTTP
        (443, Severity.LOW),  # HTTPS
    ],
)
def test_known_ports_rank_as_expected(number: int, expected: Severity) -> None:
    """The curated table places well-known services in the right band."""
    assert assess_port(_port(number)).severity is expected


def test_an_unknown_port_is_info_not_alarm() -> None:
    """A port with no known concern is noted, not escalated."""
    verdict = assess_port(_port(1443, service="ies-lm"))
    assert verdict.severity is Severity.INFO
    assert verdict.reason


def test_the_port_number_wins_over_the_service_guess() -> None:
    """443 stays LOW even if Nmap mislabels the service as telnet."""
    assert assess_port(_port(443, service="telnet")).severity is Severity.LOW


def test_a_database_on_a_nonstandard_port_is_caught_by_service() -> None:
    """When the port is unknown, a recognised service name still classifies it."""
    verdict = assess_port(_port(49999, service="redis"))
    assert verdict.severity is Severity.CRITICAL


def test_every_verdict_carries_a_reason() -> None:
    """A severity with no explanation would be useless in a report."""
    for number in (23, 22, 443, 12345):
        assert assess_port(_port(number)).reason


def test_severity_orders_from_info_to_critical() -> None:
    """The ordering the summary relies on for 'highest' and sorting."""
    assert Severity.INFO < Severity.LOW < Severity.MEDIUM < Severity.HIGH < Severity.CRITICAL
    assert max([Severity.LOW, Severity.CRITICAL, Severity.MEDIUM]) is Severity.CRITICAL
