"""Parsing and normalisation of network targets.

This module is a security boundary, not a convenience. Values accepted here are
persisted and later become arguments to Nmap, so anything that is not a literal
IP address or CIDR block must be rejected at the point of entry. Restricting the
grammar to what :mod:`ipaddress` accepts eliminates shell metacharacters,
Nmap option injection such as ``--script=http-shellshock``, hostname lookups and
Nmap's own shorthand ranges (``10.0.0.1-254``) in one step.

The functions here deliberately do **not** apply scanning policy. Whether a
tenant is allowed to scan a given range is a separate decision made against the
configured denylist and the tenant's own target ownership.
"""

from __future__ import annotations

import ipaddress
from typing import Final

#: Longest value this module will accept: a full IPv6 address plus ``/128``.
#: Bounding the input keeps a pathological string out of the parser and out of
#: the database column, which is sized to match.
MAX_TARGET_LENGTH: Final[int] = 45

#: Networks are rendered back in this canonical form regardless of how the
#: caller wrote them, so equality comparisons and uniqueness constraints behave.
_IPv4Network = ipaddress.IPv4Network
_IPv6Network = ipaddress.IPv6Network


class InvalidNetworkError(ValueError):
    """Raised when a value is not a usable IP address or CIDR block."""


def _reject_unusable_input(value: object) -> str:
    """Apply the checks that are common to every parser in this module.

    The parameter is deliberately typed ``object`` rather than ``str``. These
    parsers sit behind SQLAlchemy ``@validates`` hooks, which receive whatever
    was assigned to the attribute, so the type check is a real runtime guard and
    not dead code.
    """
    if not isinstance(value, str):
        msg = f"Network target must be a string, got {type(value).__name__}."
        raise InvalidNetworkError(msg)

    candidate = value.strip()
    if not candidate:
        msg = "Network target must not be empty."
        raise InvalidNetworkError(msg)
    if len(candidate) > MAX_TARGET_LENGTH:
        msg = f"Network target must be at most {MAX_TARGET_LENGTH} characters."
        raise InvalidNetworkError(msg)
    # A leading hyphen would be read by Nmap as an option rather than a target.
    # `ipaddress` rejects it too; failing here makes the reason explicit.
    if candidate.startswith("-"):
        msg = "Network target must not start with a hyphen."
        raise InvalidNetworkError(msg)
    return candidate


def normalise_network(value: str) -> str:
    """Validate a target and return it in canonical CIDR form.

    A bare address becomes a single-host network (``/32`` or ``/128``). A value
    carrying a prefix must already have its host bits cleared: ``10.0.0.5/24``
    is rejected rather than silently widened to ``10.0.0.0/24``, because
    quietly turning one host into 256 of them is exactly the kind of scope
    expansion an audit platform must never perform on its own.

    Args:
        value: User-supplied address or CIDR block.

    Returns:
        The canonical ``network/prefix`` representation.

    Raises:
        InvalidNetworkError: If the value is not a valid address or network, or
            if it carries a prefix with host bits set.
    """
    candidate = _reject_unusable_input(value)

    try:
        network = ipaddress.ip_network(candidate, strict=True)
    except ValueError as exc:
        if "/" in candidate:
            # Distinguish "not an address at all" from "host bits set", because
            # the corrective action differs.
            try:
                relaxed = ipaddress.ip_network(candidate, strict=False)
            except ValueError:
                msg = f"{candidate!r} is not a valid IP address or CIDR block."
                raise InvalidNetworkError(msg) from exc
            msg = (
                f"{candidate!r} has host bits set. Write {relaxed!s} to scan the "
                f"whole network, or drop the prefix to scan the single host."
            )
            raise InvalidNetworkError(msg) from exc
        msg = f"{candidate!r} is not a valid IP address or CIDR block."
        raise InvalidNetworkError(msg) from exc

    return str(network)


def normalise_host_address(value: str) -> str:
    """Validate a single host address and return it in canonical form.

    Unlike :func:`normalise_network` this rejects any prefix: a scan result
    belongs to exactly one host.

    Args:
        value: Address discovered by a scan.

    Returns:
        The canonical address, with IPv6 compressed to its shortest form.

    Raises:
        InvalidNetworkError: If the value is not a single IP address.
    """
    candidate = _reject_unusable_input(value)

    if "/" in candidate:
        msg = f"{candidate!r} must be a single host address, without a prefix."
        raise InvalidNetworkError(msg)

    try:
        address = ipaddress.ip_address(candidate)
    except ValueError as exc:
        msg = f"{candidate!r} is not a valid IP address."
        raise InvalidNetworkError(msg) from exc

    return str(address)


def address_count(network_cidr: str) -> int:
    """Return how many addresses a canonical CIDR block covers.

    Used to enforce the per-scan target ceiling before a job is enqueued.

    Args:
        network_cidr: A value previously returned by :func:`normalise_network`.

    Raises:
        InvalidNetworkError: If the value does not parse as a network.
    """
    try:
        network = ipaddress.ip_network(network_cidr, strict=False)
    except ValueError as exc:
        msg = f"{network_cidr!r} is not a valid CIDR block."
        raise InvalidNetworkError(msg) from exc
    return network.num_addresses


def is_contained_in(candidate_cidr: str, container_cidr: str) -> bool:
    """Whether one network lies entirely inside another.

    Used to check that a range an operator typed falls within one their client
    has registered. Containment rather than equality, so a customer can scan a
    single host inside their own block without registering it separately.

    Mismatched address families are never contained in one another, which is
    what stops an IPv6 range appearing to sit inside an IPv4 one.

    Args:
        candidate_cidr: The range being checked.
        container_cidr: The range it must fall inside.

    Returns:
        ``False`` when either value does not parse, rather than raising: the
        caller is making an authorisation decision, and an unparseable range is
        simply not authorised.
    """
    try:
        candidate = ipaddress.ip_network(candidate_cidr, strict=False)
        container = ipaddress.ip_network(container_cidr, strict=False)
    except ValueError:
        return False

    if candidate.version != container.version:
        return False
    return candidate.subnet_of(container)  # type: ignore[arg-type]
