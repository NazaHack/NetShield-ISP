"""Scan policy and Nmap argument construction.

Two responsibilities live here, and both are security-critical:

1. Deciding whether a target may be scanned at all. Ownership is established by
   the target belonging to the tenant; this module applies the platform-wide
   rules that override ownership, such as the denylist.
2. Building the argument vector. Nothing is ever concatenated into a string and
   nothing is passed to a shell, so there is no command line for a hostile value
   to break out of. The remaining risk is *option* injection, and that is closed
   by validating every target as an IP network before it reaches the vector.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from app.core.config import settings
from app.core.network import InvalidNetworkError, address_count, normalise_network

#: Port range scanned only by the thorough profile. Covers the registered-port
#: space where an ISP audit finds exposed management interfaces.
THOROUGH_PORT_RANGE: Final[str] = "1-10000"

#: Kept as the historical name so callers importing it do not break; it is the
#: range the thorough profile uses.
DEFAULT_PORT_RANGE: Final[str] = THOROUGH_PORT_RANGE

#: How many of the most common ports the fast and balanced profiles scan.
#: One thousand is Nmap's own default, the set a bare ``nmap <target>`` covers.
TOP_PORTS: Final[int] = 1000

#: Nmap timing template. T4 is the usual choice for a network the operator owns:
#: fast enough to finish, slow enough not to be mistaken for an attack.
DEFAULT_TIMING_TEMPLATE: Final[str] = "-T4"


class ScanProfile(StrEnum):
    """How thoroughly, and therefore how quickly, a scan runs.

    Two independent costs drive scan time: how many ports are probed, and
    whether each open port is interrogated for its service and version. These
    profiles trade one against the other so an operator picks the point they
    want rather than always paying for the most expensive scan.

    ``FAST``
        The 1000 most common ports, no version detection. This is what a bare
        ``nmap <target>`` does, and it finishes a live host in seconds.
    ``BALANCED``
        The 1000 most common ports *with* version detection. The default:
        roughly ten times fewer ports than ``THOROUGH`` while still reporting
        what each open service is.
    ``THOROUGH``
        Ports 1 through 10000 with version detection. The most complete and, on
        a large network, by far the slowest.
    """

    FAST = "fast"
    BALANCED = "balanced"
    THOROUGH = "thorough"

    @property
    def detects_versions(self) -> bool:
        """Whether this profile interrogates open ports for service versions."""
        return self is not ScanProfile.FAST


#: The profile used when a request names none. Balanced rather than thorough:
#: an audit wants service versions, but almost never needs all 10000 ports, and
#: the port count is what makes a large scan slow.
DEFAULT_SCAN_PROFILE: Final[ScanProfile] = ScanProfile.BALANCED

#: Networks that are never scannable regardless of tenant configuration or of
#: the operator-supplied denylist. Scanning these is either meaningless or
#: actively harmful: multicast and broadcast traffic hits unintended hosts, and
#: link-local space includes cloud instance-metadata endpoints.
ALWAYS_FORBIDDEN_NETWORKS: Final[tuple[str, ...]] = (
    "0.0.0.0/8",  # "this network"
    "224.0.0.0/4",  # IPv4 multicast
    "240.0.0.0/4",  # reserved, includes 255.255.255.255
    "169.254.0.0/16",  # IPv4 link-local, includes cloud metadata
    "::/128",  # unspecified
    "ff00::/8",  # IPv6 multicast
    "fe80::/10",  # IPv6 link-local
)


class TargetNotPermittedError(ValueError):
    """Raised when a target is valid but policy forbids scanning it."""


@dataclass(frozen=True, slots=True)
class ScanCommand:
    """A fully resolved, ready-to-execute Nmap invocation."""

    #: The argument vector, passed to ``subprocess`` with ``shell=False``.
    argv: tuple[str, ...]

    #: Canonical targets included in this scan, in the order given to Nmap.
    targets: tuple[str, ...]

    #: Total number of addresses covered, used for logging and quota reporting.
    total_addresses: int

    def redacted(self) -> str:
        """Render the command for logs without inlining every target.

        A scan of 256 ranges would otherwise produce an unreadable log line and
        copy a tenant's whole network map into the log store.
        """
        head = " ".join(self.argv[: len(self.argv) - len(self.targets)])
        return f"{head} <{len(self.targets)} target(s), {self.total_addresses} address(es)>"


def _forbidden_networks() -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    """Combine the hard-coded and operator-configured denylists."""
    always = tuple(ipaddress.ip_network(entry, strict=False) for entry in ALWAYS_FORBIDDEN_NETWORKS)
    return always + settings.scan_denylist_networks


def assert_target_is_permitted(target: str) -> str:
    """Validate a target against platform policy and return its canonical form.

    Args:
        target: An address or CIDR block, typically read from a tenant's
            registered network targets.

    Returns:
        The canonical ``network/prefix`` form.

    Raises:
        InvalidNetworkError: The value is not a valid address or network.
        TargetNotPermittedError: The value is valid but policy forbids it.
    """
    canonical = normalise_network(target)
    network = ipaddress.ip_network(canonical, strict=False)

    for forbidden in _forbidden_networks():
        if network.version != forbidden.version:
            continue
        # `overlaps` rather than `subnet_of`: a tenant must not be able to smuggle
        # a forbidden range inside a wider block it happens to own.
        if network.overlaps(forbidden):
            msg = f"{canonical} overlaps the forbidden range {forbidden}."
            raise TargetNotPermittedError(msg)

    if not settings.scan_allow_private_ranges and network.is_private:
        msg = f"{canonical} is private and SCAN_ALLOW_PRIVATE_RANGES is disabled."
        raise TargetNotPermittedError(msg)

    return canonical


@dataclass(frozen=True, slots=True)
class TargetSelection:
    """The outcome of applying policy to a tenant's registered ranges."""

    #: Canonical targets that passed every check.
    accepted: tuple[str, ...]

    #: Targets that were refused, each paired with the reason.
    rejected: tuple[tuple[str, str], ...]

    #: Total addresses covered by the accepted targets.
    total_addresses: int


def select_scannable_targets(targets: Sequence[str]) -> TargetSelection:
    """Filter a tenant's ranges down to those this scan may actually cover.

    A target that policy forbids is skipped rather than failing the whole scan:
    one misconfigured range must not prevent an ISP from auditing the rest of its
    estate. Every rejection is reported so it can be surfaced and logged.

    The per-scan address ceiling is applied last, in the order the targets were
    given, so that the result is deterministic.

    Args:
        targets: Raw range strings belonging to one tenant.

    Raises:
        TargetNotPermittedError: If no target survives, which makes the scan
            meaningless and is treated as a failure rather than an empty success.
    """
    accepted: list[str] = []
    rejected: list[tuple[str, str]] = []
    total = 0
    ceiling = settings.nmap_max_targets_per_scan

    for raw in targets:
        try:
            canonical = assert_target_is_permitted(raw)
        except (InvalidNetworkError, TargetNotPermittedError) as exc:
            rejected.append((raw, str(exc)))
            continue

        size = address_count(canonical)
        if total + size > ceiling:
            rejected.append(
                (
                    canonical,
                    f"would exceed the per-scan ceiling of {ceiling} addresses",
                )
            )
            continue

        accepted.append(canonical)
        total += size

    if not accepted:
        detail = "; ".join(f"{value}: {reason}" for value, reason in rejected) or "none supplied"
        msg = f"No scannable target remains for this scan ({detail})."
        raise TargetNotPermittedError(msg)

    return TargetSelection(
        accepted=tuple(accepted),
        rejected=tuple(rejected),
        total_addresses=total,
    )


def _port_selection(profile: ScanProfile, port_range: str | None) -> tuple[str, ...]:
    """Return the Nmap flags that choose which ports to scan.

    An explicit ``port_range`` always wins, whatever the profile: an operator
    who typed one means it. Otherwise the profile decides, and the fast and
    balanced profiles use the top-1000 set rather than a numeric range because
    that is both faster and the set a plain ``nmap`` covers.
    """
    if port_range is not None:
        _validate_port_range(port_range)
        return ("-p", port_range)
    if profile is ScanProfile.THOROUGH:
        return ("-p", THOROUGH_PORT_RANGE)
    return ("--top-ports", str(TOP_PORTS))


def build_scan_command(
    targets: Sequence[str],
    *,
    profile: ScanProfile = DEFAULT_SCAN_PROFILE,
    port_range: str | None = None,
) -> ScanCommand:
    """Build the Nmap argument vector for a set of already-selected targets.

    The shape is ``nmap [-sV] -T4 <port selection> --open -n --privileged
    -oX - <targets>``, where the profile decides whether ``-sV`` is present and
    which ports are scanned.

    Flags common to every profile, each deliberate:

    ``-n``
        Disables DNS resolution. A reverse lookup of every scanned address leaks
        the tenant's address list to whichever resolver is configured, and it is
        a common cause of scans that appear to hang.

    ``--privileged``
        Nmap gates raw-socket scan types on ``geteuid()`` rather than on its own
        capabilities. The worker runs unprivileged with file capabilities on the
        binary, so without this flag Nmap silently downgrades to a connect scan.

    ``-oX -`` writes the report to standard output. No filesystem path derived
    from tenant data is ever passed to Nmap, which removes file overwrite as a
    consequence of a parsing mistake elsewhere.

    Args:
        targets: Canonical targets, already passed through policy.
        profile: How thorough the scan is. See :class:`ScanProfile`.
        port_range: An explicit Nmap port specification that overrides the
            profile's own port selection. ``None`` lets the profile choose.

    Raises:
        ValueError: If no target is supplied or the port range is malformed.
    """
    if not targets:
        msg = "A scan command needs at least one target."
        raise ValueError(msg)

    version_flags: tuple[str, ...] = ("-sV",) if profile.detects_versions else ()

    argv: tuple[str, ...] = (
        settings.nmap_binary_path,
        *version_flags,
        DEFAULT_TIMING_TEMPLATE,
        *_port_selection(profile, port_range),
        "--open",
        "-n",
        "--privileged",
        "-oX",
        "-",
        *targets,
    )

    return ScanCommand(
        argv=argv,
        targets=tuple(targets),
        total_addresses=sum(address_count(target) for target in targets),
    )


def _validate_port_range(port_range: str) -> None:
    """Reject a port specification that is anything other than digits and separators.

    The port range is not tenant-supplied today, but it is the one remaining
    free-form element of the command vector, so it is constrained here rather
    than trusted.
    """
    if not port_range:
        msg = "Port range must not be empty."
        raise ValueError(msg)
    if not all(char.isdigit() or char in ",-" for char in port_range):
        msg = f"Port range {port_range!r} may contain only digits, commas and hyphens."
        raise ValueError(msg)

    for part in port_range.split(","):
        bounds = part.split("-")
        if len(bounds) > 2 or not all(bound.isdigit() for bound in bounds if bound != ""):
            msg = f"Port range {port_range!r} is malformed."
            raise ValueError(msg)
        for bound in bounds:
            if bound and not 1 <= int(bound) <= 65535:
                msg = f"Port {bound} in {port_range!r} is outside 1-65535."
                raise ValueError(msg)
