"""Comparison of a scan against the tenant's previous completed scan.

What an ISP audit actually cares about is not the current state of a network but
how it changed: a port that opened between Tuesday and Wednesday is a finding,
while one that has been open for a year is a known condition.

The comparison is a pure function over two snapshots. It is computed at the end
of every scan and returned with the task result, and because both snapshots are
persisted it can be recomputed at any time from stored data. No diff is written
to the database, so a change in how differences are defined does not require a
backfill.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from app.models.scan_result import OpenPort

#: A port identified independently of the service running on it.
PortKey = tuple[str, int]

#: One host's findings, keyed by ``(protocol, port)``.
HostSnapshot = dict[PortKey, OpenPort]

#: A whole scan's findings, keyed by host address.
ScanSnapshot = dict[str, HostSnapshot]


def _port_key(port: OpenPort) -> PortKey:
    """Identity of a port within a host."""
    return (port["protocol"], port["port"])


def build_snapshot(results: Mapping[str, Sequence[OpenPort]]) -> ScanSnapshot:
    """Turn ``{host: [ports]}`` into the keyed form the comparison works on."""
    return {host: {_port_key(port): port for port in ports} for host, ports in results.items()}


@dataclass(frozen=True, slots=True)
class PortChange:
    """A port whose service or version differs from the previous scan."""

    protocol: str
    port: int
    previous_service: str | None
    current_service: str | None
    previous_version: str | None
    current_version: str | None

    def as_dict(self) -> dict[str, Any]:
        """Render for JSON transport in the Celery result."""
        return {
            "protocol": self.protocol,
            "port": self.port,
            "previous_service": self.previous_service,
            "current_service": self.current_service,
            "previous_version": self.previous_version,
            "current_version": self.current_version,
        }


@dataclass(frozen=True, slots=True)
class HostDiff:
    """How one host changed between two scans."""

    host_ip: str
    opened_ports: tuple[OpenPort, ...]
    closed_ports: tuple[OpenPort, ...]
    changed_ports: tuple[PortChange, ...]

    @property
    def has_changes(self) -> bool:
        """True when anything about this host differs."""
        return bool(self.opened_ports or self.closed_ports or self.changed_ports)

    def as_dict(self) -> dict[str, Any]:
        """Render for JSON transport in the Celery result."""
        return {
            "host_ip": self.host_ip,
            "opened_ports": [dict(port) for port in self.opened_ports],
            "closed_ports": [dict(port) for port in self.closed_ports],
            "changed_ports": [change.as_dict() for change in self.changed_ports],
        }


@dataclass(frozen=True, slots=True)
class ScanDiff:
    """The full comparison between two scans of one tenant."""

    #: Whether a previous completed scan existed at all. A first scan produces a
    #: diff with no changes rather than one where everything looks new, which
    #: would bury the operator in noise on day one.
    has_baseline: bool

    #: Hosts present now that were absent from the previous scan.
    new_hosts: tuple[str, ...]

    #: Hosts present previously that did not answer this time.
    disappeared_hosts: tuple[str, ...]

    #: Per-host changes, for hosts present in both scans.
    host_diffs: tuple[HostDiff, ...]

    @property
    def has_changes(self) -> bool:
        """True when the two scans differ in any way."""
        return bool(self.new_hosts or self.disappeared_hosts or self.host_diffs)

    @property
    def opened_port_count(self) -> int:
        """Total ports that opened, across hosts present in both scans."""
        return sum(len(diff.opened_ports) for diff in self.host_diffs)

    @property
    def closed_port_count(self) -> int:
        """Total ports that closed, across hosts present in both scans."""
        return sum(len(diff.closed_ports) for diff in self.host_diffs)

    def as_dict(self) -> dict[str, Any]:
        """Render for JSON transport in the Celery result."""
        return {
            "has_baseline": self.has_baseline,
            "has_changes": self.has_changes,
            "new_hosts": list(self.new_hosts),
            "disappeared_hosts": list(self.disappeared_hosts),
            "opened_port_count": self.opened_port_count,
            "closed_port_count": self.closed_port_count,
            "host_diffs": [diff.as_dict() for diff in self.host_diffs],
        }


def _changed_ports(previous: HostSnapshot, current: HostSnapshot) -> list[PortChange]:
    """Find ports open in both scans whose service or version moved."""
    changes: list[PortChange] = []
    for key in sorted(previous.keys() & current.keys()):
        before = previous[key]
        after = current[key]
        if before.get("service") == after.get("service") and before.get("version") == after.get(
            "version"
        ):
            continue
        protocol, port = key
        changes.append(
            PortChange(
                protocol=protocol,
                port=port,
                previous_service=before.get("service"),
                current_service=after.get("service"),
                previous_version=before.get("version"),
                current_version=after.get("version"),
            )
        )
    return changes


def _sorted_ports(snapshot: HostSnapshot, keys: Iterable[PortKey]) -> tuple[OpenPort, ...]:
    """Return the named ports in a stable order."""
    return tuple(snapshot[key] for key in sorted(keys))


def compare_scans(
    previous: Mapping[str, Sequence[OpenPort]] | None,
    current: Mapping[str, Sequence[OpenPort]],
) -> ScanDiff:
    """Compare a scan against its predecessor.

    Args:
        previous: Findings of the tenant's last completed scan, or ``None`` when
            this is the tenant's first one.
        current: Findings of the scan that just completed.

    Returns:
        The differences. When there is no baseline, the result reports
        ``has_baseline=False`` and no changes: treating every host as newly
        discovered on a first scan produces noise, not information.
    """
    if previous is None:
        return ScanDiff(
            has_baseline=False,
            new_hosts=(),
            disappeared_hosts=(),
            host_diffs=(),
        )

    before = build_snapshot(previous)
    after = build_snapshot(current)

    new_hosts = tuple(sorted(after.keys() - before.keys()))
    disappeared_hosts = tuple(sorted(before.keys() - after.keys()))

    host_diffs: list[HostDiff] = []
    for host in sorted(before.keys() & after.keys()):
        host_before = before[host]
        host_after = after[host]

        diff = HostDiff(
            host_ip=host,
            opened_ports=_sorted_ports(host_after, host_after.keys() - host_before.keys()),
            closed_ports=_sorted_ports(host_before, host_before.keys() - host_after.keys()),
            changed_ports=tuple(_changed_ports(host_before, host_after)),
        )
        if diff.has_changes:
            host_diffs.append(diff)

    return ScanDiff(
        has_baseline=True,
        new_hosts=new_hosts,
        disappeared_hosts=disappeared_hosts,
        host_diffs=tuple(host_diffs),
    )
