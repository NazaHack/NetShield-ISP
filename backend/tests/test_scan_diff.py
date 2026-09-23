"""Tests for the comparison between consecutive scans.

The diff is what turns a list of open ports into a finding. Its job is to be
precise about what changed and quiet about what did not.
"""

from __future__ import annotations

from typing import Any

from app.models.scan_result import OpenPort
from app.workers.scanning.diff import compare_scans


def _port(
    number: int,
    *,
    protocol: str = "tcp",
    service: str | None = "ssh",
    version: str | None = None,
) -> OpenPort:
    """Build one open-port finding."""
    return OpenPort(port=number, protocol=protocol, service=service, version=version)


def test_first_scan_reports_no_changes() -> None:
    """A tenant's first scan has no baseline, so nothing is "new".

    Reporting every host as newly discovered on day one would bury the operator
    in noise at exactly the moment the data is least meaningful.
    """
    diff = compare_scans(None, {"10.0.0.1": [_port(22)]})

    assert diff.has_baseline is False
    assert diff.has_changes is False
    assert diff.new_hosts == ()


def test_identical_scans_report_no_changes() -> None:
    """An unchanged network produces an empty diff."""
    findings = {"10.0.0.1": [_port(22), _port(80, service="http")]}
    diff = compare_scans(findings, findings)

    assert diff.has_baseline is True
    assert diff.has_changes is False
    assert diff.host_diffs == ()


def test_a_newly_opened_port_is_detected() -> None:
    """The headline finding: a port that was not open before."""
    diff = compare_scans(
        {"10.0.0.1": [_port(22)]},
        {"10.0.0.1": [_port(22), _port(23, service="telnet")]},
    )

    assert diff.has_changes is True
    assert diff.opened_port_count == 1
    host_diff = diff.host_diffs[0]
    assert host_diff.host_ip == "10.0.0.1"
    assert host_diff.opened_ports[0]["port"] == 23
    assert host_diff.closed_ports == ()


def test_a_closed_port_is_detected() -> None:
    """A port that stopped answering is reported as closed."""
    diff = compare_scans(
        {"10.0.0.1": [_port(22), _port(23, service="telnet")]},
        {"10.0.0.1": [_port(22)]},
    )

    assert diff.closed_port_count == 1
    assert diff.host_diffs[0].closed_ports[0]["port"] == 23
    assert diff.host_diffs[0].opened_ports == ()


def test_same_port_on_a_different_protocol_is_a_separate_finding() -> None:
    """Port identity includes the protocol: 53/tcp and 53/udp are not the same."""
    diff = compare_scans(
        {"10.0.0.1": [_port(53, protocol="tcp", service="domain")]},
        {"10.0.0.1": [_port(53, protocol="udp", service="domain")]},
    )

    host_diff = diff.host_diffs[0]
    assert host_diff.opened_ports[0]["protocol"] == "udp"
    assert host_diff.closed_ports[0]["protocol"] == "tcp"


def test_a_new_host_is_detected() -> None:
    """A host that answered for the first time is listed separately."""
    diff = compare_scans(
        {"10.0.0.1": [_port(22)]},
        {"10.0.0.1": [_port(22)], "10.0.0.2": [_port(22)]},
    )

    assert diff.new_hosts == ("10.0.0.2",)
    assert diff.disappeared_hosts == ()


def test_a_disappeared_host_is_detected() -> None:
    """A host that stopped answering is reported rather than silently dropped."""
    diff = compare_scans(
        {"10.0.0.1": [_port(22)], "10.0.0.2": [_port(22)]},
        {"10.0.0.1": [_port(22)]},
    )

    assert diff.disappeared_hosts == ("10.0.0.2",)
    assert diff.new_hosts == ()


def test_a_version_change_is_detected() -> None:
    """A service that was upgraded or downgraded on a stable port is a finding."""
    diff = compare_scans(
        {"10.0.0.1": [_port(22, service="ssh", version="OpenSSH 8.4")]},
        {"10.0.0.1": [_port(22, service="ssh", version="OpenSSH 9.2")]},
    )

    change = diff.host_diffs[0].changed_ports[0]
    assert change.port == 22
    assert change.previous_version == "OpenSSH 8.4"
    assert change.current_version == "OpenSSH 9.2"
    assert diff.opened_port_count == 0


def test_a_service_change_is_detected() -> None:
    """A different service on a familiar port is worth surfacing."""
    diff = compare_scans(
        {"10.0.0.1": [_port(8080, service="http")]},
        {"10.0.0.1": [_port(8080, service="http-proxy")]},
    )

    change = diff.host_diffs[0].changed_ports[0]
    assert change.previous_service == "http"
    assert change.current_service == "http-proxy"


def test_unchanged_hosts_are_omitted_from_the_diff() -> None:
    """Only hosts that actually changed appear, so the report stays readable."""
    diff = compare_scans(
        {"10.0.0.1": [_port(22)], "10.0.0.2": [_port(22)]},
        {"10.0.0.1": [_port(22)], "10.0.0.2": [_port(22), _port(443, service="https")]},
    )

    assert [host_diff.host_ip for host_diff in diff.host_diffs] == ["10.0.0.2"]


def test_a_host_going_quiet_is_not_the_same_as_disappearing() -> None:
    """A host with every port closed still exists, and is reported that way."""
    diff = compare_scans({"10.0.0.1": [_port(22)]}, {"10.0.0.1": []})

    assert diff.disappeared_hosts == ()
    assert diff.host_diffs[0].closed_ports[0]["port"] == 22


def test_results_are_ordered_for_stable_reporting() -> None:
    """Deterministic ordering keeps two runs of the same comparison identical."""
    previous = {"10.0.0.3": [_port(22)], "10.0.0.1": [_port(22)]}
    current = {
        "10.0.0.2": [_port(22)],
        "10.0.0.1": [_port(22), _port(443, service="https"), _port(80, service="http")],
    }
    diff = compare_scans(previous, current)

    assert diff.new_hosts == ("10.0.0.2",)
    assert diff.disappeared_hosts == ("10.0.0.3",)
    opened = [entry["port"] for entry in diff.host_diffs[0].opened_ports]
    assert opened == sorted(opened)


def test_diff_serialises_to_json_safe_primitives() -> None:
    """The diff travels in a Celery result, which accepts JSON only."""
    import json

    diff = compare_scans(
        {"10.0.0.1": [_port(22, version="OpenSSH 8.4")], "10.0.0.9": [_port(22)]},
        {
            "10.0.0.1": [_port(22, version="OpenSSH 9.2"), _port(23, service="telnet")],
            "10.0.0.2": [_port(22)],
        },
    )

    payload: dict[str, Any] = diff.as_dict()
    round_tripped = json.loads(json.dumps(payload))

    assert round_tripped["has_baseline"] is True
    assert round_tripped["has_changes"] is True
    assert round_tripped["new_hosts"] == ["10.0.0.2"]
    assert round_tripped["disappeared_hosts"] == ["10.0.0.9"]
    assert round_tripped["opened_port_count"] == 1
    assert round_tripped["host_diffs"][0]["changed_ports"][0]["current_version"] == "OpenSSH 9.2"
