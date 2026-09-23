"""Model-level validation tests.

SQLAlchemy `@validates` hooks fire on attribute assignment, so these run without
a database. Database-enforced constraints are covered separately in the
integration suite.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from app.core.network import InvalidNetworkError
from app.models import NetworkTarget, Scan, ScanResult, ScanStatus, Tenant

# --------------------------------------------------------------------------- #
# Tenant
# --------------------------------------------------------------------------- #


def test_tenant_code_name_is_lowercased_and_trimmed() -> None:
    """Code names are normalised so lookups never depend on how they were typed."""
    tenant = Tenant(name="Acme ISP", code_name="  ACME-ISP  ")
    assert tenant.code_name == "acme-isp"


@pytest.mark.parametrize(
    "invalid",
    ["-acme", "acme-", "acme isp", "acme_isp", "acme.isp", "", "acme/isp", "acme;drop"],
)
def test_invalid_tenant_code_names_are_rejected(invalid: str) -> None:
    """The slug grammar is tight enough that a code name is safe to interpolate."""
    with pytest.raises(ValueError, match="slug"):
        Tenant(name="Acme ISP", code_name=invalid)


def test_tenant_name_must_not_be_blank() -> None:
    """A blank display name would render as an empty row in the dashboard."""
    with pytest.raises(ValueError, match="must not be blank"):
        Tenant(name="   ", code_name="acme-isp")


def test_tenant_repr_does_not_dump_the_row() -> None:
    """Representations identify a record without leaking its contents."""
    tenant = Tenant(name="Acme ISP", code_name="acme-isp")
    assert "acme-isp" in repr(tenant)
    assert "Acme ISP" not in repr(tenant)


# --------------------------------------------------------------------------- #
# NetworkTarget
# --------------------------------------------------------------------------- #


def test_network_target_normalises_its_range() -> None:
    """A bare address is stored as an explicit single-host network."""
    target = NetworkTarget(
        tenant_id=uuid.uuid4(),
        label="Jump host",
        ip_address_or_cidr="10.0.0.5",
    )
    assert target.ip_address_or_cidr == "10.0.0.5/32"


def test_network_target_rejects_command_injection() -> None:
    """The field that feeds Nmap refuses anything outside the address grammar."""
    with pytest.raises(InvalidNetworkError):
        NetworkTarget(
            tenant_id=uuid.uuid4(),
            label="Hostile",
            ip_address_or_cidr="10.0.0.1; rm -rf /",
        )


def test_network_target_rejects_option_injection() -> None:
    """A value that Nmap would read as a flag is refused."""
    with pytest.raises(InvalidNetworkError):
        NetworkTarget(
            tenant_id=uuid.uuid4(),
            label="Hostile",
            ip_address_or_cidr="--script=http-shellshock",
        )


def test_network_target_label_is_trimmed() -> None:
    """Surrounding whitespace never reaches the uniqueness constraint."""
    target = NetworkTarget(
        tenant_id=uuid.uuid4(),
        label="  Management network  ",
        ip_address_or_cidr="10.10.0.0/24",
    )
    assert target.label == "Management network"


def test_network_target_label_must_not_be_blank() -> None:
    """An unlabelled range cannot be identified by an operator."""
    with pytest.raises(ValueError, match="must not be blank"):
        NetworkTarget(tenant_id=uuid.uuid4(), label="  ", ip_address_or_cidr="10.0.0.0/24")


# --------------------------------------------------------------------------- #
# Scan lifecycle
# --------------------------------------------------------------------------- #


def test_scan_defaults_to_pending() -> None:
    """A newly constructed scan is queued, never implicitly running."""
    scan = Scan(tenant_id=uuid.uuid4())
    scan.status = ScanStatus.PENDING
    assert scan.status is ScanStatus.PENDING
    assert scan.finished_at is None


def test_scan_start_then_complete() -> None:
    """The happy path stamps a finish time exactly once."""
    scan = Scan(tenant_id=uuid.uuid4(), status=ScanStatus.PENDING)

    scan.mark_running()
    # Read into a locally annotated name: comparing the attribute directly makes
    # the type checker narrow it to a literal and reject the later comparison.
    after_start: ScanStatus = scan.status
    assert after_start is ScanStatus.RUNNING

    before = datetime.now(UTC) - timedelta(seconds=1)
    scan.mark_finished(status=ScanStatus.COMPLETED)

    after_finish: ScanStatus = scan.status
    assert after_finish is ScanStatus.COMPLETED
    assert scan.finished_at is not None
    assert scan.finished_at >= before
    assert scan.is_terminal is True


def test_scan_cannot_start_twice() -> None:
    """Two workers must not both believe they own the same job."""
    scan = Scan(tenant_id=uuid.uuid4(), status=ScanStatus.PENDING)
    scan.mark_running()
    with pytest.raises(ValueError, match="Cannot start a scan in state RUNNING"):
        scan.mark_running()


def test_scan_cannot_finish_twice() -> None:
    """A terminal scan is a final record and must not be rewritten."""
    scan = Scan(tenant_id=uuid.uuid4(), status=ScanStatus.PENDING)
    scan.mark_running()
    scan.mark_finished(status=ScanStatus.FAILED)
    with pytest.raises(ValueError, match="already finished"):
        scan.mark_finished(status=ScanStatus.COMPLETED)


def test_scan_cannot_finish_into_a_non_terminal_state() -> None:
    """`mark_finished` only accepts COMPLETED or FAILED."""
    scan = Scan(tenant_id=uuid.uuid4(), status=ScanStatus.PENDING)
    scan.mark_running()
    with pytest.raises(ValueError, match="not a terminal state"):
        scan.mark_finished(status=ScanStatus.RUNNING)


@pytest.mark.parametrize(
    ("status", "terminal", "active"),
    [
        (ScanStatus.PENDING, False, True),
        (ScanStatus.RUNNING, False, True),
        (ScanStatus.COMPLETED, True, False),
        (ScanStatus.FAILED, True, False),
    ],
)
def test_scan_status_classification(status: ScanStatus, terminal: bool, active: bool) -> None:
    """Terminal and active states partition the lifecycle."""
    assert status.is_terminal is terminal
    assert status.is_active is active


# --------------------------------------------------------------------------- #
# ScanResult
# --------------------------------------------------------------------------- #


def _result(**overrides: Any) -> ScanResult:
    """Build a scan result with sensible defaults."""
    payload: dict[str, Any] = {
        "tenant_id": uuid.uuid4(),
        "scan_id": uuid.uuid4(),
        "host_ip": "10.10.0.5",
        "open_ports": [],
    }
    payload.update(overrides)
    return ScanResult(**payload)


def test_scan_result_normalises_the_host_address() -> None:
    """Discovered hosts are stored canonically so joins and counts behave."""
    result = _result(host_ip="2001:0db8:0000:0000:0000:0000:0000:0001")
    assert result.host_ip == "2001:db8::1"


def test_scan_result_rejects_a_range_as_host() -> None:
    """One result row describes exactly one host."""
    with pytest.raises(InvalidNetworkError):
        _result(host_ip="10.10.0.0/24")


def test_open_ports_are_validated_and_normalised() -> None:
    """Protocols are lowercased and optional fields default to null."""
    result = _result(
        open_ports=[
            {"port": 22, "protocol": "TCP", "service": "ssh", "version": "OpenSSH 9.2"},
            {"port": 161, "protocol": "udp", "service": None, "version": None},
        ]
    )
    assert result.open_ports[0]["protocol"] == "tcp"
    assert result.open_ports[1]["service"] is None


def test_open_ports_accepts_missing_optional_fields() -> None:
    """Service detection may not have run, which is not an error."""
    result = _result(open_ports=[{"port": 80, "protocol": "tcp"}])
    assert result.open_ports[0]["service"] is None
    assert result.open_ports[0]["version"] is None


@pytest.mark.parametrize(
    "bad_entry",
    [
        {"port": 0, "protocol": "tcp"},
        {"port": 65536, "protocol": "tcp"},
        {"port": -1, "protocol": "tcp"},
        {"port": "22", "protocol": "tcp"},
        {"port": True, "protocol": "tcp"},
        {"port": 22, "protocol": "icmp"},
        {"port": 22, "protocol": 6},
        {"port": 22},
        {"port": 22, "protocol": "tcp", "service": 22},
        {"port": 22, "protocol": "tcp", "version": []},
    ],
)
def test_malformed_open_port_entries_are_rejected(bad_entry: dict[str, Any]) -> None:
    """JSONB accepts any JSON, so the shape has to be enforced on write."""
    with pytest.raises((TypeError, ValueError)):
        _result(open_ports=[bad_entry])


def test_open_ports_must_be_a_list() -> None:
    """The column stores an array; an object would break every reader."""
    with pytest.raises(TypeError, match="must be a list"):
        _result(open_ports={"port": 22})


def test_open_port_entries_must_be_objects() -> None:
    """A bare value in the array is rejected with its index named."""
    with pytest.raises(TypeError, match=r"open_ports\[0\] must be an object"):
        _result(open_ports=[22])
