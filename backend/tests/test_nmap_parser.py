"""Tests for Nmap XML parsing.

The report is treated as untrusted input. Its service fields are banner text
returned by the scanned host, and the document itself arrives from a subprocess,
so the parser is tested against hostile documents as well as real ones.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from app.workers.scanning.parser import (
    MAX_BANNER_LENGTH,
    MAX_RAW_OUTPUT_LENGTH,
    NmapParseError,
    _sanitise,
    parse_nmap_xml,
)

FIXTURES = Path(__file__).parent / "fixtures"


def _wrap(hosts_xml: str) -> str:
    """Wrap host elements in a minimal but realistic nmaprun document."""
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<nmaprun scanner="nmap" version="7.93">\n'
        f"{hosts_xml}\n"
        "</nmaprun>"
    )


def _host(
    address: str = "10.10.0.5",
    *,
    state: str = "up",
    ports_xml: str = "",
    addrtype: str = "ipv4",
) -> str:
    """Build a single host element."""
    return (
        f'<host><status state="{state}"/>'
        f'<address addr="{address}" addrtype="{addrtype}"/>'
        f"<ports>{ports_xml}</ports></host>"
    )


def _port(
    portid: int = 22,
    *,
    protocol: str = "tcp",
    state: str = "open",
    service: str | None = "ssh",
    product: str | None = None,
    version: str | None = None,
    extrainfo: str | None = None,
) -> str:
    """Build a single port element."""
    attributes = ""
    if service is not None:
        attributes += f' name="{service}"'
    if product is not None:
        attributes += f' product="{product}"'
    if version is not None:
        attributes += f' version="{version}"'
    if extrainfo is not None:
        attributes += f' extrainfo="{extrainfo}"'
    service_xml = f"<service{attributes}/>" if attributes else ""
    return (
        f'<port protocol="{protocol}" portid="{portid}">'
        f'<state state="{state}"/>{service_xml}</port>'
    )


# --------------------------------------------------------------------------- #
# Real Nmap output
# --------------------------------------------------------------------------- #


def test_real_nmap_report_is_parsed() -> None:
    """Genuine Nmap 7.93 output, DOCTYPE and hosthint elements included."""
    report = parse_nmap_xml((FIXTURES / "nmap_real_scan.xml").read_text())

    assert len(report.hosts) == 2
    addresses = [host.host_ip for host in report.hosts]
    assert addresses == sorted(addresses), "hosts must come back in a stable order"

    by_address = {host.host_ip: host for host in report.hosts}
    postgres = next(host for host in by_address.values() if host.open_ports[0]["port"] == 5432)
    assert postgres.open_ports[0]["service"] == "postgresql"
    assert postgres.open_ports[0]["version"] == "PostgreSQL DB 9.6.0 or later"
    assert postgres.raw_output


def test_hosthint_elements_are_not_mistaken_for_hosts() -> None:
    """Nmap emits <hosthint> previews that must not become findings."""
    report = parse_nmap_xml((FIXTURES / "nmap_real_scan.xml").read_text())
    assert len(report.hosts) == 2


# --------------------------------------------------------------------------- #
# Hostile documents
# --------------------------------------------------------------------------- #


def test_external_entity_is_refused() -> None:
    """An XXE payload must not be resolved."""
    payload = (
        '<?xml version="1.0"?>'
        "<!DOCTYPE nmaprun [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>"
        '<nmaprun><host><status state="up"/>'
        '<address addr="&xxe;" addrtype="ipv4"/></host></nmaprun>'
    )
    with pytest.raises(NmapParseError):
        parse_nmap_xml(payload)


def test_entity_expansion_bomb_is_refused() -> None:
    """A billion-laughs document must not be expanded."""
    payload = (
        '<?xml version="1.0"?>'
        "<!DOCTYPE nmaprun ["
        "<!ENTITY a 'aaaaaaaaaa'>"
        "<!ENTITY b '&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;'>"
        "<!ENTITY c '&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;'>"
        "]>"
        "<nmaprun>&c;</nmaprun>"
    )
    with pytest.raises(NmapParseError):
        parse_nmap_xml(payload)


def test_delete_character_is_stripped_from_banners() -> None:
    """A control byte that XML permits must not survive into a finding.

    XML 1.0 forbids most control characters outright, so DEL (0x7f) is the one
    an actual document can carry.
    """
    xml = _wrap(_host(ports_xml=_port(product="Evil\x7fServer")))
    report = parse_nmap_xml(xml)

    version = report.hosts[0].open_ports[0]["version"]
    assert version == "EvilServer"


@pytest.mark.parametrize(
    ("hostile", "expected"),
    [
        # Stripping ESC leaves the literal "[31m", which is inert text. The
        # guarantee is that no control byte survives, not that the payload
        # vanishes.
        ("Evil\x1b[31mServer", "Evil[31mServer"),
        ("Evil\x00Server", "EvilServer"),
        ("Evil\x07Server", "EvilServer"),
        ("Evil\x7fServer", "EvilServer"),
        ("Evil\x08\x0b\x0cServer", "EvilServer"),
    ],
)
def test_sanitiser_strips_every_control_character(hostile: str, expected: str) -> None:
    """The sanitiser is the guard, independent of what XML happens to allow.

    Banner text is rendered in an operator's browser and written to a log
    aggregator, so control bytes are removed wherever they come from.
    """
    cleaned = _sanitise(hostile)

    assert cleaned == expected
    assert cleaned is not None
    assert not any(ord(char) < 0x20 or ord(char) == 0x7F for char in cleaned)


def test_sanitiser_maps_blank_input_to_null() -> None:
    """Whitespace-only detail is absent detail."""
    assert _sanitise("   ") is None
    assert _sanitise(None) is None


def test_overlong_banner_is_truncated() -> None:
    """A padded banner cannot be used to bloat the database."""
    xml = _wrap(_host(ports_xml=_port(product="A" * 5000)))
    report = parse_nmap_xml(xml)

    version = report.hosts[0].open_ports[0]["version"]
    assert version is not None
    assert len(version) <= MAX_BANNER_LENGTH


def test_raw_output_is_bounded() -> None:
    """The retained evidence fragment is length-capped."""
    padding = "B" * 200_000
    xml = _wrap(_host(ports_xml=_port(product=padding)))
    report = parse_nmap_xml(xml)

    assert len(report.hosts[0].raw_output) <= MAX_RAW_OUTPUT_LENGTH


def test_malformed_address_is_skipped_not_stored() -> None:
    """An address the platform cannot validate never reaches the database."""
    xml = _wrap(_host(address="10.0.0.1; rm -rf /", ports_xml=_port()))
    report = parse_nmap_xml(xml)

    assert report.hosts == ()


# --------------------------------------------------------------------------- #
# Filtering
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("state", ["closed", "filtered", "open|filtered"])
def test_non_open_ports_are_ignored(state: str) -> None:
    """`--open` should already filter these, but the parser does not rely on it."""
    xml = _wrap(_host(ports_xml=_port(state=state)))
    report = parse_nmap_xml(xml)

    assert report.hosts == ()
    assert report.hosts_without_open_ports == ("10.10.0.5",)


def test_host_that_is_down_is_ignored() -> None:
    """A host that did not answer produces no row at all."""
    xml = _wrap(_host(state="down", ports_xml=_port()))
    report = parse_nmap_xml(xml)

    assert report.hosts == ()
    assert report.hosts_without_open_ports == ()


def test_unknown_protocol_is_ignored() -> None:
    """Only protocols the results model accepts are stored."""
    xml = _wrap(_host(ports_xml=_port(protocol="icmp")))
    report = parse_nmap_xml(xml)

    assert report.hosts == ()


@pytest.mark.parametrize("portid", ["0", "65536", "notanumber", "-1"])
def test_out_of_range_ports_are_ignored(portid: str) -> None:
    """A port number outside 1-65535 is dropped rather than stored."""
    xml = _wrap(
        _host(ports_xml=f'<port protocol="tcp" portid="{portid}"><state state="open"/></port>')
    )
    report = parse_nmap_xml(xml)

    assert report.hosts == ()


def test_ports_are_sorted_for_stable_diffs() -> None:
    """A stable order keeps comparisons between scans meaningful."""
    ports = _port(443) + _port(22) + _port(80)
    report = parse_nmap_xml(_wrap(_host(ports_xml=ports)))

    numbers = [entry["port"] for entry in report.hosts[0].open_ports]
    assert numbers == [22, 80, 443]


def test_ipv6_host_is_parsed_and_compressed() -> None:
    """IPv6 addresses are stored in canonical compressed form."""
    xml = _wrap(
        _host(
            address="2001:0db8:0000:0000:0000:0000:0000:0001",
            addrtype="ipv6",
            ports_xml=_port(),
        )
    )
    report = parse_nmap_xml(xml)

    assert report.hosts[0].host_ip == "2001:db8::1"


def test_version_joins_product_version_and_extrainfo() -> None:
    """The stored version reads the way Nmap's own output column does."""
    xml = _wrap(_host(ports_xml=_port(product="OpenSSH", version="9.2p1", extrainfo="Debian 2")))
    report = parse_nmap_xml(xml)

    assert report.hosts[0].open_ports[0]["version"] == "OpenSSH 9.2p1 Debian 2"


def test_absent_service_detail_becomes_null() -> None:
    """An undetected service is represented as null, never as an empty string."""
    xml = _wrap(_host(ports_xml=_port(service=None)))
    report = parse_nmap_xml(xml)

    assert report.hosts[0].open_ports[0]["service"] is None
    assert report.hosts[0].open_ports[0]["version"] is None


def test_total_open_ports_counts_across_hosts() -> None:
    """The summary count spans every host in the run."""
    xml = _wrap(
        _host(address="10.0.0.1", ports_xml=_port(22) + _port(80))
        + _host(address="10.0.0.2", ports_xml=_port(443))
    )
    report = parse_nmap_xml(xml)

    assert report.total_open_ports == 3


# --------------------------------------------------------------------------- #
# Malformed documents
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "payload",
    ["", "   ", "not xml at all", "<nmaprun><host>", '<?xml version="1.0"?><other/>'],
)
def test_unusable_documents_raise(payload: str) -> None:
    """An empty, malformed or foreign document is an error, not an empty result."""
    with pytest.raises(NmapParseError):
        parse_nmap_xml(payload)
