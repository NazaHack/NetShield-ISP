"""Parsing of Nmap XML reports.

Everything in an Nmap report that describes a *service* is under the control of
the host being scanned. Product names, version strings and extra info are banner
text: a hostile host can return terminal escape sequences, megabytes of padding
or markup that will later be rendered in an operator's browser.

This module therefore treats the document as untrusted data:

* ``defusedxml`` parses it, closing entity-expansion denial of service and
  external entity resolution.
* Every text value is stripped of control characters and length-bounded before
  it becomes a finding.
* Addresses are re-validated through the same parser the rest of the platform
  uses, so a malformed address cannot reach the database.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Final

# Only the element type and the serialiser are taken from the standard
# library. Parsing is done by defusedxml below, so no untrusted document is
# ever handed to the stdlib parser.
from xml.etree.ElementTree import Element, tostring  # nosec B405

from defusedxml.common import DefusedXmlException
from defusedxml.ElementTree import ParseError, fromstring

from app.core.logging import get_logger
from app.core.network import InvalidNetworkError, normalise_host_address
from app.models.scan_result import ALLOWED_PROTOCOLS, MAX_PORT, MIN_PORT, OpenPort

logger = get_logger(__name__)

#: Maximum length kept from any single banner-derived string.
MAX_BANNER_LENGTH: Final[int] = 255

#: Maximum length of the per-host XML fragment retained as evidence.
MAX_RAW_OUTPUT_LENGTH: Final[int] = 64 * 1024

#: Control characters are stripped: they are meaningless in a service banner and
#: dangerous in a terminal or a log aggregator.
_CONTROL_CHARACTERS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


class NmapParseError(ValueError):
    """Raised when the report is not a usable Nmap XML document."""


@dataclass(frozen=True, slots=True)
class HostFinding:
    """Findings for one host that answered the scan."""

    #: Canonical address of the host.
    host_ip: str

    #: Open ports, in ascending port order.
    open_ports: tuple[OpenPort, ...]

    #: The host's XML fragment, kept as evidence and length-bounded.
    raw_output: str


@dataclass(frozen=True, slots=True)
class NmapReport:
    """A parsed Nmap run."""

    #: Hosts that were up and had at least one reportable port.
    hosts: tuple[HostFinding, ...] = field(default_factory=tuple)

    #: Hosts that were reachable but exposed no open port in the scanned range.
    #: Recorded so that "the host went quiet" is distinguishable from "the host
    #: disappeared" when a later scan is compared against this one.
    hosts_without_open_ports: tuple[str, ...] = field(default_factory=tuple)

    @property
    def total_open_ports(self) -> int:
        """How many open ports the run found across every host."""
        return sum(len(host.open_ports) for host in self.hosts)


def _sanitise(value: str | None) -> str | None:
    """Make a banner-derived string safe to store, log and render.

    Returns ``None`` for an absent or empty value, so that "not detected" is
    represented consistently rather than as an empty string in some rows.
    """
    if value is None:
        return None
    cleaned = _CONTROL_CHARACTERS.sub("", value).strip()
    if not cleaned:
        return None
    return cleaned[:MAX_BANNER_LENGTH]


def _service_version(service: Element | None) -> str | None:
    """Assemble the version string the way Nmap's own output column does.

    Nmap splits what an operator reads as one version into ``product``,
    ``version`` and ``extrainfo``. Joining them here keeps the stored value
    recognisable to anyone who has read Nmap output before.
    """
    if service is None:
        return None
    parts = [
        _sanitise(service.get("product")),
        _sanitise(service.get("version")),
        _sanitise(service.get("extrainfo")),
    ]
    joined = " ".join(part for part in parts if part)
    return _sanitise(joined)


def _host_address(host: Element) -> str | None:
    """Return the host's IP address, preferring IPv4 when both are present."""
    addresses = host.findall("address")
    for wanted in ("ipv4", "ipv6"):
        for address in addresses:
            if address.get("addrtype") != wanted:
                continue
            raw = address.get("addr")
            if not raw:
                continue
            try:
                return normalise_host_address(raw)
            except InvalidNetworkError:
                logger.warning("scan.parser_bad_address", address=raw[:64])
                return None
    return None


def _open_ports(host: Element) -> list[OpenPort]:
    """Extract the open ports of one host, skipping anything malformed."""
    findings: list[OpenPort] = []

    for port in host.iterfind("./ports/port"):
        state = port.find("state")
        if state is None or state.get("state") != "open":
            # `--open` already filters these out, but a report can also be
            # produced by another tool or an older Nmap.
            continue

        raw_port = port.get("portid")
        if raw_port is None or not raw_port.isdigit():
            continue
        number = int(raw_port)
        if not MIN_PORT <= number <= MAX_PORT:
            continue

        protocol = (port.get("protocol") or "").lower()
        if protocol not in ALLOWED_PROTOCOLS:
            continue

        service = port.find("service")
        findings.append(
            OpenPort(
                port=number,
                protocol=protocol,
                service=_sanitise(service.get("name")) if service is not None else None,
                version=_service_version(service),
            )
        )

    findings.sort(key=lambda entry: (entry["protocol"], entry["port"]))
    return findings


def _host_fragment(host: Element) -> str:
    """Serialise one host element as evidence, bounded in length."""
    try:
        fragment = tostring(host, encoding="unicode")
    except (TypeError, ValueError):  # pragma: no cover - defensive
        return ""
    cleaned = _CONTROL_CHARACTERS.sub("", fragment)
    return cleaned[:MAX_RAW_OUTPUT_LENGTH]


def parse_nmap_xml(xml_report: str) -> NmapReport:
    """Parse an Nmap XML report into validated findings.

    Args:
        xml_report: The document written by ``nmap -oX -``.

    Returns:
        The hosts that answered, each with its open ports.

    Raises:
        NmapParseError: The document is empty, malformed, not an Nmap run, or
            contains an XML construct the hardened parser refuses.
    """
    if not xml_report.strip():
        msg = "Nmap produced an empty report."
        raise NmapParseError(msg)

    try:
        root = fromstring(xml_report)
    except DefusedXmlException as exc:
        # An entity definition, an external reference or another construct the
        # hardened parser refuses. Nmap never emits these, so a report that
        # contains one did not come from a trustworthy run.
        logger.error("scan.report_rejected", reason=type(exc).__name__)
        msg = f"Nmap report contains a forbidden XML construct: {type(exc).__name__}"
        raise NmapParseError(msg) from exc
    except ParseError as exc:
        msg = f"Nmap report is not well-formed XML: {exc}"
        raise NmapParseError(msg) from exc

    if root.tag != "nmaprun":
        msg = f"Expected an <nmaprun> document, got <{root.tag}>."
        raise NmapParseError(msg)

    hosts: list[HostFinding] = []
    quiet_hosts: list[str] = []

    for host in root.iterfind("host"):
        status = host.find("status")
        if status is not None and status.get("state") != "up":
            continue

        address = _host_address(host)
        if address is None:
            continue

        ports = _open_ports(host)
        if not ports:
            quiet_hosts.append(address)
            continue

        hosts.append(
            HostFinding(
                host_ip=address,
                open_ports=tuple(ports),
                raw_output=_host_fragment(host),
            )
        )

    hosts.sort(key=lambda finding: finding.host_ip)

    logger.info(
        "scan.report_parsed",
        hosts_with_open_ports=len(hosts),
        hosts_without_open_ports=len(quiet_hosts),
        open_ports=sum(len(host.open_ports) for host in hosts),
    )

    return NmapReport(hosts=tuple(hosts), hosts_without_open_ports=tuple(sorted(quiet_hosts)))
