"""Exposure assessment for scan findings.

The scanner reports which ports are open; this module says which of those
*matter*, so an operator reading a report sees the telnet service that should
never be on the internet, not just another row in a list of a hundred.

What this is, and is not
------------------------
It is a heuristic classification by service and port: it flags a port as risky
because of *what it exposes* (a plaintext admin protocol, a database, a
deprecated VPN), not because it has found a vulnerability. It does not check
versions for CVEs, and a LOW rating is "not obviously dangerous to expose", not
"safe". Treat it as triage that points attention, not as a verdict.

It is a pure function over the ports already parsed and stored, computed on read
like the scan diff. Nothing here changes how Nmap runs or what is persisted, so
the taxonomy can be tuned without a migration.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from typing import Final

from app.models.scan_result import OpenPort


class Severity(IntEnum):
    """How concerning it is to find a service exposed.

    An ``IntEnum`` so severities sort and take a maximum naturally; the string
    name is what the API and UI display.
    """

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        """Lowercase name used in the API and UI, e.g. 'critical'."""
        return self.name.lower()


@dataclass(frozen=True, slots=True)
class PortAssessment:
    """The verdict on one open port."""

    severity: Severity
    reason: str


# Ports whose exposure is judged individually. The number is the reliable
# signal; the service name Nmap guessed is secondary and used only as a
# fallback below. Each entry pairs a severity with a short, plain reason.
_PORT_RULES: Final[dict[int, PortAssessment]] = {
    # Plaintext or legacy remote access, and admin surfaces that should never
    # face the internet: the highest concern.
    23: PortAssessment(Severity.CRITICAL, "Telnet exposes remote login in plaintext."),
    512: PortAssessment(Severity.CRITICAL, "rexec runs commands over an unauthenticated channel."),
    513: PortAssessment(Severity.CRITICAL, "rlogin trusts the network for authentication."),
    514: PortAssessment(Severity.CRITICAL, "rsh runs commands with no real authentication."),
    445: PortAssessment(
        Severity.CRITICAL, "SMB exposed to the internet is a frequent ransomware entry point."
    ),
    3389: PortAssessment(Severity.CRITICAL, "RDP exposed to the internet is heavily brute-forced."),
    2375: PortAssessment(Severity.CRITICAL, "Unencrypted Docker API grants full host control."),
    # Databases and data stores that should sit behind the network edge.
    1433: PortAssessment(Severity.CRITICAL, "Microsoft SQL Server should not be internet-facing."),
    3306: PortAssessment(Severity.CRITICAL, "MySQL should not be internet-facing."),
    5432: PortAssessment(Severity.CRITICAL, "PostgreSQL should not be internet-facing."),
    6379: PortAssessment(Severity.CRITICAL, "Redis often has no authentication by default."),
    9200: PortAssessment(
        Severity.CRITICAL, "Elasticsearch exposed often means an open data store."
    ),
    27017: PortAssessment(Severity.CRITICAL, "MongoDB exposed often means an open data store."),
    11211: PortAssessment(
        Severity.HIGH, "Memcached is unauthenticated and abused for amplification."
    ),
    # Legacy, cleartext or weak protocols.
    21: PortAssessment(Severity.HIGH, "FTP is cleartext and often anonymous."),
    69: PortAssessment(Severity.HIGH, "TFTP is unauthenticated file transfer."),
    161: PortAssessment(Severity.HIGH, "SNMP leaks device detail and is weakly authenticated."),
    1723: PortAssessment(Severity.HIGH, "PPTP is a deprecated VPN with broken encryption."),
    137: PortAssessment(Severity.HIGH, "NetBIOS leaks host and share information."),
    139: PortAssessment(Severity.HIGH, "NetBIOS session service exposes SMB over the network."),
    389: PortAssessment(
        Severity.HIGH, "LDAP without TLS carries directory credentials in the clear."
    ),
    # Management and web surfaces: worth review, not alarm.
    22: PortAssessment(
        Severity.MEDIUM, "SSH is encrypted but a common brute-force target when public."
    ),
    80: PortAssessment(Severity.MEDIUM, "Plaintext HTTP; confirm it only redirects to HTTPS."),
    8080: PortAssessment(Severity.MEDIUM, "Alternate HTTP, often an admin or proxy interface."),
    8000: PortAssessment(Severity.MEDIUM, "Alternate HTTP, often a device management interface."),
    8443: PortAssessment(Severity.MEDIUM, "Alternate HTTPS, often an admin interface."),
    8888: PortAssessment(Severity.MEDIUM, "Alternate HTTP, often an admin or notebook interface."),
    5000: PortAssessment(
        Severity.MEDIUM, "Alternate HTTP, often an application or admin interface."
    ),
    # Expected, encrypted services.
    443: PortAssessment(Severity.LOW, "HTTPS is expected on a public host."),
    993: PortAssessment(Severity.LOW, "IMAPS is encrypted mail retrieval."),
    995: PortAssessment(Severity.LOW, "POP3S is encrypted mail retrieval."),
    465: PortAssessment(Severity.LOW, "SMTPS is encrypted mail submission."),
}

# Fallbacks by service name for ports not in the table, so a database on a
# non-standard port is still caught when Nmap identified the service.
_SERVICE_KEYWORDS: Final[tuple[tuple[str, PortAssessment], ...]] = (
    ("telnet", PortAssessment(Severity.CRITICAL, "Telnet exposes remote login in plaintext.")),
    ("mysql", PortAssessment(Severity.CRITICAL, "A database should not be internet-facing.")),
    ("postgres", PortAssessment(Severity.CRITICAL, "A database should not be internet-facing.")),
    ("mongo", PortAssessment(Severity.CRITICAL, "A database should not be internet-facing.")),
    ("redis", PortAssessment(Severity.CRITICAL, "Redis often has no authentication by default.")),
    ("ms-sql", PortAssessment(Severity.CRITICAL, "A database should not be internet-facing.")),
    (
        "vnc",
        PortAssessment(Severity.CRITICAL, "VNC exposes a remote desktop, often weakly secured."),
    ),
    (
        "rdp",
        PortAssessment(Severity.CRITICAL, "RDP exposed to the internet is heavily brute-forced."),
    ),
    ("ftp", PortAssessment(Severity.HIGH, "FTP is cleartext and often anonymous.")),
    (
        "snmp",
        PortAssessment(Severity.HIGH, "SNMP leaks device detail and is weakly authenticated."),
    ),
    (
        "smb",
        PortAssessment(Severity.CRITICAL, "SMB exposed to the internet is a frequent entry point."),
    ),
    ("http", PortAssessment(Severity.MEDIUM, "A web interface; confirm it is meant to be public.")),
)

#: Applied when nothing above matches: an open port is worth noting, no more.
_UNKNOWN = PortAssessment(Severity.INFO, "Open port with no service-specific concern identified.")


def assess_port(port: OpenPort) -> PortAssessment:
    """Classify one open port by what it exposes.

    Ranked-port rules win over service-name fallbacks, because the port number
    is the more reliable signal and the service string is Nmap's guess.
    """
    ranked = _PORT_RULES.get(port["port"])
    if ranked is not None:
        return ranked

    service = (port.get("service") or "").lower()
    if service:
        for keyword, assessment in _SERVICE_KEYWORDS:
            if keyword in service:
                return assessment

    return _UNKNOWN
