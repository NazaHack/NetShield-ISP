"""Request and response schemas for scans."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.core.network import InvalidNetworkError, normalise_network
from app.models.enums import ScanStatus
from app.workers.scanning.command import DEFAULT_SCAN_PROFILE, ScanProfile

#: Most ranges a single ad-hoc request may name. The per-scan address ceiling
#: still applies on top of this; the count bound just keeps an absurd payload
#: from reaching the policy filter at all.
MAX_INLINE_TARGETS = 32


class ScanLaunchRequest(BaseModel):
    """Payload for queueing a scan.

    Two ways to say what to scan:

    * Name a ``tenant_id`` and nothing else, and the client's registered ranges
      are scanned. This is what the per-client console does.
    * Supply ``targets`` directly, for a one-off check of a range that is not
      registered anywhere. ``tenant_id`` may then be omitted entirely.

    ``tenant_id`` is checked against the caller's token rather than trusted. A
    token scoped to one client that names another is answered with a 404.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    tenant_id: uuid.UUID | None = Field(
        default=None,
        description=(
            "Client whose registered ranges will be scanned. Omit it to run an "
            "ad-hoc scan, which is attributed to the platform's own workspace."
        ),
    )
    targets: list[str] | None = Field(
        default=None,
        max_length=MAX_INLINE_TARGETS,
        description=(
            "Addresses or CIDR blocks to scan instead of the client's registered "
            "ranges. Each is validated and checked against platform policy."
        ),
        examples=[["10.0.0.0/24"]],
    )
    profile: ScanProfile = Field(
        default=DEFAULT_SCAN_PROFILE,
        description=(
            "How thorough the scan is. 'fast' scans the 1000 common ports "
            "without version detection; 'balanced' adds version detection; "
            "'thorough' scans ports 1-10000 with version detection."
        ),
    )
    port_range: str | None = Field(
        default=None,
        min_length=1,
        max_length=100,
        # Digits, commas and hyphens only. The engine validates this again
        # before it reaches the argument vector; rejecting it here turns a
        # failed scan into a 422 the caller can act on.
        pattern=r"^[0-9,\-]+$",
        description=(
            "An explicit Nmap port specification, such as '22,80,443', that "
            "overrides the profile's own port selection. Omit it to let the "
            "profile choose."
        ),
        examples=["1-10000"],
    )

    @field_validator("targets")
    @classmethod
    def _validate_targets(cls, value: list[str] | None) -> list[str] | None:
        """Normalise each range and reject anything outside the address grammar.

        Validating here means a typo comes back as a 422 naming the field rather
        than as a failed scan the operator has to go and read logs about.
        """
        if value is None:
            return None
        if not value:
            msg = "targets must not be empty; omit the field to use the client's ranges"
            raise ValueError(msg)

        normalised: list[str] = []
        for raw in value:
            try:
                candidate = normalise_network(raw)
            except InvalidNetworkError as exc:
                raise ValueError(str(exc)) from exc
            if candidate not in normalised:
                normalised.append(candidate)
        return normalised


class ScanLaunchResponse(BaseModel):
    """Acknowledgement that a scan was queued."""

    model_config = ConfigDict(frozen=True)

    scan_id: uuid.UUID
    tenant_id: uuid.UUID
    status: ScanStatus
    task_id: str = Field(description="Celery task identifier, for correlating worker logs.")
    created_at: datetime
    targets: list[str] = Field(
        default_factory=list,
        description="The canonical ranges this scan will cover.",
    )
    profile: ScanProfile = Field(
        default=DEFAULT_SCAN_PROFILE,
        description="The thoroughness the scan will run at.",
    )
    is_adhoc: bool = Field(
        default=False,
        description="True when the scan was launched without naming a client.",
    )


class OpenPortRead(BaseModel):
    """One open port as reported by the scanner, with an exposure verdict.

    ``service`` and ``version`` are banner text from the scanned host. They have
    been stripped of control characters and length-bounded on the way in, but a
    client rendering them must still treat them as untrusted content.

    ``severity`` and ``severity_reason`` are the platform's own assessment of
    what exposing this port implies, derived on read. They are triage, not a
    vulnerability finding: see ``app.core.risk``.
    """

    model_config = ConfigDict(frozen=True)

    port: int = Field(ge=1, le=65535)
    protocol: str
    service: str | None = None
    version: str | None = None
    severity: str = Field(default="info", description="One of info, low, medium, high, critical.")
    severity_reason: str = Field(default="", description="Why the port earned that severity.")


class NotableFinding(BaseModel):
    """One high- or critical-severity finding, tied to its host."""

    model_config = ConfigDict(frozen=True)

    host_ip: str
    port: int
    protocol: str
    service: str | None
    severity: str
    reason: str


class AssessmentSummary(BaseModel):
    """A scan-level rollup of the exposure assessment.

    Gives an operator the headline before the host table: how many findings at
    each severity, and the concerning ones called out with the host they are on.
    """

    model_config = ConfigDict(frozen=True)

    counts: dict[str, int] = Field(
        default_factory=dict, description="Open-port count per severity level."
    )
    highest_severity: str = Field(
        default="info", description="The most severe finding in the whole scan."
    )
    notable: list[NotableFinding] = Field(
        default_factory=list,
        description="Findings at high or critical severity, worst first.",
    )


class ScanResultRead(BaseModel):
    """Findings for one host within a scan."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    host_ip: str
    open_ports: list[OpenPortRead]
    created_at: datetime


class ScanRead(BaseModel):
    """A scan without its findings, as listed in the history."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    tenant_id: uuid.UUID
    status: ScanStatus
    created_at: datetime
    finished_at: datetime | None


class PortChangeRead(BaseModel):
    """A port whose service or version moved between two scans."""

    model_config = ConfigDict(frozen=True)

    protocol: str
    port: int
    previous_service: str | None
    current_service: str | None
    previous_version: str | None
    current_version: str | None


class HostDiffRead(BaseModel):
    """How one host changed between two scans."""

    model_config = ConfigDict(frozen=True)

    host_ip: str
    opened_ports: list[OpenPortRead]
    closed_ports: list[OpenPortRead]
    changed_ports: list[PortChangeRead]


class ScanDiffRead(BaseModel):
    """Comparison against the tenant's previous completed scan."""

    model_config = ConfigDict(frozen=True)

    has_baseline: bool = Field(
        description=(
            "False when this is the tenant's first completed scan, in which case "
            "no change is reported rather than every host appearing as new."
        )
    )
    has_changes: bool
    previous_scan_id: uuid.UUID | None = None
    new_hosts: list[str]
    disappeared_hosts: list[str]
    opened_port_count: int
    closed_port_count: int
    host_diffs: list[HostDiffRead]


class ScanDetailRead(BaseModel):
    """A scan with its findings, returned once it has finished.

    ``results`` and ``diff`` are populated only for a COMPLETED scan. A pending
    or running scan reports its status with empty findings rather than a
    partial picture that could be mistaken for a final one.
    """

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    tenant_id: uuid.UUID
    status: ScanStatus
    created_at: datetime
    finished_at: datetime | None
    is_finished: bool = Field(description="True once the scan reached a terminal state.")
    host_count: int
    open_port_count: int
    results: list[ScanResultRead]
    assessment: AssessmentSummary | None = Field(
        default=None,
        description="Exposure assessment of the findings. Present once completed.",
    )
    diff: ScanDiffRead | None = None
