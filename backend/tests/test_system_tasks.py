"""Tests for the worker's self-diagnostic probes.

Raw-socket readiness is decided empirically at runtime, by performing a real
loopback SYN scan. What is unit-tested here is the diagnosis that explains a
failure, because that is what an operator reads when scanning is broken, and the
kernel behaviour it encodes is easy to get wrong and silent when wrong.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Any

import pytest

from app.workers.tasks import system

#: Capability masks as `/proc/self/status` renders them.
_NET_RAW = f"{1 << 13:016x}"
_NET_RAW_AND_BIND = f"{(1 << 13) | (1 << 10):016x}"
_NONE = f"{0:016x}"

#: The fully correct production configuration.
_HEALTHY_FACTORS: dict[str, bool] = {
    "raw_in_bounding_set": True,
    "raw_already_effective": False,
    "binary_has_file_capabilities": True,
    "no_new_privs": False,
    "nmap_privileged_env": True,
}


def _explain(**overrides: bool) -> str:
    """Run the diagnosis against the healthy configuration with overrides."""
    return system._explain_missing_privileges(**{**_HEALTHY_FACTORS, **overrides})


# --------------------------------------------------------------------------- #
# Capability decoding
# --------------------------------------------------------------------------- #


def test_capability_bit_decoding() -> None:
    """Capability masks are decoded per bit, and garbage never raises."""
    assert system._has_capability(_NET_RAW, system._CAP_NET_RAW_BIT) is True
    assert system._has_capability(_NET_RAW_AND_BIND, system._CAP_NET_BIND_SERVICE_BIT) is True
    assert system._has_capability(_NONE, system._CAP_NET_RAW_BIT) is False
    assert system._has_capability("not-hex", system._CAP_NET_RAW_BIT) is False
    assert system._has_capability("", system._CAP_NET_RAW_BIT) is False


def test_proc_status_parsing_degrades_gracefully(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """An unreadable /proc/self/status yields an empty mapping, never a crash."""
    monkeypatch.setattr(system, "_PROC_STATUS_PATH", tmp_path / "definitely-absent")
    assert system._read_proc_status() == {}


def test_proc_status_parsing_reads_real_capability_fields() -> None:
    """On Linux the real status file exposes the fields the probe depends on."""
    fields = system._read_proc_status()
    assert {"CapBnd", "CapEff", "NoNewPrivs"} <= set(fields)


# --------------------------------------------------------------------------- #
# Diagnosis of a failed scan probe
# --------------------------------------------------------------------------- #


def test_missing_bounding_capability_is_diagnosed_first() -> None:
    """Without CAP_NET_RAW in the bounding set nothing else can rescue the worker."""
    assert "bounding set" in _explain(raw_in_bounding_set=False)


def test_missing_file_capabilities_is_diagnosed() -> None:
    """An unprivileged process gains capabilities on exec only through the binary."""
    assert "file capabilities" in _explain(binary_has_file_capabilities=False)


def test_no_new_privs_is_diagnosed() -> None:
    """The kernel discards a binary's file capabilities when NoNewPrivs is set.

    This is the combination that silently breaks every SYN scan, which is why
    `no-new-privileges` is not applied to the worker container.
    """
    assert "no_new_privs" in _explain(no_new_privs=True)


def test_effective_capability_makes_file_capabilities_irrelevant() -> None:
    """A process that already holds CAP_NET_RAW needs no file capabilities."""
    reason = _explain(raw_already_effective=True, binary_has_file_capabilities=False)
    assert "file capabilities" not in reason


def test_missing_nmap_privileged_is_diagnosed() -> None:
    """Nmap gates raw scans on geteuid(), so the capabilities alone are not enough."""
    assert "NMAP_PRIVILEGED" in _explain(nmap_privileged_env=False)


def test_fully_correct_configuration_has_no_obvious_cause() -> None:
    """When every precondition holds, the diagnosis says so rather than guessing."""
    assert "unrecognised" in _explain()


# --------------------------------------------------------------------------- #
# Verification of the scan probe itself
# --------------------------------------------------------------------------- #


def _fake_run(stdout: str = "", stderr: str = "", returncode: int = 0) -> Any:
    """Build a stand-in for a completed subprocess."""
    return subprocess.CompletedProcess(
        args=["nmap"], returncode=returncode, stdout=stdout, stderr=stderr
    )


def test_scan_probe_detects_privilege_refusal(monkeypatch: pytest.MonkeyPatch) -> None:
    """Nmap's own refusal is recognised even though it exits successfully."""
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *_a, **_k: _fake_run(
            stdout="You requested a scan type which requires root privileges."
        ),
    )
    verified, reason = system._verify_raw_socket_scan()

    assert verified is False
    assert "unprivileged" in reason


def test_scan_probe_detects_nonzero_exit(monkeypatch: pytest.MonkeyPatch) -> None:
    """A failing scanner is reported with its exit code."""
    monkeypatch.setattr(subprocess, "run", lambda *_a, **_k: _fake_run(returncode=2))
    verified, reason = system._verify_raw_socket_scan()

    assert verified is False
    assert "exited with code 2" in reason


def test_scan_probe_survives_a_missing_binary(monkeypatch: pytest.MonkeyPatch) -> None:
    """An absent scanner is a reportable condition, not a crash."""

    def raise_oserror(*_args: Any, **_kwargs: Any) -> Any:
        raise OSError(2, "No such file or directory")

    monkeypatch.setattr(subprocess, "run", raise_oserror)
    verified, reason = system._verify_raw_socket_scan()

    assert verified is False
    assert "could not be executed" in reason


def test_successful_scan_probe_reports_verification(monkeypatch: pytest.MonkeyPatch) -> None:
    """A clean run is reported as empirically verified."""
    monkeypatch.setattr(subprocess, "run", lambda *_a, **_k: _fake_run(stdout="Nmap done: 1 IP"))
    verified, reason = system._verify_raw_socket_scan()

    assert verified is True
    assert "loopback SYN scan" in reason


# --------------------------------------------------------------------------- #
# The combined probe
# --------------------------------------------------------------------------- #


def test_probe_reports_all_diagnostic_factors(monkeypatch: pytest.MonkeyPatch) -> None:
    """The report carries every field an operator needs to locate the problem."""
    monkeypatch.setattr(
        system,
        "_read_proc_status",
        lambda: {"CapBnd": _NET_RAW_AND_BIND, "CapEff": _NONE, "NoNewPrivs": "0"},
    )
    monkeypatch.setattr(system, "_verify_raw_socket_scan", lambda: (True, "verified"))
    monkeypatch.setattr(os, "getxattr", lambda *_a, **_k: b"\x01\x00\x00\x02")
    monkeypatch.setenv("NMAP_PRIVILEGED", "1")

    report = system._probe_scan_privileges()

    assert report["raw_socket_scanning"] is True
    assert report["cap_net_raw_in_bounding_set"] is True
    assert report["cap_net_bind_service_in_bounding_set"] is True
    assert report["binary_has_file_capabilities"] is True
    assert report["no_new_privs"] is False
    assert report["nmap_privileged_env"] is True


def test_probe_explains_a_failed_verification(monkeypatch: pytest.MonkeyPatch) -> None:
    """When the real scan fails, the report names the missing precondition."""
    monkeypatch.setattr(
        system,
        "_read_proc_status",
        lambda: {"CapBnd": _NONE, "CapEff": _NONE, "NoNewPrivs": "0"},
    )
    monkeypatch.setattr(system, "_verify_raw_socket_scan", lambda: (False, "probe failed"))
    monkeypatch.setattr(os, "getxattr", lambda *_a, **_k: b"\x01\x00\x00\x02")

    report = system._probe_scan_privileges()

    assert report["raw_socket_scanning"] is False
    assert "bounding set" in report["reason"]
