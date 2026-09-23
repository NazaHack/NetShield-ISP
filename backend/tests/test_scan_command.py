"""Tests for scan policy and Nmap argument construction.

The argument vector is the last place a hostile value could become an executed
option, so both the policy filter and the vector itself are covered closely.
"""

from __future__ import annotations

import pytest

from app.core.config import Settings, get_settings
from app.core.network import InvalidNetworkError
from app.workers.scanning.command import (
    DEFAULT_PORT_RANGE,
    THOROUGH_PORT_RANGE,
    TOP_PORTS,
    ScanCommand,
    ScanProfile,
    TargetNotPermittedError,
    assert_target_is_permitted,
    build_scan_command,
    select_scannable_targets,
)


@pytest.fixture(autouse=True)
def _clear_settings_cache() -> None:
    """Drop the cached settings so per-test overrides take effect."""
    get_settings.cache_clear()


def _override_settings(monkeypatch: pytest.MonkeyPatch, **overrides: object) -> None:
    """Replace the settings object seen by the command module."""
    from app.workers.scanning import command as command_module

    base: Settings = get_settings()
    monkeypatch.setattr(command_module, "settings", base.model_copy(update=overrides))


# --------------------------------------------------------------------------- #
# Policy
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "target",
    ["10.10.0.0/24", "100.64.0.0/22", "192.168.1.0/24", "203.0.113.0/24"],
)
def test_ordinary_targets_are_permitted(target: str) -> None:
    """A private or documentation range an ISP owns passes policy."""
    assert assert_target_is_permitted(target) == target


@pytest.mark.parametrize(
    "forbidden",
    [
        "169.254.0.0/16",  # link-local, includes cloud instance metadata
        "169.254.169.254",  # the metadata endpoint itself
        "127.0.0.0/8",  # loopback, from the configured denylist
        "127.0.0.1",
        "224.0.0.0/4",  # multicast
        "239.255.255.250",
        "255.255.255.255",
        "0.0.0.0/8",
        "ff02::1",  # IPv6 multicast
        "fe80::1",  # IPv6 link-local
    ],
)
def test_forbidden_ranges_are_refused(forbidden: str) -> None:
    """Ranges that are never scannable are refused whatever the tenant owns."""
    with pytest.raises(TargetNotPermittedError):
        assert_target_is_permitted(forbidden)


def test_a_wide_range_containing_a_forbidden_one_is_refused() -> None:
    """A tenant must not reach a forbidden range by owning a block around it.

    Containment is tested by overlap rather than by subset, so `0.0.0.0/0` does
    not become a way to scan loopback and link-local space.
    """
    with pytest.raises(TargetNotPermittedError):
        assert_target_is_permitted("0.0.0.0/0")


def test_private_ranges_can_be_disallowed(monkeypatch: pytest.MonkeyPatch) -> None:
    """An operator running only against public space can turn RFC 1918 off."""
    _override_settings(monkeypatch, scan_allow_private_ranges=False)

    with pytest.raises(TargetNotPermittedError, match="private"):
        assert_target_is_permitted("10.10.0.0/24")


@pytest.mark.parametrize(
    "hostile",
    ["10.0.0.1; id", "--script=http-shellshock", "-iL /etc/passwd", "attacker.test", ""],
)
def test_non_addresses_are_refused_before_policy(hostile: str) -> None:
    """Anything outside the address grammar fails at parsing, not at policy."""
    with pytest.raises(InvalidNetworkError):
        assert_target_is_permitted(hostile)


# --------------------------------------------------------------------------- #
# Selection
# --------------------------------------------------------------------------- #


def test_a_forbidden_target_does_not_fail_the_whole_scan(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """One bad range must not stop an ISP auditing the rest of its estate."""
    _override_settings(monkeypatch, nmap_max_targets_per_scan=4096)

    selection = select_scannable_targets(["10.10.0.0/24", "127.0.0.0/8", "192.168.5.0/24"])

    assert selection.accepted == ("10.10.0.0/24", "192.168.5.0/24")
    assert len(selection.rejected) == 1
    assert selection.rejected[0][0] == "127.0.0.0/8"
    assert selection.total_addresses == 512


def test_the_shipped_default_ceiling_is_realistic_for_an_isp() -> None:
    """The default must accommodate the ranges an ISP actually registers.

    A /22 CGNAT pool is 1024 addresses. The value is read from the field
    declaration rather than from a live settings object, so the assertion holds
    regardless of what the surrounding environment sets.
    """
    shipped_default = Settings.model_fields["nmap_max_targets_per_scan"].default

    assert shipped_default >= 1024, "a /22 CGNAT pool must fit within the default"


def test_a_cgnat_pool_and_a_management_network_scan_together(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The two ranges the seed creates are scannable in one job."""
    _override_settings(
        monkeypatch,
        nmap_max_targets_per_scan=Settings.model_fields["nmap_max_targets_per_scan"].default,
    )

    selection = select_scannable_targets(["10.10.0.0/24", "100.64.0.0/22"])

    assert selection.accepted == ("10.10.0.0/24", "100.64.0.0/22")
    assert selection.rejected == ()


def test_selection_fails_when_nothing_remains() -> None:
    """A scan with no scannable target is a failure, not an empty success."""
    with pytest.raises(TargetNotPermittedError, match="No scannable target"):
        select_scannable_targets(["127.0.0.1", "169.254.169.254"])


def test_selection_fails_on_an_empty_target_list() -> None:
    """A tenant with no registered range cannot be scanned."""
    with pytest.raises(TargetNotPermittedError):
        select_scannable_targets([])


def test_address_ceiling_is_enforced(monkeypatch: pytest.MonkeyPatch) -> None:
    """The per-scan ceiling stops an accidental sweep of a very large block."""
    _override_settings(monkeypatch, nmap_max_targets_per_scan=300)

    selection = select_scannable_targets(["10.0.0.0/24", "10.1.0.0/16", "10.2.0.0/28"])

    assert "10.0.0.0/24" in selection.accepted
    assert "10.1.0.0/16" not in selection.accepted
    assert selection.total_addresses <= 300
    assert any("ceiling" in reason for _, reason in selection.rejected)


# --------------------------------------------------------------------------- #
# Argument vector
# --------------------------------------------------------------------------- #


def test_command_matches_the_specified_shape() -> None:
    """The vector carries the intended timing, output mode and common flags."""
    command = build_scan_command(["10.10.0.0/24"])

    assert "-T4" in command.argv
    assert "--open" in command.argv
    # `-oX -` writes to stdout, so no filesystem path is ever passed to Nmap.
    assert command.argv[command.argv.index("-oX") + 1] == "-"


def test_the_default_profile_is_balanced() -> None:
    """The default scans the common ports with version detection, not all 10000.

    The port count is what makes a large scan slow, so the default trades the
    9000 rarely-open high ports for a scan that finishes in a fraction of the
    time while still reporting service versions.
    """
    command = build_scan_command(["10.10.0.0/24"])

    assert "-sV" in command.argv
    assert command.argv[command.argv.index("--top-ports") + 1] == str(TOP_PORTS)
    assert "-p" not in command.argv


def test_the_fast_profile_skips_version_detection() -> None:
    """Fast is the quickest: common ports, and no probing for banners.

    This is what a bare `nmap <target>` does, and it is the profile that matches
    an operator's "it took fifteen seconds on the console" expectation.
    """
    command = build_scan_command(["10.10.0.0/24"], profile=ScanProfile.FAST)

    assert "-sV" not in command.argv
    assert command.argv[command.argv.index("--top-ports") + 1] == str(TOP_PORTS)


def test_the_thorough_profile_scans_the_full_range_with_versions() -> None:
    """Thorough is the old behaviour: ports 1-10000 with version detection."""
    command = build_scan_command(["10.10.0.0/24"], profile=ScanProfile.THOROUGH)

    assert "-sV" in command.argv
    assert command.argv[command.argv.index("-p") + 1] == THOROUGH_PORT_RANGE
    assert command.argv[command.argv.index("-p") + 1] == DEFAULT_PORT_RANGE
    assert "--top-ports" not in command.argv


def test_an_explicit_port_range_overrides_the_profile() -> None:
    """A port range the operator typed wins over the profile's own selection."""
    command = build_scan_command(["10.10.0.0/24"], profile=ScanProfile.FAST, port_range="22,80,443")

    assert command.argv[command.argv.index("-p") + 1] == "22,80,443"
    assert "--top-ports" not in command.argv


def test_fast_is_meaningfully_cheaper_than_thorough() -> None:
    """The whole point: fast probes far fewer ports and skips version detection."""
    fast = build_scan_command(["10.10.0.0/24"], profile=ScanProfile.FAST)
    thorough = build_scan_command(["10.10.0.0/24"], profile=ScanProfile.THOROUGH)

    assert "-sV" not in fast.argv
    assert "-sV" in thorough.argv
    assert "--top-ports" in fast.argv
    assert "1-10000" in thorough.argv


def test_command_disables_dns_and_asserts_privilege() -> None:
    """Both additions to the baseline command are present and deliberate."""
    command = build_scan_command(["10.10.0.0/24"])

    assert "-n" in command.argv
    assert "--privileged" in command.argv


def test_targets_are_the_trailing_arguments() -> None:
    """Targets come last, after every flag, so none can be read as an option."""
    targets = ["10.10.0.0/24", "192.168.1.0/24"]
    command = build_scan_command(targets)

    assert command.argv[-2:] == tuple(targets)
    assert command.targets == tuple(targets)


def test_command_reports_the_address_count() -> None:
    """The covered address count is available for logging and quotas."""
    command = build_scan_command(["10.10.0.0/24", "192.168.1.0/30"])

    assert command.total_addresses == 256 + 4


def test_command_requires_at_least_one_target() -> None:
    """Nmap with no target would scan nothing and exit non-zero."""
    with pytest.raises(ValueError, match="at least one target"):
        build_scan_command([])


@pytest.mark.parametrize(
    "hostile_range",
    ["1-10000; id", "$(id)", "1-10000 --script=vuln", "0-100", "1-70000", "", "1-2-3"],
)
def test_malformed_port_ranges_are_refused(hostile_range: str) -> None:
    """The port range is the one free-form element, so it is constrained too."""
    with pytest.raises(ValueError):
        build_scan_command(["10.10.0.0/24"], port_range=hostile_range)


@pytest.mark.parametrize("valid_range", ["1-10000", "22", "22,80,443", "1-1024,8080"])
def test_reasonable_port_ranges_are_accepted(valid_range: str) -> None:
    """Ordinary Nmap port specifications still work."""
    command = build_scan_command(["10.10.0.0/24"], port_range=valid_range)

    assert valid_range in command.argv


def test_redacted_command_does_not_inline_every_target() -> None:
    """Log lines must not copy a tenant's whole network map into the log store."""
    command = build_scan_command([f"10.{index}.0.0/24" for index in range(20)])
    rendered = command.redacted()

    assert "10.5.0.0/24" not in rendered
    assert "20 target(s)" in rendered
    assert "-sV" in rendered


def test_scan_command_is_immutable() -> None:
    """A prepared command cannot be altered between validation and execution."""
    command = build_scan_command(["10.10.0.0/24"])

    assert isinstance(command, ScanCommand)
    with pytest.raises(AttributeError):
        command.argv = ()  # type: ignore[misc]
