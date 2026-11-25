"""Configuration state, backups and release channel rules (#181)."""

from datetime import timedelta

from factories import SITE, T0, device, snapshot
from signalbox.merge import merge
from signalbox.model import ConfigState, Firmware, FirmwareChannel, LocalBackups
from signalbox.rules import evaluate
from signalbox.rules import firmware as firmware_rules
from signalbox.rules.config_state import RULES
from signalbox.sightings import History


def run(rules, *devices, now=T0):  # type: ignore[no-untyped-def]
    net = merge([SITE], [snapshot(d) for d in devices])
    return [(f.rule_id, f.message) for f in evaluate(net, rules, history=History(now=now))]


def test_unsaved_and_pending_are_warnings() -> None:
    out = run(
        RULES,
        device("sw", config_state=ConfigState(unsaved=True)),
        device("ap", config_state=ConfigState(pending=True)),
    )
    assert (
        "config.unsaved",
        "sw runs a configuration that is not saved; a restart loses the changes",
    ) in out
    assert ("config.pending", "ap has configuration changes that are staged and not applied") in out
    assert len(out) == 2


def test_saved_or_unknown_configuration_is_quiet() -> None:
    quiet = run(
        RULES,
        device("a", config_state=ConfigState(unsaved=False, pending=False)),
        device("b", config_state=ConfigState(last_changed=T0)),
        device("c"),
    )
    assert quiet == []


def test_backup_none_needs_a_known_empty_list_and_no_signalbox_backup() -> None:
    out = run(
        RULES,
        device("none", local_backups=LocalBackups(count=0)),
        device("unknown"),
        device("mine", local_backups=LocalBackups(count=0), signalbox_backup_newest=T0),
        device(
            "old-mine",
            local_backups=LocalBackups(count=0),
            signalbox_backup_newest=T0 - timedelta(days=90),
        ),
    )
    assert sorted(m.split()[0] for r, m in out if r == "backup.none") == ["none", "old-mine"]


def test_old_backup_counts_only_when_the_configuration_changed_since() -> None:
    old = T0 - timedelta(days=60)
    out = run(
        RULES,
        device(
            "changed",
            local_backups=LocalBackups(count=3, newest=old),
            config_state=ConfigState(last_changed=T0 - timedelta(days=1)),
        ),
        device(
            "unchanged",
            local_backups=LocalBackups(count=3, newest=old),
            config_state=ConfigState(last_changed=old - timedelta(days=5)),
        ),
        device(
            "recent",
            local_backups=LocalBackups(count=3, newest=T0 - timedelta(days=2)),
            config_state=ConfigState(last_changed=T0),
        ),
    )
    assert [m.split()[0] for r, m in out if r == "backup.none"] == ["changed"]


def test_backup_rule_is_silent_without_a_clock() -> None:
    net = merge([SITE], [snapshot(device("x", local_backups=LocalBackups(count=0)))])
    assert evaluate(net, RULES) == []


def fw(**kw: object) -> Firmware:
    return Firmware(current="1.0", **kw)  # type: ignore[arg-type]


def test_beta_channel_and_security_update() -> None:
    out = run(
        firmware_rules.RULES,
        device("beta", firmware=fw(channel=FirmwareChannel.BETA)),
        device("stable", firmware=fw(channel=FirmwareChannel.STABLE)),
        device("sec", firmware=fw(available="1.1", security_update=True)),
        device("flag", firmware=fw(upgradable=True)),
    )
    assert ("firmware.beta-channel", "beta follows the beta channel") in out
    assert ("firmware.security-update", "sec has a security update available (1.1)") in out
    assert ("firmware.update-available", "flag has a firmware update available") in out
    assert len(out) == 3  # the security update is not reported a second time


def test_drift_does_not_compare_channels() -> None:
    def ap(i: str, version: str, channel: FirmwareChannel) -> object:
        return device(i, vendor="X", model="M", firmware=Firmware(current=version, channel=channel))

    out = run(
        [r for r in firmware_rules.RULES if r.id == "firmware.drift"],
        ap("a", "1.0", FirmwareChannel.STABLE),
        ap("b", "2.0b", FirmwareChannel.BETA),
    )
    assert out == []
