"""Device identity rules (#444): name mismatch and outdated boot loader."""

from typing import Any

from factories import SITE, device, snapshot
from signalbox.merge import merge
from signalbox.model import Device, Network
from signalbox.rules import Finding, Rule, RuleSettings, evaluate
from signalbox.rules.device_identity import RULES, bootloader_outdated, name_mismatch


def net_of(*devices: Device) -> Network:
    return merge([SITE], [snapshot(d) for d in devices])


def run(r: Rule, net: Network, raw: dict[str, Any] | None = None) -> list[Finding]:
    settings = {k: RuleSettings.model_validate(v) for k, v in (raw or {}).items()}
    return [f for f in evaluate(net, [r], settings) if f.rule_id == r.id]


def test_rules_are_exported() -> None:
    assert [r.id for r in RULES] == ["device.name-mismatch", "device.bootloader-outdated"]


def test_name_mismatch_reported() -> None:
    net = net_of(device("r1", name="Living room", hostname="hap-ax2"))
    (f,) = run(name_mismatch, net)
    assert f.params == {"name": "Living room", "hostname": "hap-ax2"}
    assert f.objects == ["r1"]


def test_name_mismatch_ignores_case_and_domain() -> None:
    for name, host in [("NAS", "nas"), ("nas", "nas.example.lan"), ("nas.lan", "NAS.example.org")]:
        assert run(name_mismatch, net_of(device("d", name=name, hostname=host))) == []


def test_name_mismatch_domain_stripping_can_be_switched_off() -> None:
    net = net_of(device("d", name="nas", hostname="nas.example.lan"))
    full = {"device.name-mismatch": {"params": {"strip_domain": 0}}}
    assert len(run(name_mismatch, net, full)) == 1


def test_name_mismatch_stays_quiet() -> None:
    assert run(name_mismatch, net_of(device("d", name="x"))) == []  # no hostname
    assert run(name_mismatch, net_of(device("d", name="x", hostname="  "))) == []
    assert run(name_mismatch, net_of(device("d", name="x", hostname="y", hosted_on="h"))) == []
    assert run(name_mismatch, net_of(device("d", name="192.0.2.1", hostname="router"))) == []
    assert run(name_mismatch, net_of(device("d", name="router", hostname="192.0.2.1"))) == []


def test_bootloader_outdated() -> None:
    net = net_of(device("r1", bootloader="7.15.3", bootloader_available="7.16"))
    (f,) = run(bootloader_outdated, net)
    assert f.params == {"name": "r1", "current": "7.15.3", "available": "7.16"}


def test_bootloader_current_missing_or_newer_stays_quiet() -> None:
    cases = [("7.16", "7.16"), ("7.16", "7.15.3"), ("7.16", None), (None, "7.16"), ("7.9", "7.10")]
    quiet = [c for c in cases if c != ("7.9", "7.10")]
    for cur, avail in quiet:
        net = net_of(device("r", bootloader=cur, bootloader_available=avail))
        assert run(bootloader_outdated, net) == []
    # numeric comparison: 7.9 is older than 7.10
    assert (
        len(
            run(
                bootloader_outdated,
                net_of(device("r", bootloader="7.9", bootloader_available="7.10")),
            )
        )
        == 1
    )


def test_uncomparable_versions_that_differ_are_reported() -> None:
    net = net_of(device("r", bootloader="old", bootloader_available="new"))
    assert len(run(bootloader_outdated, net)) == 1
