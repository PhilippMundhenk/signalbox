from factories import SITE, device, snapshot
from signalbox.merge import merge
from signalbox.model import DeviceRole, Firmware
from signalbox.rules import evaluate
from signalbox.rules.firmware import RULES


def run(*devices):  # type: ignore[no-untyped-def]
    net = merge([SITE], [snapshot(d) for d in devices])
    return [(f.rule_id, f.message) for f in evaluate(net, RULES)]


def ap(i: str, version: str | None, **fw: object):  # type: ignore[no-untyped-def]
    return device(
        i, DeviceRole.AP, vendor="Example", model="X1", firmware=Firmware(current=version, **fw)
    )


def test_same_firmware_is_fine() -> None:
    assert run(ap("a", "1.0"), ap("b", "1.0"), device("gw")) == []


def test_drift_between_identical_devices() -> None:
    ((rule, msg),) = run(ap("a", "1.0"), ap("b", "1.1"), ap("c", "1.1"))
    assert rule == "firmware.drift" and "3 devices of model x1 run 2 firmware versions" in msg
    assert "a: 1.0" in msg


def test_update_available_and_end_of_life() -> None:
    out = run(ap("a", "1.0", available="1.2", end_of_life=True), ap("b", None, available="1.2"))
    assert ("firmware.update-available", "a runs 1.0, 1.2 is available") in out
    assert ("firmware.end-of-life", "a runs firmware 1.0, which is end of life") in out
    assert len(out) == 2


def test_auto_update_off_and_reboot_pending() -> None:
    out = run(
        ap("off", "1.0", auto_update=False, reboot_pending=True),
        ap("on", "1.0", auto_update=True, reboot_pending=False),
        ap("unknown", "1.0"),
    )
    assert out == [
        ("firmware.auto-update-off", "off does not install updates by itself"),
        ("firmware.reboot-pending", "off needs a restart to finish an update"),
    ]


def test_package_update_counts_replace_the_generic_message() -> None:
    out = run(
        ap(
            "sec",
            "1.0",
            upgradable=True,
            security_update=True,
            pending_updates=5,
            pending_security_updates=2,
        ),
        ap("plain", "1.0", upgradable=True, pending_updates=3),
        ap("none", "1.0", upgradable=False, pending_updates=0, pending_security_updates=0),
    )
    assert out == [
        ("firmware.security-update", "sec has 2 security updates waiting"),
        ("firmware.update-available", "plain has 3 package updates waiting"),
    ]
