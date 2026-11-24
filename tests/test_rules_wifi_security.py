"""Wi-Fi security rules (#86, #89, #101, #104)."""

from typing import Any

import pytest

from factories import SITE, secure_wlan, wlan, wps
from signalbox.merge import merge
from signalbox.model import (
    Band,
    Cipher,
    SaePwe,
    SaeSettings,
    Security,
    SegmentPurpose,
    Site,
    Snapshot,
    WpsMethod,
    segment_id,
)
from signalbox.rules import Finding, Rule, Severity, evaluate
from signalbox.rules.wifi_security import (
    passphrase_reuse,
    six_ghz_h2e,
    weak_security,
    wpa3_available,
)
from signalbox.rules.wifi_security import wps as wps_rule
from signalbox.testing import passphrase_digest_key
from test_rules_wireless import ap, radio


def run(r: Rule, *snaps: Snapshot) -> list[Finding]:
    net = merge([SITE, Site(id="cabin", name="Cabin")], snaps, [])
    return [f for f in evaluate(net, [r]) if f.rule_id == r.id]


def one(dev: str = "ap1", ssid: str = "Example", **kw: Any) -> Snapshot:
    return ap(dev, wlans=[secure_wlan(dev, ssid, **kw)])


# wifi.weak-security ---------------------------------------------------------------------------


def test_weak_security_quiet_on_clean_baseline() -> None:
    assert run(weak_security, one()) == []
    assert run(weak_security, one(security=Security.OWE)) == []
    assert run(weak_security, one(security=Security.WPA3)) == []


def test_weak_security_quiet_without_details() -> None:
    assert run(weak_security, ap("ap1", wlans=[wlan("ap1", security=Security.WPA2)])) == []


@pytest.mark.parametrize(
    ("kw", "text", "severity"),
    [
        ({"security": Security.OPEN}, "open (no password)", Severity.ERROR),
        ({"security": Security.WEP}, "WEP", Severity.ERROR),
        ({"security": Security.WPA}, "WPA (version 1)", Severity.ERROR),
        ({"security": Security.WPA_WPA2}, "WPA/WPA2 mixed", Severity.WARNING),
        ({"ciphers": [Cipher.TKIP]}, "only TKIP", Severity.ERROR),
        ({"ciphers": [Cipher.CCMP, Cipher.TKIP]}, "also TKIP", Severity.WARNING),
        ({"group_cipher": Cipher.TKIP}, "TKIP (broadcast)", Severity.WARNING),
    ],
)
def test_weak_security_findings(kw: dict[str, Any], text: str, severity: Severity) -> None:
    (f,) = run(weak_security, one(**kw))
    assert text in f.message
    assert f.severity is severity
    assert f.fix and "AES" in f.fix


def test_weak_security_open_guest_is_a_warning() -> None:
    snap = ap(
        "ap1",
        wlans=[secure_wlan("ap1", security=Security.OPEN, purpose=SegmentPurpose.GUEST)],
    )
    (f,) = run(weak_security, snap)
    assert f.severity is Severity.WARNING
    assert f.fix and "OWE" in f.fix


# wifi.wpa3-available --------------------------------------------------------------------------


def wpa2_ap(supported: list[Security] | None, security: Security = Security.WPA2) -> Snapshot:
    return ap(
        "ap1",
        radios=[radio("ap1", supported_security=supported)],
        wlans=[secure_wlan("ap1", security=security)],
    )


def test_wpa3_available_finding() -> None:
    (f,) = run(wpa3_available, wpa2_ap([Security.WPA2, Security.WPA3]))
    assert f.severity is Severity.INFO
    assert "'Example' on ap1 uses WPA2 only" in f.message
    assert run(wpa3_available, wpa2_ap([Security.WPA2_WPA3]))


def test_wpa3_available_quiet() -> None:
    assert run(wpa3_available, wpa2_ap(None)) == []
    assert run(wpa3_available, wpa2_ap([Security.WPA2])) == []
    assert run(wpa3_available, wpa2_ap([Security.WPA3], Security.WPA2_WPA3)) == []


# wifi.passphrase-reuse ------------------------------------------------------------------------

LAN = segment_id(SITE.id, 10)
GUEST = segment_id(SITE.id, 30)


def two(
    a: dict[str, Any], b: dict[str, Any], pa: str = "same one", pb: str = "same one"
) -> Snapshot:
    return ap(
        "ap1",
        wlans=[
            secure_wlan("ap1", "Home", passphrase=pa, **a),
            secure_wlan("ap1", "Other", passphrase=pb, **b),
        ],
    )


def test_reuse_guest_with_main() -> None:
    with passphrase_digest_key():
        (f,) = run(passphrase_reuse, two({}, {"purpose": SegmentPurpose.GUEST}))
    assert f.message == "SSIDs 'Home', 'Other' use the same passphrase"
    assert f.fix and "guest network its own" in f.fix


def test_reuse_different_networks() -> None:
    with passphrase_digest_key():
        (f,) = run(passphrase_reuse, two({"segment_id": LAN}, {"segment_id": GUEST}))
    assert f.fix and "each network" in f.fix


def test_reuse_quiet_cases() -> None:
    with passphrase_digest_key():
        assert run(passphrase_reuse, two({}, {}, pb="other")) == []
        # one SSID per band in the same network
        assert run(passphrase_reuse, two({"segment_id": LAN}, {"segment_id": LAN})) == []
        # networks unknown, nobody a guest
        assert run(passphrase_reuse, two({}, {})) == []
        # same SSID on two radios
        snap = ap(
            "ap1",
            radios=[radio("ap1", "radio0"), radio("ap1", "radio1", Band.GHZ_2_4)],
            wlans=[secure_wlan("ap1", "Home"), secure_wlan("ap1", "Home", "radio1")],
        )
        assert run(passphrase_reuse, snap) == []
        # disabled guest
        off = two({}, {"purpose": SegmentPurpose.GUEST, "enabled": False})
        assert run(passphrase_reuse, off) == []
    # no digest key: nothing to compare
    assert run(passphrase_reuse, two({}, {"purpose": SegmentPurpose.GUEST})) == []


# wifi.wps -------------------------------------------------------------------------------------


def test_wps_pin_and_push_button() -> None:
    (f,) = run(wps_rule, one(wps=wps(WpsMethod.PIN)))
    assert f.severity is Severity.WARNING
    assert f.message == "WPS (PIN) is turned on for SSID 'Example' on ap1"
    (f,) = run(wps_rule, one(wps=wps()))
    assert f.severity is Severity.INFO
    assert "(push button)" in f.message
    (f,) = run(wps_rule, one(wps=wps(WpsMethod.NFC)))
    assert f.severity is Severity.INFO
    assert "(" not in f.message


def test_wps_quiet() -> None:
    assert run(wps_rule, one(wps=wps(enabled=False))) == []
    assert run(wps_rule, one(wps=None)) == []
    assert run(wps_rule, one(wps=wps(WpsMethod.PIN), enabled=False)) == []


# wifi.6ghz-h2e --------------------------------------------------------------------------------


def six(
    pwe: SaePwe | None, security: Security = Security.WPA3, band: Band = Band.GHZ_6
) -> Snapshot:
    return ap(
        "ap1",
        radios=[radio("ap1", band=band)],
        wlans=[secure_wlan("ap1", security=security, sae=SaeSettings(pwe=pwe))],
    )


def test_h2e_finding() -> None:
    (f,) = run(six_ghz_h2e, six(SaePwe.HUNTING_AND_PECKING))
    assert f.severity is Severity.ERROR
    assert "6 GHz radio of ap1" in f.message


def test_h2e_quiet() -> None:
    assert run(six_ghz_h2e, six(SaePwe.HASH_TO_ELEMENT)) == []
    assert run(six_ghz_h2e, six(SaePwe.BOTH)) == []
    assert run(six_ghz_h2e, six(None)) == []
    assert run(six_ghz_h2e, six(SaePwe.HUNTING_AND_PECKING, Security.WPA2_WPA3)) == []
    assert run(six_ghz_h2e, six(SaePwe.HUNTING_AND_PECKING, band=Band.GHZ_5)) == []
