"""Wi-Fi security details of the model (#167): fields, keyed passphrase digest, contract checks."""

from __future__ import annotations

from pathlib import Path

import pytest
from cryptography.fernet import Fernet
from pydantic import ValidationError

from factories import SITE, device, radio, secure_wlan, snapshot, wlan, wps
from signalbox.merge import merge
from signalbox.model import (
    Cipher,
    DeviceRole,
    Network,
    SaePwe,
    SaeSettings,
    Security,
    Snapshot,
    Wps,
    WpsMethod,
    json_schema,
    passphrase_digest,
    passphrase_fingerprint,
    set_passphrase_digest_key,
)
from signalbox.recording import SECRET_FIELDS
from signalbox.rules.wifi_hygiene import SECURITY_TEXT
from signalbox.secrets import Vault
from signalbox.service import build
from signalbox.testing import (
    TEST_DIGEST_KEY,
    passphrase_digest_key,
    radio_problems,
    wlan_problems,
)
from signalbox.web.app import public_network

PASS = "correct horse battery staple"


def test_details_default_to_not_reported() -> None:
    w = wlan("ap")
    for field in (
        "ciphers",
        "group_cipher",
        "sae",
        "wps",
        "passphrase_digest",
        "key_rotation_seconds",
        "beacon_protection",
    ):
        assert getattr(w, field) is None, field
    assert radio("ap").supported_security is None


def test_new_security_values_and_bounds() -> None:
    assert [
        Security(v)
        for v in ("wep", "wpa-psk", "wpa-wpa2-psk", "wpa-enterprise", "wpa3-enterprise-192")
    ]
    assert {c.value for c in Cipher} == {"ccmp", "ccmp-256", "gcmp", "gcmp-256", "tkip", "wep"}
    assert SaeSettings(pwe=SaePwe.HASH_TO_ELEMENT).pwe is SaePwe.HASH_TO_ELEMENT
    for bad in (
        {"key_rotation_seconds": -1},
        {"passphrase_digest": "not hex"},
    ):
        with pytest.raises(ValidationError):
            wlan("ap", **bad)
    with pytest.raises(ValidationError):
        SaeSettings(anti_clogging_threshold=-1)


def test_every_security_value_has_a_rule_text() -> None:
    assert set(SECURITY_TEXT) == set(Security)


def test_digest_needs_the_installation_key() -> None:
    assert passphrase_digest(PASS) is None
    with passphrase_digest_key() as key:
        assert key == TEST_DIGEST_KEY
        one = passphrase_digest(PASS)
        assert one is not None and len(one) == 16
        assert one == passphrase_digest(PASS)  # comparable across SSIDs: no SSID in it
        assert one != passphrase_digest(PASS + "!")
        assert one not in (
            passphrase_fingerprint("Example", PASS),
            passphrase_fingerprint("", PASS),
        )
        with passphrase_digest_key(b"x" * 32):
            assert passphrase_digest(PASS) != one  # another installation, another digest
        assert passphrase_digest(PASS) == one
    assert passphrase_digest(PASS) is None
    with pytest.raises(ValueError, match="32 bytes"):
        set_passphrase_digest_key(b"short")


def test_vault_derives_separate_keys() -> None:
    vault = Vault(Fernet.generate_key())
    key = vault.derive_key("passphrase-digest")
    assert len(key) == 32 and key == vault.derive_key("passphrase-digest")
    assert key != vault.derive_key("other")
    assert key != Vault(Fernet.generate_key()).derive_key("passphrase-digest")


def test_service_installs_a_key_from_the_vault(tmp_path: Path) -> None:
    secret = Fernet.generate_key()
    old = set_passphrase_digest_key(None)
    try:
        build(tmp_path, env={"SIGNALBOX_SECRET_KEY": secret.decode()}, adapters={}, rules=[])
        digest = passphrase_digest(PASS)
        with passphrase_digest_key(Vault(secret).derive_key("passphrase-digest")):
            assert digest is not None and digest == passphrase_digest(PASS)
    finally:
        set_passphrase_digest_key(old)


def test_digest_never_leaves_the_server() -> None:
    with passphrase_digest_key():
        w = secure_wlan("ap")
    assert w.passphrase_digest is not None
    data = public_network(Network(wlans=[w]))
    assert "passphrase_digest" not in data["wlans"][0]
    assert "passphrase_fingerprint" not in data["wlans"][0]
    assert SECRET_FIELDS.search("passphrase_digest")  # recordings redact it


def test_details_survive_json_and_merge() -> None:
    with passphrase_digest_key():
        w = secure_wlan("ap", wps=wps(WpsMethod.PIN, ap_pin_locked=True))
    r = radio("ap", supported_security=[Security.WPA2, Security.WPA3, Security.WPA2_WPA3])
    snap = snapshot(device("ap", DeviceRole.AP), radios=[r], wlans=[w])
    assert Snapshot.model_validate_json(snap.model_dump_json()) == snap
    net = merge([SITE], [snap])
    assert net.wlans == [w] and net.radios == [r]
    assert "passphrase_digest" in json_schema()["$defs"]["Wlan"]["properties"]


def test_a_clean_wlan_has_no_problems() -> None:
    r = radio("ap", supported_security=[Security.WPA2, Security.WPA2_WPA3])
    with passphrase_digest_key():
        assert wlan_problems(secure_wlan("ap"), r) == []
    assert radio_problems(r) == []
    assert wlan_problems(wlan("ap", security=Security.OPEN, ciphers=[]), None) == []
    assert wlan_problems(wlan("ap", security=Security.WEP, ciphers=[Cipher.WEP]), None) == []
    assert (
        wlan_problems(
            wlan("ap", security=Security.OTHER), radio("ap", supported_security=[Security.WPA2])
        )
        == []
    )


def test_contract_finds_inconsistent_details() -> None:
    def text(*problems: list[str]) -> str:
        return "\n".join(p for ps in problems for p in ps)

    found = text(
        wlan_problems(wlan("ap", "a", security=Security.OPEN, passphrase_digest="0" * 16)),
        wlan_problems(wlan("ap", "b", security=Security.OWE, passphrase_fingerprint="0" * 16)),
        wlan_problems(wlan("ap", "c", ciphers=[])),
        wlan_problems(wlan("ap", "d", ciphers=[Cipher.CCMP, Cipher.CCMP])),
        wlan_problems(wlan("ap", "e", security=Security.OPEN, ciphers=[Cipher.CCMP])),
        wlan_problems(wlan("ap", "f", security=Security.WEP, ciphers=[Cipher.TKIP])),
        wlan_problems(wlan("ap", "g", security=Security.WPA2, ciphers=[Cipher.WEP])),
        wlan_problems(wlan("ap", "h", security=Security.OPEN, group_cipher=Cipher.CCMP)),
        wlan_problems(wlan("ap", "i", security=Security.WPA2, sae=SaeSettings())),
        wlan_problems(wlan("ap", "j", wps=Wps(enabled=False, methods=[WpsMethod.PIN]))),
        wlan_problems(wlan("ap", "k"), radio("ap", supported_security=[Security.WPA2])),
        radio_problems(radio("ap", "r1", supported_security=[])),
        radio_problems(radio("ap", "r2", supported_security=[Security.WPA2, Security.WPA2])),
    )
    for needle in [
        "a/radio0: passphrase digest with security open",
        "b/radio0: passphrase fingerprint with security owe",
        "c/radio0: empty ciphers (None: not reported)",
        "d/radio0: ciphers list a cipher twice",
        "e/radio0: an open network has no ciphers",
        "f/radio0: a WEP network with other ciphers than wep",
        "g/radio0: cipher wep with security wpa2-psk",
        "h/radio0: an open network has no group cipher",
        "i/radio0: SAE settings with security wpa2-psk",
        "j/radio0: WPS methods while WPS is off",
        "k/radio0: wpa2-wpa3 is not in its radio's supported_security",
        "radio ap/radio/r1: empty supported_security",
        "radio ap/radio/r2: supported_security lists a mode twice",
    ]:
        assert needle in found, needle


def test_wps_factory() -> None:
    assert wps() == Wps(enabled=True, methods=[WpsMethod.PUSH_BUTTON])
    assert wps(enabled=False) == Wps(enabled=False)
