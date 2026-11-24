"""BSSIDs and neighbouring networks in the integrations, the contract and the API (#169)."""

from __future__ import annotations

from typing import Any

import pytest

from signalbox.adapters import Observation, _cap_scan
from signalbox.adapters.omada import _rogue_security
from signalbox.adapters.openwrt import radio as radio_state
from signalbox.model import (
    SCAN_LIMIT,
    Band,
    Security,
    WifiScanResult,
    scan_id,
)
from signalbox.testing import scan_problems
from test_rules_wireless import radio


def result(dev: str = "ap1", bssid: str = "02:5e:00:00:00:01", **kw: Any) -> WifiScanResult:
    rid = kw.pop("radio_id", f"{dev}/radio/radio0")
    return WifiScanResult(
        id=kw.pop("id", scan_id(rid or dev, bssid)), device_id=dev, radio_id=rid, bssid=bssid, **kw
    )


# OpenWrt ------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("enc", "expected"),
    [
        (None, None),
        ({"enabled": False}, Security.OPEN),
        ({}, None),
        ({"enabled": True, "authentication": ["owe"], "wpa": [3]}, Security.OWE),
        ({"enabled": True, "wep": ["open"]}, Security.WEP),
        ({"enabled": True}, Security.WEP),
        ({"enabled": True, "wpa": [3], "authentication": ["802.1x"]}, Security.WPA3_ENTERPRISE),
        ({"enabled": True, "wpa": [1, 2], "authentication": ["802.1x"]}, Security.WPA_ENTERPRISE),
        ({"enabled": True, "wpa": [2], "authentication": ["802.1x"]}, Security.WPA2_ENTERPRISE),
        ({"enabled": True, "wpa": [3], "authentication": ["sae"]}, Security.WPA3),
        ({"enabled": True, "wpa": [1], "authentication": ["psk"]}, Security.WPA),
        ({"enabled": True, "wpa": [1, 2], "authentication": ["psk"]}, Security.WPA_WPA2),
        ({"enabled": True, "wpa": [2], "authentication": ["psk"]}, Security.WPA2),
        ({"enabled": True, "wpa": [2], "authentication": ["ft"]}, Security.OTHER),
    ],
)
def test_scan_security(enc: Any, expected: Security | None) -> None:
    assert radio_state.scan_security(enc) is expected


def test_scan_rows_skip_what_is_no_access_point() -> None:
    rows = radio_state.scan(
        {
            "results": [
                {"bssid": "02:5E:00:00:00:01", "mode": "Ad-Hoc"},
                {"bssid": "bogus"},
                {
                    "bssid": "02:5E:00:00:00:02",
                    "signal": 0,
                    "vht_operation": {"channel_width": 8080},
                },
                "junk",
            ]
        }
    )
    assert rows == [
        {
            "bssid": "02:5e:00:00:00:02",
            "ssid": None,
            "band": None,
            "channel": None,
            "width_mhz": 160,
            "signal_dbm": None,
            "security": None,
        }
    ]
    assert radio_state.scan(None) == []
    assert radio_state.bssid_of({"bssid": "nope"}) is None and radio_state.bssid_of(None) is None


# Omada --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("", None),
        ("None", Security.OPEN),
        ("OWE", Security.OWE),
        ("WEP", Security.WEP),
        ("WPA3-Enterprise", Security.WPA3_ENTERPRISE),
        ("WPA2/WPA3-SAE", Security.WPA2_WPA3),
        ("WPA3-SAE", Security.WPA3),
        ("WPA2-Enterprise", Security.WPA2_ENTERPRISE),
        ("WPA/WPA2-PSK", Security.WPA_WPA2),
        ("WPA2-PSK", Security.WPA2),
        ("WPA-Enterprise", Security.WPA_ENTERPRISE),
        ("WPA-PSK", Security.WPA),
        ("something", Security.OTHER),
    ],
)
def test_omada_rogue_security(text: str, expected: Security | None) -> None:
    assert _rogue_security(text) is expected


# framework and contract ---------------------------------------------------------------------


def test_observe_keeps_the_strongest_per_device() -> None:
    many = [
        result(bssid=f"02:5e:00:00:{i // 256:02x}:{i % 256:02x}", signal_dbm=-30 - i % 90)
        for i in range(SCAN_LIMIT + 10)
    ]
    twice = [result(signal_dbm=-80), result(signal_dbm=-40), result(signal_dbm=None)]
    kept = _cap_scan(many)
    assert len(kept) == SCAN_LIMIT and kept[0].signal_dbm == -30
    (best,) = _cap_scan(twice)
    assert best.signal_dbm == -40
    assert Observation(wifi_scan=twice).wifi_scan == twice


def test_scan_contract_problems() -> None:
    radios = {"ap1/radio/radio0": radio("ap1", band=Band.GHZ_5), "ap2/radio/radio0": radio("ap2")}
    bad = [
        result(band=Band.GHZ_5),
        result(band=Band.GHZ_5),  # twice
        result(dev="x", radio_id=None),  # unknown device
        result(bssid="02:5e:00:00:00:02", id="ap1/scan/wrong"),
        result(bssid="02:5e:00:00:00:03", radio_id="ap1/radio/nope"),
        result(bssid="02:5e:00:00:00:04", radio_id="ap2/radio/radio0"),
        result(bssid="02:5e:00:00:00:05", band=Band.GHZ_2_4),
        result(bssid="03:5e:00:00:00:06"),
    ]
    problems = scan_problems(bad, ["ap1", "ap2"], radios)
    text = "\n".join(problems)
    for part in (
        "reported twice",
        "has device_id x",
        "is not ap1/radio/radio0/scan/02:5e:00:00:00:02",
        "unknown radio ap1/radio/nope",
        "a radio of another device",
        "heard by a 5 GHz radio",
        "multicast BSSID",
    ):
        assert part in text, (part, text)
    many = [
        result(bssid=f"02:5e:00:00:{i // 256:02x}:{i % 256:02x}") for i in range(SCAN_LIMIT + 1)
    ]
    assert any("over" in p for p in scan_problems(many, ["ap1"], radios))


def test_api_wifi_scan_and_the_network_leaves_it_out(monkeypatch: pytest.MonkeyPatch) -> None:
    import tempfile
    from pathlib import Path

    from fastapi.testclient import TestClient

    from factories import SITE
    from signalbox.merge import merge
    from signalbox.service import build
    from signalbox.web.app import create_app, public_network
    from test_rules_wireless import ap, wlan
    from test_runner import Dev

    snap = ap(
        "ap1",
        radios=[radio("ap1", channel=36)],
        wlans=[wlan("ap1", bssid="02:00:00:00:0a:01")],
        wifi_scan=[
            result(ssid="Example", band=Band.GHZ_5, channel=36, signal_dbm=-50),
            result(bssid="02:00:00:00:0a:01", ssid="Example", band=Band.GHZ_5, channel=36),
        ],
    )
    net = merge([SITE], [snap], [])
    data = public_network(net)
    assert "wifi_scan" not in data
    assert data["radios"][0]["neighbour_count"] == 1
    assert data["radios"][0]["strongest_foreign_dbm"] == -50
    svc = build(
        Path(tempfile.mkdtemp()),
        env={"SIGNALBOX_AUTH_PASSWORD": "correct-horse-battery"},
        adapters={"dev": Dev},
    )
    try:
        monkeypatch.setattr(svc.runner, "network", lambda: net)
        with TestClient(create_app(svc, run_background=False)) as c:
            assert (
                c.post("/api/login", json={"password": "correct-horse-battery"}).status_code == 200
            )
            rows = c.get("/api/wifi-scan?device=ap1").json()
            assert [(r["own"], r["own_ssid"]) for r in rows] == [(False, True), (True, False)]
            assert len(c.get("/api/wifi-scan").json()) == 2
            assert c.get("/api/wifi-scan?device=other").json() == []
    finally:
        svc.close()
