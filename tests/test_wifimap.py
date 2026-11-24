"""The data of the Wi-Fi map (#366): own radios, anonymous neighbours, signal edges."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any

import pytest

from factories import SITE
from signalbox.merge import merge
from signalbox.model import Band, WifiScanResult, scan_id
from signalbox.wifimap import MAX_NEIGHBOURS, wifi_map
from test_rules_wireless import ap, radio, wlan


def heard(dev: str, bssid: str, rname: str | None = "radio0", **kw: Any) -> WifiScanResult:
    rid = f"{dev}/radio/{rname}" if rname else None
    kw.setdefault("band", Band.GHZ_5)
    kw.setdefault("channel", 36)
    kw.setdefault("signal_dbm", -60)
    return WifiScanResult(
        id=scan_id(rid or dev, bssid), device_id=dev, radio_id=rid, bssid=bssid, **kw
    )


def test_without_a_scan_only_own_radios() -> None:
    net = merge([SITE], [ap("ap1", radios=[radio("ap1"), radio("ap1", "radio1")])], [])
    data = wifi_map(net)
    assert data["has_scan"] is False
    assert [n["kind"] for n in data["nodes"]] == ["own", "own"]
    assert data["edges"] == []
    assert data["nodes"][0]["site_id"] == SITE.id


def test_neighbours_are_anonymous_numbered_and_grouped() -> None:
    scan = [
        heard("ap1", "02:5e:00:00:01:01", ssid="Secret-Name", signal_dbm=-70),
        heard("ap1", "02:5e:00:00:01:02", ssid="Secret-Guest", signal_dbm=-72),  # same box
        heard("ap1", "02:5e:00:00:02:01", ssid="Other", signal_dbm=-50, channel=44),
        heard("ap1", "02:5e:00:00:03:01", ssid=None, signal_dbm=None, channel=100),
    ]
    net = merge([SITE], [ap("ap1", radios=[radio("ap1")], wifi_scan=scan)], [])
    data = wifi_map(net)
    assert data["has_scan"] is True
    nbr = [n for n in data["nodes"] if n["kind"] == "neighbour"]
    assert [(n["index"], n["channel"], n["signal_dbm"]) for n in nbr] == [
        (1, 44, -50),
        (2, 36, -70),
        (3, 100, None),
    ]
    raw = json.dumps(data)
    for secret in ("Secret", "Other", "02:5e", "bssid", "ssid"):
        assert secret not in raw
    assert {(e["a"], e["b"]): e["signal_dbm"] for e in data["edges"]}[
        ("ap1/radio/radio0", "neighbour/2")
    ] == -70


def test_own_access_points_hearing_each_other_are_linked() -> None:
    a = ap(
        "ap1",
        radios=[radio("ap1", channel=36)],
        wlans=[wlan("ap1", bssid="02:00:00:00:0a:01")],
        wifi_scan=[heard("ap1", "02:00:00:00:0b:01", signal_dbm=-55)],
    )
    b = ap(
        "ap2",
        radios=[radio("ap2", channel=36)],
        wlans=[wlan("ap2", bssid="02:00:00:00:0b:01")],
        wifi_scan=[
            heard("ap2", "02:00:00:00:0a:01", signal_dbm=-48),
            heard("ap2", "02:00:00:00:0a:01", rname=None, signal_dbm=-80),  # no radio
        ],
    )
    data = wifi_map(merge([SITE], [a, b], []))
    assert all(n["kind"] == "own" for n in data["nodes"])
    assert data["edges"] == [{"a": "ap1/radio/radio0", "b": "ap2/radio/radio0", "signal_dbm": -48}]


def test_neighbours_are_capped_and_a_controller_result_uses_the_band_radio() -> None:
    scan = [
        heard("ap1", f"02:5e:00:00:{i:02x}:01", rname=None, signal_dbm=-40 - i)
        for i in range(MAX_NEIGHBOURS + 5)
    ]
    net = merge([SITE], [ap("ap1", radios=[radio("ap1")], wifi_scan=scan)], [])
    data = wifi_map(net)
    assert len([n for n in data["nodes"] if n["kind"] == "neighbour"]) == MAX_NEIGHBOURS
    assert all(e["a"] == "ap1/radio/radio0" for e in data["edges"])


def test_disabled_radios_are_left_out() -> None:
    net = merge([SITE], [ap("ap1", radios=[radio("ap1", enabled=False)])], [])
    assert wifi_map(net)["nodes"] == []


def test_endpoint(monkeypatch: pytest.MonkeyPatch) -> None:
    from fastapi.testclient import TestClient

    from signalbox.service import build
    from signalbox.web.app import create_app
    from test_runner import Dev

    net = merge(
        [SITE],
        [ap("ap1", radios=[radio("ap1")], wifi_scan=[heard("ap1", "02:5e:00:00:01:01", ssid="X")])],
        [],
    )
    svc = build(
        Path(tempfile.mkdtemp()),
        env={"SIGNALBOX_AUTH_PASSWORD": "correct-horse-battery"},
        adapters={"dev": Dev},
    )
    try:
        monkeypatch.setattr(svc.runner, "network", lambda: net)
        with TestClient(create_app(svc, run_background=False)) as c:
            assert c.get("/api/wifi-map").status_code == 401
            c.post("/api/login", json={"password": "correct-horse-battery"})
            data = c.get("/api/wifi-map").json()
            assert data["has_scan"] is True
            assert len(data["nodes"]) == 2
            assert "02:5e" not in json.dumps(data)
    finally:
        svc.close()
