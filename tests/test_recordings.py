"""Recordings of real devices as regression tests, and the recorder and neutraliser behind them.

Every file in tests/fixtures/recordings/ is replayed through its adapter (over pinned TLS);
the adapter must report exactly the snapshot stored with the recording and must not ask for
anything that was not recorded. How to make one: docs/TESTING.md (tools/record_device.py).
"""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
from pydantic import SecretStr

from signalbox.adapters import AdapterContext
from signalbox.adapters.fritzbox import FritzboxAdapter, FritzboxConfig
from signalbox.adapters.https import DeviceHttp
from signalbox.model import DeviceRole
from signalbox.recording import (
    PLACEHOLDER_SECRET,
    PLACEHOLDER_USER,
    Exchange,
    Neutraliser,
    Replay,
    adapter_for,
    build,
    create_app,
    load,
    recording,
    replay_snapshot,
)
from signalbox.sim.fritzbox import FritzboxSim
from signalbox.sim.fritzbox import create_app as fritzbox_app
from signalbox.sim.server import self_signed_certificate, serve
from signalbox.testing import assert_contract

ROOT = Path(__file__).parents[1]
RECORDINGS = sorted((ROOT / "tests" / "fixtures" / "recordings").glob("*.json"))


# --- the committed recordings ----------------------------------------------------------------


@pytest.mark.parametrize("path", RECORDINGS, ids=[p.stem for p in RECORDINGS])
async def test_recording_replays_to_its_snapshot(path: Path) -> None:
    data = load(path)
    snapshot, unmatched = await replay_snapshot(data)
    assert unmatched == []
    assert snapshot == data["snapshot"], "run python tools/regen_recordings.py and review the diff"


@pytest.mark.parametrize("path", RECORDINGS, ids=[p.stem for p in RECORDINGS])
async def test_recording_passes_the_contract(path: Path) -> None:
    data = load(path)
    with tempfile.TemporaryDirectory() as tmp:
        tls = self_signed_certificate(Path(tmp), "replay")
        with serve(create_app(data), tls=tls) as url:
            adapter = adapter_for(data, url, tls.fingerprint)
            try:
                await assert_contract(adapter)
            finally:
                await adapter.close()


def test_recordings_hold_no_simulator_values() -> None:
    """The example recording of the simulator must show the neutraliser at work."""
    for path in RECORDINGS:
        text = path.read_text()
        for private in ("example-passphrase", "example-password", "laptop", ">Example<"):
            assert private not in text, (path.name, private)
        assert "02:00:00:00" not in text.lower()


# --- recording -------------------------------------------------------------------------------


@pytest.fixture(scope="module")
def fritzbox() -> Iterator[tuple[FritzboxSim, str]]:
    sim = FritzboxSim()
    with serve(fritzbox_app(sim)) as url:
        yield sim, url


async def test_recording_hook_leaves_out_digest_challenges(
    fritzbox: tuple[FritzboxSim, str],
) -> None:
    sim, url = fritzbox
    sim.reset()
    original = DeviceHttp.connect
    adapter = FritzboxAdapter(
        AdapterContext(
            site_id="home",
            device_id="fb",
            device_name="Fritz!Box",
            role=DeviceRole.GATEWAY,
            config=FritzboxConfig(
                url=url,
                username=sim.username,
                password=SecretStr(sim.password),
                allow_insecure_http=True,
            ),
        )
    )
    exchanges: list[Exchange] = []
    try:
        with recording(exchanges):
            await adapter.read_system()
            await adapter.http.connect()  # already connected: no second hook
            await adapter.read_dhcp()
    finally:
        await adapter.close()
    assert DeviceHttp.connect is original
    assert [e.status for e in exchanges][:2] == [200, 200]  # then the LAN info and the hosts
    assert exchanges[0].headers["soapaction"].endswith('DeviceInfo:1#GetInfo"')
    assert "authorization" not in json.dumps([e.as_json() for e in exchanges]).lower()
    assert "<NewModelName>" in exchanges[0].response


def _tool() -> Any:
    spec = importlib.util.spec_from_file_location("record_device", ROOT / "tools/record_device.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["record_device"] = module
    spec.loader.exec_module(module)
    return module


def test_record_device_tool(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    tool = _tool()
    sim = FritzboxSim(version="fritzos-8.02")
    tls = self_signed_certificate(tmp_path, "fritzbox")
    with serve(fritzbox_app(sim), tls=tls) as url:
        monkeypatch.delenv("SIGNALBOX_RECORD_PASSWORD", raising=False)
        assert tool.main(["--adapter", "fritzbox", "--url", url, "--pin", tls.fingerprint]) == 2
        assert tool.main(["--adapter", "fritzbox", "--url", url, "--show-fingerprint"]) == 0
        assert tls.fingerprint in capsys.readouterr().out
        assert sim.authenticated == 0  # neither sent anything to the device


def test_record_device_tool_writes_a_replayable_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    tool = _tool()
    sim = FritzboxSim(version="fritzos-8.02", denied={"GetSecurityKeys"})
    out = tmp_path / "rec.json"
    tls = self_signed_certificate(tmp_path, "fritzbox")
    monkeypatch.setenv("SIGNALBOX_RECORD_PASSWORD", sim.password)
    with serve(fritzbox_app(sim), tls=tls) as url:
        args = ["--adapter", "fritzbox", "--url", url, "--username", sim.username]
        assert tool.main([*args, "--pin", tls.fingerprint, "--out", str(out)]) == 0
    assert "wireless" in capsys.readouterr().err  # the read error is shown
    data = load(out)
    assert data["device"] == {"model": "FRITZ!Box 7530", "firmware": "164.08.02"}
    text = out.read_text()
    assert f">{sim.username}<" not in text and sim.password not in text
    assert sim.writes == []


def _http_simulators() -> list[tuple[str, Any, str, list[str], dict[str, str]]]:
    from signalbox.sim import dnsfilter, mikrotik, omada, openwrt, opnsense

    return [
        (
            "openwrt",
            openwrt.create_app(openwrt.OpenWrtSim()),
            "/ubus",
            ["--username", openwrt.OpenWrtSim().username],
            {"SIGNALBOX_RECORD_PASSWORD": openwrt.OpenWrtSim().password},
        ),
        (
            "opnsense",
            opnsense.OpnsenseSimulator().app(),
            "",
            [],
            {
                "SIGNALBOX_RECORD_PASSWORD": opnsense.KEY,
                "SIGNALBOX_RECORD_API_SECRET": opnsense.SECRET,
            },
        ),
        (
            "mikrotik",
            mikrotik.MikrotikSimulator().app(),
            "",
            ["--username", mikrotik.USER],
            {"SIGNALBOX_RECORD_PASSWORD": mikrotik.PASSWORD},
        ),
        (
            "omada",
            omada.OmadaSimulator().app(),
            "",
            ["--set", f"omadac_id={omada.OMADAC_ID}", "--set", f"client_id={omada.CLIENT_ID}"],
            {"SIGNALBOX_RECORD_PASSWORD": omada.CLIENT_SECRET},
        ),
        (
            "adguardhome",
            dnsfilter.AdGuardSim().app(),
            "",
            ["--username", dnsfilter.AG_USER],
            {"SIGNALBOX_RECORD_PASSWORD": dnsfilter.AG_PASSWORD},
        ),
        (
            "pihole",
            dnsfilter.PiholeSim().app(),
            "",
            [],
            {"SIGNALBOX_RECORD_PASSWORD": dnsfilter.PH_PASSWORD},
        ),
        (
            "pihole",  # Pi-hole v5: only the API token, in the query string (#385)
            dnsfilter.PiholeSim(version="v5").app(),
            "",
            [],
            {"SIGNALBOX_RECORD_API_TOKEN": dnsfilter.PH_TOKEN},
        ),
    ]


@pytest.mark.parametrize(
    "index",
    range(7),
    ids=["openwrt", "opnsense", "mikrotik", "omada", "adguardhome", "pihole", "pihole-v5"],
)
def test_every_http_adapter_records_and_replays(
    index: int, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    name, app, path, extra, env = _http_simulators()[index]
    tool = _tool()
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    out = tmp_path / f"{name}.json"
    tls = self_signed_certificate(tmp_path, name)
    with serve(app, tls=tls) as url:
        args = ["--adapter", name, "--url", url + path, "--pin", tls.fingerprint, *extra]
        assert tool.main([*args, "--out", str(out)]) == 0
    assert "warning" not in capsys.readouterr().err  # the replay found every request
    data = load(out)
    assert data["snapshot"]["status"] == "ok"
    text = out.read_text()
    for value in env.values():
        assert value not in text


def test_a_second_secret_setting_must_be_given(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("SIGNALBOX_RECORD_PASSWORD", "key")
    monkeypatch.delenv("SIGNALBOX_RECORD_API_SECRET", raising=False)
    args = ["--adapter", "opnsense", "--url", "https://192.0.2.1"]
    assert _tool().main(args) == 2
    assert "SIGNALBOX_RECORD_API_SECRET" in capsys.readouterr().err


async def test_a_new_recording_replays(tmp_path: Path) -> None:
    """build() on raw exchanges, then the replay gives the same snapshot as the device."""
    sim = FritzboxSim()
    exchanges: list[Exchange] = []
    with serve(fritzbox_app(sim)) as url:
        adapter = FritzboxAdapter(
            AdapterContext(
                site_id="home",
                device_id="recorded",
                device_name="recorded device",
                role=DeviceRole.GATEWAY,
                config=FritzboxConfig(
                    url=url,
                    username=sim.username,
                    password=SecretStr(sim.password),
                    allow_insecure_http=True,
                ),
            )
        )
        try:
            with recording(exchanges):
                live = await adapter.observe()
        finally:
            await adapter.close()
    data = build(
        "fritzbox",
        exchanges,
        role="gateway",
        path="",
        settings={"allow_insecure_http": True},
        password=sim.password,
        username=sim.username,
        today=lambda: datetime(2026, 1, 15, tzinfo=UTC),
    )
    assert data["recorded"] == "2026-01-15"
    snapshot, unmatched = await replay_snapshot(data)
    assert unmatched == []
    assert len(snapshot["clients"]) == len(live.clients)
    assert snapshot["status"] == "ok"
    assert {w["ssid"] for w in snapshot["wlans"]} == {"name-3", "name-4"}


# --- neutralising ----------------------------------------------------------------------------


def test_ipv4_by_network_keeping_the_host() -> None:
    n = Neutraliser()
    text = "10.0.0.1 10.0.0.77 10.0.1.5 172.16.4.4 10.0.0.1 255.255.255.0 255.255.0.0 0.0.0.0"
    assert n.addresses(text) == (
        "192.0.2.1 192.0.2.77 198.51.100.5 203.0.113.4 192.0.2.1 255.255.255.0 255.255.0.0 0.0.0.0"
    )
    kept = "127.0.0.1 224.0.0.251 255.255.255.255 192.0.2.9 198.51.100.1 203.0.113.7 198.18.0.1"
    assert n.addresses(kept) == kept
    assert n.addresses("8.8.8.8 1.2.3") == "198.18.0.8 1.2.3"  # public too; not an address
    assert n.addresses("300.1.1.1") == "300.1.1.1"
    assert n.addresses("255.1.2.3") == "198.18.1.3"  # starts like a mask, is none


def test_ipv6() -> None:
    n = Neutraliser()
    out = n.addresses("2a00:1:2:3::10 fe80::1234:5678:9abc:def0 2a00:1:2:3::11 fd00::1")
    assert out == "2001:db8:1::1 fe80::2 2001:db8:1::3 2001:db8:2::4"
    kept = "::1 :: ff02::1 2001:db8::5 12:00:00"
    assert n.addresses(kept) == kept
    assert n.addresses(out) == out  # placeholders stay as they are
    assert n.addresses("1::2::3") == "1::2::3"


def test_macs_keep_case_and_separator() -> None:
    n = Neutraliser()
    assert n.addresses("A0:B1:C2:D3:E4:F5 a0-b1-c2-d3-e4-f5 a0:b1:c2:d3:e4:f6") == (
        "00:00:5E:00:53:00 00-00-5e-00-53-00 00:00:5e:00:53:01"
    )
    kept = "00:00:00:00:00:00 ff:ff:ff:ff:ff:ff 00:00:5e:00:53:99"
    assert n.addresses(kept) == kept
    n.macs.update({f"x{i}": "" for i in range(300)})
    assert n.addresses("a0:b1:c2:d3:e4:f7") == "02:00:5e:00:01:2e"
    assert n.addresses("02:00:5e:00:01:2e") == "02:00:5e:00:01:2e"


def test_fields_secrets_names_and_logs() -> None:
    n = Neutraliser()
    n.given(password="hunter2-password", username="admin")
    xml = (
        "<r><NewSSID>Family Wifi</NewSSID><NewKeyPassphrase>sesame-123</NewKeyPassphrase>"
        "<NewDomainName>fritz.box</NewDomainName><NewDeviceLog>12:00 x 10.0.0.9</NewDeviceLog>"
        "<NewX_AVM-DE_HostListPath>/devicehostlist.lua?sid=abcdef0123</NewX_AVM-DE_HostListPath>"
        '<u:X a="1">10.0.0.9</u:X><NewUserName>admin</NewUserName><Other>sesame-123!</Other></r>'
    )
    assert n.document(xml) == (
        "<r><NewSSID>name-2</NewSSID><NewKeyPassphrase>redacted-secret-03</NewKeyPassphrase>"
        "<NewDomainName>fritz.box</NewDomainName><NewDeviceLog></NewDeviceLog>"
        "<NewX_AVM-DE_HostListPath>/devicehostlist.lua?sid=redacted-secret-02"
        '</NewX_AVM-DE_HostListPath><u:X a="1">192.0.2.9</u:X>'
        f"<NewUserName>{PLACEHOLDER_USER}</NewUserName><Other>redacted-secret-03!</Other></r>"
    )
    body = json.dumps(
        {
            "id": 3,
            "params": ["s", {"password": "hunter2-password", "ssid": "Family Wifi"}],
            "n": 1,
            "note": "the hunter2-password",
        }
    )
    assert json.loads(n.document(body)) == {
        "id": 3,
        "params": ["s", {"password": PLACEHOLDER_SECRET, "ssid": "name-2"}],
        "n": 1,
        "note": f"the {PLACEHOLDER_SECRET}",
    }
    assert n.document("not json { 10.0.0.9", "application/json") == "not json { 192.0.2.9"
    assert n.document("{broken") == "{broken"
    assert n.url("/devicehostlist.lua?sid=abcdef0123&ip=10.0.0.9") == (
        "/devicehostlist.lua?sid=redacted-secret-02&ip=192.0.2.9"
    )
    assert n.url("/cgi-bin/luci/10.0.0.9") == "/cgi-bin/luci/192.0.2.9"
    assert n.secret("") == "" and n.name("lan") == "lan"
    # the password rules of a PPP login are no secret (and "0" must not become one)
    rules = "<r><NewMinCharsPassword>0</NewMinCharsPassword><NewIndex>0</NewIndex></r>"
    assert n.document(rules) == rules


def test_neutralising_twice_changes_nothing() -> None:
    n = Neutraliser()
    e = Exchange(
        "POST",
        "/x?token=abc123456",
        {"soapaction": "a#b"},
        '{"key": "s3cret-value", "mac": "a0:b1:c2:d3:e4:f5"}',
        200,
        "application/json",
        "<a><NewSSID>Home</NewSSID><B>fe80::1:2:3:4</B></a>",
    )
    once = n.all([e])
    assert n.all(once) == once


# --- replaying -------------------------------------------------------------------------------


def _exchange(path: str, response: str, body: str = "") -> Exchange:
    return Exchange("POST", path, {}, body, 200, "application/json", response)


def test_replay_answers_in_order_and_repeats_the_last() -> None:
    replay = Replay(
        [
            _exchange("/a", "1", '{"id": 1, "x": 1}'),
            _exchange("/a", "2", '{"id": 2, "x": 1}'),
            _exchange("/b%20c", "3", "<a> <b/></a>"),
        ]
    )
    answers = [replay.answer("POST", "/a", {}, '{"x": 1, "id": 9}') for _ in range(3)]
    assert [a.response for a in answers if a] == ["1", "2", "2"]
    found = replay.answer("post", "/b c", {}, "<a><b/></a>")
    assert found is not None and found.response == "3"
    assert replay.answer("GET", "/a", {"soapaction": '"u#X"'}, "") is None
    assert replay.answer("POST", "/a", {}, "[1, 2]") is None
    assert replay.answer("POST", "/a", {}, "[broken") is None
    assert replay.unmatched == ['GET /a "u#X"', "POST /a", "POST /a"]


def test_replay_app(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    data = build(
        "fritzbox",
        [_exchange("/x", '{"ok": true}')],
        role="gateway",
        path="/base/10.0.0.1",
        settings={"name": "x"},
        password=None,
        username=None,
        device={"model": "M", "firmware": "1"},
    )
    assert data["path"] == "/base/192.0.2.1"
    path = tmp_path / "r.json"
    path.write_text(json.dumps(data))
    monkeypatch.setenv("SIGNALBOX_REPLAY", str(path))
    app = create_app()
    with serve(app) as url, httpx.Client(base_url=url, trust_env=False) as client:
        assert client.post("/x").json() == {"ok": True}
        missing = client.get("/y?z=1")
        assert missing.status_code == 501 and "GET /y?z=1" in missing.text
    assert app.state.replay.unmatched == ["GET /y?z=1"]
    monkeypatch.delenv("SIGNALBOX_REPLAY")
    with pytest.raises(ValueError, match="SIGNALBOX_REPLAY"):
        create_app()
    path.write_text(json.dumps({"format": "other"}))
    with pytest.raises(ValueError, match="not a signalbox-recording"):
        load(path)


def test_adapter_for_uses_the_placeholders() -> None:
    data = {"adapter": "fritzbox", "role": "ap", "settings": {}, "path": ""}
    adapter = adapter_for(data, "http://127.0.0.1:1", None)
    config = adapter.context.config
    assert isinstance(config, FritzboxConfig)
    assert config.password.get_secret_value() == PLACEHOLDER_SECRET
    assert config.username == PLACEHOLDER_USER and config.allow_insecure_http
    assert adapter.context.role is DeviceRole.AP
