import shutil
import subprocess
from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from signalbox import desired
from signalbox.demo import demo_devices
from signalbox.desired import DesiredError, drift_rules, from_network, parse
from signalbox.model import Network
from signalbox.rules import evaluate
from signalbox.service import Services, build
from signalbox.web.app import create_app

PW = "desired-password-1"


@pytest.fixture(scope="module")
def demo(tmp_path_factory: pytest.TempPathFactory) -> Iterator[tuple[Services, Network]]:
    import asyncio

    svc = build(tmp_path_factory.mktemp("d"), env={"SIGNALBOX_AUTH_PASSWORD": PW})
    with demo_devices(svc, compact=True):
        asyncio.run(svc.runner.observe_all())
        yield svc, svc.runner.network()
    svc.close()


def drift(net: Network, state: desired.DesiredState, secrets: dict[str, str] | None = None):  # type: ignore[no-untyped-def]
    lookup = (secrets or {}).get
    return [f for f in evaluate(net, drift_rules(state, lookup)) if f.rule_id.startswith("drift")]


def test_import_of_observed_state_has_no_drift(demo: tuple[Services, Network]) -> None:
    _, net = demo
    state = from_network(net, "home")
    text = desired.dump(state)
    again = parse(text)
    assert again == state
    spec = state.sites["home"]
    assert {str(s.vlan) for s in spec.segments} >= {"native", "20"}
    assert any(w.ssid == "Example" for w in spec.wlans)
    assert any(p.device == "ap-1" and p.port == "lan1" for p in spec.ports)
    assert drift(net, again) == []


def test_drift_reports_every_difference(demo: tuple[Services, Network]) -> None:
    _, net = demo
    state = from_network(net, "home")
    site = state.sites["home"]
    seg = next(s for s in site.segments if s.vlan == 20)
    assert seg.dhcp is not None and seg.gateway is not None
    wlan = next(w for w in site.wlans if w.ssid == "Example")
    port = next(p for p in site.ports if p.device == "ap-1" and p.port == "lan1")
    changed = desired.DesiredState(
        sites={
            "home": site.model_copy(
                update={
                    "segments": [
                        *[s for s in site.segments if s is not seg],
                        seg.model_copy(
                            update={
                                "name": "Things",
                                "gateway": seg.gateway.model_copy(
                                    update={"address": "198.51.100.254/24"}
                                ),
                                "dhcp": seg.dhcp.model_copy(
                                    update={"dns": ["198.51.100.53"], "lease_seconds": 99999}
                                ),
                                "reservations": [
                                    desired.ReservationSpec(
                                        mac="02:00:00:00:99:99", address="198.51.100.9"
                                    )
                                ],
                            }
                        ),
                        desired.SegmentSpec(vlan=99, name="Lab"),
                    ],
                    "wlans": [
                        *[w for w in site.wlans if w is not wlan],
                        wlan.model_copy(
                            update={
                                "hidden": True,
                                "passphrase_secret": "main",
                                "roaming": desired.RoamingSpec(r=False),
                                "devices": [*(wlan.devices or []), "nope"],
                            }
                        ),
                        desired.WlanSpec(ssid="Absent", security="wpa3-sae", devices=["ap-1"]),
                    ],
                    "ports": [
                        *[p for p in site.ports if p is not port],
                        port.model_copy(update={"tagged": [30], "untagged": 20}),
                        desired.PortSpec(device="ap-1", port="lan9", untagged="native"),
                        desired.PortSpec(device="ghost", port="1"),
                    ],
                }
            )
        }
    )
    found = drift(net, changed, {"main": "not-the-passphrase"})
    text = "\n".join(f.message for f in found)
    for needle in [
        "Segment 20 name: should be Things",
        "router address on gateway: should be 198.51.100.254/24",
        "DHCP DNS servers: should be 198.51.100.53",
        "DHCP lease time: should be 99999",
        "reservation 02:00:00:00:99:99",
        "Segment 99 (Lab) does not exist",
        "SSID Example on ap-1 hidden: should be True, is False",
        "802.11r: should be False",
        "passphrase differs from the stored secret",
        "SSID Absent is missing on ap-1",
        "port ap-1/port/lan1 untagged: should be home/segment/20",
        "port ap-1/port/lan1 tagged: should be home/segment/30",
        "port ap-1/port/lan9 does not exist",
    ]:
        assert needle in text, needle
    incomplete = [f.message for f in found if f.incomplete]
    assert any("device nope not read" in m for m in incomplete)
    assert any("ghost" in m for m in incomplete)
    missing_secret = drift(net, changed, {})
    assert any("secret 'main' is not stored" in f.message for f in missing_secret)


def test_dhcp_and_gateway_edge_cases(demo: tuple[Services, Network]) -> None:
    _, net = demo
    state = parse(
        """
sites:
  home:
    segments:
      - vlan: 77
      - vlan: 20
        gateway: {device: nobody, address: 198.51.100.1/24}
        dhcp: {device: ap-1, enabled: true}
      - vlan: native
        dhcp: {enabled: false}
"""
    )
    text = "\n".join(f.message for f in drift(net, state))
    assert "gateway device nobody is not configured" in text
    assert "no DHCP server on ap-1" in text
    assert "home/segment/native DHCP on gateway: should be off, is on" in text
    pool = parse(
        "sites: {home: {segments: [{vlan: native, dhcp: {pool: [192.0.2.1, 192.0.2.2]}}]}}"
    )
    assert "DHCP pool: should be 192.0.2.1, 192.0.2.2" in "\n".join(
        f.message for f in drift(net, pool)
    )
    off = parse(
        "sites: {home: {segments: [{vlan: native, dhcp: {device: gateway, enabled: false}}]}}"
    )
    assert "DHCP enabled: should be False, is True" in "\n".join(f.message for f in drift(net, off))


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("sites: [", "not valid YAML"),
        ("- a", "mapping with a 'sites' key"),
        ("sites: {home: {colour: red}}", "colour"),
        ("sites: {home: {segments: [{vlan: 20}, {vlan: 20}]}}", "segment declared twice: 20"),
        (
            "sites: {home: {wlans: [{ssid: A, security: open}, {ssid: A, security: open}]}}",
            "SSID declared twice: A",
        ),
        (
            "sites: {home: {ports: [{device: a, port: '1'}, {device: a, port: '1'}]}}",
            "port declared twice: a/1",
        ),
        (
            "sites: {home: {segments: [{vlan: 20, reservations: [{mac: x, address: 192.0.2.1}]}]}}",
            "not a MAC",
        ),
    ],
)
def test_parse_errors(text: str, message: str) -> None:
    with pytest.raises(DesiredError, match=message):
        parse(text)


def test_load_merges_files_and_checks_across_them(tmp_path: Path) -> None:
    assert desired.load(tmp_path) is None
    folder = tmp_path / "desired"
    folder.mkdir()
    (folder / "a.yaml").write_text("sites: {home: {segments: [{vlan: 20}]}}")
    (folder / "b.yaml").write_text(
        "sites: {home: {wlans: [{ssid: A, security: open}]}, office: {}}"
    )
    state = desired.load(tmp_path)
    assert state is not None and set(state.sites) == {"home", "office"}
    assert len(state.sites["home"].segments) == 1 and len(state.sites["home"].wlans) == 1
    (folder / "c.yaml").write_text("sites: {home: {segments: [{vlan: 20}]}}")
    with pytest.raises(DesiredError, match="declared twice"):
        desired.load(tmp_path)
    assert parse("") == desired.DesiredState()


@pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")
def test_save_commits_into_a_git_folder(tmp_path: Path) -> None:
    assert desired.save(tmp_path, "sites: {}\n", "first") is None  # no repository yet
    folder = tmp_path / "desired"
    subprocess.run(["git", "init", "-q", str(folder)], check=True)
    first = desired.save(tmp_path, "sites: {home: {}}\n", "add home")
    assert first and len(first) == 40
    assert desired.save(tmp_path, "sites: {home: {}}\n", "unchanged") == first
    log = subprocess.run(
        ["git", "-C", str(folder), "log", "--format=%an %s"], capture_output=True, text=True
    ).stdout
    assert "Signalbox add home" in log
    with pytest.raises(DesiredError):
        desired.save(tmp_path, "sites: [", "broken")


def test_api_two_routers_import_and_save(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """#305: the editor loads the import of a two-router site and saving it works."""
    from test_double_nat import reported

    svc = build(tmp_path, env={"SIGNALBOX_AUTH_PASSWORD": PW})
    try:
        with (
            demo_devices(svc, compact=True),
            TestClient(create_app(svc, run_background=False)) as c,
        ):
            c.post("/api/login", json={"password": PW})
            monkeypatch.setattr(svc.runner, "network", reported)
            text = c.post("/api/desired/import/home").json()["yaml"]
            assert "vlan: native-isp" in text
            r = c.put("/api/desired", json={"yaml": text})
            assert r.status_code == 200 and r.json()["saved"], r.text
    finally:
        svc.close()


def test_api_and_runner(tmp_path: Path) -> None:
    import asyncio

    svc = build(tmp_path, env={"SIGNALBOX_AUTH_PASSWORD": PW})
    try:
        with (
            demo_devices(svc, compact=True),
            TestClient(create_app(svc, run_background=False)) as c,
        ):
            asyncio.run(svc.runner.observe_all())
            c.post("/api/login", json={"password": PW})
            assert c.get("/api/desired").json() == {
                "yaml": "",
                "valid": True,
                "error": None,
                "sites": [],
            }
            assert c.post("/api/desired/import/mars").status_code == 404
            text = c.post("/api/desired/import/home").json()["yaml"]
            assert "Example" in text
            state = parse(text)
            site = state.sites["home"]
            site.wlans[0] = site.wlans[0].model_copy(update={"hidden": True})
            r = c.put("/api/desired", json={"yaml": desired.dump(state)})
            assert r.status_code == 200 and r.json()["saved"]
            assert c.get("/api/desired").json()["sites"] == ["home"]
            rules = {f["finding"]["rule_id"] for f in c.get("/api/findings").json()}
            assert "drift.wlan" in rules
            bad = c.put("/api/desired", json={"yaml": "sites: ["})
            assert bad.status_code == 422 and "not valid YAML" in bad.json()["message"]
            # a broken file on disk becomes a finding and the API says so
            (tmp_path / "desired" / "extra.yaml").write_text("sites: [")
            assert c.get("/api/desired").json()["valid"] is False
            _, findings = svc.runner.evaluate()
            assert any(f.rule_id == "desired.invalid" for f in findings)
            # secrets
            assert c.put("/api/secrets/bad name!", json={"value": "x"}).status_code == 422
            assert c.put("/api/secrets/main-psk", json={"value": "s3cret-pass"}).json()["stored"]
            assert c.get("/api/secrets").json() == ["main-psk"]
            assert svc.store.get_secret("main-psk") == "s3cret-pass"
            assert "s3cret" not in (svc.store.get_setting("secret:main-psk") or "")
            assert c.delete("/api/secrets/main-psk").status_code == 204
            assert svc.store.get_secret("main-psk") is None
    finally:
        svc.close()


def test_plan_api(tmp_path: Path) -> None:
    import asyncio

    svc = build(tmp_path, env={"SIGNALBOX_AUTH_PASSWORD": PW})
    try:
        with (
            demo_devices(svc, compact=True),
            TestClient(create_app(svc, run_background=False)) as c,
        ):
            asyncio.run(svc.runner.observe_all())
            c.post("/api/login", json={"password": PW})
            assert c.post("/api/plan").json()["error"] == "no_desired_state"
            c.put("/api/desired", json={"yaml": "sites: {home: {ports: [{device: x, port: '1'}]}}"})
            assert "device x is not configured" in c.post("/api/plan").json()["message"]
            text = (
                "sites: {home: {wlans: [{ssid: New, security: wpa2-psk, "
                "passphrase_secret: s, devices: [ap-1]}]}}"
            )
            c.put("/api/desired", json={"yaml": text})
            assert "secret 's' is not stored" in c.post("/api/plan").json()["message"]
            c.put("/api/secrets/s", json={"value": "new passphrase"})
            p = c.post("/api/plan").json()
            assert p["changes"][0]["text"].startswith("ap-1: create wlan New")
            assert "new passphrase" not in str(p) and p["devices"] == ["ap-1"]
            (tmp_path / "desired" / "bad.yaml").write_text("sites: [")
            assert c.post("/api/plan").json()["error"] == "invalid"
    finally:
        svc.close()
