import json
from typing import Any

import pytest
from pydantic import SecretStr

from factories import SITE, device, port, snapshot
from signalbox.config import MqttConfig
from signalbox.merge import merge
from signalbox.model import Client, DeviceRole, DeviceStatus, Firmware, Network, Site
from signalbox.mqtt import Discovery, MqttBridge, device_state, node_id, site_state
from signalbox.rules import Finding, Severity


def net() -> Network:
    gw = snapshot(
        device("gw", DeviceRole.GATEWAY, name="Gateway", firmware=Firmware(current="25.1")),
        ports=[port("gw", "lan")],
    )
    ap = snapshot(
        device("ap", DeviceRole.AP, name="AP", vendor="Example", model="X"),
        clients=[Client(id="ap/c/1", mac="02:00:00:00:00:01", seen_on="ap/wlan/0")],
    )
    off = snapshot(device("off", DeviceRole.AP), status=DeviceStatus.UNREACHABLE)
    other = snapshot(device("far", DeviceRole.GATEWAY, site_id="office"))
    return merge([SITE, Site(id="office", name="Office")], [gw, ap, off, other])


def finding(fid: str, severity: Severity, objects: list[str], incomplete: bool = False) -> Finding:
    return Finding(
        id=fid,
        rule_id="r",
        severity=severity,
        title="t",
        message=fid,
        objects=objects,
        incomplete=incomplete,
    )


FINDINGS = [
    finding("1", Severity.ERROR, ["gw/port/lan"]),
    finding("2", Severity.WARNING, ["ap"]),
    finding("3", Severity.INFO, ["ap"], incomplete=True),
    finding("4", Severity.ERROR, ["far"]),
    finding("5", Severity.INFO, []),
]


def test_site_and_device_state() -> None:
    n = net()
    assert site_state(n, FINDINGS, "home") == {
        "errors": 1,
        "warnings": 1,
        "info": 1,
        "incomplete": 1,
        "problem": "ON",
        "devices": 3,
        "unreachable": 1,
    }
    assert site_state(n, FINDINGS, "office")["errors"] == 1
    assert device_state(n, FINDINGS, "gw") == {
        "status": "ok",
        "reachable": "ON",
        "firmware": "25.1",
        "clients": 0,
        "findings": 1,
    }
    ap = device_state(n, FINDINGS, "ap")
    assert ap["clients"] == 1 and ap["firmware"] == "unknown" and ap["findings"] == 1
    assert device_state(n, FINDINGS, "off")["reachable"] == "OFF"
    assert device_state(n, [], "missing")["status"] == "unreachable"


def test_discovery_configs() -> None:
    d = Discovery(MqttConfig(topic_prefix="/sb/", discovery_prefix="ha"), "https://sb.example")
    configs = d.configs(net())
    site = configs["ha/binary_sensor/site_home/problem/config"]
    assert site["state_topic"] == "sb/site/home/state"
    assert site["availability_topic"] == "sb/status"
    assert site["device"]["configuration_url"] == "https://sb.example"
    gw = configs["ha/sensor/device_gw/firmware/config"]
    assert gw["device"]["sw_version"] == "25.1" and gw["device"]["via_device"] == (
        "signalbox_site_home"
    )
    status = configs["ha/sensor/device_ap/status/config"]
    assert status["options"] == [s.value for s in DeviceStatus]
    assert len({c["unique_id"] for c in configs.values()}) == len(configs)
    assert node_id("a b/c") == "a_b_c"
    assert Discovery(MqttConfig(topic_prefix="", discovery_prefix="")).status_topic == (
        "signalbox/status"
    )
    states = d.states(net(), FINDINGS)
    assert states["sb/device/ap/state"]["clients"] == 1


class FakeInfo:
    def __init__(self, fail: bool = False) -> None:
        self.fail = fail

    def wait_for_publish(self, timeout: float) -> None:
        if self.fail:
            raise RuntimeError("not acknowledged")


class FakeClient:
    def __init__(self) -> None:
        self.published: list[tuple[str, str, bool]] = []
        self.calls: list[str] = []
        self.will: tuple[str, str] | None = None
        self.fail_wait = False

    def username_pw_set(self, user: str, password: str | None) -> None:
        self.calls.append(f"auth {user} {password}")

    def tls_set(self, **kw: Any) -> None:
        self.calls.append("tls")

    def will_set(self, topic: str, payload: str, qos: int, retain: bool) -> None:
        self.will = (topic, payload)

    def reconnect_delay_set(self, a: int, b: int) -> None:
        pass

    def connect_async(self, host: str, port: int, keepalive: int) -> None:
        self.calls.append(f"connect {host}:{port}")

    def loop_start(self) -> None:
        self.calls.append("loop_start")

    def loop_stop(self) -> None:
        self.calls.append("loop_stop")

    def disconnect(self) -> None:
        self.calls.append("disconnect")

    def publish(self, topic: str, payload: str, qos: int = 0, retain: bool = False) -> FakeInfo:
        self.published.append((topic, payload, retain))
        return FakeInfo(self.fail_wait)


class Reason:
    def __init__(self, failure: bool) -> None:
        self.is_failure = failure

    def __str__(self) -> str:
        return "Not authorized"


def bridge(**kw: Any) -> tuple[MqttBridge, FakeClient]:
    fake = FakeClient()
    cfg = MqttConfig(enabled=True, host="broker", **kw)
    return MqttBridge(cfg, client_factory=lambda: fake), fake


def test_bridge_lifecycle(monkeypatch: pytest.MonkeyPatch) -> None:
    import signalbox.mqtt as m

    monkeypatch.setattr(m.time, "sleep", lambda s: None)
    b, fake = bridge(username="u", password=SecretStr("p"), tls=True)
    b.publish(net(), FINDINGS)  # before start: remembered only
    assert fake.published == []
    b.start()
    assert fake.calls[:3] == ["auth u p", "tls", "connect broker:1883"]
    assert fake.will == ("signalbox/status", "offline")
    b.publish(net(), FINDINGS)  # not connected yet: nothing sent
    assert fake.published == []

    b._on_connect(fake, None, None, Reason(False))
    topics = [t for t, _, _ in fake.published]
    assert topics[0] == "signalbox/status"
    assert "homeassistant/sensor/device_gw/status/config" in topics
    assert "signalbox/site/home/state" in topics
    assert all(retain for _, _, retain in fake.published)
    state = next(p for t, p, _ in fake.published if t == "signalbox/device/gw/state")
    assert json.loads(state)["firmware"] == "25.1"

    # a device disappears: its discovery configs are removed with an empty payload
    fake.published.clear()
    smaller = net().model_copy(update={"devices": [d for d in net().devices if d.id != "ap"]})
    b.publish(smaller, [])
    removed = [t for t, p, _ in fake.published if p == ""]
    assert "homeassistant/sensor/device_ap/status/config" in removed
    assert not any(t.endswith("/config") and p for t, p, _ in fake.published)  # no re-send

    b._on_disconnect(fake, None, None, "gone")
    assert b.status["state"] == "connecting" and not b.connected.is_set()
    fake.fail_wait = True
    b._on_connect(fake, None, None, Reason(False))
    b.stop()
    assert fake.calls[-2:] == ["disconnect", "loop_stop"] and b.status["state"] == "off"
    assert ("signalbox/status", "offline", True) in fake.published
    b.stop()  # idempotent


def test_bridge_refused_and_disabled(caplog: pytest.LogCaptureFixture) -> None:
    b, fake = bridge()
    b.start()
    b._on_connect(fake, None, None, Reason(True))
    assert b.status["state"] == "error" and "Not authorized" in b.status["error"]
    b.stop()
    assert fake.calls[-1] == "loop_stop"

    off = MqttBridge(MqttConfig(enabled=True, host=""))
    off.start()
    assert off.client is None and "mqtt.host is empty" in caplog.text
    MqttBridge(MqttConfig()).start()
    assert not MqttBridge(MqttConfig()).enabled


def test_default_client() -> None:
    from signalbox.mqtt import _default_client

    assert _default_client() is not None
