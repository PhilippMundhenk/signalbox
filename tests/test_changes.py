from collections.abc import Iterator

import pytest
from pydantic import ValidationError

from signalbox.changes import (
    Change,
    ChangeKind,
    DhcpValue,
    PlanError,
    PortValue,
    RouterValue,
    WlanValue,
    changes_for,
    gateway_distance,
    order,
    plan,
    predict,
    revert_plan,
)
from signalbox.demo import demo_devices
from signalbox.desired import DesiredState, drift_rules, from_network, parse
from signalbox.model import Network
from signalbox.rules import evaluate
from signalbox.rules.builtin import RULES
from signalbox.service import Services, build


@pytest.fixture(scope="module")
def demo(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Network]:
    import asyncio

    svc: Services = build(tmp_path_factory.mktemp("c"), env={"SIGNALBOX_AUTH_PASSWORD": "x" * 12})
    with demo_devices(svc):
        asyncio.run(svc.runner.observe_all())
        yield svc.runner.network()
    svc.close()


def drift(net: Network, state: DesiredState, secrets: dict[str, str] | None = None) -> list[str]:
    found = evaluate(net, drift_rules(state, (secrets or {}).get))
    return [f.message for f in found if f.rule_id.startswith("drift") and not f.incomplete]


WANT = """
sites:
  home:
    segments:
      - vlan: 50
        name: Cameras
        gateway: {device: gateway, address: 203.0.113.129/25}
        dhcp: {enabled: true, pool: [203.0.113.150, 203.0.113.199], dns: [203.0.113.129]}
        reservations:
          - {mac: "02:00:00:00:50:01", address: 203.0.113.140, hostname: cam1}
    wlans:
      - ssid: Example
        security: wpa2-wpa3
        hidden: true
        devices: [ap-1]
      - ssid: Cameras
        security: wpa2-psk
        passphrase_secret: cam-psk
        segment: 50
        devices: [ap-1, ap-2]
    ports:
      - {device: ap-1, port: lan1, untagged: native, tagged: [20, 50]}
      - {device: gateway, port: igb0, untagged: native, tagged: [20, 30, 40, 50]}
"""
SECRETS = {"cam-psk": "camera passphrase"}


def test_no_changes_when_desired_is_the_observed_state(demo: Network) -> None:
    assert changes_for(from_network(demo, "home"), demo) == []


def test_plan_orders_changes_and_reaches_the_desired_state(demo: Network) -> None:
    state = parse(WANT)
    p = plan(state, demo, RULES, secret=SECRETS.get)
    kinds = [c.kind for c in p.changes]
    assert kinds == sorted(kinds, key=lambda k: list(ChangeKind).index(k))
    ports = [c.device_id for c in p.changes if c.kind is ChangeKind.PORT]
    assert ports == ["gateway", "ap-1"]  # outwards from the gateway
    actions = {(c.kind.value, c.device_id, c.action) for c in p.changes}
    assert ("router", "gateway", "create") in actions
    assert ("dhcp", "gateway", "create") in actions
    assert ("reservation", "gateway", "create") in actions
    assert ("wlan", "ap-1", "update") in actions
    assert ("wlan", "ap-2", "create") in actions
    assert drift(demo, state, SECRETS)  # there is drift now ...
    assert drift(predict(demo, p.changes), state, SECRETS) == []  # ... and none afterwards
    assert p.id.startswith("plan-") and p.devices() == ["gateway", "ap-1", "ap-2"]
    assert all(c.device_id == "ap-2" for c in p.for_device("ap-2"))


def test_risky_changes_are_flagged(demo: Network) -> None:
    p = plan(parse(WANT), demo, RULES, secret=SECRETS.get)
    port = next(c for c in p.changes if c.kind is ChangeKind.PORT and c.device_id == "ap-1")
    assert port.risk and "one end of a link" in port.risk
    managed = demo.model_copy(
        update={
            "devices": [
                d.model_copy(update={"management_address": "192.0.2.2"}) if d.id == "ap-1" else d
                for d in demo.devices
            ]
        }
    )
    move = parse(
        "sites: {home: {segments: [{vlan: native, "
        "gateway: {device: gateway, address: 192.0.2.254/24}}]}}"
    )
    router = plan(move, managed, RULES).changes[0]
    assert router.kind is ChangeKind.ROUTER and router.risk and "ap-1" in router.risk


def test_plan_reports_new_errors_on_the_predicted_network(demo: Network) -> None:
    # turning on DHCP on an access point gives the LAN a second DHCP server
    state = parse(
        "sites: {home: {segments: [{vlan: native, dhcp: {device: ap-1, enabled: true}}]}}"
    )
    p = plan(state, demo, RULES)
    assert any(f.rule_id == "dhcp.one-server" for f in p.blocking)
    fixed = plan(from_network(demo, "home"), demo, RULES)
    assert fixed.blocking == [] and fixed.changes == []


def test_revert_restores_the_observed_state(demo: Network) -> None:
    before = from_network(demo, "home")
    p = plan(parse(WANT), demo, RULES, secret=SECRETS.get)
    after = predict(demo, p.changes)
    back = revert_plan(p.changes, after, RULES)
    assert [c.inverse() for c in back.changes] != []
    restored = predict(after, back.changes)
    assert drift(restored, before) == []
    # removals run in reverse phase order (Wi-Fi first, router last)
    kinds = [c.kind for c in back.changes if c.new is None]
    assert kinds[0] is ChangeKind.WLAN and kinds[-1] is ChangeKind.ROUTER


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("sites: {home: {ports: [{device: ghost, port: '1'}]}}", "device ghost is not configured"),
        (
            "sites: {home: {ports: [{device: ap-1, port: lan9}]}}",
            "port ap-1/port/lan9 does not exist",
        ),
        (
            "sites: {home: {wlans: [{ssid: X, security: wpa2-psk, passphrase_secret: nope}]}}",
            "secret 'nope' is not stored",
        ),
        ("sites: {office: {segments: [{vlan: 9, dhcp: {}}]}}", "DHCP needs a device"),
    ],
)
def test_plan_errors(demo: Network, text: str, message: str) -> None:
    with pytest.raises(PlanError, match=message):
        changes_for(parse(text), demo, {}.get)


def test_passphrase_change_is_planned_from_the_fingerprint(demo: Network) -> None:
    ssid = next(w for w in demo.wlans if w.device_id == "ap-1" and w.passphrase_fingerprint)
    observed = from_network(demo, "home").sites["home"].wlans
    spec = next(w for w in observed if w.ssid == ssid.ssid)
    state = DesiredState.model_validate(
        {
            "sites": {
                "home": {
                    "wlans": [
                        {
                            **spec.model_dump(mode="json", exclude_defaults=True),
                            "passphrase_secret": "s",
                            "devices": ["ap-1"],
                        }
                    ]
                }
            }
        }
    )
    changes = changes_for(state, demo, {"s": "a different passphrase"}.get)
    assert [c.kind for c in changes] == [ChangeKind.WLAN]
    assert changes_for(state, demo, None) == []  # without secrets: nothing to compare


def test_change_model() -> None:
    r = RouterValue(address="198.51.100.1/24", vlan=20, name="IoT")
    c = Change(kind=ChangeKind.ROUTER, device_id="gw", site_id="home", key="home/segment/20", new=r)
    assert c.action == "create" and c.id == "gw:router:home/segment/20"
    assert c.inverse().action == "remove" and c.inverse().inverse() == c
    assert "create router" in c.describe() and "remove router" in c.inverse().describe()
    upd = Change(
        kind=ChangeKind.PORT,
        device_id="sw",
        site_id="home",
        key="sw/port/1",
        old=PortValue(untagged="native", tagged=[20]),
        new=PortValue(untagged="native", tagged=[20, 30]),
    )
    assert upd.action == "update" and "tagged [20] → [20, 30]" in upd.describe()
    w = WlanValue(ssid="A", security="wpa2-psk", passphrase_secret="secret-name")
    wc = Change(kind=ChangeKind.WLAN, device_id="ap", site_id="home", key="A", new=w)
    assert "secret-name" not in wc.describe()
    with pytest.raises(ValidationError, match="needs RouterValue"):
        Change(
            kind=ChangeKind.ROUTER,
            device_id="gw",
            site_id="h",
            key="k",
            new=DhcpValue(enabled=True),
        )
    with pytest.raises(ValidationError, match="old or a new value"):
        Change(kind=ChangeKind.DHCP, device_id="gw", site_id="h", key="k")


def test_order_and_distance(demo: Network) -> None:
    assert gateway_distance(demo, "home") == {"gateway": 0, "ap-1": 1}
    a = Change(kind=ChangeKind.PORT, device_id="x", site_id="home", key="x/port/1", new=PortValue())
    assert order([a]) == [a]


def test_adapter_declaring_writes_must_implement_them() -> None:
    from signalbox.adapters import AdapterContractError
    from test_adapters import Fake, ctx

    class Writer(Fake):
        manifest = Fake.manifest.model_copy(update={"writes": frozenset({ChangeKind.WLAN})})

    with pytest.raises(AdapterContractError, match="WritesConfig"):
        Writer(ctx())
