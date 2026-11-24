"""Firewall desired state, planner, lockout check and OpenWrt deployment (#295).

The deployments run through the real Deployer against the OpenWrt simulator as a router
(zones lan, wan and iot, the lan→wan and iot→wan forwardings, the ``Allow-*`` rules and the
owner's ``nas-https`` forward).
"""

from __future__ import annotations

import copy
from collections.abc import Iterator
from ipaddress import ip_address
from pathlib import Path
from typing import Any

import pytest

from signalbox.adapters.openwrt import OpenWrtAdapter, OpenWrtConfig
from signalbox.adapters.openwrt.firewall import tag
from signalbox.changes import (
    Change,
    ChangeKind,
    FirewallRuleValue,
    PlanError,
    PortForwardValue,
    ZonePolicyValue,
    apply_change,
    changes_for,
    management_cuts,
    management_endpoint,
    plan,
)
from signalbox.deploy import Deployer, DeployError
from signalbox.desired import DesiredError, drift_rules, dump, from_network, parse
from signalbox.history import ChangeStatus, DeviceStatus
from signalbox.model import (
    DeviceRole,
    FirewallAction,
    FirewallChain,
    FirewallProtocol,
    Network,
    Site,
    Verdict,
)
from signalbox.rules import evaluate
from signalbox.rules.builtin import RULES
from signalbox.service import Services, build
from signalbox.sim.openwrt import OpenWrtSim, create_app
from signalbox.sim.server import serve
from signalbox.store import DeviceRecord

DEV = "gw"
SITE = Site(id="home", name="Home")
ENV = {"SIGNALBOX_AUTH_PASSWORD": "x" * 12, "SIGNALBOX_DEPLOY_ENABLED": "true"}
SIM = OpenWrtSim(router=True)

WANT = f"""
sites:
  home:
    firewalls:
      - device: {DEV}
        policies:
          - {{from: iot, to: lan, action: accept}}
          - {{from: {{segment: 20}}, to: device, action: drop}}
        rules:
          - name: iot-printer
            from: {{segment: 20}}
            to: {{zone: lan, network: 192.0.2.10}}
            protocol: tcp
            port: 631
            action: accept
          - name: no-telnet
            to: device
            port: 23
            action: reject
        forwards:
          - name: web
            protocol: tcp
            port: 443
            to: {{address: 192.0.2.20, port: 8443}}
"""


@pytest.fixture(scope="module")
def url() -> Iterator[str]:
    with serve(create_app(SIM)) as base:
        yield base


@pytest.fixture
def sim() -> OpenWrtSim:
    SIM.reset()
    SIM.router = True
    return SIM


@pytest.fixture
def svc(sim: OpenWrtSim, url: str, tmp_path: Path) -> Iterator[Services]:
    s = build(tmp_path, env=ENV, adapters={"openwrt": OpenWrtAdapter}, rules=RULES, link_sources=[])
    s.store.put_site(SITE)
    rec = DeviceRecord(
        id=DEV,
        site_id="home",
        name="Router",
        role=DeviceRole.GATEWAY,
        adapter="openwrt",
        allow_writes=True,
    )
    values = {"url": f"{url}/ubus", "password": OpenWrtSim().password, "allow_insecure_http": True}
    s.store.put_device(rec, values, OpenWrtConfig)
    yield s
    s.close()


def firewall(sim: OpenWrtSim) -> dict[str, Any]:
    return copy.deepcopy(sim.state["firewall"])


async def net_of(svc: Services) -> Network:
    await svc.runner.observe_all()
    return svc.runner.network()


async def deploy(d: Deployer, svc: Services, text: str, **approve: Any) -> Any:
    p = plan(parse(text), svc.runner.network(), RULES)
    rec = await d.prepare(p, "firewall", "tester")
    d.approve(rec.id, "tester", override="lab" if rec.plan.blocking else None, **approve)
    return rec, await d.deploy(rec.id)


# --- desired state ----------------------------------------------------------------------------


def test_syntax_round_trips_and_defaults() -> None:
    state = parse(WANT)
    [fw] = state.sites["home"].firewalls
    rule = fw.rules[0]
    assert rule.protocols() == [FirewallProtocol.TCP] and str(rule.port[0]) == "631"
    assert fw.rules[1].protocols() == [FirewallProtocol.TCP, FirewallProtocol.UDP]
    assert fw.forwards[0].to.port == 8443
    assert parse(dump(state)) == state
    text = dump(state)
    assert "from:" in text and "from_" not in text and "- 631" in text


@pytest.mark.parametrize(
    ("body", "message"),
    [
        ("rules: [{name: Bad Name, to: device, action: drop}]", "name"),
        ("rules: [{name: a, to: device, protocol: icmp, port: 22, action: drop}]", "ports need"),
        ("rules: [{name: a, to: device, port: x-y, action: drop}]", "not a port"),
        ("rules: [{name: a, to: {zone: lan, segment: 20}, action: drop}]", "not both"),
        ("forwards: [{name: f, protocol: icmp, port: 1, to: {address: 192.0.2.9}}]", "tcp"),
        (
            "rules: [{name: a-b, to: device, action: drop}, {name: a_b, to: device, action: drop}]",
            "rule declared twice",
        ),
        (
            "policies: [{from: lan, to: wan, action: accept}, {from: lan, to: wan, action: drop}]",
            "policy declared twice",
        ),
    ],
)
def test_invalid_declarations(body: str, message: str) -> None:
    with pytest.raises(DesiredError, match=message):
        parse(f"sites:\n  home:\n    firewalls:\n      - device: gw\n        {body}\n")


def test_a_firewall_declared_twice_in_two_files_is_refused() -> None:
    one = parse("sites: {home: {firewalls: [{device: gw}]}}")
    with pytest.raises(DesiredError, match="declared twice"):
        from signalbox.desired import _check_unique

        _check_unique(one.merged(one), "desired")


# --- planner ----------------------------------------------------------------------------------


async def test_plan_resolves_zones_and_orders_by_kind(svc: Services) -> None:
    net = await net_of(svc)
    changes = changes_for(parse(WANT), net)
    kinds = {c.key: c for c in changes}
    assert set(kinds) == {
        "policy/iot/lan",
        "policy/iot/device",
        "rule/iot_printer",
        "rule/no_telnet",
        "forward/web",
    }
    assert kinds["policy/iot/lan"].old == ZonePolicyValue(action=FirewallAction.REJECT)
    printer = kinds["rule/iot_printer"].new
    assert isinstance(printer, FirewallRuleValue)
    assert (printer.source_zone, printer.destination_zone, printer.chain) == (
        "iot",
        "lan",
        FirewallChain.FORWARD,
    )
    web = kinds["forward/web"].new
    assert isinstance(web, PortForwardValue) and web.zone == "wan"
    p = plan(parse(WANT), net, RULES)
    assert [c.kind for c in p.changes] == [
        ChangeKind.ZONE_POLICY,
        ChangeKind.ZONE_POLICY,
        ChangeKind.FIREWALL_RULE,
        ChangeKind.FIREWALL_RULE,
        ChangeKind.PORT_FORWARD,
    ]
    assert p.lockouts == []  # the simulator's management address is 127.0.0.1


@pytest.mark.parametrize(
    ("body", "message"),
    [
        ("policies: [{from: dmz, to: lan, action: accept}]", "no zone 'dmz'"),
        ("policies: [{from: {segment: 99}, to: lan, action: accept}]", "is in no zone"),
        ("forwards: [{name: f, port: 1, from: lan, to: {address: 192.0.2.9}}]", None),
    ],
)
async def test_plan_errors(svc: Services, body: str, message: str | None) -> None:
    net = await net_of(svc)
    state = parse(f"sites:\n  home:\n    firewalls:\n      - device: gw\n        {body}\n")
    if message is None:
        assert changes_for(state, net)[0].new.zone == "lan"  # type: ignore[union-attr]
        return
    with pytest.raises(PlanError, match=message):
        changes_for(state, net)


async def test_plan_needs_a_read_firewall_and_one_internet_zone(svc: Services) -> None:
    net = await net_of(svc)
    unread = net.model_copy(update={"firewalls": []})
    with pytest.raises(PlanError, match="has not been read"):
        changes_for(parse(WANT), unread)
    fw = net.firewalls[0]
    zones = [z.model_copy(update={"uplinks": []}) for z in fw.zones]
    no_wan = net.model_copy(update={"firewalls": [fw.model_copy(update={"zones": zones})]})
    with pytest.raises(PlanError, match="say which zone"):
        changes_for(parse(WANT), no_wan)


def test_management_endpoint() -> None:
    assert management_endpoint("192.0.2.1") == (ip_address("192.0.2.1"), None)
    assert management_endpoint("https://192.0.2.1:8443/ubus") == (ip_address("192.0.2.1"), 8443)
    assert management_endpoint("[2001:db8::1]:443") == (ip_address("2001:db8::1"), 443)
    assert management_endpoint("router.example") is None
    assert management_endpoint(None) is None


# --- lockout ----------------------------------------------------------------------------------

LOCKOUT = f"""
sites:
  home:
    firewalls:
      - device: {DEV}
        policies:
          - {{from: lan, to: device, action: reject}}
"""


async def test_a_plan_that_cuts_management_access_needs_the_override(svc: Services) -> None:
    net = await net_of(svc)
    devices = [d.model_copy(update={"management_address": "192.0.2.2:443"}) for d in net.devices]
    net = net.model_copy(update={"devices": devices})
    p = plan(parse(LOCKOUT), net, RULES)
    [cut] = p.lockouts
    assert "Router" in cut and "192.0.2.2 port 443" in cut and "denied after" in cut
    # from another network (Signalbox's own address) the lan policy does not matter
    other = plan(parse(LOCKOUT), net, RULES, signalbox_address=ip_address("203.0.113.9"))
    assert other.lockouts == []
    # a change of something else is not checked
    assert management_cuts(net, net, [], None) == []
    d = Deployer(svc.runner)
    rec = await d.prepare(p, "lock myself out", "tester")
    with pytest.raises(DeployError, match="cut Signalbox off"):
        d.approve(rec.id, "tester")
    ok = d.approve(rec.id, "tester", allow_lockout=True)
    assert ok.allow_lockout and ok.status is ChangeStatus.APPROVED
    [event] = [e for e in svc.store.events(rec.id) if e.event == "approved"]
    assert "ALLOWS LOSING MANAGEMENT ACCESS" in event.detail


async def test_lockout_only_when_the_answer_gets_worse(svc: Services) -> None:
    net = await net_of(svc)
    devices = [d.model_copy(update={"management_address": "192.0.2.2"}) for d in net.devices]
    net = net.model_copy(update={"devices": devices})
    accept = LOCKOUT.replace("reject", "accept")
    c = changes_for(parse(LOCKOUT), net)
    after = apply_change(net, c[0])
    assert management_cuts(net, after, c) != []
    back = changes_for(parse(accept), after)
    assert management_cuts(after, apply_change(after, back[0]), back) == []
    from signalbox.firewall import reach

    assert reach(after, "home/segment/native", "192.0.2.2").verdict is Verdict.DENIED


# --- deployment against the simulator ---------------------------------------------------------


async def test_deploy_then_revert_restores_the_original(sim: OpenWrtSim, svc: Services) -> None:
    before = firewall(sim)
    await net_of(svc)
    d = Deployer(svc.runner)
    rec, done = await deploy(d, svc, WANT)
    calls = [(c.method, c.target) for c in rec.devices[0].calls]
    assert ("uci.add", "firewall.sb_rule_iot_printer") in calls
    assert ("uci.add", "firewall.sb_fwd_web") in calls
    assert ("uci.add", "firewall.sb_pol_iot_lan") in calls
    assert ("uci.order", "firewall.*") in calls
    assert done.status is ChangeStatus.APPLIED, [r.error for r in done.devices]
    assert done.devices[0].status is DeviceStatus.CONFIRMED
    fw = sim.state["firewall"]
    assert fw["sb_rule_iot_printer"] == {
        ".anonymous": False,
        ".type": "rule",
        "name": "iot-printer",
        "src": "iot",
        "dest": "lan",
        "proto": ["tcp"],
        "target": "ACCEPT",
        "dest_ip": ["192.0.2.10/32"],
        "dest_port": "631",
    }
    assert fw["sb_fwd_web"]["dest"] == "lan" and fw["sb_fwd_web"]["dest_port"] == "8443"
    assert fw["iot"]["input"] == "DROP"
    # Signalbox's rules come first, the device's own rules keep their order
    rules = [n for n, s in fw.items() if s[".type"] == "rule"]
    assert rules[:2] == ["sb_rule_iot_printer", "sb_rule_no_telnet"]
    assert [n for n in before if before[n][".type"] == "rule"] == rules[2:]
    # the read side reports exactly what was planned
    net = svc.runner.network()
    assert plan(parse(WANT), net, RULES).changes == []
    assert not [f for f in evaluate(net, drift_rules(parse(WANT))) if f.problem]
    # an import gives the policies and Signalbox's rules and forwards, and plans nothing
    imported = from_network(net, "home")
    [spec] = imported.sites["home"].firewalls
    assert {r.name for r in spec.rules} == {"iot-printer", "no-telnet"}
    assert [f.name for f in spec.forwards] == ["web"]
    assert plan(parse(dump(imported)), net, RULES).changes == []
    back = await d.revert(done.id, "not needed", "tester")
    d.approve(back.id, "tester", override="lab" if back.plan.blocking else None)
    undone = await d.deploy(back.id)
    assert undone.status is ChangeStatus.APPLIED, [r.error for r in undone.devices]
    after = firewall(sim)
    assert after == dict(before.items())
    assert list(after) == list(before)


async def test_undeclared_rules_of_signalbox_are_removed(sim: OpenWrtSim, svc: Services) -> None:
    before = firewall(sim)
    await net_of(svc)
    d = Deployer(svc.runner)
    _, done = await deploy(d, svc, WANT)
    assert done.status is ChangeStatus.APPLIED
    empty = f"sites:\n  home:\n    firewalls:\n      - device: {DEV}\n"
    drift = [f for f in evaluate(svc.runner.network(), drift_rules(parse(empty))) if f.problem]
    assert len(drift) == 3 and all("no longer declared" in f.message for f in drift)
    p = plan(parse(empty), svc.runner.network(), RULES)
    assert {c.action for c in p.changes} == {"remove"} and len(p.changes) == 3
    _, gone = await deploy(d, svc, empty)
    assert gone.status is ChangeStatus.APPLIED, [r.error for r in gone.devices]
    fw = sim.state["firewall"]
    assert not [n for n in fw if n.startswith(("sb_rule_", "sb_fwd_"))]
    # the policies stay as deployed (they are the zones' own settings)
    assert fw["iot"]["input"] == "DROP" and "sb_pol_iot_lan" in fw
    assert set(before) <= set(fw)


REJECT_LAN_WAN = f"""
sites:
  home:
    firewalls:
      - device: {DEV}
        policies:
          - {{from: lan, to: wan, action: reject{{adopt}}}}
"""


async def test_the_devices_own_forwarding_needs_adopt(sim: OpenWrtSim, svc: Services) -> None:
    await net_of(svc)
    d = Deployer(svc.runner)
    p = plan(parse(REJECT_LAN_WAN.replace("{adopt}", "")), svc.runner.network(), RULES)
    with pytest.raises(DeployError, match="adopt: true"):
        await d.prepare(p, "no internet", "tester")
    _rec, done = await deploy(d, svc, REJECT_LAN_WAN.replace("{adopt}", ", adopt: true"))
    assert done.status is ChangeStatus.APPLIED, [r.error for r in done.devices]
    assert "cfg04ad58" not in sim.state["firewall"]
    back = await d.revert(done.id, "internet again", "tester")
    d.approve(back.id, "tester", override="lab" if back.plan.blocking else None)
    undone = await d.deploy(back.id)
    assert undone.status is ChangeStatus.APPLIED, [r.error for r in undone.devices]
    # the forwarding comes back as Signalbox's own
    assert sim.state["firewall"]["sb_pol_lan_wan"] == {
        ".anonymous": False,
        ".type": "forwarding",
        "src": "lan",
        "dest": "wan",
    }


ADOPT = f"""
sites:
  home:
    firewalls:
      - device: {DEV}
        rules:
          - name: iot-dns
            adopt: Allow-DNS-IoT
            from: {{zone: iot}}
            to: device
            port: 53
            action: accept
"""


async def test_adopting_a_rule_replaces_it_with_a_tagged_one(
    sim: OpenWrtSim, svc: Services
) -> None:
    await net_of(svc)
    d = Deployer(svc.runner)
    p = plan(parse(ADOPT), svc.runner.network(), RULES)
    [c] = p.changes
    assert c.adopt == "Allow-DNS-IoT" and c.old is not None and c.old.name == "Allow-DNS-IoT"
    _, done = await deploy(d, svc, ADOPT)
    assert done.status is ChangeStatus.APPLIED, [r.error for r in done.devices]
    fw = sim.state["firewall"]
    assert "iot_dns" not in fw and fw["sb_rule_iot_dns"]["name"] == "iot-dns"
    assert plan(parse(ADOPT), svc.runner.network(), RULES).changes == []


async def test_refused_firewall_changes(sim: OpenWrtSim, svc: Services) -> None:
    await net_of(svc)
    d = Deployer(svc.runner)
    drop = REJECT_LAN_WAN.replace("reject{adopt}", "drop")
    with pytest.raises(DeployError, match="declare reject"):
        await d.prepare(plan(parse(drop), svc.runner.network(), RULES), "x", "tester")
    nowhere = WANT.replace("192.0.2.20", "100.64.0.20")
    with pytest.raises(DeployError, match="in no network"):
        await d.prepare(plan(parse(nowhere), svc.runner.network(), RULES), "x", "tester")
    net = svc.runner.network()
    bad = Change(
        kind=ChangeKind.ZONE_POLICY,
        device_id=DEV,
        site_id="home",
        key="policy/dmz/device",
        old=None,
        new=ZonePolicyValue(action=FirewallAction.DROP),
    )
    adapter = d.adapter(DEV)
    try:
        with pytest.raises(Exception, match="no zone 'dmz'"):
            await adapter.plan_changes([bad], {})  # type: ignore[attr-defined]
    finally:
        await adapter.close()
    adopt = ADOPT.replace("Allow-DNS-IoT", "No-Such-Rule")
    with pytest.raises(DeployError, match="no rule named"):
        await d.prepare(plan(parse(adopt), net, RULES), "x", "tester")


async def test_without_read_access_to_the_firewall_other_changes_still_work(
    sim: OpenWrtSim, svc: Services
) -> None:
    await net_of(svc)
    sim.denied.add("uci:firewall")
    d = Deployer(svc.runner)
    adapter = d.adapter(DEV)
    try:
        backup = await adapter.backup()  # type: ignore[attr-defined]
        assert "firewall" not in backup.content
        c = changes_for(parse(WANT), svc.runner.network())[0]
        with pytest.raises(Exception, match="firewall could not be read"):
            await adapter.plan_changes([c], {})  # type: ignore[attr-defined]
    finally:
        await adapter.close()


def test_tag_of_sections() -> None:
    assert tag({".name": "sb_rule_x", ".anonymous": False}, "sb_rule_") == "x"
    assert tag({".name": "sb_rule_", ".anonymous": False}, "sb_rule_") is None
    assert tag({".name": "cfg01", ".anonymous": True}, "sb_rule_") is None


async def test_drift_findings(svc: Services) -> None:
    net = await net_of(svc)
    msgs = [f.message for f in evaluate(net, drift_rules(parse(WANT))) if f.problem]
    assert any("zone policy iot/lan: action: should be accept, is reject" in m for m in msgs)
    assert any("firewall rule iot_printer is missing" in m for m in msgs)
    bad = parse(
        "sites: {home: {firewalls: [{device: gw, policies: [{from: dmz, to: lan, "
        "action: accept}]}]}}"
    )
    [f] = [f for f in evaluate(net, drift_rules(bad)) if f.rule_id == "drift.firewall"]
    assert "cannot be compared" in f.message and "no zone 'dmz'" in f.message
    unread = net.model_copy(update={"firewalls": []})
    [g] = [f for f in evaluate(unread, drift_rules(parse(WANT))) if f.rule_id == "drift.firewall"]
    assert g.incomplete
