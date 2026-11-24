"""Firewall rules, port forwards and zone policies on OPNsense (#295, ADR 0017).

Deployments run through the real Deployer against the OPNsense simulator (zones lan, opt1 "IoT",
opt2 "Guest", wan and the interface group internal; the device's own rules of the new page, of
the legacy pages and the automatic ones; the owner's port forward "NAS web interface").
OPNsense 26.7 has no savepoint and rollback timer for the filter API: the changes are applied
with ``apply`` and undone, when the verification fails, by restoring the backup.
"""

from __future__ import annotations

import copy
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from signalbox.adapters import AdapterError
from signalbox.adapters.opnsense import OpnsenseAdapter, OpnsenseConfig
from signalbox.adapters.opnsense import firewall as fw
from signalbox.changes import (
    Change,
    ChangeKind,
    FirewallRuleValue,
    PlanError,
    PortForwardValue,
    ZonePolicyValue,
    changes_for,
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
)
from signalbox.rules import evaluate
from signalbox.rules.builtin import RULES
from signalbox.service import Services, build
from signalbox.sim.opnsense import DNAT, FILTER, KEY, SECRET, OpnsenseSimulator
from signalbox.sim.server import serve
from signalbox.store import DeviceRecord

DEV = "fw"
SITE = Site(id="home", name="Home")
ENV = {"SIGNALBOX_AUTH_PASSWORD": "x" * 12, "SIGNALBOX_DEPLOY_ENABLED": "true"}
SIM = OpnsenseSimulator()

WANT = f"""
sites:
  home:
    firewalls:
      - device: {DEV}
        policies:
          - {{from: opt1, to: lan, action: accept}}
          - {{from: opt1, to: device, action: reject}}
        rules:
          - name: iot-printer
            from: {{zone: opt1}}
            to: {{network: 192.0.2.10}}
            protocol: tcp
            port: 631
            action: accept
          - name: no-telnet
            to: device
            protocol: tcp
            port: 23
            action: reject
          - name: guest-to-iot
            from: {{zone: opt2}}
            to: {{zone: opt1}}
            action: drop
        forwards:
          - name: web
            protocol: tcp
            port: 443
            to: {{address: 192.0.2.20, port: 8443}}
"""


@pytest.fixture(scope="module")
def url() -> Iterator[str]:
    with serve(SIM.app()) as base:
        yield base


@pytest.fixture
def sim() -> OpnsenseSimulator:
    SIM.__dict__.update(OpnsenseSimulator().__dict__)
    return SIM


@pytest.fixture
def svc(sim: OpnsenseSimulator, url: str, tmp_path: Path) -> Iterator[Services]:
    s = build(
        tmp_path, env=ENV, adapters={"opnsense": OpnsenseAdapter}, rules=RULES, link_sources=[]
    )
    s.store.put_site(SITE)
    rec = DeviceRecord(
        id=DEV,
        site_id="home",
        name="Firewall",
        role=DeviceRole.GATEWAY,
        adapter="opnsense",
        allow_writes=True,
    )
    values = {"url": url, "api_key": KEY, "api_secret": SECRET, "allow_insecure_http": True}
    s.store.put_device(rec, values, OpnsenseConfig)
    yield s
    s.close()


def rows(sim: OpnsenseSimulator) -> tuple[Any, Any]:
    return copy.deepcopy(sim.data[FILTER]["rows"]), copy.deepcopy(sim.data[DNAT]["rows"])


def ours(sim: OpnsenseSimulator, path: str = FILTER) -> list[dict[str, Any]]:
    return [r for r in sim.data[path]["rows"] if fw.tagged(r) is not None]


async def net_of(svc: Services) -> Network:
    await svc.runner.observe_all()
    return svc.runner.network()


async def deploy(d: Deployer, svc: Services, text: str, **approve: Any) -> Any:
    p = plan(parse(text), svc.runner.network(), RULES)
    rec = await d.prepare(p, "firewall", "tester")
    d.approve(rec.id, "tester", override="lab" if rec.plan.blocking else None, **approve)
    return rec, await d.deploy(rec.id)


async def undo(d: Deployer, cid: str) -> Any:
    back = await d.revert(cid, "not needed", "tester")
    d.approve(back.id, "tester", override="lab" if back.plan.blocking else None)
    return await d.deploy(back.id)


def events(svc: Services, cid: str) -> list[str]:
    return [f"{e.event} {e.detail}" for e in svc.store.events(cid)]


# --- reading what Signalbox wrote -----------------------------------------------------------


def test_tags_are_read_from_the_description() -> None:
    assert fw.tagged({"description": "signalbox:web_app web-app"}) == "web_app web-app"
    assert fw.split_mark("web_app web-app") == ("web_app", "web-app")
    assert fw.split_mark("web") == ("web", "web")
    assert fw.describe("web", "web") == "signalbox:web"
    assert fw.describe("a_b", "a-b") == "signalbox:a_b a-b"
    assert fw.tagged({"descr": "signalbox:policy/lan/wan"}) == "policy/lan/wan"
    assert fw.tagged({"description": "signalbox:"}) is None
    assert fw.tagged({"description": "Anti-Lockout Rule", "is_automatic": True}) is None
    # the legacy and automatic pages never carry the tag, whatever the description says
    assert fw.tagged({"description": "signalbox:x", "legacy": True}) is None
    assert fw.key_of("web-app") == "web_app"


# --- deployment against the simulator ---------------------------------------------------------


async def test_deploy_then_revert_restores_the_identical_state(
    sim: OpnsenseSimulator, svc: Services
) -> None:
    before = rows(sim)
    await net_of(svc)
    d = Deployer(svc.runner)
    rec, done = await deploy(d, svc, WANT)
    assert done.status is ChangeStatus.APPLIED, [r.error for r in done.devices]
    assert done.devices[0].status is DeviceStatus.CONFIRMED
    calls = [(c.method, c.target) for c in rec.devices[0].calls]
    assert ("POST", "/api/firewall/filter/add_rule") in calls
    assert ("POST", "/api/firewall/d_nat/add_rule") in calls
    # the transaction is "save, then apply": the packet filter is reloaded once at the end
    assert calls[-2:] == [
        ("POST", "/api/firewall/filter/apply"),
        ("POST", "/api/firewall/d_nat/apply"),
    ]
    assert not [c for c in calls if "savepoint" in c[1] or "rollback" in c[1]]
    by_name = {r["description"]: r for r in ours(sim)}
    assert set(by_name) == {
        "signalbox:policy/opt1/lan",
        "signalbox:policy/opt1/device",
        "signalbox:iot_printer iot-printer",
        "signalbox:no_telnet no-telnet",
        "signalbox:guest_to_iot guest-to-iot",
    }
    printer = by_name["signalbox:iot_printer iot-printer"]
    assert (printer["interface"], printer["protocol"], printer["action"]) == (
        "opt1",
        "TCP",
        "pass",
    )
    assert printer["destination_net"] == "192.0.2.10/32" and printer["destination_port"] == "631"
    telnet = by_name["signalbox:no_telnet no-telnet"]
    assert telnet["destination_net"] == "(self)" and telnet["interface"] == ""
    guest = by_name["signalbox:guest_to_iot guest-to-iot"]
    assert (guest["destination_net"], guest["action"], guest["interface"]) == (
        "opt1",
        "block",
        "opt2",
    )
    # Signalbox's rules come before the device's own (sequence 1, 2, 3; the policies last)
    assert [r["sequence"] for r in ours(sim) if not r["description"].startswith("signalbox:p")] == [
        "1",
        "2",
        "3",
    ]
    assert int(by_name["signalbox:policy/opt1/lan"]["sequence"]) >= 900000
    [fwd] = ours(sim, DNAT)
    assert fwd["descr"] == "signalbox:web" and fwd["interface"] == "wan"
    assert (fwd["destination.network"], fwd["destination.port"]) == ("wanip", "443")
    assert (fwd["target"], fwd["local-port"], fwd["pass"]) == ("192.0.2.20", "8443", "pass")
    assert sim.applied == ["filter", "d_nat"]
    # the read side reports exactly what was planned
    net = svc.runner.network()
    assert plan(parse(WANT), net, RULES).changes == []
    assert not [f for f in evaluate(net, drift_rules(parse(WANT))) if f.problem]
    imported = from_network(net, "home")
    [spec] = imported.sites["home"].firewalls
    assert {r.name for r in spec.rules} == {"iot-printer", "no-telnet", "guest-to-iot"}
    assert [f.name for f in spec.forwards] == ["web"]
    assert len(spec.policies) == 2
    assert plan(parse(dump(imported)), net, RULES).changes == []
    # the device's own rules and forward are untouched
    own = [r for r in sim.data[FILTER]["rows"] if fw.tagged(r) is None]
    assert own == before[0]
    assert [r for r in sim.data[DNAT]["rows"] if fw.tagged(r) is None] == before[1]
    undone = await undo(d, done.id)
    assert undone.status is ChangeStatus.APPLIED, [r.error for r in undone.devices]
    assert rows(sim) == before


async def test_undeclared_objects_of_signalbox_are_removed(
    sim: OpnsenseSimulator, svc: Services
) -> None:
    before = rows(sim)
    await net_of(svc)
    d = Deployer(svc.runner)
    _, done = await deploy(d, svc, WANT)
    assert done.status is ChangeStatus.APPLIED
    empty = f"sites:\n  home:\n    firewalls:\n      - device: {DEV}\n"
    drift = [f for f in evaluate(svc.runner.network(), drift_rules(parse(empty))) if f.problem]
    assert len(drift) == 4 and all("no longer declared" in f.message for f in drift)
    p = plan(parse(empty), svc.runner.network(), RULES)
    assert {c.action for c in p.changes} == {"remove"} and len(p.changes) == 4
    _, gone = await deploy(d, svc, empty)
    assert gone.status is ChangeStatus.APPLIED, [r.error for r in gone.devices]
    assert not [r for r in ours(sim, FILTER) if not r["description"].startswith("signalbox:policy")]
    assert not ours(sim, DNAT)
    # the policies are rules of ours that stay until they are declared away (as on OpenWrt)
    assert len(ours(sim)) == 2
    accept_to_drop = WANT.replace("action: accept}", "action: drop}", 1).replace(
        "action: reject}", "action: drop}", 1
    )
    _, dropped = await deploy(d, svc, accept_to_drop.split("rules:")[0])
    assert dropped.status is ChangeStatus.APPLIED, [r.error for r in dropped.devices]
    # pf blocks what no rule passes: a "drop" policy is no rule at all
    assert not ours(sim)
    assert rows(sim) == before


async def test_changing_a_declared_rule_updates_it_in_place(
    sim: OpnsenseSimulator, svc: Services
) -> None:
    await net_of(svc)
    d = Deployer(svc.runner)
    _, first = await deploy(d, svc, WANT)
    assert first.status is ChangeStatus.APPLIED
    uuids = {r["description"]: r["uuid"] for r in ours(sim)}
    seq = {r["description"]: r["sequence"] for r in ours(sim)}
    changed = WANT.replace("port: 631", "port: 9100").replace("port: 443", "port: 444")
    _, second = await deploy(d, svc, changed)
    assert second.status is ChangeStatus.APPLIED, [r.error for r in second.devices]
    assert {r["description"]: r["uuid"] for r in ours(sim)} == uuids
    printer = next(r for r in ours(sim) if r["description"] == "signalbox:iot_printer iot-printer")
    assert printer["destination_port"] == "9100"
    assert printer["sequence"] == seq["signalbox:iot_printer iot-printer"]
    assert ours(sim, DNAT)[0]["destination.port"] == "444"
    paths = [p for p, _ in sim.posts]
    assert "/api/firewall/filter/set_rule/" + uuids["signalbox:iot_printer iot-printer"] in paths


ADOPT = f"""
sites:
  home:
    firewalls:
      - device: {DEV}
        rules:
          - name: iot-dns
            adopt: "IoT: DNS to the firewall"
            from: {{zone: opt1}}
            to: device
            port: 53
            action: accept
        forwards:
          - name: nas-web
            adopt: NAS web interface
            from: wan
            protocol: tcp
            port: 8443
            to: {{address: 192.0.2.10, port: 443}}
"""


async def test_adopting_replaces_the_devices_own_objects_with_tagged_ones(
    sim: OpnsenseSimulator, svc: Services
) -> None:
    before = rows(sim)
    await net_of(svc)
    # without the declaration nothing of the device's own is touched
    assert (
        plan(
            parse(f"sites: {{home: {{firewalls: [{{device: {DEV}}}]}}}}"),
            svc.runner.network(),
            RULES,
        ).changes
        == []
    )
    d = Deployer(svc.runner)
    p = plan(parse(ADOPT), svc.runner.network(), RULES)
    by_key = {c.key: c for c in p.changes}
    assert by_key["rule/iot_dns"].adopt == "IoT: DNS to the firewall"
    assert by_key["rule/iot_dns"].old is not None
    assert by_key["forward/nas_web"].adopt == "NAS web interface"
    _, done = await deploy(d, svc, ADOPT)
    assert done.status is ChangeStatus.APPLIED, [r.error for r in done.devices]
    names = [r["description"] for r in sim.data[FILTER]["rows"]]
    assert "IoT: DNS to the firewall" not in names and "signalbox:iot_dns iot-dns" in names
    assert "NAS web interface" not in [r.get("descr") for r in sim.data[DNAT]["rows"]]
    # the adopted rule keeps its place (sequence 1)
    adopted = next(
        r for r in sim.data[FILTER]["rows"] if r["description"] == "signalbox:iot_dns iot-dns"
    )
    assert adopted["sequence"] == "1"
    assert plan(parse(ADOPT), svc.runner.network(), RULES).changes == []
    undone = await undo(d, done.id)
    assert undone.status is ChangeStatus.APPLIED, [r.error for r in undone.devices]
    # the rule and the forward come back as Signalbox's own, under their old names
    assert "signalbox:iot_dns IoT: DNS to the firewall" in [r["description"] for r in ours(sim)]
    assert before != rows(sim)


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (
            "rules: [{name: x, adopt: Default allow LAN to any rule, to: device, action: drop}]",
            "legacy or automatic",
        ),
        (
            "rules: [{name: x, adopt: No such rule, to: device, action: drop}]",
            "no rule named",
        ),
        (
            "rules: [{name: x, from: {zone: lan}, "
            "to: {zone: opt1, network: 192.0.2.9}, action: drop}]",
            "not both",
        ),
        (
            "rules: [{name: x, to: device, protocol: tcp, port: [22, 23], action: drop}]",
            "one port",
        ),
        (
            "rules: [{name: x, to: device, protocol: icmp, action: drop}]",
            "ICMP needs family",
        ),
        (
            "rules: [{name: x, to: device, protocol: [tcp, icmp], action: drop}]",
            "cannot match the protocols",
        ),
        (
            "forwards: [{name: f, from: internal, port: 1, to: {address: 192.0.2.9}}]",
            "no interface 'internal'",
        ),
        (
            "forwards: [{name: f, port: 1, to: {address: '2001:db8::9'}}]",
            "only IPv4 targets",
        ),
        (
            "forwards: [{name: f, protocol: gre, port: 1, to: {address: 192.0.2.9}}]",
            "tcp",
        ),
    ],
)
async def test_refusals_name_the_reason_before_anything_is_sent(
    sim: OpnsenseSimulator, svc: Services, change: str, message: str
) -> None:
    await net_of(svc)
    text = f"sites:\n  home:\n    firewalls:\n      - device: {DEV}\n        {change}\n"
    with pytest.raises((DeployError, PlanError, DesiredError), match=message):
        p = plan(parse(text), svc.runner.network(), RULES)
        await Deployer(svc.runner).prepare(p, "x", "tester")
    assert not [p for p, _ in sim.posts]


async def test_unknown_zones_and_missing_pages(sim: OpnsenseSimulator, svc: Services) -> None:
    await net_of(svc)
    d = Deployer(svc.runner)
    adapter = d.adapter(DEV)
    try:
        bad = Change(
            kind=ChangeKind.ZONE_POLICY,
            device_id=DEV,
            site_id="home",
            key="policy/dmz/device",
            old=None,
            new=ZonePolicyValue(action=FirewallAction.REJECT),
        )
        with pytest.raises(AdapterError, match="no zone 'dmz'"):
            await adapter.plan_changes([bad], {})  # type: ignore[attr-defined]
        bad2 = bad.model_copy(update={"key": "policy/lan/dmz"})
        with pytest.raises(AdapterError, match="no zone 'dmz'"):
            await adapter.plan_changes([bad2], {})  # type: ignore[attr-defined]
        rule = FirewallRuleValue(
            name="x", chain=FirewallChain.INPUT, source_zone="dmz", action=FirewallAction.DROP
        )
        c = Change(
            kind=ChangeKind.FIREWALL_RULE,
            device_id=DEV,
            site_id="home",
            key="rule/x",
            old=None,
            new=rule,
        )
        with pytest.raises(AdapterError, match="no zone 'dmz'"):
            await adapter.plan_changes([c], {})  # type: ignore[attr-defined]
        # a release without the new NAT page cannot write port forwards, rules still work
        del sim.data[DNAT]
        forward = Change(
            kind=ChangeKind.PORT_FORWARD,
            device_id=DEV,
            site_id="home",
            key="forward/f",
            old=None,
            new=PortForwardValue(
                name="f",
                protocols=[FirewallProtocol.TCP],
                zone="wan",
                external_ports=[],
                target_address="192.0.2.9",  # type: ignore[arg-type]
            ),
        )
        with pytest.raises(AdapterError, match="no API for port forwards"):
            await adapter.plan_changes([forward], {})  # type: ignore[attr-defined]
        ok = rule.model_copy(update={"source_zone": "lan"})
        calls = await adapter.plan_changes([c.model_copy(update={"new": ok})], {})  # type: ignore[attr-defined]
        assert [(x.method, x.target) for x in calls] == [
            ("POST", "/api/firewall/filter/add_rule"),
            ("POST", "/api/firewall/filter/apply"),
        ]
        assert calls[0].payload["rule"]["description"] == "signalbox:x"
    finally:
        await adapter.close()


async def test_a_failing_apply_restores_the_backup(sim: OpnsenseSimulator, svc: Services) -> None:
    before = rows(sim)
    await net_of(svc)
    sim.invalid["/api/firewall/d_nat/apply"] = {"filter": "pf refused the rules"}
    d = Deployer(svc.runner)
    p = plan(parse(WANT), svc.runner.network(), RULES)
    rec = await d.prepare(p, "firewall", "tester")
    d.approve(rec.id, "tester", override="lab" if rec.plan.blocking else None)
    done = await d.deploy(rec.id)
    assert done.status is not ChangeStatus.APPLIED
    assert done.devices[0].status is DeviceStatus.ROLLED_BACK, events(svc, rec.id)
    assert rows(sim) == before


async def test_a_verification_failure_restores_the_backup(
    sim: OpnsenseSimulator, svc: Services
) -> None:
    """The firewall saves a rule but does not report it as planned: back to the backup."""
    before = rows(sim)
    await net_of(svc)
    d = Deployer(svc.runner)
    p = plan(parse(WANT), svc.runner.network(), RULES)
    rec = await d.prepare(p, "firewall", "tester")
    d.approve(rec.id, "tester", override="lab" if rec.plan.blocking else None)
    # the forward is saved on another interface than declared
    original = sim._dnat_row

    def wrong(body: dict[str, Any], uuid: str, old: dict[str, Any]) -> dict[str, Any]:
        row = original(body, uuid, old)
        return {**row, "interface": "opt1"}

    sim._dnat_row = wrong  # type: ignore[method-assign]
    done = await d.deploy(rec.id)
    assert done.devices[0].status is DeviceStatus.ROLLED_BACK, events(svc, rec.id)
    assert any("verification failed" in e for e in events(svc, rec.id)) or any(
        e.startswith("verify-failed") for e in events(svc, rec.id)
    )
    assert rows(sim) == before


# --- lockout ----------------------------------------------------------------------------------

LOCKOUT = f"""
sites:
  home:
    firewalls:
      - device: {DEV}
        rules:
          - name: no-ui
            from: {{zone: lan}}
            to: device
            protocol: tcp
            port: 8443
            action: reject
"""


async def test_a_plan_that_cuts_management_access_needs_the_override(
    sim: OpnsenseSimulator, svc: Services
) -> None:
    net = await net_of(svc)
    # the firewall's web interface at 192.0.2.1:8443 is not one of the anti-lockout ports
    devices = [d.model_copy(update={"management_address": "192.0.2.1:8443"}) for d in net.devices]
    net = net.model_copy(update={"devices": devices})
    p = plan(parse(LOCKOUT), net, RULES)
    [cut] = p.lockouts
    assert "Firewall" in cut and "192.0.2.1 port 8443" in cut and "denied after" in cut
    d = Deployer(svc.runner)
    rec = await d.prepare(p, "lock myself out", "tester")
    with pytest.raises(DeployError, match="cut Signalbox off"):
        d.approve(rec.id, "tester")
    ok = d.approve(rec.id, "tester", allow_lockout=True)
    assert ok.allow_lockout and ok.status is ChangeStatus.APPROVED
    [event] = [e for e in svc.store.events(rec.id) if e.event == "approved"]
    assert "ALLOWS LOSING MANAGEMENT ACCESS" in event.detail
    done = await d.deploy(rec.id)
    assert done.status is ChangeStatus.APPLIED, events(svc, rec.id)
    [row] = ours(sim)
    assert row["description"] == "signalbox:no_ui no-ui" and row["action"] == "reject"
    assert row["destination_net"] == "(self)" and row["destination_port"] == "8443"


def test_changes_for_needs_a_read_firewall(svc: Services) -> None:
    with pytest.raises(Exception, match="has not been read"):
        changes_for(parse(WANT), Network(sites=[SITE]))


def test_simulator_validates_like_the_firewall(sim: OpnsenseSimulator, url: str) -> None:
    import httpx

    def post(path: str, body: dict[str, Any]) -> dict[str, Any]:
        auth = (KEY, SECRET)
        with httpx.Client(trust_env=False) as client:
            answer: dict[str, Any] = client.post(url + path, json=body, auth=auth).json()
        return answer

    good = {
        "action": "pass",
        "interface": "lan",
        "direction": "in",
        "ipprotocol": "inet",
        "protocol": "TCP",
        "source_net": "any",
        "destination_net": "(self)",
        "destination_port": "22",
        "sequence": "1",
        "description": "t",
    }
    base = "/api/firewall/filter/add_rule"
    bad_fields = {
        "action": ("block2", "rule.action"),
        "interface": ("dmz", "rule.interface"),
        "direction": ("up", "rule.direction"),
        "ipprotocol": ("v5", "rule.ipprotocol"),
        "protocol": ("SCTP", "rule.protocol"),
        "source_net": ("nowhere", "rule.source_net"),
        "destination_port": ("x", "rule.destination_port"),
        "sequence": ("0", "rule.sequence"),
    }
    for key, (value, field) in bad_fields.items():
        answer = post(base, {"rule": {**good, key: value}})
        assert answer["result"] == "failed" and field in answer["validations"], (key, answer)
    answer = post(base, {"rule": {**good, "protocol": "any"}})
    assert "rule.destination_port" in answer["validations"]  # ports need tcp or udp
    answer = post(base, {"rule": {**good, "destination_port": "70000"}})
    assert "rule.destination_port" in answer["validations"]
    assert post(base, {"rule": good})["result"] == "saved"
    nat = "/api/firewall/d_nat/add_rule"
    item = {
        "interface": "wan",
        "protocol": "tcp",
        "destination": {"network": "wanip", "port": "80"},
        "target": "192.0.2.9",
        "local-port": "80",
        "sequence": "1",
    }
    for key, value, field in [
        ("interface", "dmz", "rule.interface"),
        ("protocol", "icmp", "rule.protocol"),
        ("target", "web", "rule.target"),
        ("local-port", "x", "rule.local-port"),
        ("sequence", "x", "rule.sequence"),
    ]:
        answer = post(nat, {"rule": {**item, key: value}})
        assert field in answer["validations"], (key, answer)
    assert post(nat, {"rule": item})["result"] == "saved"
    # the device's own legacy and automatic rows cannot be changed or deleted through the API
    legacy = next(r for r in sim.data[FILTER]["rows"] if r.get("legacy"))
    assert post(f"/api/firewall/filter/del_rule/{legacy['uuid']}", {})["result"] == "not found"
    assert (
        post(f"/api/firewall/filter/set_rule/{legacy['uuid']}", {"rule": {}})["result"] == "failed"
    )
    assert post("/api/firewall/filter/set_rule/nope", {"rule": {}})["result"] == "failed"
    assert post("/api/firewall/d_nat/set_rule/nope", {"rule": {}})["result"] == "failed"
    assert post("/api/firewall/d_nat/del_rule/nope", {})["result"] == "not found"
