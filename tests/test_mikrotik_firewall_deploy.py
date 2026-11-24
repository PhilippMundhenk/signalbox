"""Firewall rules, port forwards and zone policies on MikroTik (#295, ADR 0017).

Deployments run through the real Deployer against the RouterOS simulator (interface lists LAN,
WAN, IOT; the device's own rules, among them a user chain and a dst-nat). Rows Signalbox writes
carry the comment ``signalbox:<key>``. While they are written a scheduler entry
(``signalbox-revert``) holds a script that undoes them; the simulator runs that script on
``fire_scheduler`` (a small interpreter of the lines the writer produces).
"""

from __future__ import annotations

import copy
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from pydantic import SecretStr

from signalbox.adapters import AdapterContext, AdapterError
from signalbox.adapters.mikrotik import MikrotikAdapter, MikrotikConfig
from signalbox.adapters.mikrotik import firewall as fw
from signalbox.adapters.mikrotik.fwwrite import REVERT_NAME, ros_quote
from signalbox.changes import (
    Change,
    ChangeKind,
    FirewallRuleValue,
    PlanError,
    PortForwardValue,
    ZonePolicyValue,
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
from signalbox.sim.mikrotik import (
    FW_FILTER,
    FW_FILTER6,
    FW_NAT,
    PASSWORD,
    SCHEDULER,
    MikrotikSimulator,
    _script_words,
)
from signalbox.sim.server import serve
from signalbox.store import DeviceRecord

DEV = "rt"
SITE = Site(id="home", name="Home")
ENV = {"SIGNALBOX_AUTH_PASSWORD": "x" * 12, "SIGNALBOX_DEPLOY_ENABLED": "true"}
SIM = MikrotikSimulator()
MENUS = (FW_FILTER, FW_FILTER6, FW_NAT)

WANT = f"""
sites:
  home:
    firewalls:
      - device: {DEV}
        policies:
          - {{from: IOT, to: LAN, action: drop}}
          - {{from: IOT, to: device, action: reject}}
        rules:
          - name: iot-printer
            from: {{zone: IOT}}
            to: {{network: 192.0.2.10}}
            protocol: tcp
            family: 4
            port: 631
            action: accept
          - name: no-telnet
            to: device
            family: 4
            protocol: tcp
            port: 23
            action: reject
          - name: guest-to-iot
            from: {{zone: LAN}}
            to: {{zone: IOT}}
            family: 4
            action: drop
        forwards:
          - name: web
            from: WAN
            protocol: tcp
            port: 443
            to: {{address: 192.0.2.20, port: 8443}}
"""


@pytest.fixture(scope="module")
def url() -> Iterator[str]:
    with serve(SIM.app()) as base:
        yield base


@pytest.fixture
def sim() -> MikrotikSimulator:
    SIM.__dict__.update(MikrotikSimulator().__dict__)
    return SIM


@pytest.fixture
def svc(sim: MikrotikSimulator, url: str, tmp_path: Path) -> Iterator[Services]:
    s = build(
        tmp_path, env=ENV, adapters={"mikrotik": MikrotikAdapter}, rules=RULES, link_sources=[]
    )
    s.store.put_site(SITE)
    rec = DeviceRecord(
        id=DEV,
        site_id="home",
        name="Router",
        role=DeviceRole.GATEWAY,
        adapter="mikrotik",
        allow_writes=True,
    )
    values = {"url": url, "password": PASSWORD, "allow_insecure_http": True}
    s.store.put_device(rec, values, MikrotikConfig)
    yield s
    s.close()


def adapter(url: str) -> MikrotikAdapter:
    config = MikrotikConfig(url=url, password=SecretStr(PASSWORD), allow_insecure_http=True)
    return MikrotikAdapter(
        AdapterContext(
            site_id="home",
            device_id=DEV,
            device_name="Router",
            role=DeviceRole.GATEWAY,
            config=config,
        )
    )


def rows(sim: MikrotikSimulator) -> dict[str, Any]:
    """The firewall menus without the ids (a re-created row has a new one)."""
    return {
        m: [{k: v for k, v in r.items() if k != ".id"} for r in copy.deepcopy(sim.data[m])]
        for m in MENUS
    }


def ours(sim: MikrotikSimulator, menu: str = FW_FILTER) -> list[dict[str, Any]]:
    return [r for r in sim.data[menu] if fw.tagged(r) is not None]


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


# --- reading what Signalbox wrote -------------------------------------------------------------


def test_tags_are_read_from_the_comment() -> None:
    assert fw.tagged({"comment": "signalbox:web_app web-app"}) == "web_app web-app"
    assert fw.split_mark("web_app web-app") == ("web_app", "web-app")
    assert fw.split_mark("web") == ("web", "web")
    assert fw.describe("web", "web") == "signalbox:web"
    assert fw.describe("a_b", "a-b") == "signalbox:a_b a-b"
    assert fw.tagged({"comment": "signalbox:policy/LAN/IOT"}) == "policy/LAN/IOT"
    assert fw.tagged({"comment": "signalbox:"}) is None
    assert fw.tagged({"comment": "defconf: accept"}) is None
    assert fw.tagged({"comment": "signalbox:x", "dynamic": "true"}) is None
    assert fw.key_of("web-app") == "web_app"


def test_script_quoting_round_trips() -> None:
    text = 'a "quoted" $name? and \\ backslash'
    assert _script_words(f"x={ros_quote(text)}") == ["x=" + text]


# --- deployment against the simulator ---------------------------------------------------------


async def test_deploy_then_revert_restores_the_identical_state(
    sim: MikrotikSimulator, svc: Services
) -> None:
    before = rows(sim)
    await net_of(svc)
    d = Deployer(svc.runner)
    rec, done = await deploy(d, svc, WANT)
    assert done.status is ChangeStatus.APPLIED, [r.error for r in done.devices]
    assert done.devices[0].status is DeviceStatus.CONFIRMED
    calls = [(c.method, c.target) for c in rec.devices[0].calls]
    # the revert timer is armed first, before any row is written
    assert calls[0] == ("PUT", "/rest/system/scheduler")
    assert ("PUT", FW_FILTER) in calls and ("PUT", FW_NAT) in calls
    # ... and removed again after the verification
    assert sim.data[SCHEDULER] == []
    by_name = {r["comment"]: r for r in ours(sim)}
    assert set(by_name) == {
        "signalbox:policy/IOT/LAN",
        "signalbox:policy/IOT/device",
        "signalbox:iot_printer iot-printer",
        "signalbox:no_telnet no-telnet",
        "signalbox:guest_to_iot guest-to-iot",
    }
    printer = by_name["signalbox:iot_printer iot-printer"]
    assert (printer["chain"], printer["protocol"], printer["action"]) == (
        "forward",
        "tcp",
        "accept",
    )
    assert printer["in-interface-list"] == "IOT" and printer["dst-address"] == "192.0.2.10"
    assert printer["dst-port"] == "631"
    telnet = by_name["signalbox:no_telnet no-telnet"]
    assert (telnet["chain"], telnet["action"], telnet["dst-port"]) == ("input", "reject", "23")
    guest = by_name["signalbox:guest_to_iot guest-to-iot"]
    assert (guest["in-interface-list"], guest["out-interface-list"]) == ("LAN", "IOT")
    # the rules go before the first rule of the device's own in their chain, the policies
    # (fallbacks) at the end of theirs
    chain = [r for r in sim.data[FW_FILTER] if r["chain"] == "forward"]
    names = [r["comment"] for r in chain]
    assert names.index("signalbox:iot_printer iot-printer") < names.index(
        "defconf: accept in ipsec"
    )
    assert names[-1] == "signalbox:policy/IOT/LAN"
    # the IPv6 filter has the policies too (and no rule: they are IPv4 rules)
    assert {r["comment"] for r in ours(sim, FW_FILTER6)} == {
        "signalbox:policy/IOT/LAN",
        "signalbox:policy/IOT/device",
    }
    [fwd] = ours(sim, FW_NAT)
    assert fwd["comment"] == "signalbox:web" and fwd["in-interface-list"] == "WAN"
    assert (fwd["dst-port"], fwd["to-addresses"], fwd["to-ports"]) == ("443", "192.0.2.20", "8443")
    assert (fwd["chain"], fwd["action"], fwd["protocol"]) == ("dstnat", "dst-nat", "tcp")
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
    # the device's own rows are untouched
    for menu in MENUS:
        own = [
            {k: v for k, v in r.items() if k != ".id"}
            for r in sim.data[menu]
            if fw.tagged(r) is None
        ]
        assert own == before[menu]
    undone = await undo(d, done.id)
    assert undone.status is ChangeStatus.APPLIED, [r.error for r in undone.devices]
    assert rows(sim) == before
    assert sim.data[SCHEDULER] == []


async def test_undeclared_objects_of_signalbox_are_removed(
    sim: MikrotikSimulator, svc: Services
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
    assert not ours(sim, FW_NAT)
    # the policies are rules of ours that stay until they are declared away
    assert {r["comment"] for r in ours(sim)} == {
        "signalbox:policy/IOT/LAN",
        "signalbox:policy/IOT/device",
    }
    _, away = await deploy(
        d,
        svc,
        f"sites:\n  home:\n    firewalls:\n      - device: {DEV}\n        policies:\n"
        "          - {from: IOT, to: LAN, action: accept}\n"
        "          - {from: IOT, to: device, action: accept}\n",
    )
    assert away.status is ChangeStatus.APPLIED, [r.error for r in away.devices]
    assert rows(sim) == before


async def test_changing_a_declared_rule_updates_it_in_place(
    sim: MikrotikSimulator, svc: Services
) -> None:
    await net_of(svc)
    d = Deployer(svc.runner)
    _, first = await deploy(d, svc, WANT)
    assert first.status is ChangeStatus.APPLIED
    ids = {r["comment"]: r[".id"] for r in ours(sim) + ours(sim, FW_NAT)}
    position = [r["comment"] for r in sim.data[FW_FILTER]]
    changed = WANT.replace("port: 631", "port: 9100").replace("port: 443", "port: 444")
    sim.writes.clear()
    _, second = await deploy(d, svc, changed)
    assert second.status is ChangeStatus.APPLIED, [r.error for r in second.devices]
    assert {r["comment"]: r[".id"] for r in ours(sim) + ours(sim, FW_NAT)} == ids
    assert [r["comment"] for r in sim.data[FW_FILTER]] == position
    printer = next(r for r in ours(sim) if r["comment"] == "signalbox:iot_printer iot-printer")
    assert printer["dst-port"] == "9100"
    assert ours(sim, FW_NAT)[0]["dst-port"] == "444"
    assert {m for m, _, _ in sim.writes if m == "PUT"} == {"PUT"}
    assert [m for m, p, _ in sim.writes if m == "PATCH" and p.startswith(FW_FILTER)]


ADOPT = f"""
sites:
  home:
    firewalls:
      - device: {DEV}
        rules:
          - name: iot-dns
            adopt: "IoT: DNS"
            from: {{zone: IOT}}
            to: device
            family: 4
            protocol: udp
            port: 53
            action: accept
        forwards:
          - name: nas-web
            adopt: NAS web interface
            from: WAN
            protocol: tcp
            port: 8443
            to: {{address: 192.0.2.10, port: 443}}
"""


async def test_adopting_replaces_the_devices_own_objects_with_tagged_ones(
    sim: MikrotikSimulator, svc: Services
) -> None:
    before = rows(sim)
    await net_of(svc)
    # without the declaration nothing of the device's own is touched
    nothing = plan(
        parse(f"sites: {{home: {{firewalls: [{{device: {DEV}}}]}}}}"), svc.runner.network(), RULES
    )
    assert nothing.changes == []
    d = Deployer(svc.runner)
    p = plan(parse(ADOPT), svc.runner.network(), RULES)
    by_key = {c.key: c for c in p.changes}
    assert by_key["rule/iot_dns"].adopt == "IoT: DNS"
    assert by_key["forward/nas_web"].adopt == "NAS web interface"
    before_chain = [r["comment"] for r in sim.data[FW_FILTER] if r["chain"] == "input"]
    _, done = await deploy(d, svc, ADOPT)
    assert done.status is ChangeStatus.APPLIED, [r.error for r in done.devices]
    comments = [r["comment"] for r in sim.data[FW_FILTER]]
    assert "IoT: DNS" not in comments and "signalbox:iot_dns iot-dns" in comments
    assert "NAS web interface" not in [r["comment"] for r in sim.data[FW_NAT]]
    # the adopted rule keeps its place
    after_chain = [r["comment"] for r in sim.data[FW_FILTER] if r["chain"] == "input"]
    assert after_chain == [
        "signalbox:iot_dns iot-dns" if c == "IoT: DNS" else c for c in before_chain
    ]
    assert plan(parse(ADOPT), svc.runner.network(), RULES).changes == []
    # the way back is the backup, which brings the device's rows back in their places
    rec = svc.store.change(done.id)
    assert rec is not None and rec.devices[0].backup_id
    restore = await d.restore_backup(rec.devices[0].backup_id, "adoption not wanted", "tester")
    d.approve(restore.id, "tester")
    back = await d.deploy(restore.id)
    assert back.status is ChangeStatus.APPLIED, events(svc, restore.id)
    assert rows(sim) == before


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (
            "rules: [{name: x, adopt: No such rule, to: device, family: 4, action: drop}]",
            "no rule commented",
        ),
        ("rules: [{name: x, to: device, action: drop}]", "family: 4"),
        (
            "rules: [{name: x, from: {zone: LAN}, to: {zone: IOT}, family: 4, "
            "protocol: [tcp, udp], port: 1, action: drop}]",
            "one protocol per rule",
        ),
        (
            "rules: [{name: x, from: {zone: LAN}, to: {zone: nowhere}, family: 4, action: drop}]",
            "no zone 'nowhere'",
        ),
        (
            "rules: [{name: x, to: {network: 192.0.2.9}, family: 4, protocol: icmp, "
            "port: 1, action: drop}]",
            "ports need",
        ),
        (
            "rules: [{name: x, to: {network: [192.0.2.9, 192.0.2.10]}, family: 4, action: drop}]",
            "one destination network",
        ),
        (
            "rules: [{name: x, to: {network: '2001:db8::9'}, family: 4, action: drop}]",
            "not an IPv4",
        ),
        (
            "forwards: [{name: f, from: nowhere, protocol: tcp, port: 1, "
            "to: {address: 192.0.2.9}}]",
            "no zone 'nowhere'",
        ),
        (
            "forwards: [{name: f, protocol: tcp, port: 1, to: {address: '2001:db8::9'}}]",
            "only IPv4 targets",
        ),
        (
            "forwards: [{name: f, protocol: gre, port: 1, to: {address: 192.0.2.9}}]",
            "protocol must be tcp",
        ),
    ],
)
async def test_refusals_name_the_reason_before_anything_is_sent(
    sim: MikrotikSimulator, svc: Services, change: str, message: str
) -> None:
    await net_of(svc)
    text = f"sites:\n  home:\n    firewalls:\n      - device: {DEV}\n        {change}\n"
    sim.writes.clear()
    with pytest.raises((DeployError, PlanError, DesiredError, AdapterError), match=message):
        p = plan(parse(text), svc.runner.network(), RULES)
        rec = await Deployer(svc.runner).prepare(p, "x", "tester")
        await Deployer(svc.runner).adapter(DEV).plan_changes(rec.plan.changes, {})  # type: ignore[attr-defined]
    assert not sim.writes


async def test_unknown_zones_are_refused(sim: MikrotikSimulator, url: str) -> None:
    a = adapter(url)
    try:
        bad = Change(
            kind=ChangeKind.ZONE_POLICY,
            device_id=DEV,
            site_id="home",
            key="policy/DMZ/device",
            old=None,
            new=ZonePolicyValue(action=FirewallAction.REJECT),
        )
        with pytest.raises(AdapterError, match="no interface list 'DMZ'"):
            await a.plan_changes([bad], {})
        rule = FirewallRuleValue(
            name="x",
            chain=FirewallChain.INPUT,
            family=4,
            source_zone="DMZ",
            action=FirewallAction.DROP,
        )
        c = bad.model_copy(update={"kind": ChangeKind.FIREWALL_RULE, "key": "rule/x", "new": rule})
        with pytest.raises(AdapterError, match="no interface list 'DMZ'"):
            await a.plan_changes([c], {})
        both = rule.model_copy(update={"source_zone": "LAN", "destination_zone": "WAN"})
        with pytest.raises(AdapterError, match="no destination zone"):
            await a.plan_changes([c.model_copy(update={"new": both})], {})
        forward = Change(
            kind=ChangeKind.PORT_FORWARD,
            device_id=DEV,
            site_id="home",
            key="forward/f",
            old=None,
            new=PortForwardValue(
                name="f",
                protocols=[FirewallProtocol.TCP],
                zone="WAN",
                external_ports=[],
                target_address="192.0.2.9",  # type: ignore[arg-type]
            ),
        )
        with pytest.raises(AdapterError, match="one external port"):
            await a.plan_changes([forward], {})
        ok = c.model_copy(update={"new": rule.model_copy(update={"source_zone": "LAN"})})
        calls = await a.plan_changes([ok], {})
        assert [(x.method, x.target) for x in calls] == [
            ("PUT", "/rest/system/scheduler"),
            ("PUT", FW_FILTER),
        ]
        assert calls[1].payload["comment"] == "signalbox:x"
        assert "remove [find where comment=" in calls[0].payload["on-event"]
    finally:
        await a.close()


async def test_a_failing_apply_restores_the_backup(sim: MikrotikSimulator, svc: Services) -> None:
    before = rows(sim)
    await net_of(svc)
    sim.fail_write[FW_NAT] = 500
    d = Deployer(svc.runner)
    p = plan(parse(WANT), svc.runner.network(), RULES)
    rec = await d.prepare(p, "firewall", "tester")
    d.approve(rec.id, "tester", override="lab" if rec.plan.blocking else None)
    done = await d.deploy(rec.id)
    assert done.status is not ChangeStatus.APPLIED
    assert done.devices[0].status is DeviceStatus.ROLLED_BACK, events(svc, rec.id)
    assert rows(sim) == before
    assert sim.data[SCHEDULER] == []


async def test_a_verification_failure_restores_the_backup(
    sim: MikrotikSimulator, svc: Services
) -> None:
    """The router accepts the writes but does not keep them: back to the backup."""
    before = rows(sim)
    await net_of(svc)
    d = Deployer(svc.runner)
    p = plan(parse(WANT), svc.runner.network(), RULES)
    rec = await d.prepare(p, "firewall", "tester")
    d.approve(rec.id, "tester", override="lab" if rec.plan.blocking else None)
    sim.ignore_writes = True
    done = await d.deploy(rec.id)
    sim.ignore_writes = False
    assert done.devices[0].status is DeviceStatus.ROLLED_BACK, events(svc, rec.id)
    assert any(e.startswith("verify-failed") for e in events(svc, rec.id))
    assert rows(sim) == before
    assert sim.data[SCHEDULER] == []


# --- the revert timer -------------------------------------------------------------------------


async def apply_plan(url: str, svc: Services, text: str, seconds: int = 120) -> Any:
    await net_of(svc)
    p = plan(parse(text), svc.runner.network(), RULES)
    a = adapter(url)
    try:
        return await a.apply(p.changes, {}, seconds), a
    except Exception:
        await a.close()
        raise


async def test_the_revert_timer_undoes_what_is_not_confirmed(
    sim: MikrotikSimulator, svc: Services, url: str
) -> None:
    before = rows(sim)
    applied, a = await apply_plan(url, svc, WANT, 120)
    try:
        assert rows(sim) != before
        [timer] = sim.data[SCHEDULER]
        assert timer["name"] == REVERT_NAME and timer["interval"] == "0s"
        # the timer is set by the router's clock, the confirm time from now (+- a second)
        at = datetime.fromisoformat(f"{timer['start-date']}T{timer['start-time']}")
        assert applied.confirm_deadline is not None
        ahead = applied.confirm_deadline - datetime.now(UTC)
        assert timedelta(seconds=110) < ahead <= timedelta(seconds=120)
        assert at > datetime.now() - timedelta(days=1)
        # the router's time comes: everything is as it was, and the timer is gone
        assert sim.fire_scheduler() == 1
        assert not sim.script_errors, sim.script_errors
        assert rows(sim) == before
        # the entry removed itself, as the script says
        assert sim.data[SCHEDULER] == []
        with pytest.raises(AdapterError, match="ran before the change was confirmed"):
            await a.confirm()
    finally:
        await a.close()


async def test_the_revert_timer_undoes_adoption_and_updates_too(
    sim: MikrotikSimulator, svc: Services, url: str
) -> None:
    await net_of(svc)
    d = Deployer(svc.runner)
    _, first = await deploy(d, svc, WANT)
    assert first.status is ChangeStatus.APPLIED
    before = rows(sim)
    mixed = WANT.replace("port: 631", "port: 9100").replace("action: reject}", "action: drop}", 1)
    _, a = await apply_plan(url, svc, mixed)
    try:
        assert rows(sim) != before
        sim.fire_scheduler()
        assert not sim.script_errors, sim.script_errors
        assert rows(sim) == before
    finally:
        await a.close()
    adopt_before = rows(sim)
    _, again = await apply_plan(url, svc, ADOPT)
    try:
        assert rows(sim) != adopt_before
        sim.fire_scheduler()
        assert not sim.script_errors, sim.script_errors
        assert rows(sim) == adopt_before
    finally:
        await again.close()


async def test_confirm_removes_the_timer(sim: MikrotikSimulator, svc: Services, url: str) -> None:
    _, a = await apply_plan(url, svc, WANT)
    try:
        assert len(sim.data[SCHEDULER]) == 1
        await a.confirm()
        assert sim.data[SCHEDULER] == []
        assert len(ours(sim)) == 5  # the change stays
    finally:
        await a.close()


async def test_a_router_without_a_readable_clock_gets_no_firewall_change(
    sim: MikrotikSimulator, svc: Services, url: str
) -> None:
    await net_of(svc)
    sim.data["/rest/system/clock"] = {"date": "?", "time": "?", "gmt-offset": "+00:00"}
    sim.clock_ticks = False
    before = rows(sim)
    with pytest.raises(AdapterError, match="revert timer: the router's clock is unreadable"):
        await apply_plan(url, svc, WANT)
    assert rows(sim) == before and sim.data[SCHEDULER] == []


async def test_the_old_date_format_is_used_when_the_clock_has_it(
    sim: MikrotikSimulator, svc: Services, url: str
) -> None:
    sim.clock_ticks = False
    sim.data["/rest/system/clock"] = {
        "date": "nov/24/2026",
        "time": "23:59:30",
        "gmt-offset": "+00:00",
    }
    _, a = await apply_plan(url, svc, WANT, 60)
    try:
        [timer] = sim.data[SCHEDULER]
        assert (timer["start-date"], timer["start-time"]) == ("nov/25/2026", "00:00:30")
    finally:
        await a.close()


# --- lockout ----------------------------------------------------------------------------------

LOCKOUT = f"""
sites:
  home:
    firewalls:
      - device: {DEV}
        rules:
          - name: no-ui
            from: {{zone: LAN}}
            to: device
            family: 4
            protocol: tcp
            port: 8443
            action: reject
"""


async def test_a_plan_that_cuts_management_access_needs_the_override(
    sim: MikrotikSimulator, svc: Services
) -> None:
    net = await net_of(svc)
    devices = [d.model_copy(update={"management_address": "192.0.2.1:8443"}) for d in net.devices]
    net = net.model_copy(update={"devices": devices})
    p = plan(parse(LOCKOUT), net, RULES)
    [cut] = p.lockouts
    assert "Router" in cut and "192.0.2.1 port 8443" in cut and "denied after" in cut
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
    assert row["comment"] == "signalbox:no_ui no-ui" and row["action"] == "reject"
    assert row["chain"] == "input" and row["dst-port"] == "8443"


def test_simulator_validates_like_routeros(sim: MikrotikSimulator, url: str) -> None:
    import httpx

    def put(path: str, body: dict[str, Any]) -> httpx.Response:
        with httpx.Client(trust_env=False, auth=(SIM.username, PASSWORD)) as client:
            return client.put(url + path, json=body)

    base = {"chain": "forward", "action": "drop", "comment": "t"}
    for key, value in [
        ("action", "explode"),
        ("in-interface-list", "NOPE"),
        ("dst-port", "80"),  # no protocol
        ("dst-address", "2001:db8::1"),
        ("dst-address", "x"),
        ("disabled", "maybe"),
    ]:
        assert put(FW_FILTER, {**base, key: value}).status_code == 400, (key, value)
    assert (
        put(FW_FILTER, {**base, "chain": "input", "out-interface-list": "WAN"}).status_code == 400
    )
    assert put(FW_FILTER, {**base, "place-before": "*nope"}).status_code == 400
    assert put(FW_NAT, {"chain": "dstnat", "action": "dst-nat"}).status_code == 400
    assert put(FW_NAT, {"chain": "forward", "action": "dst-nat"}).status_code == 400
    assert put(FW_FILTER, base).status_code == 201
    assert put(SCHEDULER, {"name": "x", "start-time": "x"}).status_code == 400
    ok = {"name": "x", "start-time": "00:00:01", "start-date": "2026-01-01", "on-event": "/x"}
    assert put(SCHEDULER, {**ok, "start-date": "x"}).status_code == 400
    assert put(SCHEDULER, {**ok, "on-event": ""}).status_code == 400
    assert put(SCHEDULER, {**ok, "policy": "read,fly"}).status_code == 400
    assert put(SCHEDULER, ok).status_code == 201
    sim.data[SCHEDULER][0]["on-event"] = "/ip firewall filter bogus"
    assert sim.fire_scheduler() == 1 and "unsupported" in sim.script_errors[0]
    for line in ('/odd menu remove [find where a="b"]', "/ip firewall filter remove [x]"):
        with pytest.raises(ValueError):
            sim._script_line(line)
