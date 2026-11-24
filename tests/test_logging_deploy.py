"""Syslog targets and the SNMP policy: desired state, planner, drift and the OpenWrt and
MikroTik writers (#327, ADR 0021), through the real Deployer against the simulators.

The simulators start with a target of the device's own (``192.0.2.5``): OpenWrt's logd, the
RouterOS action ``syslog``; the SNMP agent runs with the factory community.
"""

from __future__ import annotations

import copy
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from pydantic import SecretStr

from signalbox.adapters import AdapterContext
from signalbox.adapters.mikrotik import MikrotikAdapter, MikrotikConfig
from signalbox.adapters.mikrotik.logwrite import PREFIX
from signalbox.adapters.openwrt import OpenWrtAdapter, OpenWrtConfig
from signalbox.adapters.openwrt.write import LOG_TAG
from signalbox.changes import (
    ChangeKind,
    LogTargetValue,
    PlanError,
    SnmpPolicyValue,
    apply_change,
    changes_for,
    plan,
)
from signalbox.deploy import Deployer, DeployError
from signalbox.desired import DesiredError, drift_rules, dump, from_network, parse
from signalbox.history import ChangeStatus, DeviceStatus
from signalbox.model import DeviceRole, LogKind, LogTransport, Network, Site
from signalbox.rules import evaluate
from signalbox.rules.builtin import RULES
from signalbox.service import Services, build
from signalbox.sim.mikrotik import (
    LOG_ACTION,
    LOG_RULES,
    PASSWORD,
    SCHEDULER,
    SNMP,
    MikrotikSimulator,
)
from signalbox.sim.openwrt import OpenWrtSim, create_app
from signalbox.sim.server import serve
from signalbox.store import DeviceRecord

SITE = Site(id="home", name="Home")
ENV = {"SIGNALBOX_AUTH_PASSWORD": "x" * 12, "SIGNALBOX_DEPLOY_ENABLED": "true"}
OWRT = OpenWrtSim(router=True)
ROS = MikrotikSimulator()

# --- desired state, planner and drift (no devices) ----------------------------------------------


def test_syntax_reads_off_as_a_word_and_round_trips() -> None:
    state = parse(
        """
sites:
  home:
    logging:
      syslog:
        - {address: 192.0.2.9, port: 1514, transport: tcp}
      snmp: off
      adopt: [192.0.2.5]
      overrides:
        - {device: ap, syslog: [], snmp: v3-only}
"""
    )
    spec = state.sites["home"].logging
    assert spec is not None and spec.snmp == "off" and spec.syslog is not None
    assert spec.overrides[0].syslog == [] and spec.overrides[0].snmp == "v3-only"
    assert parse(dump(state)) == state


@pytest.mark.parametrize(
    ("body", "message"),
    [
        ("snmp: v2c", "snmp"),
        ("syslog: [{address: 192.0.2.9, transport: tls}]", "transport"),
        ("syslog: [{address: 192.0.2.9}, {address: 192.0.2.9}]", "declared twice"),
        ("overrides: [{device: a}, {device: a}]", "declared twice"),
        ("syslog: [{address: '', port: 514}]", "address"),
    ],
)
def test_wrong_logging_is_refused(body: str, message: str) -> None:
    with pytest.raises(DesiredError, match=message):
        parse(f"sites:\n  home:\n    logging:\n      {body}\n")


def test_two_files_merge_their_logging() -> None:
    from signalbox.desired import DesiredState

    a = parse("sites: {home: {logging: {syslog: [{address: 192.0.2.9}], adopt: [192.0.2.5]}}}")
    b = parse("sites: {home: {logging: {snmp: off, overrides: [{device: x, snmp: off}]}}}")
    spec = a.merged(b).sites["home"].logging
    assert isinstance(a.merged(b), DesiredState) and spec is not None
    assert spec.syslog is not None and spec.snmp == "off" and spec.adopt == ["192.0.2.5"]
    assert [o.device for o in spec.overrides] == ["x"]


# --- OpenWrt ----------------------------------------------------------------------------------

AP = "gw"


@pytest.fixture(scope="module")
def owrt_url() -> Iterator[str]:
    with serve(create_app(OWRT)) as base:
        yield base


@pytest.fixture
def owrt(owrt_url: str) -> OpenWrtSim:
    OWRT.reset()
    OWRT.router = True
    OWRT.packages = {"snmpd"}
    return OWRT


@pytest.fixture
def owrt_svc(owrt: OpenWrtSim, owrt_url: str, tmp_path: Path) -> Iterator[Services]:
    s = build(tmp_path, env=ENV, adapters={"openwrt": OpenWrtAdapter}, rules=RULES, link_sources=[])
    s.store.put_site(SITE)
    rec = DeviceRecord(
        id=AP,
        site_id="home",
        name="Router",
        role=DeviceRole.GATEWAY,
        adapter="openwrt",
        allow_writes=True,
    )
    values = {
        "url": f"{owrt_url}/ubus",
        "password": OpenWrtSim().password,
        "allow_insecure_http": True,
    }
    s.store.put_device(rec, values, OpenWrtConfig)
    yield s
    s.close()


def system(sim: OpenWrtSim) -> dict[str, Any]:
    return copy.deepcopy(sim.state["system"])


def own_section(sim: OpenWrtSim) -> dict[str, Any]:
    return next(s for s in sim.state["system"].values() if s[".type"] == "system")


async def net_of(svc: Services) -> Network:
    await svc.runner.observe_all()
    return svc.runner.network()


async def deploy(d: Deployer, svc: Services, text: str) -> Any:
    p = plan(parse(text), svc.runner.network(), RULES)
    rec = await d.prepare(p, "logging", "tester")
    d.approve(rec.id, "tester", override="lab" if rec.plan.blocking else None)
    return rec, await d.deploy(rec.id)


async def undo(d: Deployer, cid: str) -> Any:
    back = await d.revert(cid, "not needed", "tester")
    d.approve(back.id, "tester", override="lab" if back.plan.blocking else None)
    return await d.deploy(back.id)


def logging_text(body: str, device: str = AP) -> str:
    return f"sites:\n  home:\n    logging:\n      devices: [{device}]\n{body}"


NEW = logging_text("      syslog: [{address: 192.0.2.9, port: 1514, transport: tcp}]\n")
REPLACE = NEW + "      adopt: [192.0.2.5]\n"


async def test_the_devices_own_target_is_read_as_not_ours(
    owrt: OpenWrtSim, owrt_svc: Services
) -> None:
    net = await net_of(owrt_svc)
    dev = net.device(AP)
    assert dev is not None and dev.log_targets is not None
    [t] = [t for t in dev.log_targets if t.kind is LogKind.SYSLOG]
    assert (t.address, t.managed) == ("192.0.2.5", False)


async def test_a_new_target_never_replaces_the_devices_own(
    owrt: OpenWrtSim, owrt_svc: Services
) -> None:
    await net_of(owrt_svc)
    d = Deployer(owrt_svc.runner)
    before = system(owrt)
    p = plan(parse(NEW), owrt_svc.runner.network(), RULES)
    assert [c.key for c in p.changes] == ["syslog/192.0.2.9"]
    with pytest.raises(DeployError, match="did not set up"):
        await d.prepare(p, "x", "tester")
    assert system(owrt) == before


async def test_adopting_replaces_it_and_the_backup_restores_it(
    owrt: OpenWrtSim, owrt_svc: Services
) -> None:
    await net_of(owrt_svc)
    d = Deployer(owrt_svc.runner)
    before = system(owrt)
    p = plan(parse(REPLACE), owrt_svc.runner.network(), RULES)
    kinds = {(c.key, c.action, c.adopt) for c in p.changes}
    assert kinds == {
        ("syslog/192.0.2.9", "create", None),
        ("syslog/192.0.2.5", "remove", "192.0.2.5"),
    }
    rec, done = await deploy(d, owrt_svc, REPLACE)
    assert done.status is ChangeStatus.APPLIED, [r.error for r in done.devices]
    s = own_section(owrt)
    assert (s["log_ip"], s["log_port"], s["log_proto"], s[LOG_TAG]) == (
        "192.0.2.9",
        "1514",
        "tcp",
        "1",
    )
    assert s["hostname"] == "ap"  # nothing else of the section changed
    # what is there now is Signalbox's: no further changes, no drift
    net = owrt_svc.runner.network()
    assert plan(parse(REPLACE), net, RULES).changes == []
    assert not [f for f in evaluate(net, drift_rules(parse(REPLACE))) if f.problem]
    assert system(owrt) != before
    # reverting the adoption brings the device's target back (now tagged as Signalbox's)
    back = await undo(d, rec.id)
    assert back.status is ChangeStatus.APPLIED, [r.error for r in back.devices]
    s = own_section(owrt)
    assert (s["log_ip"], s["log_port"], s["log_proto"]) == ("192.0.2.5", "514", "udp")


async def test_the_backup_restores_the_configuration_exactly(
    owrt: OpenWrtSim, owrt_svc: Services, owrt_url: str
) -> None:
    await net_of(owrt_svc)
    before = system(owrt)
    a = OpenWrtAdapter(
        AdapterContext(
            site_id="home",
            device_id=AP,
            device_name="Router",
            role=DeviceRole.GATEWAY,
            config=OpenWrtConfig(
                url=f"{owrt_url}/ubus",
                password=SecretStr(OpenWrtSim().password),
                allow_insecure_http=True,
            ),
        )
    )
    try:
        backup = await a.backup()
        p = plan(parse(REPLACE), owrt_svc.runner.network(), RULES)
        await a.apply(p.changes, {}, 60)
        await a.confirm()
        assert system(owrt) != before
        await a.restore(backup)
    finally:
        await a.close()
    assert system(owrt) == before


async def test_a_new_target_in_an_empty_slot_reverts_to_the_identical_state(
    owrt: OpenWrtSim, owrt_svc: Services
) -> None:
    section = own_section(owrt)
    for option in ("log_ip", "log_port", "log_proto"):
        del section[option]
    await net_of(owrt_svc)
    before = system(owrt)
    d = Deployer(owrt_svc.runner)
    rec, done = await deploy(d, owrt_svc, NEW)
    assert done.status is ChangeStatus.APPLIED, [r.error for r in done.devices]
    assert done.devices[0].status is DeviceStatus.CONFIRMED
    assert own_section(owrt)["log_ip"] == "192.0.2.9"
    [dev] = [x for x in owrt_svc.runner.network().devices if x.id == AP]
    assert [t.managed for t in dev.log_targets or [] if t.kind is LogKind.SYSLOG] == [True]
    back = await undo(d, rec.id)
    assert back.status is ChangeStatus.APPLIED, [r.error for r in back.devices]
    assert system(owrt) == before


async def test_changing_and_removing_our_own_target(owrt: OpenWrtSim, owrt_svc: Services) -> None:
    await net_of(owrt_svc)
    d = Deployer(owrt_svc.runner)
    await deploy(d, owrt_svc, REPLACE)
    other = REPLACE.replace("1514", "2514")
    p = plan(parse(other), owrt_svc.runner.network(), RULES)
    [c] = p.changes
    assert c.action == "update" and c.adopt is None
    _, done = await deploy(d, owrt_svc, other)
    assert done.status is ChangeStatus.APPLIED
    assert own_section(owrt)["log_port"] == "2514"
    gone = logging_text("      syslog: []\n")
    _, done = await deploy(d, owrt_svc, gone)
    assert done.status is ChangeStatus.APPLIED
    s = own_section(owrt)
    assert not {"log_ip", "log_port", "log_proto", LOG_TAG} & set(s)


async def test_one_slot_only_and_no_tls(owrt: OpenWrtSim, owrt_svc: Services) -> None:
    await net_of(owrt_svc)
    d = Deployer(owrt_svc.runner)
    two = logging_text(
        "      syslog: [{address: 192.0.2.9}, {address: 192.0.2.10}]\n      adopt: [192.0.2.5]\n"
    )
    with pytest.raises(DeployError, match="one remote syslog target"):
        await d.prepare(plan(parse(two), owrt_svc.runner.network(), RULES), "x", "tester")
    net = owrt_svc.runner.network()
    [c] = changes_for(parse(REPLACE), net)[:1]
    bad = c.model_copy(
        update={"new": LogTargetValue(address="192.0.2.9", transport=LogTransport.TLS)}
    )
    p = plan(parse(REPLACE), net, RULES).model_copy(update={"changes": [bad]})
    with pytest.raises(DeployError, match="cannot be written"):
        await d.prepare(p, "x", "tester")


async def test_the_agent_is_switched_off_and_on_again(owrt: OpenWrtSim, owrt_svc: Services) -> None:
    await net_of(owrt_svc)
    d = Deployer(owrt_svc.runner)
    before = system(owrt), copy.deepcopy(owrt.state["snmpd"])
    want = logging_text("      snmp: off\n")
    p = plan(parse(want), owrt_svc.runner.network(), RULES)
    [c] = p.changes
    assert c.kind is ChangeKind.SNMP_POLICY and c.old == SnmpPolicyValue(mode="on")
    assert "public" not in c.model_dump_json()  # never a community
    rec, done = await deploy(d, owrt_svc, want)
    assert done.status is ChangeStatus.APPLIED, [r.error for r in done.devices]
    assert owrt.state["snmpd"]["general"]["enabled"] == "0"
    net = owrt_svc.runner.network()
    assert plan(parse(want), net, RULES).changes == []
    assert not [f for f in evaluate(net, drift_rules(parse(want))) if f.problem]
    back = await undo(d, rec.id)
    assert back.status is ChangeStatus.APPLIED
    assert (system(owrt), owrt.state["snmpd"]) == before


async def test_v3_only_and_a_missing_agent_are_refused(
    owrt: OpenWrtSim, owrt_svc: Services
) -> None:
    await net_of(owrt_svc)
    d = Deployer(owrt_svc.runner)
    want = logging_text("      snmp: v3-only\n")
    p = plan(parse(want), owrt_svc.runner.network(), RULES)
    assert p.changes[0].new == SnmpPolicyValue(mode="v3-only")
    with pytest.raises(DeployError, match="SNMPv3 users"):
        await d.prepare(p, "x", "tester")
    # an agent that is not installed is off: nothing to do for `off`
    owrt.packages = set()
    await net_of(owrt_svc)
    assert (
        plan(parse(logging_text("      snmp: off\n")), owrt_svc.runner.network(), RULES).changes
        == []
    )
    forced = p.model_copy(
        update={"changes": [p.changes[0].model_copy(update={"new": SnmpPolicyValue(mode="off")})]}
    )
    with pytest.raises(DeployError, match="no snmpd configuration"):
        await d.prepare(forced, "x", "tester")


async def test_the_devices_switch_for_changes_still_applies(
    owrt: OpenWrtSim, owrt_svc: Services
) -> None:
    await net_of(owrt_svc)
    rec = owrt_svc.store.device(AP)
    assert rec is not None
    owrt_svc.store.put_device(
        rec.model_copy(update={"allow_writes": False}),
        {
            "url": rec.config["url"],
            "password": OpenWrtSim().password,
            "allow_insecure_http": True,
        },
        OpenWrtConfig,
    )
    d = Deployer(owrt_svc.runner)
    p = plan(parse(REPLACE), owrt_svc.runner.network(), RULES)
    with pytest.raises(DeployError, match="not allowed on this device"):
        await d.prepare(p, "x", "tester")


# --- MikroTik ---------------------------------------------------------------------------------

RT = "rt"


@pytest.fixture(scope="module")
def ros_url() -> Iterator[str]:
    with serve(ROS.app()) as base:
        yield base


@pytest.fixture
def ros(ros_url: str) -> MikrotikSimulator:
    ROS.__dict__.update(MikrotikSimulator().__dict__)
    return ROS


@pytest.fixture
def ros_svc(ros: MikrotikSimulator, ros_url: str, tmp_path: Path) -> Iterator[Services]:
    s = build(
        tmp_path, env=ENV, adapters={"mikrotik": MikrotikAdapter}, rules=RULES, link_sources=[]
    )
    s.store.put_site(SITE)
    rec = DeviceRecord(
        id=RT,
        site_id="home",
        name="Router",
        role=DeviceRole.GATEWAY,
        adapter="mikrotik",
        allow_writes=True,
    )
    values = {"url": ros_url, "password": PASSWORD, "allow_insecure_http": True}
    s.store.put_device(rec, values, MikrotikConfig)
    yield s
    s.close()


def ros_adapter(url: str) -> MikrotikAdapter:
    config = MikrotikConfig(url=url, password=SecretStr(PASSWORD), allow_insecure_http=True)
    return MikrotikAdapter(
        AdapterContext(
            site_id="home",
            device_id=RT,
            device_name="Router",
            role=DeviceRole.GATEWAY,
            config=config,
        )
    )


def logs(sim: MikrotikSimulator) -> dict[str, Any]:
    """Logging menus and the SNMP object without the row ids (re-created rows get new ones)."""
    out: dict[str, Any] = {
        m: [
            {k: v for k, v in r.items() if k not in (".id", "dynamic", "default")}
            for r in copy.deepcopy(sim.data[m])
        ]
        for m in (LOG_ACTION, LOG_RULES)
    }
    out["snmp"] = dict(sim.data[SNMP])
    return out


def ros_text(body: str) -> str:
    return f"sites:\n  home:\n    logging:\n      devices: [{RT}]\n{body}"


ROS_NEW = ros_text("      syslog: [{address: 192.0.2.9, port: 1514, transport: tcp}]\n")
ROS_ADOPT = ROS_NEW + "      adopt: [192.0.2.5]\n"


async def test_a_second_target_is_added_beside_the_devices_own(
    ros: MikrotikSimulator, ros_svc: Services
) -> None:
    before = logs(ros)
    await net_of(ros_svc)
    d = Deployer(ros_svc.runner)
    rec, done = await deploy(d, ros_svc, ROS_NEW)
    assert done.status is ChangeStatus.APPLIED, [r.error for r in done.devices]
    calls = [(c.method, c.target) for c in rec.devices[0].calls]
    assert calls[0] == ("PUT", SCHEDULER)  # the revert timer comes first
    assert sim_timer_gone(ros)
    [action] = [a for a in ros.data[LOG_ACTION] if a["name"].startswith(PREFIX)]
    assert action["name"] == "signalbox192x0x2x9"
    assert (action["remote"], action["remote-port"], action["remote-protocol"]) == (
        "192.0.2.9",
        "1514",
        "tcp",
    )
    mine = [r for r in ros.data[LOG_RULES] if r["action"] == action["name"]]
    assert [r["topics"] for r in mine] == ["info", "warning", "error", "critical"]
    # the device's own action and rules are untouched
    assert any(a["name"] == "syslog" for a in ros.data[LOG_ACTION])
    net = ros_svc.runner.network()
    assert plan(parse(ROS_NEW), net, RULES).changes == []
    assert not [f for f in evaluate(net, drift_rules(parse(ROS_NEW))) if f.problem]
    back = await undo(d, rec.id)
    assert back.status is ChangeStatus.APPLIED, [r.error for r in back.devices]
    assert logs(ros) == before


def sim_timer_gone(sim: MikrotikSimulator) -> bool:
    return sim.data[SCHEDULER] == []


async def test_the_timer_undoes_a_target_that_is_not_confirmed(
    ros: MikrotikSimulator, ros_svc: Services, ros_url: str
) -> None:
    before = logs(ros)
    await net_of(ros_svc)
    p = plan(parse(ROS_ADOPT), ros_svc.runner.network(), RULES)
    a = ros_adapter(ros_url)
    try:
        await a.apply(p.changes, {}, 120)
        assert logs(ros) != before and len(ros.data[SCHEDULER]) == 1
        assert ros.fire_scheduler() == 1
        assert not ros.script_errors, ros.script_errors
        assert logs(ros) == before
    finally:
        await a.close()


async def test_adopting_the_devices_own_target_removes_it_with_its_rules(
    ros: MikrotikSimulator, ros_svc: Services
) -> None:
    await net_of(ros_svc)
    d = Deployer(ros_svc.runner)
    rec, done = await deploy(d, ros_svc, ROS_ADOPT)
    assert done.status is ChangeStatus.APPLIED, [r.error for r in done.devices]
    assert [a["name"] for a in ros.data[LOG_ACTION]] == [
        "memory",
        "disk",
        "echo",
        "remote",
        "signalbox192x0x2x9",
    ]
    assert not [r for r in ros.data[LOG_RULES] if r["action"] == "syslog"]
    back = await undo(d, rec.id)
    assert back.status is ChangeStatus.APPLIED, [r.error for r in back.devices]
    # the target is back, now created by Signalbox (an undone adoption is a creation)
    [again] = [a for a in ros.data[LOG_ACTION] if a.get("remote") == "192.0.2.5"]
    assert again["name"] == "signalbox192x0x2x5"
    assert len([r for r in ros.data[LOG_RULES] if r["action"] == again["name"]]) == 4


async def test_a_deployment_that_fails_is_restored_from_the_backup(
    ros: MikrotikSimulator, ros_svc: Services
) -> None:
    before = logs(ros)
    await net_of(ros_svc)
    d = Deployer(ros_svc.runner)
    ros.ignore_writes = True  # the router says yes and changes nothing: the verification fails
    _, done = await deploy(d, ros_svc, ROS_ADOPT)
    ros.ignore_writes = False
    assert done.status is not ChangeStatus.APPLIED
    assert logs(ros) == before


async def test_changing_a_target_and_the_foreign_one_needs_adopt(
    ros: MikrotikSimulator, ros_svc: Services
) -> None:
    await net_of(ros_svc)
    d = Deployer(ros_svc.runner)
    foreign = ros_text("      syslog: [{address: 192.0.2.5, port: 1514}]\n")
    with pytest.raises(PlanError, match="did not set that up"):
        plan(parse(foreign), ros_svc.runner.network(), RULES)
    _, done = await deploy(d, ros_svc, ROS_NEW)
    assert done.status is ChangeStatus.APPLIED
    other = ROS_NEW.replace("tcp", "udp").replace("1514", "2514")
    [c] = plan(parse(other), ros_svc.runner.network(), RULES).changes
    assert c.action == "update"
    before = logs(ros)
    rec, done = await deploy(d, ros_svc, other)
    assert done.status is ChangeStatus.APPLIED
    [action] = [a for a in ros.data[LOG_ACTION] if a["name"].startswith(PREFIX)]
    assert (action["remote-port"], action["remote-protocol"]) == ("2514", "udp")
    assert (await undo(d, rec.id)).status is ChangeStatus.APPLIED
    assert logs(ros) == before
    gone = ros_text("      syslog: []\n")
    _, done = await deploy(d, ros_svc, gone)
    assert done.status is ChangeStatus.APPLIED
    assert not [a for a in ros.data[LOG_ACTION] if a["name"].startswith(PREFIX)]
    assert any(a["name"] == "syslog" for a in ros.data[LOG_ACTION])


async def test_the_agent_is_switched_off_by_the_timer_proof_patch(
    ros: MikrotikSimulator, ros_svc: Services, ros_url: str
) -> None:
    await net_of(ros_svc)
    want = ros_text("      snmp: off\n")
    before = logs(ros)
    d = Deployer(ros_svc.runner)
    rec, done = await deploy(d, ros_svc, want)
    assert done.status is ChangeStatus.APPLIED, [r.error for r in done.devices]
    assert ros.data[SNMP]["enabled"] == "false"
    net = ros_svc.runner.network()
    assert plan(parse(want), net, RULES).changes == []
    assert (await undo(d, rec.id)).status is ChangeStatus.APPLIED
    assert logs(ros) == before
    # not confirmed: the router's own timer switches it on again
    p = plan(parse(want), ros_svc.runner.network(), RULES)
    a = ros_adapter(ros_url)
    try:
        await a.apply(p.changes, {}, 120)
        assert ros.data[SNMP]["enabled"] == "false"
        ros.fire_scheduler()
        assert not ros.script_errors, ros.script_errors
        assert logs(ros) == before
    finally:
        await a.close()


async def test_v3_only_and_tls_are_refused(ros: MikrotikSimulator, ros_svc: Services) -> None:
    await net_of(ros_svc)
    d = Deployer(ros_svc.runner)
    p = plan(parse(ros_text("      snmp: v3-only\n")), ros_svc.runner.network(), RULES)
    with pytest.raises(DeployError, match="SNMPv3 users"):
        await d.prepare(p, "x", "tester")
    net = ros_svc.runner.network()
    [c] = plan(parse(ROS_NEW), net, RULES).changes
    bad = c.model_copy(
        update={"new": LogTargetValue(address="192.0.2.9", transport=LogTransport.TLS)}
    )
    with pytest.raises(DeployError, match="cannot be written"):
        await d.prepare(
            plan(parse(ROS_NEW), net, RULES).model_copy(update={"changes": [bad]}), "x", "t"
        )
    predicted = apply_change(net, c).device(RT)
    assert predicted is not None and predicted.log_targets is not None
    assert [t.managed for t in predicted.log_targets if t.address == "192.0.2.9"] == [True]


# --- import -----------------------------------------------------------------------------------


async def test_import_exports_the_devices_targets_as_adopted(
    owrt: OpenWrtSim, owrt_svc: Services
) -> None:
    net = await net_of(owrt_svc)
    state = from_network(net, "home")
    spec = state.sites["home"].logging
    assert spec is not None and spec.devices == []
    [o] = spec.overrides
    assert o.device == AP and o.adopt == ["192.0.2.5"]
    assert o.syslog is not None and o.syslog[0].address == "192.0.2.5"
    assert parse(dump(state)) == state
    # what was imported is already the state of the device
    assert plan(state, net, RULES).changes == []
    assert not [f for f in evaluate(net, drift_rules(state)) if f.problem]


async def test_unread_devices_are_incomplete_where_named_and_skipped_otherwise(
    owrt: OpenWrtSim, owrt_svc: Services
) -> None:
    net = await net_of(owrt_svc)
    ghost = logging_text("      syslog: []\n", device="nowhere")
    with pytest.raises(PlanError, match="not configured"):
        plan(parse(ghost), net, RULES)
    findings = evaluate(net, drift_rules(parse(ghost)))
    assert [f for f in findings if f.rule_id == "drift.logging"]
    # the site default skips a device without log targets (a plain host, a switch)
    bare = net.model_copy(
        update={"devices": [d.model_copy(update={"log_targets": None}) for d in net.devices]}
    )
    site_wide = "sites:\n  home:\n    logging:\n      syslog: [{address: 192.0.2.9}]\n"
    assert plan(parse(site_wide), bare, RULES).changes == []
