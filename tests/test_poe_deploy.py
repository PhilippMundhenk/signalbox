"""PoE writes (#484, ADR 0036) through the real Deployer against the MikroTik simulator
(``/interface/ethernet/poe`` ``poe-out``): plan, apply, verify, undo, the revert timer, the
backup, the outage refusal, and nothing changed where nothing is declared. CHR has no PoE-out,
so this is the only test of the writer; integrations that do not write PoE refuse the plan."""

from __future__ import annotations

import copy
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from pydantic import SecretStr

from signalbox.adapters import AdapterContext
from signalbox.adapters.mikrotik import MikrotikAdapter, MikrotikConfig, poewrite
from signalbox.adapters.omada import OmadaAdapter
from signalbox.adapters.openwrt import OpenWrtAdapter
from signalbox.adapters.plusswitch import EasySmartAdapter, ProsafeAdapter
from signalbox.adapters.unifi import UnifiAdapter
from signalbox.changes import ChangeKind, PlanError, PoeValue, plan
from signalbox.deploy import Deployer
from signalbox.desired import drift_rules, parse
from signalbox.history import ChangeStatus
from signalbox.model import DeviceRole, Network, PoeStatus, Site, port_id
from signalbox.rules import evaluate
from signalbox.rules.builtin import RULES
from signalbox.service import Services, build
from signalbox.sim.mikrotik import PASSWORD, POE_MENU, SCHEDULER, MikrotikSimulator
from signalbox.sim.server import serve
from signalbox.store import DeviceRecord

SITE = Site(id="home", name="Home")
ENV = {"SIGNALBOX_AUTH_PASSWORD": "x" * 12, "SIGNALBOX_DEPLOY_ENABLED": "true"}
ROS = MikrotikSimulator()


def poe_text(*entries: str) -> str:
    return "sites:\n  home:\n    poe:\n" + "".join(f"      - {e}\n" for e in entries)


ON5 = poe_text("{device: sw, port: ether5, enabled: true}")
OFF4 = poe_text("{device: sw, port: ether4, enabled: false}")


@pytest.fixture(scope="module")
def ros_url() -> Iterator[str]:
    with serve(ROS.app()) as base:
        yield base


@pytest.fixture
def ros(ros_url: str) -> MikrotikSimulator:
    ROS.__dict__.update(MikrotikSimulator().__dict__)
    return ROS


@pytest.fixture
def svc(ros: MikrotikSimulator, ros_url: str, tmp_path: Path) -> Iterator[Services]:
    s = build(
        tmp_path, env=ENV, adapters={"mikrotik": MikrotikAdapter}, rules=RULES, link_sources=[]
    )
    s.store.put_site(SITE)
    rec = DeviceRecord(
        id="sw",
        site_id="home",
        name="Switch",
        role=DeviceRole.SWITCH,
        adapter="mikrotik",
        allow_writes=True,
    )
    values = {"url": ros_url, "password": PASSWORD, "allow_insecure_http": True}
    s.store.put_device(rec, values, MikrotikConfig)
    yield s
    s.close()


def adapter(url: str) -> MikrotikAdapter:
    config = MikrotikConfig(url=url, password=SecretStr(PASSWORD), allow_insecure_http=True)
    return MikrotikAdapter(
        AdapterContext(
            site_id="home",
            device_id="sw",
            device_name="Switch",
            role=DeviceRole.SWITCH,
            config=config,
        )
    )


def poe_out(sim: MikrotikSimulator) -> dict[str, str]:
    return copy.deepcopy({r["name"]: r["poe-out"] for r in sim.data[POE_MENU]})


async def net_of(svc: Services) -> Network:
    await svc.runner.observe_all()
    return svc.runner.network()


async def deploy(d: Deployer, svc: Services, text: str) -> Any:
    p = plan(parse(text), svc.runner.network(), RULES)
    rec = await d.prepare(p, "poe", "tester")
    d.approve(rec.id, "tester", override="lab" if rec.plan.blocking else None)
    return rec, await d.deploy(rec.id)


def no_poe_drift(net: Network, text: str) -> bool:
    return not [f for f in evaluate(net, drift_rules(parse(text))) if f.rule_id == "drift.poe"]


async def test_on_deploys_verifies_and_undoes(ros: MikrotikSimulator, svc: Services) -> None:
    assert poe_out(ros) == {"ether4": "auto-on", "ether5": "off"}
    net = await net_of(svc)
    p5 = net.port(port_id("sw", "ether5"))
    assert p5 is not None and p5.poe is not None and p5.poe.enabled is False
    d = Deployer(svc.runner)
    rec, done = await deploy(d, svc, ON5)
    [c] = rec.plan.changes
    assert (c.kind, c.new) == (ChangeKind.POE, PoeValue(enabled=True))
    # RouterOS reports no PoE budget: not checked, and the plan says so
    assert c.risk == "the switch reports no PoE budget; not checked"
    assert done.status is ChangeStatus.APPLIED, [r.error for r in done.devices]
    calls = [(x.method, x.target, x.payload) for x in rec.devices[0].calls]
    assert calls[0][:2] == ("PUT", SCHEDULER)  # the revert timer comes first
    ref = ros.data[POE_MENU][1][".id"]
    assert ("PATCH", f"{POE_MENU}/{ref}", {"poe-out": "auto-on"}) in calls
    assert ros.data[SCHEDULER] == []  # confirmed
    assert poe_out(ros) == {"ether4": "auto-on", "ether5": "auto-on"}
    net = svc.runner.network()
    assert plan(parse(ON5), net, RULES).changes == [] and no_poe_drift(net, ON5)
    back = await d.revert(rec.id, "not needed", "tester")
    d.approve(back.id, "tester", override="lab" if back.plan.blocking else None)
    undone = await d.deploy(back.id)
    assert undone.status is ChangeStatus.APPLIED, [r.error for r in undone.devices]
    assert poe_out(ros) == {"ether4": "auto-on", "ether5": "off"}


async def test_off_names_the_load_and_the_monitor_follows(
    ros: MikrotikSimulator, svc: Services
) -> None:
    await net_of(svc)
    d = Deployer(svc.runner)
    rec, done = await deploy(d, svc, OFF4)
    [c] = rec.plan.changes
    assert c.risk == "cuts power to an unknown device that draws 5.8 W"
    assert done.status is ChangeStatus.APPLIED, [r.error for r in done.devices]
    assert poe_out(ros)["ether4"] == "off"
    p4 = svc.runner.network().port(port_id("sw", "ether4"))
    assert p4 is not None and p4.poe is not None
    assert (p4.poe.enabled, p4.poe.status) == (False, PoeStatus.DISABLED)


async def test_the_timer_undoes_a_change_that_is_not_confirmed(
    ros: MikrotikSimulator, svc: Services, ros_url: str
) -> None:
    before = poe_out(ros)
    await net_of(svc)
    p = plan(parse(OFF4), svc.runner.network(), RULES)
    a = adapter(ros_url)
    try:
        await a.apply(p.changes, {}, 120)
        assert poe_out(ros) != before
        assert ros.fire_scheduler() == 1
        assert not ros.script_errors, ros.script_errors
        assert poe_out(ros) == before
    finally:
        await a.close()


async def test_the_backup_restores_poe_out(
    ros: MikrotikSimulator, svc: Services, ros_url: str
) -> None:
    before = poe_out(ros)
    a = adapter(ros_url)
    try:
        backup = await a.backup()
        ros.data[POE_MENU][0]["poe-out"] = "off"
        ros.data[POE_MENU][1]["poe-out"] = "forced-on"
        await a.restore(backup)
        assert poe_out(ros) == before
    finally:
        await a.close()


async def test_a_failed_deployment_is_restored_from_the_backup(
    ros: MikrotikSimulator, svc: Services
) -> None:
    before = poe_out(ros)
    await net_of(svc)
    d = Deployer(svc.runner)
    ros.fail_write[POE_MENU] = 500  # the revert timer is armed, then the port change fails
    _, done = await deploy(d, svc, ON5)
    ros.fail_write.clear()
    assert done.status is not ChangeStatus.APPLIED
    assert poe_out(ros) == before


async def test_off_of_an_access_point_is_refused_unless_allowed(
    ros: MikrotikSimulator, svc: Services
) -> None:
    ros.data["/rest/ip/neighbor"].append(
        {
            ".id": "*AP1",
            "interface": "ether4",
            "identity": "ap-garden",
            "mac-address": "02:00:00:00:00:44",
            "discovered-by": "lldp",
            "system-caps": "wlan-ap",
            "system-caps-enabled": "wlan-ap",
        }
    )
    net = await net_of(svc)
    with pytest.raises(PlanError) as err:
        plan(parse(OFF4), net, RULES)
    assert err.value.message_id == "plan.poeOutage" and "ap-garden" in str(err.value)
    assert poe_out(ros)["ether4"] == "auto-on"
    allowed = poe_text("{device: sw, port: ether4, enabled: false, allow_outage: true}")
    [c] = plan(parse(allowed), net, RULES).changes
    assert c.risk == "cuts power to ap-garden (announces itself as wlan-access-point)"


async def test_nothing_changes_without_a_declaration(ros: MikrotikSimulator, svc: Services) -> None:
    net = await net_of(svc)
    assert plan(parse("sites:\n  home: {}\n"), net, RULES).changes == []
    on4 = poe_text("{device: sw, port: ether4, enabled: true}")
    assert plan(parse(on4), net, RULES).changes == []


def test_a_forced_on_port_counts_as_on_and_is_left_alone() -> None:
    from signalbox.adapters.mikrotik.poe import port as read_port

    assert read_port({"name": "ether4", "poe-out": "forced-on"}, {}).enabled is True
    assert poewrite.backup_rows([{"name": "ether4", "poe-out": "forced-on"}, {"name": "x"}]) == {
        "ether4": "forced-on"
    }


def test_integrations_that_do_not_write_poe_say_so() -> None:
    for cls in (OpenWrtAdapter, OmadaAdapter, UnifiAdapter, ProsafeAdapter, EasySmartAdapter):
        assert ChangeKind.POE not in cls.manifest.writes, cls
    assert ChangeKind.POE in MikrotikAdapter.manifest.writes
