"""Gateway group writes (#463, ADR 0032) through the real Deployer against the simulators:
OpenWrt mwan3 (metric, weight, track_ip, copies of shared members) and MikroTik default routes
(distance, check-gateway, the netwatch host), with plan, apply, verify, undo, the backup and the
ownership rules (only adopted groups, never a group or member created or removed)."""

from __future__ import annotations

import copy
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from pydantic import SecretStr

from signalbox.adapters import AdapterContext, AdapterError
from signalbox.adapters.mikrotik import MikrotikAdapter, MikrotikConfig
from signalbox.adapters.openwrt import OpenWrtAdapter, OpenWrtConfig
from signalbox.adapters.openwrt import write as owrt_write
from signalbox.changes import ChangeKind, GatewayGroupValue, PlanError, plan
from signalbox.deploy import Deployer, DeployError
from signalbox.desired import drift_rules, parse
from signalbox.history import ChangeStatus
from signalbox.model import DeviceRole, Network, Site
from signalbox.rules import evaluate
from signalbox.rules.builtin import RULES
from signalbox.service import Services, build
from signalbox.sim.mikrotik import (
    IP_ROUTE,
    NETWATCH,
    PASSWORD,
    SCHEDULER,
    MikrotikSimulator,
    add_second_wan,
)
from signalbox.sim.openwrt import OpenWrtSim, create_app
from signalbox.sim.server import serve
from signalbox.store import DeviceRecord

SITE = Site(id="home", name="Home")
ENV = {"SIGNALBOX_AUTH_PASSWORD": "x" * 12, "SIGNALBOX_DEPLOY_ENABLED": "true"}
OWRT = OpenWrtSim(router=True)
ROS = MikrotikSimulator()


def groups_text(device: str, name: str, members: str, adopt: bool = True) -> str:
    return (
        f"sites:\n  home:\n    gateway_groups:\n      - device: {device}\n"
        f"        name: {name}\n        adopt: {str(adopt).lower()}\n        members:\n{members}"
    )


async def net_of(svc: Services) -> Network:
    await svc.runner.observe_all()
    return svc.runner.network()


async def deploy(d: Deployer, svc: Services, text: str) -> Any:
    p = plan(parse(text), svc.runner.network(), RULES)
    rec = await d.prepare(p, "gateway groups", "tester")
    d.approve(rec.id, "tester", override="lab" if rec.plan.blocking else None)
    return rec, await d.deploy(rec.id)


async def undo(d: Deployer, cid: str) -> Any:
    back = await d.revert(cid, "not needed", "tester")
    d.approve(back.id, "tester", override="lab" if back.plan.blocking else None)
    return await d.deploy(back.id)


def services(tmp_path: Path, adapter: str, cls: Any, values: dict[str, Any], config: Any) -> Any:
    s = build(tmp_path, env=ENV, adapters={adapter: cls}, rules=RULES, link_sources=[])
    s.store.put_site(SITE)
    rec = DeviceRecord(
        id="gw",
        site_id="home",
        name="Router",
        role=DeviceRole.GATEWAY,
        adapter=adapter,
        allow_writes=True,
    )
    s.store.put_device(rec, values, config)
    return s


# --- OpenWrt mwan3 ------------------------------------------------------------------------------


@pytest.fixture(scope="module")
def owrt_url() -> Iterator[str]:
    with serve(create_app(OWRT)) as base:
        yield base


@pytest.fixture
def owrt(owrt_url: str) -> OpenWrtSim:
    OWRT.reset()
    OWRT.router = True
    OWRT.packages = {"mwan3"}
    return OWRT


@pytest.fixture
def owrt_svc(owrt: OpenWrtSim, owrt_url: str, tmp_path: Path) -> Iterator[Services]:
    values = {
        "url": f"{owrt_url}/ubus",
        "password": OpenWrtSim().password,
        "allow_insecure_http": True,
    }
    s = services(tmp_path, "openwrt", OpenWrtAdapter, values, OpenWrtConfig)
    yield s
    s.close()


def mwan3(sim: OpenWrtSim) -> dict[str, Any]:
    return copy.deepcopy(sim.state["mwan3"])


SWAP = groups_text(
    "gw",
    "failover",
    "          - {name: wan, tier: 2}\n"
    "          - {name: wanb, tier: 1, weight: 4, monitor: [198.51.100.53, 203.0.113.53]}\n",
)


async def test_openwrt_tiers_weights_and_monitor_deploy_and_undo(
    owrt: OpenWrtSim, owrt_svc: Services
) -> None:
    before = mwan3(owrt)
    await net_of(owrt_svc)
    d = Deployer(owrt_svc.runner)
    rec, done = await deploy(d, owrt_svc, SWAP)
    assert [c.kind for c in rec.plan.changes] == [ChangeKind.GATEWAY_GROUP]
    assert done.status is ChangeStatus.APPLIED, [r.error for r in done.devices]
    now = mwan3(owrt)
    assert (now["wan_m1"]["metric"], now["wanb_m2"]["metric"]) == ("2", "1")
    assert now["wanb_m2"]["weight"] == "4" and now["wan_m1"]["weight"] == "3"
    assert sorted(now["wanb"]["track_ip"]) == ["198.51.100.53", "203.0.113.53"]
    assert now["wan"] == before["wan"]  # a monitor that was not declared stays
    net = owrt_svc.runner.network()
    [g] = net.gateway_groups
    assert {m.name: m.tier for m in g.members} == {"wan": 2, "wanb": 1}
    assert plan(parse(SWAP), net, RULES).changes == []
    assert not [
        f for f in evaluate(net, drift_rules(parse(SWAP))) if f.problem and "drift" in f.rule_id
    ]
    back = await undo(d, rec.id)
    assert back.status is ChangeStatus.APPLIED, [r.error for r in back.devices]
    again = mwan3(owrt)
    assert (again["wan_m1"]["metric"], again["wanb_m2"]["metric"]) == ("1", "2")
    assert again["wanb_m2"]["weight"] == "1" and again["wanb"] == before["wanb"]


async def test_openwrt_a_shared_member_gets_a_copy_and_the_backup_restores_it(
    owrt: OpenWrtSim, owrt_svc: Services
) -> None:
    owrt.state["mwan3"]["wan_only"] = {
        ".anonymous": False,
        ".type": "policy",
        ".name": "wan_only",
        ".index": 9,
        "use_member": ["wan_m1"],
    }
    before = mwan3(owrt)
    await net_of(owrt_svc)
    d = Deployer(owrt_svc.runner)
    text = groups_text("gw", "failover", "          - {name: wan, weight: 7}\n")
    _, done = await deploy(d, owrt_svc, text)
    assert done.status is ChangeStatus.APPLIED, [r.error for r in done.devices]
    now = mwan3(owrt)
    assert now["wan_m1"] == before["wan_m1"] and now["wan_only"] == before["wan_only"]
    [copy_name] = [n for n in now if n not in before]
    assert copy_name == "sb_failover_wan"
    assert (now[copy_name]["weight"], now[copy_name]["signalbox"]) == ("7", "1")
    assert now[copy_name]["interface"] == "wan" and now[copy_name]["metric"] == "1"
    assert now["failover"]["use_member"] == ["sb_failover_wan", "wanb_m2"]
    # the group that was not declared is left exactly as it was
    net = owrt_svc.runner.network()
    only = next(g for g in net.gateway_groups if g.name == "wan_only")
    assert only.members[0].weight == 3
    backup = done.devices[0].backup_id
    assert backup is not None
    restore = await d.restore_backup(backup, "lab", "tester")
    d.approve(restore.id, "tester", override="lab" if restore.plan.blocking else None)
    restored = await d.deploy(restore.id)
    assert restored.status is ChangeStatus.APPLIED, [r.error for r in restored.devices]
    assert mwan3(owrt) == before


async def test_openwrt_only_adopted_and_existing_groups_are_changed(
    owrt: OpenWrtSim, owrt_svc: Services
) -> None:
    before = mwan3(owrt)
    net = await net_of(owrt_svc)
    with pytest.raises(PlanError, match="add adopt: true"):
        plan(parse(SWAP.replace("adopt: true", "adopt: false")), net, RULES)
    with pytest.raises(PlanError, match="does not create groups"):
        plan(parse(SWAP.replace("name: failover", "name: balanced")), net, RULES)
    with pytest.raises(PlanError, match="does not add members"):
        plan(parse(SWAP.replace("name: wanb", "name: lte")), net, RULES)
    assert mwan3(owrt) == before


async def test_openwrt_a_login_without_mwan3_write_access_changes_nothing(
    owrt: OpenWrtSim, owrt_svc: Services
) -> None:
    owrt.writable.discard("mwan3")
    before = mwan3(owrt)
    await net_of(owrt_svc)
    d = Deployer(owrt_svc.runner)
    p = plan(parse(SWAP), owrt_svc.runner.network(), RULES)
    try:
        rec = await d.prepare(p, "x", "tester")
    except DeployError:
        assert mwan3(owrt) == before
        return
    d.approve(rec.id, "tester", override="lab" if rec.plan.blocking else None)
    done = await d.deploy(rec.id)
    assert done.status is not ChangeStatus.APPLIED
    assert mwan3(owrt) == before


def test_openwrt_without_the_mwan3_config_is_refused() -> None:
    net_changes = plan(
        parse(SWAP),
        _network_with_group(),
        RULES,
    ).changes
    data = {"network": {"values": {}}}
    with pytest.raises(AdapterError) as err:
        owrt_write.translate(net_changes, data, {"interface": []}, "home", {})
    assert err.value.message_id == "openwrt.noMwan3"


def _network_with_group() -> Network:
    from factories import device
    from signalbox.model import GatewayGroup, GatewayGroupMember, object_id

    return Network(
        sites=[SITE],
        devices=[device("gw")],
        gateway_groups=[
            GatewayGroup(
                id=object_id("gw", "gateway-group", "failover"),
                device_id="gw",
                name="failover",
                members=[
                    GatewayGroupMember(name="wan", tier=1, weight=3),
                    GatewayGroupMember(name="wanb", tier=2, weight=1),
                ],
            )
        ],
    )


# --- MikroTik default routes --------------------------------------------------------------------


@pytest.fixture(scope="module")
def ros_url() -> Iterator[str]:
    with serve(ROS.app()) as base:
        yield base


@pytest.fixture
def ros(ros_url: str) -> MikrotikSimulator:
    ROS.__dict__.update(MikrotikSimulator().__dict__)
    return add_second_wan(ROS)


@pytest.fixture
def ros_svc(ros: MikrotikSimulator, ros_url: str, tmp_path: Path) -> Iterator[Services]:
    values = {"url": ros_url, "password": PASSWORD, "allow_insecure_http": True}
    s = services(tmp_path, "mikrotik", MikrotikAdapter, values, MikrotikConfig)
    yield s
    s.close()


def ros_adapter(url: str) -> MikrotikAdapter:
    config = MikrotikConfig(url=url, password=SecretStr(PASSWORD), allow_insecure_http=True)
    return MikrotikAdapter(
        AdapterContext(
            site_id="home",
            device_id="gw",
            device_name="Router",
            role=DeviceRole.GATEWAY,
            config=config,
        )
    )


def routes(sim: MikrotikSimulator) -> dict[str, Any]:
    """The default routes and netwatch entries by comment (what the writer may change)."""
    out: dict[str, Any] = {
        r["comment"]: {k: r.get(k) for k in ("distance", "check-gateway", "gateway")}
        for r in sim.data[IP_ROUTE]
        if r.get("dst-address") == "0.0.0.0/0"
    }
    out["netwatch"] = [dict(n) for n in sim.data[NETWATCH]]
    return copy.deepcopy(out)


ROS_SWAP = groups_text(
    "gw", "default", "          - {name: cable, tier: 2}\n          - {name: lte, tier: 1}\n"
)


async def test_mikrotik_tiers_are_distances_with_the_revert_timer(
    ros: MikrotikSimulator, ros_svc: Services
) -> None:
    before = routes(ros)
    net = await net_of(ros_svc)
    [g] = net.gateway_groups
    assert {m.name: m.tier for m in g.members} == {"cable": 1, "lte": 2}
    d = Deployer(ros_svc.runner)
    rec, done = await deploy(d, ros_svc, ROS_SWAP)
    assert done.status is ChangeStatus.APPLIED, [r.error for r in done.devices]
    calls = [(c.method, c.target) for c in rec.devices[0].calls]
    assert calls[0] == ("PUT", SCHEDULER)  # the revert timer comes first
    assert ros.data[SCHEDULER] == []  # confirmed
    now = routes(ros)
    assert (now["cable"]["distance"], now["lte"]["distance"]) == ("2", "1")
    assert now["netwatch"] == before["netwatch"]
    net = ros_svc.runner.network()
    assert plan(parse(ROS_SWAP), net, RULES).changes == []
    back = await undo(d, rec.id)
    assert back.status is ChangeStatus.APPLIED, [r.error for r in back.devices]
    again = routes(ros)
    assert (again["cable"]["distance"], again["lte"]["distance"]) == ("1", "2")


async def test_mikrotik_the_timer_undoes_a_change_that_is_not_confirmed(
    ros: MikrotikSimulator, ros_svc: Services, ros_url: str
) -> None:
    before = routes(ros)
    await net_of(ros_svc)
    text = groups_text(
        "gw",
        "default",
        "          - {name: cable, tier: 2, monitor: []}\n"
        "          - {name: lte, tier: 1, monitor: [198.51.100.1, 203.0.113.99]}\n",
    )
    p = plan(parse(text), ros_svc.runner.network(), RULES)
    a = ros_adapter(ros_url)
    try:
        await a.apply(p.changes, {}, 120)
        now = routes(ros)
        assert now["cable"]["check-gateway"] is None and now["lte"]["check-gateway"] == "ping"
        assert now["netwatch"][0]["host"] == "203.0.113.99"
        assert now["netwatch"][0]["up-script"] == before["netwatch"][0]["up-script"]
        assert len(ros.data[SCHEDULER]) == 1
        assert ros.fire_scheduler() == 1
        assert not ros.script_errors, ros.script_errors
        assert routes(ros) == before
    finally:
        await a.close()


@pytest.mark.parametrize(
    ("members", "message_id"),
    [
        ("          - {name: lte, weight: 2}\n", "mikrotik.noWeight"),
        ("          - {name: lte, monitor: []}\n", "mikrotik.netwatchNeeded"),
        (
            "          - {name: cable, monitor: [203.0.113.1, 192.0.2.7]}\n",
            "mikrotik.netwatchNeeded",
        ),
    ],
)
async def test_mikrotik_refuses_what_routeros_cannot_do(
    ros: MikrotikSimulator, ros_svc: Services, members: str, message_id: str
) -> None:
    before = routes(ros)
    await net_of(ros_svc)
    d = Deployer(ros_svc.runner)
    p = plan(parse(groups_text("gw", "default", members)), ros_svc.runner.network(), RULES)
    with pytest.raises(DeployError) as err:
        await d.prepare(p, "x", "tester")
    assert err.value.message_id == message_id
    assert routes(ros) == before


async def test_mikrotik_a_dynamic_route_is_refused(
    ros: MikrotikSimulator, ros_svc: Services
) -> None:
    lte = next(r for r in ros.data[IP_ROUTE] if r.get("comment") == "lte")
    lte.update({"dynamic": "true", "dhcp": "true"})
    before = routes(ros)
    await net_of(ros_svc)
    d = Deployer(ros_svc.runner)
    p = plan(parse(ROS_SWAP), ros_svc.runner.network(), RULES)
    with pytest.raises(DeployError, match="default-route-distance"):
        await d.prepare(p, "x", "tester")
    assert routes(ros) == before


async def test_mikrotik_a_failed_deployment_is_restored_from_the_backup(
    ros: MikrotikSimulator, ros_svc: Services
) -> None:
    before = routes(ros)
    await net_of(ros_svc)
    d = Deployer(ros_svc.runner)
    ros.fail_write[NETWATCH] = 500  # the route is changed, then the netwatch call fails
    text = groups_text(
        "gw",
        "default",
        "          - {name: cable, tier: 2}\n"
        "          - {name: lte, tier: 1, monitor: [203.0.113.99]}\n",
    )
    _, done = await deploy(d, ros_svc, text)
    ros.fail_write.clear()
    assert done.status is not ChangeStatus.APPLIED
    assert routes(ros) == before


async def test_mikrotik_groups_that_are_not_adopted_are_never_touched(
    ros: MikrotikSimulator, ros_svc: Services
) -> None:
    net = await net_of(ros_svc)
    with pytest.raises(PlanError, match="add adopt: true"):
        plan(parse(ROS_SWAP.replace("adopt: true", "adopt: false")), net, RULES)
    findings = evaluate(net, drift_rules(parse(ROS_SWAP.replace("adopt: true", "adopt: false"))))
    assert [f for f in findings if f.rule_id == "drift.gateway-group" and f.problem]
    [c] = plan(parse(ROS_SWAP), net, RULES).changes
    assert isinstance(c.new, GatewayGroupValue) and c.adopt == "default"
