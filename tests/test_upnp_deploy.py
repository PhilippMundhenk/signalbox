"""UPnP writes (#513, ADR 0035) through the real Deployer against the simulators: OpenWrt
miniupnpd (UCI ``upnpd``), MikroTik ``/ip/upnp`` and the FRITZ!Box switch, with plan, apply,
verify, undo, the revert timer, the backup, refusals, and nothing changed where nothing is
declared."""

from __future__ import annotations

import copy
from collections.abc import AsyncIterator, Iterator
from pathlib import Path
from typing import Any

import pytest
from pydantic import SecretStr

from signalbox.adapters import AdapterContext, AdapterError
from signalbox.adapters.fritzbox import FritzboxAdapter, FritzboxConfig
from signalbox.adapters.fritzbox.write import upnp_calls
from signalbox.adapters.mikrotik import MikrotikAdapter, MikrotikConfig
from signalbox.adapters.openwrt import OpenWrtAdapter, OpenWrtConfig
from signalbox.adapters.openwrt import write as owrt_write
from signalbox.changes import Change, ChangeKind, UpnpValue, plan
from signalbox.deploy import Deployer, DeployError
from signalbox.desired import drift_rules, parse
from signalbox.history import ChangeStatus
from signalbox.model import DeviceRole, Network, ServiceKind, Site
from signalbox.rules import evaluate
from signalbox.rules.builtin import RULES
from signalbox.service import Services, build
from signalbox.sim.fritzbox import FritzboxSim
from signalbox.sim.fritzbox import create_app as fritz_app
from signalbox.sim.mikrotik import PASSWORD, SCHEDULER, UPNP, UPNP_INTERFACES, MikrotikSimulator
from signalbox.sim.openwrt import OpenWrtSim, create_app
from signalbox.sim.server import serve
from signalbox.store import DeviceRecord

SITE = Site(id="home", name="Home")
ENV = {"SIGNALBOX_AUTH_PASSWORD": "x" * 12, "SIGNALBOX_DEPLOY_ENABLED": "true"}
OWRT = OpenWrtSim(router=True)
ROS = MikrotikSimulator()


def upnp_text(body: str, device: str = "gw") -> str:
    return f"sites:\n  home:\n    upnp:\n      - device: {device}\n{body}"


async def net_of(svc: Services) -> Network:
    await svc.runner.observe_all()
    return svc.runner.network()


async def deploy(d: Deployer, svc: Services, text: str) -> Any:
    p = plan(parse(text), svc.runner.network(), RULES)
    rec = await d.prepare(p, "upnp", "tester")
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


def no_upnp_drift(net: Network, text: str) -> bool:
    return not [f for f in evaluate(net, drift_rules(parse(text))) if f.rule_id == "drift.upnp"]


# --- OpenWrt miniupnpd --------------------------------------------------------------------------


@pytest.fixture(scope="module")
def owrt_url() -> Iterator[str]:
    with serve(create_app(OWRT)) as base:
        yield base


@pytest.fixture
def owrt(owrt_url: str) -> OpenWrtSim:
    OWRT.reset()
    OWRT.router = True
    OWRT.packages = {"upnpd"}
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


def upnpd(sim: OpenWrtSim) -> dict[str, Any]:
    return copy.deepcopy(sim.state["upnpd"])


def main(sections: dict[str, Any]) -> dict[str, Any]:
    return next(s for s in sections.values() if s.get(".type") == "upnpd")


def perms(sections: dict[str, Any]) -> list[tuple[str, str, str, str]]:
    rows = sorted(
        (s for s in sections.values() if s.get(".type") == "perm_rule"),
        key=lambda s: int(s.get(".index", 0)),
    )
    return [(s["action"], s["ext_ports"], s["int_addr"], s["int_ports"]) for s in rows]


OFF = upnp_text("        enabled: false\n")


async def test_openwrt_off_deploys_verifies_and_undoes(
    owrt: OpenWrtSim, owrt_svc: Services
) -> None:
    before = upnpd(owrt)
    await net_of(owrt_svc)
    d = Deployer(owrt_svc.runner)
    rec, done = await deploy(d, owrt_svc, OFF)
    assert [c.kind for c in rec.plan.changes] == [ChangeKind.UPNP]
    assert rec.plan.changes[0].risk is None
    assert done.status is ChangeStatus.APPLIED, [r.error for r in done.devices]
    texts = [c.description for c in rec.devices[0].calls]
    assert any("does not remove open mappings" in t for t in texts), texts
    now = upnpd(owrt)
    assert main(now)["enabled"] == "0"
    assert {k: v for k, v in main(now).items() if k != "enabled"} == {
        k: v for k, v in main(before).items() if k != "enabled"
    }
    assert perms(now) == perms(before)  # not declared: left as they are
    net = owrt_svc.runner.network()
    [svc] = [s for s in net.services if s.kind is ServiceKind.UPNP]
    assert not svc.enabled
    assert plan(parse(OFF), net, RULES).changes == [] and no_upnp_drift(net, OFF)
    back = await undo(d, rec.id)
    assert back.status is ChangeStatus.APPLIED, [r.error for r in back.devices]
    assert main(upnpd(owrt))["enabled"] == "1"


async def test_openwrt_networks_rules_and_secure_mode(owrt: OpenWrtSim, owrt_svc: Services) -> None:
    await net_of(owrt_svc)
    d = Deployer(owrt_svc.runner)
    text = upnp_text(
        "        secure_mode: false\n        networks: [native, 20]\n"
        "        allow:\n          - {network: 192.0.2.0/25, ports: 5000-5100}\n"
    )
    rec, done = await deploy(d, owrt_svc, text)
    [c] = rec.plan.changes
    assert c.risk == "widens UPnP: turns secure mode off, adds networks"
    assert done.status is ChangeStatus.APPLIED, [r.error for r in done.devices]
    now = upnpd(owrt)
    assert (main(now)["secure_mode"], main(now)["internal_iface"]) == ("0", "iot lan")
    assert main(now)["enabled"] == "1"
    assert perms(now) == [
        ("allow", "5000-5100", "192.0.2.0/25", "5000-5100"),
        ("deny", "0-65535", "0.0.0.0/0", "0-65535"),
    ]
    assert all(
        s.get("comment") == "Signalbox" for s in now.values() if s.get(".type") == "perm_rule"
    )
    net = owrt_svc.runner.network()
    assert plan(parse(text), net, RULES).changes == [] and no_upnp_drift(net, text)


async def test_openwrt_the_backup_restores_the_rules(owrt: OpenWrtSim, owrt_svc: Services) -> None:
    before = upnpd(owrt)
    await net_of(owrt_svc)
    d = Deployer(owrt_svc.runner)
    text = upnp_text("        allow:\n          - {network: 192.0.2.0/26}\n")
    _, done = await deploy(d, owrt_svc, text)
    assert done.status is ChangeStatus.APPLIED, [r.error for r in done.devices]
    assert perms(upnpd(owrt)) != perms(before)
    backup = done.devices[0].backup_id
    assert backup is not None
    restore = await d.restore_backup(backup, "lab", "tester")
    d.approve(restore.id, "tester", override="lab" if restore.plan.blocking else None)
    restored = await d.deploy(restore.id)
    assert restored.status is ChangeStatus.APPLIED, [r.error for r in restored.devices]
    assert perms(upnpd(owrt)) == perms(before)


async def test_openwrt_nothing_changes_without_a_declaration(
    owrt: OpenWrtSim, owrt_svc: Services
) -> None:
    net = await net_of(owrt_svc)
    assert plan(parse("sites:\n  home: {}\n"), net, RULES).changes == []
    # a declaration that matches the router needs no change either
    same = upnp_text(
        "        enabled: true\n        secure_mode: true\n        networks: [native]\n"
    )
    assert plan(parse(same), net, RULES).changes == []


async def test_openwrt_a_login_without_upnpd_write_access_changes_nothing(
    owrt: OpenWrtSim, owrt_svc: Services
) -> None:
    owrt.writable.discard("upnpd")
    before = upnpd(owrt)
    await net_of(owrt_svc)
    d = Deployer(owrt_svc.runner)
    p = plan(parse(OFF), owrt_svc.runner.network(), RULES)
    try:
        rec = await d.prepare(p, "x", "tester")
    except DeployError:
        assert upnpd(owrt) == before
        return
    d.approve(rec.id, "tester", override="lab" if rec.plan.blocking else None)
    done = await d.deploy(rec.id)
    assert done.status is not ChangeStatus.APPLIED
    assert upnpd(owrt) == before


def configs(sim: OpenWrtSim, upnpd: bool = True) -> dict[str, Any]:
    """``uci get`` answers as the writer gets them."""
    out = {"network": {"values": copy.deepcopy(sim.state["network"])}}
    if upnpd:
        out["upnpd"] = {"values": copy.deepcopy(sim.state["upnpd"])}
    return out


async def test_openwrt_refusals(owrt: OpenWrtSim, owrt_svc: Services) -> None:
    net = await net_of(owrt_svc)
    [c] = plan(parse(OFF), net, RULES).changes
    assert isinstance(c.new, UpnpValue)
    # no upnpd config (the package is not installed)
    with pytest.raises(AdapterError) as err:
        owrt_write.translate([c], configs(owrt, upnpd=False), {"interface": []}, "home", {})
    assert err.value.message_id == "openwrt.noUpnpd"
    # turning it on while both protocols are off
    data = configs(owrt)
    for section in data["upnpd"]["values"].values():
        if section.get(".type") == "upnpd":
            section.update(enabled="0", enable_upnp="0", enable_natpmp="0")
    with pytest.raises(AdapterError) as err:
        owrt_write.translate([c.inverse()], data, {"interface": []}, "home", {})
    assert err.value.message_id == "openwrt.upnpNoProtocol"
    # a network the router has no interface in
    far = c.model_copy(update={"new": c.new.model_copy(update={"networks": ["home/segment/99"]})})
    with pytest.raises(AdapterError) as err:
        owrt_write.translate([far], configs(owrt), {"interface": []}, "home", {})
    assert err.value.message_id == "openwrt.upnpNoInterface"


# --- MikroTik /ip/upnp --------------------------------------------------------------------------


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


def ros_upnp(sim: MikrotikSimulator) -> dict[str, Any]:
    return copy.deepcopy(
        {
            "enabled": sim.data[UPNP]["enabled"],
            "rows": sorted(
                (r["interface"], r["type"], r.get("disabled", "false"))
                for r in sim.data[UPNP_INTERFACES]
            ),
        }
    )


ROS_ON = upnp_text("        enabled: true\n        networks: [20]\n")


async def test_mikrotik_on_in_one_network_with_the_revert_timer(
    ros: MikrotikSimulator, ros_svc: Services
) -> None:
    before = ros_upnp(ros)
    assert before["enabled"] == "false"
    await net_of(ros_svc)
    d = Deployer(ros_svc.runner)
    rec, done = await deploy(d, ros_svc, ROS_ON)
    [c] = rec.plan.changes
    assert c.risk is not None and "turns it on" in c.risk
    assert done.status is ChangeStatus.APPLIED, [r.error for r in done.devices]
    calls = [(x.method, x.target) for x in rec.devices[0].calls]
    assert calls[0] == ("PUT", SCHEDULER)  # the revert timer comes first
    assert calls[-1][1].endswith("/ip/upnp/set")  # switched on after the networks changed
    assert ros.data[SCHEDULER] == []  # confirmed
    now = ros_upnp(ros)
    assert now["enabled"] == "true"
    assert now["rows"] == [
        ("bridge", "internal", "true"),
        ("ether1", "external", "false"),
        ("iot", "internal", "false"),
    ]
    net = ros_svc.runner.network()
    assert plan(parse(ROS_ON), net, RULES).changes == [] and no_upnp_drift(net, ROS_ON)
    back = await undo(d, rec.id)
    assert back.status is ChangeStatus.APPLIED, [r.error for r in back.devices]
    assert ros_upnp(ros)["enabled"] == "false"


async def test_mikrotik_the_timer_undoes_a_change_that_is_not_confirmed(
    ros: MikrotikSimulator, ros_svc: Services, ros_url: str
) -> None:
    before = ros_upnp(ros)
    await net_of(ros_svc)
    p = plan(parse(ROS_ON), ros_svc.runner.network(), RULES)
    a = ros_adapter(ros_url)
    try:
        await a.apply(p.changes, {}, 120)
        assert ros_upnp(ros) != before
        assert ros.fire_scheduler() == 1
        assert not ros.script_errors, ros.script_errors
        assert ros_upnp(ros) == before
    finally:
        await a.close()


@pytest.mark.parametrize(
    ("body", "message_id"),
    [
        ("        secure_mode: true\n", "mikrotik.upnpNoSecureMode"),
        ("        allow:\n          - {network: 192.0.2.0/24}\n", "mikrotik.upnpNoRules"),
    ],
)
async def test_mikrotik_refuses_what_routeros_cannot_do(
    ros: MikrotikSimulator, ros_svc: Services, body: str, message_id: str
) -> None:
    before = ros_upnp(ros)
    await net_of(ros_svc)
    d = Deployer(ros_svc.runner)
    p = plan(parse(upnp_text(body)), ros_svc.runner.network(), RULES)
    with pytest.raises(DeployError) as err:
        await d.prepare(p, "x", "tester")
    assert err.value.message_id == message_id
    assert ros_upnp(ros) == before


async def test_mikrotik_a_failed_deployment_is_restored_from_the_backup(
    ros: MikrotikSimulator, ros_svc: Services
) -> None:
    before = ros_upnp(ros)
    await net_of(ros_svc)
    d = Deployer(ros_svc.runner)
    ros.fail_write[UPNP] = 500  # the interface rows change, then the switch fails
    _, done = await deploy(d, ros_svc, ROS_ON)
    ros.fail_write.clear()
    assert done.status is not ChangeStatus.APPLIED
    assert ros_upnp(ros) == before


async def test_mikrotik_nothing_changes_without_a_declaration(
    ros: MikrotikSimulator, ros_svc: Services
) -> None:
    net = await net_of(ros_svc)
    assert plan(parse("sites:\n  home: {}\n"), net, RULES).changes == []
    assert plan(parse(upnp_text("        enabled: false\n")), net, RULES).changes == []


# --- FRITZ!Box ----------------------------------------------------------------------------------


@pytest.fixture
async def fritz() -> AsyncIterator[tuple[FritzboxSim, FritzboxAdapter]]:
    sim = FritzboxSim()
    with serve(fritz_app(sim)) as url:
        a = FritzboxAdapter(
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
        try:
            yield sim, a
        finally:
            await a.close()


def fritz_change(**new: Any) -> Change:
    old = UpnpValue(enabled=True)
    return Change(
        kind=ChangeKind.UPNP,
        device_id="fb",
        site_id="home",
        key="upnp",
        old=old,
        new=old.model_copy(update=new),
    )


async def test_fritzbox_switches_upnp_and_restores_it(
    fritz: tuple[FritzboxSim, FritzboxAdapter],
) -> None:
    sim, a = fritz
    sim.upnp["NewUPnPMediaServer"] = "1"
    backup = await a.backup()
    result = await a.apply([fritz_change(enabled=False)], {}, 60)
    assert [c.target for c in result.calls] == ["X_AVM-DE_UPnP1 SetConfig"]
    assert "does not remove open mappings" in result.calls[0].description
    assert sim.upnp == {"NewEnable": "0", "NewUPnPMediaServer": "1"}  # media server kept
    assert await a.plan_changes([fritz_change(enabled=True)], {}) != []
    await a.restore(backup)
    assert sim.upnp["NewEnable"] == "1"


def test_fritzbox_refuses_all_but_the_switch() -> None:
    info = {"NewEnable": "1", "NewUPnPMediaServer": "0"}
    for change in (
        fritz_change(secure_mode=True),
        fritz_change(networks=["home/segment/native"]),
    ):
        with pytest.raises(AdapterError) as err:
            upnp_calls(change, info)
        assert err.value.message_id == "fritzbox.upnpOnlySwitch"
    with pytest.raises(AdapterError) as err:
        upnp_calls(fritz_change(enabled=False), {"NewEnable": "1"})
    assert err.value.message_id == "fritzbox.upnpNoMediaServer"
    with pytest.raises(AdapterError) as err:
        upnp_calls(fritz_change(enabled=False), None)
    assert err.value.message_id == "fritzbox.noUpnpService"
    assert upnp_calls(fritz_change(enabled=True), info) == []
