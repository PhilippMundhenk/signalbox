"""WireGuard tunnel writes (#152, ADR 0034) through the real Deployer against the simulators: a
tunnel between an OpenWrt router and a MikroTik router in two steps, where each side's peer gets
the other side's public key; undo, the revert timer, restore from the backup, the key helper,
and that no private or pre-shared key ever appears in plans, records, backups, the store, logs
or API answers (the simulated keys are derived from seeds marked ``do-not-leak``)."""

from __future__ import annotations

import base64
import hashlib
import json
import logging
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from signalbox.adapters.mikrotik import MikrotikAdapter, MikrotikConfig
from signalbox.adapters.mikrotik.write import without_keys
from signalbox.adapters.openwrt import OpenWrtAdapter, OpenWrtConfig
from signalbox.changes import ChangeKind, TunnelPeerValue, plan
from signalbox.deploy import Deployer, DeployError
from signalbox.desired import drift_rules, parse
from signalbox.history import ChangeStatus
from signalbox.model import DeviceRole, Network, Site
from signalbox.rules import evaluate
from signalbox.rules.builtin import RULES
from signalbox.service import Services, build
from signalbox.sim import mikrotik as ros_sim
from signalbox.sim import openwrt as owrt_sim
from signalbox.sim.mikrotik import PASSWORD, SCHEDULER, MikrotikSimulator
from signalbox.sim.openwrt import OpenWrtSim, create_app
from signalbox.sim.server import serve
from signalbox.store import DeviceRecord
from signalbox.web.desired_api import plan_json

SITE = Site(id="home", name="Home")
ENV = {"SIGNALBOX_AUTH_PASSWORD": "x" * 12, "SIGNALBOX_DEPLOY_ENABLED": "true"}
OWRT = OpenWrtSim(router=True)
ROS = MikrotikSimulator()

TEXT = """sites:
  home:
    tunnels:
      - name: office
        ends:
          - device: home-gw
            interface: wg_office
            listen_port: 51820
            addresses: [2001:db8:c1::1/64]
            endpoint: 203.0.113.10
            networks: [2001:db8:a1::/64]
          - device: office-gw
            interface: wg_home
            listen_port: 51821
            addresses: [2001:db8:c1::2/64]
            networks: [2001:db8:b1::/64]
            keepalive: 25
"""


def seed_key(seed: str) -> str:
    return base64.b64encode(hashlib.sha256(seed.encode()).digest()).decode()


#: Every private or pre-shared key the simulators hold: none may leave the integrations.
SECRETS = [
    owrt_sim.wg_private_key("wg_office"),
    ros_sim.wg_private_key("wg_home"),
    seed_key("sim-secret-private"),  # the samples' own wg0
    seed_key("sim-secret-psk"),
]


@pytest.fixture(scope="module")
def owrt_url() -> Iterator[str]:
    with serve(create_app(OWRT)) as base:
        yield base


@pytest.fixture(scope="module")
def ros_url() -> Iterator[str]:
    with serve(ROS.app()) as base:
        yield base


@pytest.fixture
def sims(owrt_url: str, ros_url: str) -> tuple[OpenWrtSim, MikrotikSimulator]:
    OWRT.reset()
    OWRT.router = True
    OWRT.wireguard = True  # its own wg0 with a private and a pre-shared key
    ROS.__dict__.update(MikrotikSimulator().__dict__)
    return OWRT, ROS


@pytest.fixture
def svc(
    sims: tuple[OpenWrtSim, MikrotikSimulator], owrt_url: str, ros_url: str, tmp_path: Path
) -> Iterator[Services]:
    s = build(
        tmp_path,
        env=ENV,
        adapters={"openwrt": OpenWrtAdapter, "mikrotik": MikrotikAdapter},
        rules=RULES,
        link_sources=[],
    )
    s.store.put_site(SITE)
    for device_id, adapter, values, config in (
        (
            "home-gw",
            "openwrt",
            {
                "url": f"{owrt_url}/ubus",
                "password": OpenWrtSim().password,
                "allow_insecure_http": True,
            },
            OpenWrtConfig,
        ),
        (
            "office-gw",
            "mikrotik",
            {"url": ros_url, "password": PASSWORD, "allow_insecure_http": True},
            MikrotikConfig,
        ),
    ):
        rec = DeviceRecord(
            id=device_id,
            site_id="home",
            name=device_id,
            role=DeviceRole.GATEWAY,
            adapter=adapter,
            allow_writes=True,
        )
        s.store.put_device(rec, values, config)
    yield s
    s.close()


async def net_of(svc: Services) -> Network:
    await svc.runner.observe_all()
    return svc.runner.network()


async def deploy(d: Deployer, svc: Services, text: str = TEXT) -> Any:
    p = plan(parse(text), await net_of(svc), RULES)
    rec = await d.prepare(p, "site link", "tester")
    d.approve(rec.id, "tester", override="lab" if rec.plan.blocking else None)
    return rec, await d.deploy(rec.id)


async def undo(d: Deployer, cid: str) -> Any:
    back = await d.revert(cid, "not needed", "tester")
    d.approve(back.id, "tester", override="lab" if back.plan.blocking else None)
    return await d.deploy(back.id)


def ros_rows(sim: MikrotikSimulator, menu: str) -> list[dict[str, Any]]:
    return [r for r in sim.data[menu] if str(r.get("comment", "")).startswith("signalbox:wg/")]


def owrt_sections(sim: OpenWrtSim) -> dict[str, dict[str, Any]]:
    return {n: s for n, s in sim.state["network"].items() if s.get("signalbox") == "office"}


async def test_a_tunnel_between_two_devices_in_two_steps(
    sims: tuple[OpenWrtSim, MikrotikSimulator], svc: Services
) -> None:
    owrt, ros = sims
    d = Deployer(svc.runner)
    first, done = await deploy(d, svc)
    assert done.status is ChangeStatus.APPLIED, [r.error for r in done.devices]
    assert [(c.kind, c.device_id) for c in first.plan.changes] == [
        (ChangeKind.TUNNEL, "home-gw"),
        (ChangeKind.TUNNEL, "office-gw"),
    ]
    assert len(first.plan.pending) == 2
    # the key pairs were generated on the devices
    assert owrt.state["network"]["wg_office"]["private_key"] == owrt_sim.wg_private_key("wg_office")
    assert "wg-key wg_office" in owrt.history
    [iface] = ros_rows(ros, ros_sim.WG_MENU)
    assert iface["public-key"] == ros_sim.wg_public_key("wg_home")

    second, done = await deploy(d, svc)
    assert done.status is ChangeStatus.APPLIED, [r.error for r in done.devices]
    peers = {c.device_id: c.new for c in second.plan.changes}
    assert [c.kind for c in second.plan.changes] == [ChangeKind.TUNNEL_PEER] * 2
    assert second.plan.pending == []
    # each side's peer is the other side's public key, read after creation
    home, office = peers["home-gw"], peers["office-gw"]
    assert isinstance(home, TunnelPeerValue) and isinstance(office, TunnelPeerValue)
    assert home.public_key == ros_sim.wg_public_key("wg_home")
    assert office.public_key == owrt_sim.wg_public_key("wg_office")
    section = owrt_sections(owrt)["sb_wg_office"]
    assert section["public_key"] == ros_sim.wg_public_key("wg_home")
    assert section["route_allowed_ips"] == "1"
    assert sorted(section["allowed_ips"]) == ["2001:db8:b1::/64", "2001:db8:c1::2/128"]
    [peer] = ros_rows(ros, ros_sim.WG_PEERS)
    assert peer["public-key"] == owrt_sim.wg_public_key("wg_office")
    assert (peer["endpoint-address"], peer["endpoint-port"]) == ("203.0.113.10", "51820")
    assert peer["persistent-keepalive"] == "25s"
    [route] = ros_rows(ros, ros_sim.IPV6_ROUTE)
    assert (route["dst-address"], route["gateway"]) == ("2001:db8:a1::/64", "wg_home")
    assert ros.data[SCHEDULER] == []  # confirmed

    net = await net_of(svc)
    again = plan(parse(TEXT), net, RULES)
    assert again.changes == [] and again.pending == []
    assert not [f for f in evaluate(net, drift_rules(parse(TEXT))) if f.problem]

    # undo both steps: the peers, then the interfaces Signalbox created go away
    back = await undo(d, second.id)
    assert back.status is ChangeStatus.APPLIED, [r.error for r in back.devices]
    back = await undo(d, first.id)
    assert back.status is ChangeStatus.APPLIED, [r.error for r in back.devices]
    assert owrt_sections(owrt) == {}
    assert ros_rows(ros, ros_sim.WG_MENU) == [] and ros_rows(ros, ros_sim.WG_PEERS) == []
    assert ros_rows(ros, ros_sim.IPV6_ROUTE) == []
    assert "wg0" in owrt.state["network"]  # the device's own tunnel is left alone


async def test_no_private_or_preshared_key_leaves_the_devices(
    sims: tuple[OpenWrtSim, MikrotikSimulator],
    svc: Services,
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG)
    d = Deployer(svc.runner)
    await deploy(d, svc)
    second, _ = await deploy(d, svc)
    await undo(d, second.id)
    net = await net_of(svc)
    texts = [
        net.model_dump_json(),
        caplog.text,
        json.dumps(plan_json(plan(parse(TEXT), net, RULES))),
        *(r.model_dump_json() for r in svc.store.changes()),
        *(e.model_dump_json() for e in svc.store.events()),
    ]
    for info in svc.store.backups():
        backup = svc.store.backup(info.id)
        assert backup is not None
        texts.append(backup.content)
    for path in tmp_path.rglob("*"):
        if path.is_file():
            texts.append(path.read_bytes().decode("latin-1"))
    assert svc.store.backups(), "the deployments took backups"
    for text in texts:
        for secret in SECRETS:
            assert secret not in text
    # the simulated export shows the keys, as an export with show-sensitive does
    assert seed_key("sim-secret-private") in sims[1].export()


async def test_openwrt_without_the_key_helper_refuses_a_new_tunnel(
    sims: tuple[OpenWrtSim, MikrotikSimulator], svc: Services
) -> None:
    owrt, ros = sims
    owrt.wg_key_helper = False
    d = Deployer(svc.runner)
    p = plan(parse(TEXT), await net_of(svc), RULES)
    with pytest.raises(DeployError) as err:
        await d.prepare(p, "site link", "tester")
    assert err.value.message_id == "openwrt.wgKeyHelper"
    assert owrt_sections(owrt) == {} and ros_rows(ros, ros_sim.WG_MENU) == []


async def test_mikrotik_a_failed_peer_write_is_restored_from_the_backup(
    sims: tuple[OpenWrtSim, MikrotikSimulator], svc: Services
) -> None:
    _, ros = sims
    d = Deployer(svc.runner)
    await deploy(d, svc)
    before = {m: [dict(r) for r in ros.data[m]] for m in (ros_sim.WG_PEERS, ros_sim.IPV6_ROUTE)}
    ros.fail_write[ros_sim.IPV6_ROUTE] = 500  # the peer is added, then the route fails
    _, done = await deploy(d, svc)
    ros.fail_write.clear()
    assert done.status is not ChangeStatus.APPLIED
    after = {m: [dict(r) for r in ros.data[m]] for m in (ros_sim.WG_PEERS, ros_sim.IPV6_ROUTE)}
    strip = ".id"
    assert [{k: v for k, v in r.items() if k != strip} for r in after[ros_sim.WG_PEERS]] == [
        {k: v for k, v in r.items() if k != strip} for r in before[ros_sim.WG_PEERS]
    ]
    assert ros_rows(ros, ros_sim.IPV6_ROUTE) == []


async def test_mikrotik_the_timer_undoes_a_tunnel_that_is_not_confirmed(
    sims: tuple[OpenWrtSim, MikrotikSimulator], svc: Services, ros_url: str
) -> None:
    _, ros = sims
    p = plan(parse(TEXT), await net_of(svc), RULES)
    changes = [c for c in p.changes if c.device_id == "office-gw"]
    adapter = svc.runner.adapters["mikrotik"]
    from signalbox.adapters import AdapterContext

    a = adapter(
        AdapterContext(
            site_id="home",
            device_id="office-gw",
            device_name="office-gw",
            role=DeviceRole.GATEWAY,
            config=MikrotikConfig(url=ros_url, password=PASSWORD, allow_insecure_http=True),
        )
    )
    try:
        await a.apply(changes, {}, 120)
        assert ros_rows(ros, ros_sim.WG_MENU) and len(ros.data[SCHEDULER]) == 1
        assert ros.fire_scheduler() == 1
        assert not ros.script_errors, ros.script_errors
        assert ros_rows(ros, ros_sim.WG_MENU) == []
        assert not [r for r in ros.data["/rest/ipv6/address"] if r.get("interface") == "wg_home"]
    finally:
        await a.close()


async def test_openwrt_backup_and_restore_leave_keys_alone(
    sims: tuple[OpenWrtSim, MikrotikSimulator], svc: Services
) -> None:
    owrt, _ = sims
    d = Deployer(svc.runner)
    await net_of(svc)
    adapter = d.adapter("home-gw")
    try:
        backup = await adapter.backup()
        assert seed_key("sim-secret-private") not in backup.content
        assert seed_key("sim-secret-psk") not in backup.content
        assert "preshared_key_set" not in backup.content  # the reader's flag is not written
        await adapter.restore(backup)
    finally:
        await adapter.close()
    wg0 = owrt.state["network"]["wg0"]
    assert wg0["private_key"] == seed_key("sim-secret-private")  # neither deleted nor changed
    peer = owrt.state["network"]["cfg0a1b2c"]
    assert peer["preshared_key"] == seed_key("sim-secret-psk")


def test_the_export_text_loses_wireguard_keys() -> None:
    text = (
        '/interface wireguard\nadd listen-port=51820 name=wg0 private-key="abc+/=" \n'
        "/interface wireguard peers\nadd preshared-key=xyz= public-key=pub= interface=wg0\n"
    )
    out = without_keys(text)
    assert "abc+/=" not in out and "xyz=" not in out and "public-key=pub=" in out
