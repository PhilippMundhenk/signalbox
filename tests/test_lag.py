"""Link aggregation details (#157, ADR 0022): the bonding parsers, the readers of Linux,
OpenWrt, MikroTik and Omada against their simulators, the contract checks and the topology."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest
from pydantic import SecretStr

from factories import SITE, device, port
from signalbox.adapters import AdapterContext, bonding
from signalbox.adapters.mikrotik import MikrotikAdapter, MikrotikConfig, bond_details, member_state
from signalbox.adapters.omada import _lag_mode, _lag_type
from signalbox.adapters.openwrt import OpenWrtAdapter, OpenWrtConfig
from signalbox.adapters.openwrt.lag import uci_bonds
from signalbox.model import (
    DeviceRole,
    LacpRate,
    LagHashPolicy,
    LagMemberState,
    LagMode,
    Link,
    LinkOrigin,
    Network,
    PortKind,
    PortRole,
)
from signalbox.sim import linux as linux_sim
from signalbox.sim.mikrotik import MikrotikSimulator, add_bond
from signalbox.sim.openwrt import OpenWrtSim, create_app
from signalbox.sim.server import serve
from signalbox.testing import assert_contract, structure_problems
from signalbox.topology import view
from test_linux import adapter_for
from test_linux import device as linux_device

# --- the shared bonding parser ---------------------------------------------------------------


def test_proc_file_of_an_lacp_bond() -> None:
    bond = bonding.parse_proc("bond0", linux_sim.BOND_PROC)
    assert (bond.mode, bond.hash_policy, bond.lacp_rate, bond.min_links) == (
        "802.3ad",
        "layer2+3",
        "fast",
        1,
    )
    assert bond.details() == {
        "lag_mode": LagMode.LACP_ACTIVE,
        "hash_policy": LagHashPolicy.L2_L3,
        "min_links": 1,
        "lacp_rate": LacpRate.FAST,
    }
    assert bond.member_state("eth2") == LagMemberState(
        selected=True,
        collecting_distributing=True,
        partner_system_id="02:00:00:00:10:01",
        partner_port=5,
        partner_key=7,
    )
    # eth3: another aggregator, defaulted, no partner (all zeros)
    assert bond.member_state("eth3") == LagMemberState(
        selected=False, collecting_distributing=False
    )
    assert bond.member_state("eth9") is None


ACTIVE_BACKUP = """Ethernet Channel Bonding Driver: v6.1.0

Bonding Mode: fault-tolerance (active-backup)
Primary Slave: None
Currently Active Slave: eth1
MII Status: up

Slave Interface: eth1
MII Status: up

Slave Interface: eth2
MII Status: up
"""


def test_proc_file_of_other_modes() -> None:
    bond = bonding.parse_proc("bond1", ACTIVE_BACKUP)
    assert bond.details() == {"lag_mode": LagMode.ACTIVE_BACKUP}
    assert bond.member_state("eth1") == LagMemberState(selected=True)
    assert bond.member_state("eth2") == LagMemberState(selected=False)
    rr = bonding.parse_proc("b", "Bonding Mode: load balancing (round-robin)\nno colon line\n")
    assert rr.details() == {"lag_mode": LagMode.BALANCE_RR} and rr.member_state("x") is None
    odd = bonding.parse_proc("b", "Bonding Mode: something new\nTransmit Hash Policy: \n")
    assert odd.lag_mode() is LagMode.OTHER and odd.hash() is None
    passive = bonding.parse_proc(
        "b",
        "Bonding Mode: IEEE 802.3ad Dynamic link aggregation\nTransmit Hash Policy: encap3+4 (4)\n"
        "LACP active: off\nLACP rate: slow\nMin links: x\n",
    )
    assert passive.details() == {
        "lag_mode": LagMode.LACP_PASSIVE,
        "hash_policy": LagHashPolicy.OTHER,
        "lacp_rate": LacpRate.SLOW,
    }
    assert bonding.Bond("b").details() == {} and bonding.bond_name("/proc/net/x") is None


def test_sysfs_values() -> None:
    bond = bonding.parse_sysfs(
        "bond0",
        {
            "mode": "802.3ad 4",
            "xmit_hash_policy": "layer3+4 1",
            "lacp_rate": "slow 0",
            "lacp_active": "on 1",
            "min_links": "0",
            "ad_aggregator": "1",
            "ad_partner_mac": "02:00:00:00:10:01",
        },
        {
            "lan2": {"ad_aggregator_id": "1", "ad_actor_oper_port_state": "61"},
            "lan3": {"ad_aggregator_id": "2", "ad_actor_oper_port_state": "bogus"},
        },
    )
    assert list(bond.members) == ["lan2", "lan3"]
    assert bond.details()["hash_policy"] is LagHashPolicy.L3_L4
    two = bond.member_state("lan2")
    assert two is not None and two.partner_system_id == "02:00:00:00:10:01" and two.selected
    assert bond.member_state("lan3") == LagMemberState(selected=False)
    backup = bonding.parse_sysfs(
        "b", {"mode": "active-backup 1"}, {"a": {"state": "active"}, "b": {"state": "backup"}}
    )
    assert backup.member_state("a") == LagMemberState(selected=True)
    assert backup.member_state("b") == LagMemberState(selected=False)
    assert bonding._mac("not a mac") is None and bonding._word("") is None


# --- Linux --------------------------------------------------------------------------------


async def test_linux_reads_proc_net_bonding() -> None:
    box = linux_sim.add_bond(linux_device())
    async with adapter_for(box) as adapter:
        snap = await assert_contract(adapter)
    ports = {p.name: p for p in snap.ports}
    bond = ports["bond0"]
    assert (bond.role, bond.kind, bond.lower) == (
        PortRole.LAG,
        PortKind.LAG,
        ["gw2/port/eth2", "gw2/port/eth3"],
    )
    assert (bond.lag_mode, bond.hash_policy, bond.lacp_rate, bond.min_links) == (
        LagMode.LACP_ACTIVE,
        LagHashPolicy.L2_L3,
        LacpRate.FAST,
        1,
    )
    assert ports["eth2"].lag == ports["eth3"].lag == "bond0"
    s2, s3 = ports["eth2"].lag_member_state, ports["eth3"].lag_member_state
    assert s2 is not None and s2.collecting_distributing and s2.partner_port == 5
    assert s3 is not None and s3.selected is False
    assert "/proc/net/bonding/*" in box.scripts[0]


async def test_linux_bond_without_a_readable_proc_file() -> None:
    box = linux_sim.add_bond(linux_device())
    box.sections["bonding"] = ""
    async with adapter_for(box) as adapter:
        snap = await assert_contract(adapter)
    ports = {p.name: p for p in snap.ports}
    assert ports["bond0"].lag_mode is None and ports["eth2"].lag == "bond0"
    assert ports["eth2"].lag_member_state is None


# --- OpenWrt ------------------------------------------------------------------------------


def _openwrt_ctx(url: str, sim: OpenWrtSim) -> AdapterContext:
    return AdapterContext(
        site_id="home",
        device_id="sw",
        device_name="sw",
        role=DeviceRole.SWITCH,
        config=OpenWrtConfig(
            url=f"{url}/ubus", password=SecretStr(sim.password), allow_insecure_http=True
        ),
    )


@pytest.fixture
def openwrt() -> Iterator[tuple[OpenWrtSim, str]]:
    sim = OpenWrtSim(bond="802.3ad")
    with serve(create_app(sim)) as url:
        yield sim, url


async def _openwrt_ports(sim: OpenWrtSim, url: str) -> dict[str, Any]:
    a = OpenWrtAdapter(_openwrt_ctx(url, sim))
    try:
        snap = await assert_contract(a)
    finally:
        await a.close()
    return {p.name: p for p in snap.ports}


async def test_openwrt_bond_from_uci_and_sysfs(openwrt: tuple[OpenWrtSim, str]) -> None:
    ports = await _openwrt_ports(*openwrt)
    bond = ports["bond0"]
    assert (bond.role, bond.kind, bond.lower) == (
        PortRole.LAG,
        PortKind.LAG,
        ["sw/port/lan2", "sw/port/lan3"],
    )
    assert (bond.lag_mode, bond.hash_policy, bond.lacp_rate, bond.min_links) == (
        LagMode.LACP_ACTIVE,
        LagHashPolicy.L2_L3,
        LacpRate.FAST,
        1,
    )
    assert "sw/port/bond0" in ports["br-lan"].lower
    s2, s3 = ports["lan2"].lag_member_state, ports["lan3"].lag_member_state
    assert s2 == LagMemberState(
        selected=True, collecting_distributing=True, partner_system_id="02:00:00:00:10:01"
    )
    assert s3 == LagMemberState(selected=False, collecting_distributing=False)


async def test_openwrt_bond_with_an_older_acl(openwrt: tuple[OpenWrtSim, str]) -> None:
    sim, url = openwrt
    sim.bond, sim.bond_sysfs, sim.configs = "balance-xor", False, None
    ports = await _openwrt_ports(sim, url)
    assert ports["bond0"].lag_mode is LagMode.BALANCE_XOR
    assert ports["bond0"].hash_policy is LagHashPolicy.L2_L3 and ports["bond0"].lacp_rate is None
    assert ports["lan2"].lag == "bond0" and ports["lan2"].lag_member_state is None


def test_openwrt_uci_bonds_of_proto_bonding() -> None:
    uci = {
        "values": {
            "nas": {
                ".type": "interface",
                ".name": "nas",
                "proto": "bonding",
                "slaves": "lan2 lan3",
                "bonding_policy": "802.3ad",
                "min_links": "2",
            },
            "x": {".type": "device", "type": "bonding"},  # no name
            "y": "not a section",
        }
    }
    bonds = uci_bonds(uci)
    assert list(bonds) == ["bonding-nas"]
    b = bonds["bonding-nas"]
    assert list(b.members) == ["lan2", "lan3"]
    assert b.details() == {
        "lag_mode": LagMode.LACP_ACTIVE,
        "min_links": 2,
        "lacp_rate": LacpRate.SLOW,
    }
    assert uci_bonds(None) == {} and uci_bonds({"values": []}) == {}


# --- MikroTik -----------------------------------------------------------------------------


@pytest.fixture
def mikrotik() -> Iterator[tuple[MikrotikSimulator, str]]:
    sim = add_bond(MikrotikSimulator())
    with serve(sim.app()) as url:
        yield sim, url


def _mikrotik(url: str, sim: MikrotikSimulator) -> MikrotikAdapter:
    config = MikrotikConfig(url=url, password=SecretStr(sim.password), allow_insecure_http=True)
    return MikrotikAdapter(
        AdapterContext(
            site_id="home", device_id="rt", device_name="rt", role=DeviceRole.SWITCH, config=config
        )
    )


async def _mikrotik_ports(sim: MikrotikSimulator, url: str) -> dict[str, Any]:
    a = _mikrotik(url, sim)
    try:
        snap = await assert_contract(a)
    finally:
        await a.close()
    return {p.name: p for p in snap.ports}


async def test_mikrotik_bonding_and_monitor(mikrotik: tuple[MikrotikSimulator, str]) -> None:
    ports = await _mikrotik_ports(*mikrotik)
    bond = ports["bond1"]
    assert bond.lower == ["rt/port/ether6", "rt/port/ether7"]
    assert (bond.lag_mode, bond.hash_policy, bond.lacp_rate, bond.min_links) == (
        LagMode.LACP_ACTIVE,
        LagHashPolicy.L3_L4,
        LacpRate.FAST,
        1,
    )
    assert ports["ether6"].lag == "bond1"
    assert ports["ether6"].lag_member_state == LagMemberState(
        selected=True,
        collecting_distributing=True,
        partner_system_id="02:00:00:00:30:01",
        partner_port=1,
        partner_key=9,
    )
    assert ports["ether7"].lag_member_state == LagMemberState(
        selected=False, collecting_distributing=False
    )


async def test_mikrotik_monitor_refused(mikrotik: tuple[MikrotikSimulator, str]) -> None:
    sim, url = mikrotik
    sim.read_only_monitor = True
    ports = await _mikrotik_ports(sim, url)
    assert ports["bond1"].lag_mode is LagMode.LACP_ACTIVE
    assert ports["ether6"].lag == "bond1" and ports["ether6"].lag_member_state is None


def test_mikrotik_bond_values() -> None:
    assert bond_details({"mode": "balance-xor", "transmit-hash-policy": "layer-2"}) == {
        "lag_mode": LagMode.BALANCE_XOR,
        "hash_policy": LagHashPolicy.L2,
    }
    assert bond_details({"mode": "802.3ad", "lacp-mode": "passive", "lacp-rate": "30secs"}) == {
        "lag_mode": LagMode.LACP_PASSIVE,
        "lacp_rate": LacpRate.SLOW,
    }
    assert bond_details({"mode": "active-backup", "transmit-hash-policy": "layer-2"}) == {
        "lag_mode": LagMode.ACTIVE_BACKUP
    }
    assert bond_details({"mode": "future"}) == {"lag_mode": LagMode.OTHER}
    assert bond_details({}) == {}
    assert member_state({"mode": "802.3ad"}, None) is None
    odd = member_state({"mode": "802.3ad"}, {"partner-sys-id": "bogus", "active": "true"})
    assert odd == LagMemberState(selected=True)
    backup = member_state({"mode": "active-backup"}, {"active": "false"})
    assert backup == LagMemberState(selected=False)


# --- Omada --------------------------------------------------------------------------------


def test_omada_lag_types() -> None:
    assert _lag_mode(0) is LagMode.STATIC and _lag_mode("lacpPassive") is LagMode.LACP_PASSIVE
    assert _lag_mode(7) is LagMode.OTHER and _lag_mode(None) is None and _lag_mode(True) is None
    assert _lag_type({"lagType": 2}) == 2 and _lag_type({"lagSetting": {"lagType": 1}}) == 1
    assert _lag_type({"lagSetting": "x"}) is None


# --- contract and topology ----------------------------------------------------------------


def test_contract_refuses_lag_fields_out_of_place() -> None:
    state = LagMemberState(selected=True)
    bad = [
        port("sw", "1", lag_mode=LagMode.STATIC, lag_member_state=state),
        port("sw", "lag1", kind=PortKind.LAG, lag_mode=LagMode.STATIC, lacp_rate=LacpRate.FAST),
    ]
    assert structure_problems(bad) == [
        "port sw/port/1: LAG settings on a port that is not a LAG",
        "port sw/port/1: LAG member state on a port that is not a LAG member",
        "port sw/port/lag1: LACP rate on a LAG without LACP",
    ]
    good = [
        port("sw", "1", lag_member_state=state),
        port("sw", "2", lag="ae0", lag_member_state=state),
        port("sw", "ae", kind=PortKind.LAG, role=PortRole.LAG, lower=["sw/port/1"]),
    ]
    assert structure_problems(good) == []


def test_topology_ends_name_their_lag() -> None:
    lag = {"kind": PortKind.LAG, "role": PortRole.LAG}
    net = Network(
        sites=[SITE],
        devices=[device("a", DeviceRole.SWITCH), device("b", DeviceRole.SWITCH)],
        ports=[
            port("a", "1"),
            port("a", "2"),
            port("a", "bond0", lower=["a/port/1", "a/port/2"], lag_mode=LagMode.STATIC, **lag),
            port("b", "1", lag="lag1"),
            port("b", "2", lag="lag1"),
            port("b", "3"),
        ],
        links=[
            Link(id="l1", a="a/port/1", b="b/port/1", origin=LinkOrigin.LLDP),
            Link(id="l2", a="b/port/2", b="a/port/2", origin=LinkOrigin.LLDP),
        ],
    )
    out = view(net)
    ends = {e["id"]: e for e in out["edges"]}
    assert ends["l1"]["a"]["lag"] == {"name": "bond0", "port_id": "a/port/bond0", "mode": "static"}
    assert ends["l1"]["b"]["lag"] == {"name": "lag1", "port_id": None, "mode": None}
    b_ports = {p["id"]: p for n in out["nodes"] if n["id"] == "b" for p in n["ports"]}
    assert b_ports["b/port/1"]["lag"] == "lag1" and b_ports["b/port/3"]["lag"] is None
