"""Omada gateway ACLs and port forwarding as a firewall (#135); mapped from the Open API
description, so the values come from the simulator (*guess* until a real gateway is read)."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest
from pydantic import SecretStr

from signalbox.adapters import AdapterContext
from signalbox.adapters.omada import OmadaAdapter, OmadaConfig, firewall
from signalbox.model import (
    DeviceRole,
    DeviceStatus,
    FirewallAction,
    FirewallChain,
    FirewallProtocol,
    Flow,
    Verdict,
)
from signalbox.sim.omada import CLIENT_ID, CLIENT_SECRET, SITE, OmadaSimulator
from signalbox.sim.server import serve
from signalbox.testing import assert_contract

SIM = OmadaSimulator()
GW = "omada1/gateway-020000000a01"


@pytest.fixture(scope="module")
def url() -> Iterator[str]:
    with serve(SIM.app()) as address:
        yield address


@pytest.fixture(autouse=True)
def sim() -> OmadaSimulator:
    SIM.__dict__.update(OmadaSimulator().__dict__)
    return SIM


def adapter(url: str) -> OmadaAdapter:
    return OmadaAdapter(
        AdapterContext(
            site_id="home",
            device_id="omada1",
            device_name="Omada",
            role=DeviceRole.OTHER,
            config=OmadaConfig(
                url=url,
                client_id=CLIENT_ID,
                client_secret=SecretStr(CLIENT_SECRET),
                allow_insecure_http=True,
            ),
        )
    )


async def test_contract_and_mapping(url: str) -> None:
    a = adapter(url)
    try:
        snap = await assert_contract(a)
    finally:
        await a.close()
    assert snap.status is DeviceStatus.OK
    (fw,) = snap.firewalls
    assert fw.id == f"{GW}/firewall" and fw.enabled and fw.rules_complete
    zones = {z.name: z for z in fw.zones}
    assert set(zones) == {"LAN", "IoT", "Guest", "wan"}
    assert zones["LAN"].segments == ["home/segment/native"]
    assert zones["IoT"].segments == ["home/segment/20"]
    assert zones["wan"].uplinks and zones["wan"].masquerade
    assert fw.policy("IoT", "wan") is FirewallAction.ACCEPT
    assert fw.policy("wan", "LAN") is FirewallAction.DROP
    assert fw.policy("wan", None) is FirewallAction.DROP
    assert fw.forward_policy is FirewallAction.ACCEPT
    # ordered by index: the WAN-in ACL (0) comes first, the switch ACL is not the gateway's
    assert [r.name for r in fw.rules] == [
        "Allow web to the NAS",
        "IoT must not reach the LAN",
        "Guests out: no UDP",
    ]
    wan_in, iot, guests = fw.rules
    assert wan_in.source.zones == ["wan"] and wan_in.protocols == [FirewallProtocol.TCP]
    assert wan_in.exact is False  # an IP group is not resolved
    assert iot.source.zones == ["IoT"] and iot.destination.zones == ["LAN"] and iot.exact
    assert iot.action is FirewallAction.DROP and iot.protocols == []
    assert guests.enabled is False and guests.destination.zones == ["wan"]
    assert guests.protocols == [FirewallProtocol.UDP]
    nas, game, off, dmz = fw.port_forwards
    assert nas.zones == ["wan"] and nas.passes_filter and str(nas.target_address) == "192.0.2.20"
    assert [str(p) for p in nas.external_ports] == ["8443"] and nas.target_port == 443
    assert nas.protocols == [FirewallProtocol.TCP] and nas.exact
    assert [str(p) for p in game.external_ports] == ["27015-27020"]
    assert game.protocols == [FirewallProtocol.TCP, FirewallProtocol.UDP]
    assert off.enabled is False
    assert dmz.external_ports == [] and dmz.protocols == [] and dmz.target_port is None
    assert [str(n) for n in dmz.sources] == ["203.0.113.0/24"] and dmz.exact

    def lan_to_lan(source: str) -> Flow:
        return Flow(
            chain=FirewallChain.FORWARD,
            source_zones={source},
            destination_zones={"LAN"},
            protocol=FirewallProtocol.TCP,
            port=80,
        )

    assert fw.evaluate(lan_to_lan("IoT")).verdict is Verdict.DENIED
    assert fw.evaluate(lan_to_lan("Guest")).verdict is Verdict.ALLOWED


async def test_no_gateway_no_firewall(url: str, sim: OmadaSimulator) -> None:
    sim.data[f"{SITE}/devices"] = [
        d for d in sim.data[f"{SITE}/devices"] if d.get("type") != "gateway"
    ]
    a = adapter(url)
    try:
        snap = await assert_contract(a)
    finally:
        await a.close()
    assert snap.firewalls == []


async def test_unreadable_lists_are_gaps(url: str, sim: OmadaSimulator) -> None:
    del sim.data[f"{SITE}/acls/osg-acls"]
    del sim.data[f"{SITE}/nat/port-forwardings"]
    a = adapter(url)
    try:
        obs = await a.read_system() and await a.read_firewall()
    finally:
        await a.close()
    (fw,) = obs.firewalls
    assert fw.rules == [] and fw.port_forwards == []
    assert fw.rules_complete is False and fw.port_forwards_complete is False
    assert [g.message.split(" (")[0] for g in obs.incomplete] == [
        "firewall: the gateway ACLs are not read",
        "firewall: the port forwarding is not read",
    ]


def test_acl_shapes() -> None:
    names = {"a": "A", "b": "B"}
    rows: list[dict[str, Any]] = [
        {"policy": 7},  # not permit or deny
        {"policy": 1, "direction": {"vpnIn": True}},  # no modelled direction
        {  # an unknown network and protocols of a strange shape
            "policy": 0,
            "name": 5,
            "protocols": "tcp",
            "sourceType": 0,
            "sourceIds": ["zzz"],
            "direction": {"lanToLan": True},
        },
        {
            "policy": 0,
            "protocols": [1, 6, 99],
            "sourceIds": ["a"],
            "destinationIds": ["b"],
            "direction": {"lanToLan": True, "lanToWan": True},
            "index": "3",
        },
    ]
    to_wan, normal, odd = firewall.acl_rules(rows, names)
    assert odd.exact is False and odd.name is None and odd.order is None
    assert odd.source.zones == ["A", "B"]  # not resolved: any LAN network
    assert normal.protocols == [
        FirewallProtocol.ICMP,
        FirewallProtocol.TCP,
        FirewallProtocol.OTHER,
    ]
    assert normal.order == 3 and normal.source.zones == ["A"] and normal.destination.zones == ["B"]
    assert to_wan.destination.zones == ["wan"]


def test_port_forward_shapes() -> None:
    rows: list[dict[str, Any]] = [
        {"forwardIp": "not an address"},
        {"forwardIp": "192.0.2.5", "externalPort": "1-2,70000"},
        {"forwardIp": "192.0.2.6", "protocol": 9, "externalPort": 80, "forwardPort": "81"},
        {"forwardIp": "192.0.2.7", "from": 1, "limitedAddresses": ["x"], "externalPort": "1"},
    ]
    first, second, third = firewall.port_forwards(rows)
    assert third.exact is False and third.sources == []
    assert first.exact is False and first.external_ports == []
    assert first.protocols == [FirewallProtocol.TCP, FirewallProtocol.UDP]
    assert second.exact is False and second.protocols == [] and second.target_port == 81
    assert firewall.zone_names({"1": "LAN", "2": "LAN", "3": "IoT"}) == {
        "1": "LAN (1)",
        "2": "LAN (2)",
        "3": "IoT",
    }


async def test_custom_mode(url: str, sim: OmadaSimulator) -> None:
    sim.data[f"{SITE}/acls/osg-config-mode"] = {"mode": 1}
    a = adapter(url)
    try:
        snap = await assert_contract(a)
    finally:
        await a.close()
    (fw,) = snap.firewalls
    (rule,) = fw.rules
    assert rule.name == "Block the printer from the internet"
    assert rule.source.zones == ["LAN", "IoT", "Guest"] and rule.destination.zones == ["wan"]
    assert [str(n) for n in rule.source.networks] == ["192.0.2.10/32"]
    assert rule.protocols == [FirewallProtocol.TCP] and rule.exact is False  # a group id
    assert [str(p) for p in rule.destination.ports] == ["443"]


def test_custom_acl_shapes() -> None:
    names = {"a": "A"}
    rows: list[dict[str, Any]] = [
        {"policy": 1, "direction": 9},
        {"policy": 1, "direction": 3, "protocol": 17, "destinationPort": "53"},
        {"policy": 0, "direction": 2, "destinationPort": "80-81", "index": 1},
        {"policy": 0, "direction": 0, "protocol": 256, "index": 0},
    ]
    lan, wan_in, local, *_ = firewall.custom_acl_rules(rows, names)[0:3]
    assert lan.source.zones == ["A"] and lan.protocols == [] and lan.chain is FirewallChain.FORWARD
    assert wan_in.source.zones == ["wan"] and wan_in.protocols == [
        FirewallProtocol.TCP,
        FirewallProtocol.UDP,
    ]
    assert local.chain is FirewallChain.INPUT and local.destination.zones == []
