"""MikroTik packet filter and NAT (#135, ADR 0013) against the simulator."""

from __future__ import annotations

from collections.abc import Iterator
from ipaddress import ip_network
from typing import Any

import pytest

from signalbox.adapters.mikrotik import MikrotikAdapter
from signalbox.adapters.mikrotik import firewall as fw
from signalbox.model import (
    Firewall,
    FirewallAction,
    FirewallChain,
    FirewallProtocol,
    Flow,
    PortRange,
    Verdict,
)
from signalbox.sim.mikrotik import MikrotikSimulator, firewall_data
from signalbox.sim.server import serve
from signalbox.testing import assert_contract
from test_mikrotik import adapter

SIM = MikrotikSimulator()
FILTER = "/rest/ip/firewall/filter"
NAT = "/rest/ip/firewall/nat"
RAW = "/rest/ip/firewall/raw"
POLICY = "/rest/ip/ipsec/policy"


@pytest.fixture(scope="module")
def url() -> Iterator[str]:
    with serve(SIM.app()) as u:
        yield u


@pytest.fixture(autouse=True)
def sim() -> MikrotikSimulator:
    SIM.__dict__.update(MikrotikSimulator().__dict__)
    return SIM


async def read(url: str) -> Firewall:
    a: MikrotikAdapter = adapter(url)
    try:
        [out] = (await a.read_firewall()).firewalls
        return out
    finally:
        await a.close()


async def test_contract_and_zones(url: str) -> None:
    a = adapter(url)
    try:
        snap = await assert_contract(a)
    finally:
        await a.close()
    [out] = snap.firewalls
    zones = {z.name: z for z in out.zones}
    assert zones["LAN"].segments == ["home/segment/native"]
    assert zones["IOT"].segments == ["home/segment/20"]
    assert zones["WAN"].uplinks == ["rt/uplink/ether1"] and zones["WAN"].complete
    assert zones["iot"].segments == ["home/segment/20"]  # a rule names the interface itself
    assert out.input_policy is out.forward_policy is FirewallAction.ACCEPT
    assert out.rules_complete and out.port_forwards_complete


async def test_default_configuration_rules(url: str) -> None:
    out = await read(url)
    names = [(r.family, r.chain.value if r.chain else None, r.name) for r in out.rules]
    # established/related, invalid, fasttrack and IPsec-only rules are left out
    assert names == [
        (4, "input", "defconf: accept ICMP"),
        (4, "input", "defconf: accept loopback"),
        (4, "input", "IoT: DNS"),
        (4, "input", "defconf: drop all not from LAN"),
        (4, "forward", "IoT: web"),  # the jump to the user chain, flattened
        (4, "forward", "IoT: nothing else to the LAN"),
        (4, "forward", "NAS from trusted hosts"),
        (4, "forward", "block scanners"),
        (4, "forward", "defconf: drop all from WAN not DSTNATed"),
        (6, "input", "defconf: accept ICMPv6"),
        (6, "input", "defconf: drop all not from LAN"),
        (6, "forward", "defconf: drop all from WAN"),
    ]
    by = {r.name: r for r in out.rules}
    drop = by["defconf: drop all not from LAN"]
    assert drop.source.zones == ["LAN"] and drop.source.zones_not and drop.exact
    wan = by["defconf: drop all from WAN not DSTNATed"]
    assert wan.forwarded is False and wan.source.zones == ["WAN"] and wan.exact
    nas = by["NAS from trusted hosts"]
    assert [str(n) for n in nas.source.networks] == [
        "192.0.2.10/32",
        "198.51.100.0/28",
        "198.51.100.64/28",  # a range of the address list, as a prefix
    ]
    assert nas.destination.ports == [PortRange(start=443)] and nas.exact
    assert not by["block scanners"].exact  # a dynamic address list entry
    web = by["IoT: web"]
    assert web.source.zones == ["IOT"] and web.destination.zones == ["WAN"] and web.exact
    # after a conditional ``return`` the rules of the chain are not exact
    assert not by["IoT: nothing else to the LAN"].exact


async def test_evaluation(url: str) -> None:
    out = await read(url)

    def verdict(zone: str, port: int, address: str, chain: FirewallChain, **kw: Any) -> Verdict:
        flow = Flow(
            chain=chain,
            source_zones={zone},
            destination=ip_network(address),
            family=4,
            protocol=FirewallProtocol.TCP,
            port=port,
            **kw,
        )
        return out.evaluate(flow).verdict

    assert verdict("LAN", 8291, "192.0.2.1", FirewallChain.INPUT) is Verdict.ALLOWED
    assert verdict("IOT", 8291, "198.51.100.1", FirewallChain.INPUT) is Verdict.DENIED
    assert verdict("WAN", 22, "203.0.113.2", FirewallChain.INPUT) is Verdict.DENIED
    # from the internet, only through a port forward (the filter sees the translated flow)
    trusted, other = ip_network("198.51.100.5/32"), ip_network("203.0.113.99/32")
    forward = {"destination_zones": {"LAN"}}
    chain = FirewallChain.FORWARD
    assert (
        verdict("WAN", 443, "192.0.2.10", chain, source=trusted, forwarded=True, **forward)
        is Verdict.ALLOWED
    )
    assert verdict("WAN", 22, "192.0.2.10", chain, source=other, **forward) is Verdict.DENIED
    # a host that is on no list: the chain's accept applies
    assert (
        verdict("WAN", 443, "192.0.2.10", chain, source=other, forwarded=True, **forward)
        is Verdict.ALLOWED
    )


async def test_nat_and_port_forwards(url: str) -> None:
    out = await read(url)
    [masq] = out.nat
    assert masq.masquerade and masq.zones == ["WAN"] and masq.exact  # ipsec-policy out,none
    [pf] = out.port_forwards
    assert pf.name == "NAS web interface" and pf.zones == ["WAN"] and pf.exact
    assert pf.external_ports == [PortRange(start=8443)] and pf.external_address is None
    assert str(pf.target_address) == "192.0.2.10" and pf.target_port == 443
    assert pf.passes_filter is False  # the filter decides


async def test_ipsec_policies_make_ipsec_rules_inexact(url: str, sim: MikrotikSimulator) -> None:
    sim.data[POLICY] = [
        {".id": "*1", "disabled": "false", "template": "true", "dynamic": "false"},
        {".id": "*2", "disabled": "false", "template": "false", "dynamic": "false"},
    ]
    out = await read(url)
    ipsec = [r for r in out.rules if r.name and "ipsec" in r.name]
    assert [r.name for r in ipsec] == ["defconf: accept in ipsec", "defconf: accept out ipsec"]
    assert not any(r.exact for r in ipsec)
    [masq] = out.nat
    assert not masq.exact


async def test_raw_drop_and_unreadable_chains(url: str, sim: MikrotikSimulator) -> None:
    sim.data[RAW] = [{".id": "*1", "chain": "prerouting", "action": "drop", "disabled": "false"}]
    assert not (await read(url)).rules_complete


async def test_without_ipv6_and_nat_menus(url: str, sim: MikrotikSimulator) -> None:
    del sim.data["/rest/ipv6/firewall/filter"], sim.data[NAT], sim.data[RAW]
    out = await read(url)
    assert {r.family for r in out.rules} == {4} and out.nat == [] and out.port_forwards == []


# --- the row parsers -------------------------------------------------------------------------


def fixed() -> tuple[fw.Lists, fw._Zones]:
    lists = fw.Lists.build(
        [{"name": "A", "include": "B", "exclude": "C"}, {"name": "B"}, {"name": "C"}],
        [
            {"list": "A", "interface": "a1"},
            {"list": "B", "interface": "b1"},
            {"list": "B", "interface": "x"},
            {"list": "C", "interface": "x"},
            {"list": "B", "interface": "off", "disabled": "true"},
        ],
        [{"list": "h", "address": "host.invalid"}, {"list": "h", "address": "192.0.2.1"}],
    )
    return lists, fw._Zones(lists, lambda _n: None)


def test_lists_and_addresses() -> None:
    lists, _ = fixed()
    assert lists.interfaces["A"] == ["a1", "b1"]  # B included, x excluded
    nets, ok = fw.addresses("192.0.2.0/24,198.51.100.1-198.51.100.3", lists, "h")
    assert not ok  # a host name in the list
    assert [str(n) for n in nets] == [
        "192.0.2.0/24",
        "198.51.100.1/32",
        "198.51.100.2/31",
        "192.0.2.1/32",
    ]
    assert fw.addresses("", lists, "missing") == ([], False)
    assert fw.ports("80,x") == ([], False)


def test_rule_details() -> None:
    lists, zones = fixed()

    def make(**row: str) -> fw.FirewallRule | None:
        return fw._rule({"chain": "forward", "action": "accept", **row}, zones, lists, False, None)

    assert make(**{"connection-state": "established"}) is None
    assert make(**{"connection-state": "!new"}) is None
    assert make(**{"connection-state": "new,established"}) is not None
    assert make(**{"connection-state": "!established"}) is not None
    r = make(protocol="!tcp")
    assert r is not None and not r.exact
    r = make(protocol="tcp", **{"dst-port": "!80"})
    assert r is not None and not r.exact
    r = make(**{"src-address": "!192.0.2.9", "in-interface": "ether2", "in-interface-list": "A"})
    assert r is not None and r.source.networks_not and r.source.zones == ["A", "ether2"]
    assert not r.source.zones_not
    r = make(**{"limit": "10,5:packet", "connection-nat-state": "srcnat"})
    assert r is not None and not r.exact
    r = make(**{"in-interface-list": "all"})
    assert r is not None and r.source.zones == [] and r.exact
    assert make(**{"in-interface-list": "dynamic"}).exact is False  # type: ignore[union-attr]
    assert make(action="").exact is False  # type: ignore[union-attr]
    assert make(protocol="gre").protocols == [FirewallProtocol.GRE]  # type: ignore[union-attr]
    assert make(protocol="ospf").protocols == [FirewallProtocol.OTHER]  # type: ignore[union-attr]
    assert make(protocol="tcp,udp").protocols == [  # type: ignore[union-attr]
        FirewallProtocol.TCP,
        FirewallProtocol.UDP,
    ]
    # an interface that has the name of a list is a zone of its own
    both = fw._Zones(lists, lambda _n: None)
    assert both.of(None, "A")[0] == ["A (interface)"]


def test_chains_loops_and_returns() -> None:
    lists, zones = fixed()
    rows = [
        {"chain": "input", "action": "jump", "jump-target": "loop", "protocol": "tcp"},
        {"chain": "input", "action": "jump", "jump-target": "nowhere"},
        {"chain": "input", "action": "accept", "comment": "after"},
        {"chain": "loop", "action": "jump", "jump-target": "loop"},
        {"chain": "forward", "action": "jump", "jump-target": "empty", "in-interface-list": "A"},
        {"chain": "forward", "action": "jump", "jump-target": "plain"},
        {"chain": "plain", "action": "return"},
        {"chain": "plain", "action": "drop", "comment": "never"},
        {"chain": "forward", "action": "drop", "comment": "end", "disabled": "true"},
        {"chain": "forward", "action": "drop", "invalid": "true"},
        {"chain": "forward", "action": "passthrough"},
    ]
    rules, complete = fw.filter_rules(rows, zones, lists, False)
    assert not complete  # the loop
    assert [r.name for r in rules] == ["after", "end"] and not rules[1].enabled
    assert rules[0].chain is FirewallChain.INPUT


def test_join_of_a_jump_and_its_chain() -> None:
    lists, zones = fixed()
    rows = [
        {
            "chain": "forward",
            "action": "jump",
            "jump-target": "c",
            "protocol": "tcp",
            "in-interface-list": "A",
            "dst-address": "192.0.2.0/24",
            "connection-nat-state": "dstnat",
        },
        {
            "chain": "c",
            "action": "accept",
            "protocol": "udp",
            "in-interface-list": "B",
            "dst-address": "192.0.2.0/24",
            "dst-port": "53",
            "connection-nat-state": "!dstnat",
        },
        {"chain": "c", "action": "accept", "src-address": "198.51.100.0/24", "dst-port": "80"},
    ]
    rules, complete = fw.filter_rules(rows, zones, lists, False)
    assert complete
    first, second = rules
    assert not first.exact  # tcp and udp, A and B, dstnat and not
    assert second.exact and second.protocols == [FirewallProtocol.TCP]
    assert second.source.zones == ["A"] and second.forwarded is True
    assert second.source.networks == [ip_network("198.51.100.0/24")]
    assert second.destination.networks == [ip_network("192.0.2.0/24")]


def test_odd_nat_rows() -> None:
    lists, zones = fixed()
    base = firewall_data()[NAT]
    rows = [
        {
            "chain": "srcnat",
            "action": "src-nat",
            "to-addresses": "203.0.113.9",
            "src-address": "192.0.2.0/24",
        },
        {"chain": "srcnat", "action": "accept", "dst-address": "198.51.100.0/24"},
        {"chain": "srcnat", "action": "netmap", "to-addresses": "198.51.100.0/24"},
        {"chain": "dstnat", "action": "redirect", "to-ports": "3128", "protocol": "tcp"},
        {"chain": "dstnat", "action": "dst-nat", "to-addresses": "198.51.100.5-198.51.100.9"},
        {
            "chain": "dstnat",
            "action": "dst-nat",
            "to-addresses": "192.0.2.5",
            "dst-address": "203.0.113.7",
            "protocol": "1",
            "disabled": "true",
        },
        {"chain": "dstnat", "action": "jump", "jump-target": "x"},
        {"chain": "srcnat", "action": "masquerade", "ipsec-policy": "out,ipsec"},
        base[0],
    ]
    rules, forwards, complete = fw.nat(rows, zones, lists)
    assert not complete
    assert [(str(r.to_address), r.masquerade, r.exact) for r in rules[:1]] == [
        ("203.0.113.9", False, False)  # an accept exception in the same chain
    ]
    [one] = forwards
    assert str(one.external_address) == "203.0.113.7" and not one.enabled
    assert one.protocols == [FirewallProtocol.ICMP] and one.exact
    assert len(rules) == 2  # the IPsec-only masquerade never matches


async def test_menus_the_group_may_not_read(url: str, sim: MikrotikSimulator) -> None:
    sim.fail[RAW] = 500
    sim.fail[POLICY] = 500
    out = await read(url)
    assert not out.rules_complete  # raw rules unknown
    assert not any(r.exact for r in out.rules if r.name and "ipsec" in r.name)
    assert not out.nat[0].exact  # ipsec-policy out,none may depend on IPsec
