"""OPNsense packet filter and NAT (#135, ADR 0013) against the simulator."""

from __future__ import annotations

import copy
from collections.abc import Iterator
from ipaddress import ip_network
from typing import Any

import pytest
from pydantic import SecretStr

from signalbox.adapters import AdapterContext, AuthFailed
from signalbox.adapters.opnsense import OpnsenseAdapter, OpnsenseConfig
from signalbox.adapters.opnsense import firewall as fw
from signalbox.model import (
    DeviceRole,
    Firewall,
    FirewallAction,
    FirewallChain,
    FirewallProtocol,
    Flow,
    PortRange,
    Verdict,
)
from signalbox.sim.opnsense import KEY, SECRET, OpnsenseSimulator, firewall_data
from signalbox.sim.server import serve
from signalbox.testing import assert_contract

SIM = OpnsenseSimulator()
RULES = "/api/firewall/filter/search_rule"
DNAT = "/api/firewall/d_nat/search_rule"
SNAT = "/api/firewall/source_nat/search_rule"
ONE = "/api/firewall/one_to_one/search_rule"


@pytest.fixture(scope="module")
def url() -> Iterator[str]:
    with serve(SIM.app()) as u:
        yield u


@pytest.fixture(autouse=True)
def sim() -> OpnsenseSimulator:
    SIM.__dict__.update(OpnsenseSimulator().__dict__)
    return SIM


def make(url: str) -> OpnsenseAdapter:
    return OpnsenseAdapter(
        AdapterContext(
            site_id="home",
            device_id="fw",
            device_name="Firewall",
            role=DeviceRole.GATEWAY,
            config=OpnsenseConfig(
                url=url,
                api_key=SecretStr(KEY),
                api_secret=SecretStr(SECRET),
                allow_insecure_http=True,
            ),
        )
    )


async def read(url: str) -> Firewall:
    a = make(url)
    try:
        [out] = (await a.read_firewall()).firewalls
        return out
    finally:
        await a.close()


async def test_contract_and_zones(url: str) -> None:
    a = make(url)
    try:
        snap = await assert_contract(a)
    finally:
        await a.close()
    [out] = snap.firewalls
    zones = {z.name: z for z in out.zones}
    assert zones["lan"].segments == ["home/segment/native"] and zones["lan"].complete
    assert zones["opt1"].segments == ["home/segment/20"] and zones["opt1"].description == "IoT"
    assert zones["wan"].uplinks == ["fw/uplink/wan"] and zones["wan"].segments == []
    assert zones["internal"].segments == ["home/segment/native", "home/segment/20"]
    assert zones["wireguard"].tunnels == ["fw/tunnel/wg0"] and zones["wireguard"].complete
    assert out.rules_complete and out.port_forwards_complete
    assert out.input_policy is out.forward_policy is FirewallAction.DROP


async def test_rules_in_pf_order(url: str) -> None:
    out = await read(url)
    names = [r.name for r in out.rules]
    # quick rules in order, then the others reversed (pf: the last matching rule wins)
    assert names == [
        "Anti-Lockout Rule",
        "IoT: DNS to the firewall",
        "IoT: nothing to the LAN",
        "IoT: the internet",
        "Guest: block list",
        "Default allow LAN to any rule",
        "Default allow LAN IPv6 to any rule",
        "Floating: SSH from the NAS",
        "Default deny / state violation rule",
    ]
    by = {r.name: r for r in out.rules}
    lockout = by["Anti-Lockout Rule"]
    assert lockout.source.zones == ["lan"] and lockout.exact
    assert lockout.destination.ports == [
        PortRange(start=22),
        PortRange(start=80),
        PortRange(start=443),
    ]
    assert len(lockout.destination.networks) == 6  # every address of the firewall itself
    assert by["Default allow LAN IPv6 to any rule"].family == 6
    block = by["IoT: nothing to the LAN"]
    assert block.action is FirewallAction.DROP
    assert [str(n) for n in block.destination.networks] == ["192.0.2.0/24", "2001:db8:1::/64"]
    # an alias of a URL table cannot be resolved
    assert not by["Guest: block list"].exact
    assert by["Guest: block list"].action is FirewallAction.REJECT
    float_ssh = by["Floating: SSH from the NAS"]
    assert float_ssh.source.zones == [] and [str(n) for n in float_ssh.source.networks] == [
        "192.0.2.10/32"
    ]


async def test_the_firewalls_own_abuse_rules_are_left_out(url: str) -> None:
    names = {r.name for r in (await read(url)).rules}
    assert not names & {"sshlockout", "virusprot overload table", "block all targeting port 0"}


def test_a_group_named_like_an_interface_is_one_zone() -> None:
    c = fw.Context(
        [fw.Iface("lan", "LAN", segments=["s/native"])],
        [{"ifname": "lan", "members": "lan"}, {"ifname": "g", "members": "lan"}],
        [],
    )
    assert [z.name for z in fw.zones(c)] == ["lan", "g"]


async def test_evaluation_matches_the_firewall(url: str) -> None:
    out = await read(url)

    def verdict(zone: str, port: int, address: str = "192.0.2.1", **kw: Any) -> Verdict:
        flow = Flow(
            chain=kw.pop("chain", FirewallChain.INPUT),
            source_zones={zone},
            destination=ip_network(address),
            protocol=FirewallProtocol.TCP,
            port=port,
            **kw,
        )
        return out.evaluate(flow).verdict

    assert verdict("lan", 443) is Verdict.ALLOWED  # anti-lockout
    assert verdict("wan", 443) is Verdict.DENIED  # default deny
    assert verdict("opt1", 443) is Verdict.DENIED
    assert verdict("opt1", 53) is Verdict.ALLOWED
    forward = {"chain": FirewallChain.FORWARD, "destination_zones": {"lan"}}
    assert verdict("opt1", 443, "192.0.2.20", **forward) is Verdict.DENIED


async def test_nat_and_port_forwards(url: str) -> None:
    out = await read(url)
    forwards = {f.name: f for f in out.port_forwards}
    nas = forwards["NAS web interface"]
    assert nas.zones == ["wan"] and nas.protocols == [FirewallProtocol.TCP]
    assert nas.external_ports == [PortRange(start=8443)] and nas.external_address is None
    assert str(nas.target_address) == "192.0.2.10" and nas.target_port == 443
    assert nas.passes_filter is True and nas.exact
    lab = forwards["Lab host"]  # one-to-one: a forward without ports
    assert (
        str(lab.external_address) == "100.64.23.46" and str(lab.target_address) == "198.51.100.50"
    )
    assert lab.external_ports == [] and lab.passes_filter is False and lab.exact
    assert len(out.port_forwards) == 2  # the automatic FTP helper is not a forward
    masq = next(n for n in out.nat if n.masquerade)
    assert masq.zones == ["wan"] and [str(n) for n in masq.sources] == [
        "192.0.2.0/24",
        "198.51.100.0/24",
    ]
    one = next(n for n in out.nat if n.to_address is not None)
    assert str(one.to_address) == "100.64.23.46" and not one.masquerade


async def test_release_without_legacy_listing_is_incomplete(
    url: str, sim: OpnsenseSimulator
) -> None:
    for row in sim.data[RULES]["rows"]:
        row.pop("sort_order", None)
    for path in (DNAT, SNAT, ONE):
        del sim.data[path]  # no MVC NAT pages
    out = await read(url)
    assert not out.rules_complete and not out.port_forwards_complete and out.port_forwards == []


async def test_missing_privilege_is_reported(url: str, sim: OpnsenseSimulator) -> None:
    sim.fail[RULES] = 403
    a = make(url)
    try:
        snap = await a.observe()
    finally:
        await a.close()
    assert snap.firewalls == []
    [err] = [e for e in snap.errors if e.capability == "firewall"]
    assert "403" in err.message and err.remedy == "privileges"
    with pytest.raises(AuthFailed):
        await make(url).read_firewall()


# --- the row parsers -------------------------------------------------------------------------


def ctx(**kw: Any) -> fw.Context:
    eth = fw.Iface("lan", "LAN", segments=["s/native"])
    return fw.Context([eth], kw.get("groups", []), kw.get("aliases", []))


def row(**kw: Any) -> dict[str, Any]:
    base = next(r for r in firewall_data()[RULES]["rows"] if r["uuid"] == "iot-block")
    return {**base, "interface": "lan", **kw}


def test_row_details() -> None:
    c = ctx(
        aliases=[
            {"name": "web", "type": "port", "content": "80,443", "enabled": "1"},
            {"name": "both", "type": "networkgroup", "content": "one,192.0.2.0/24", "enabled": "1"},
            {"name": "one", "type": "host", "content": "203.0.113.5", "enabled": "1"},
            {"name": "named", "type": "host", "content": "example.invalid", "enabled": "1"},
            {"name": "off", "type": "host", "content": "203.0.113.6", "enabled": "0"},
        ]
    )
    # unknown action, unknown interface, a schedule, an alias with a host name, inverted
    assert fw.rule(c, row(action="match")) is None
    r, quick = fw.rule(c, row(interface="nowhere", quick="0", direction="out")) or (None, None)
    assert r is not None and not r.exact and not quick and r.chain is FirewallChain.OUTPUT
    assert not fw.rule(c, row(sched="office"))[0].exact  # type: ignore[index]
    assert not fw.rule(c, row(destination_net="named"))[0].exact  # type: ignore[index]
    assert not fw.rule(c, row(destination_net="off"))[0].exact  # type: ignore[index]
    both = fw.rule(c, row(destination_net="both", destination_port="web", destination_not="1"))
    assert both is not None and both[0].destination.networks_not and both[0].exact
    assert [str(n) for n in both[0].destination.networks] == ["203.0.113.5/32", "192.0.2.0/24"]
    assert both[0].destination.ports == [PortRange(start=80), PortRange(start=443)]
    http = fw.rule(c, row(destination_port="https", protocol="TCP", source_port="1024-2000"))
    assert http is not None and http[0].destination.ports == [PortRange(start=443)]
    assert http[0].source.ports == [PortRange(start=1024, end=2000)]
    # a legacy floating rule is not quick unless it says so; a legacy interface rule is
    legacy = row(legacy=True, quick="", interface="LAN")
    assert fw.rule(c, legacy)[1] is True  # type: ignore[index]
    assert fw.rule(c, {**legacy, "interface": ""})[1] is False  # type: ignore[index]
    assert fw.rule(c, row(protocol="OSPF"))[0].protocols == [FirewallProtocol.OTHER]  # type: ignore[index]


def test_odd_forwards_and_nat() -> None:
    c = ctx(aliases=[{"name": "net", "type": "network", "content": "192.0.2.0/24", "enabled": "1"}])
    base = {
        **copy.deepcopy(firewall_data()[DNAT]["rows"][0]),
        "target": "192.0.2.10",
        "interface": "lan",
    }
    assert fw.port_forward(c, {**base, "nordr": "1"}) == (None, False)  # an exception row
    assert fw.port_forward(c, {**base, "target": "net"}) == (None, False)  # not one address
    fwd, ok = fw.port_forward(
        c, {**base, "destination.network": "203.0.113.9", "source.network": "net", "pass": ""}
    )
    assert ok and fwd is not None and str(fwd.external_address) == "203.0.113.9"
    assert fwd.passes_filter is False and [str(s) for s in fwd.sources] == ["192.0.2.0/24"]
    fwd, _ = fw.port_forward(c, {**base, "destination.network": "net", "natreflection": "purenat"})
    assert fwd is not None and not fwd.exact and fwd.reflection is True
    # one-to-one of a whole network: not expressed
    assert fw.one_to_one(c, {"source_net": "192.0.2.0/24", "external": "203.0.113.0/24"}) == (
        None,
        None,
        False,
    )
    forward, nat, _ = fw.one_to_one(
        c, {"type": "nat", "source_net": "192.0.2.5", "external": "203.0.113.5", "interface": "lan"}
    )
    assert forward is None and nat is not None and str(nat.to_address) == "203.0.113.5"
    # outbound: no-NAT exceptions make the others inexact, a fixed address is SNAT
    rows = [
        {"interface": "lan", "source_net": "192.0.2.0/24", "target": "203.0.113.7", "enabled": "1"},
        {"interface": "lan", "nonat": "1"},
    ]
    built = fw.build("fw", c, [], None, rows, None)
    [n] = built.nat
    assert not n.exact and str(n.to_address) == "203.0.113.7" and not n.masquerade
    assert not built.rules_complete and not built.port_forwards_complete
