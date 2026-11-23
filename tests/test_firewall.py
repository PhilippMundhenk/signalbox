"""Firewall model and the reachability helper (#135, ADR 0013)."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest
from pydantic import ValidationError

from factories import (
    SITE,
    device,
    firewall,
    fw_rule,
    home_firewall,
    iface,
    ip,
    policy,
    port_forward,
    ports,
    service,
    snapshot,
    uplink,
    zone,
)
from factories import net as cidr
from signalbox.adapters import API_VERSION, Capability, Observation
from signalbox.firewall import (
    address_owner,
    address_segment,
    any_of,
    in_series,
    reach,
    service_from_internet,
    service_reach,
)
from signalbox.merge import merge
from signalbox.model import (
    DeviceRole,
    FirewallAction,
    FirewallChain,
    FirewallMatch,
    FirewallProtocol,
    FirewallRule,
    FirewallVerdict,
    Flow,
    Match,
    Network,
    PortForward,
    PortRange,
    Segment,
    Subnet,
    Verdict,
    json_schema,
    object_id,
    segment_id,
)
from signalbox.testing import firewall_problems, problems
from test_adapters import Fake, ctx

LAN = segment_id(SITE.id, None)
GUEST = segment_id(SITE.id, 30)
WAN = object_id("gw", "uplink", "wan")
TCP, UDP = FirewallProtocol.TCP, FirewallProtocol.UDP
A, D, U = Verdict.ALLOWED, Verdict.DENIED, Verdict.UNKNOWN


def sub(dev: str, sid: str, text: str, gateway: bool = True) -> Subnet:
    return Subnet(
        id=f"{dev}/subnet/{text}",
        segment_id=sid,
        interface=iface(text),
        device_id=dev,
        gateway=gateway,
    )


def home(**kw: Any) -> Network:
    """A router ``gw`` (LAN 192.168.1.0/24 and 2001:db8:1::/64, guest VLAN 30
    192.168.30.0/24, public uplink) and a switch ``sw`` at 192.168.1.2 in the LAN."""
    kw.setdefault("firewalls", [home_firewall("gw", guest=GUEST)])
    return Network(
        sites=[SITE],
        devices=[
            device("gw"),
            device("sw", DeviceRole.SWITCH, management_address="192.168.1.2"),
            *kw.pop("devices", []),
        ],
        segments=[
            Segment(id=LAN, site_id=SITE.id),
            Segment(id=GUEST, site_id=SITE.id, vlan=30),
            *kw.pop("segments", []),
        ],
        subnets=[
            sub("gw", LAN, "192.168.1.1/24"),
            sub("gw", LAN, "2001:db8:1::1/64"),
            sub("gw", GUEST, "192.168.30.1/24"),
            sub("sw", LAN, "192.168.1.2/24", gateway=False),
            *kw.pop("subnets", []),
        ],
        uplinks=[uplink("gw"), *kw.pop("uplinks", [])],
        **kw,
    )


def with_fw(n: Network, **update: Any) -> Network:
    fw, *rest = n.firewalls
    return n.model_copy(update={"firewalls": [fw.model_copy(update=update), *rest]})


def v(n: Network, source: str, address: str, port: int | None = None, proto: Any = TCP) -> Verdict:
    return reach(n, source, address, port, proto).verdict


# --- model --------------------------------------------------------------------------------


def test_port_range() -> None:
    r = PortRange(start=8000, end=8010)
    assert 8005 in r and 8011 not in r and "8005" not in r
    assert (str(r), str(PortRange(start=22)), PortRange(start=22).last) == ("8000-8010", "22", 22)
    with pytest.raises(ValidationError, match="ends before it starts"):
        PortRange(start=10, end=9)


def test_match_parts() -> None:
    m = FirewallMatch(zones=["lan"], networks=[cidr("192.168.1.0/24")], ports=ports(22, (80, 90)))
    assert m.match_zones({"lan", "x"}) is Match.YES
    assert m.match_zones({"wan"}) is Match.NO
    assert m.match_zones(None) is Match.MAYBE
    assert FirewallMatch(zones=["lan"], zones_not=True).match_zones({"wan"}) is Match.YES
    assert m.match_network(cidr("192.168.1.5/32")) is Match.YES
    assert m.match_network(cidr("192.168.0.0/16")) is Match.MAYBE
    assert m.match_network(cidr("10.0.0.0/8")) is Match.NO
    assert m.match_network(cidr("2001:db8::/64")) is Match.NO
    assert m.match_network(None) is Match.MAYBE
    inv = FirewallMatch(networks=[cidr("192.168.1.0/24")], networks_not=True)
    assert inv.match_network(cidr("10.0.0.1/32")) is Match.YES
    assert inv.match_network(cidr("192.168.0.0/16")) is Match.MAYBE
    assert (m.match_port(85), m.match_port(23), m.match_port(None)) == (
        Match.YES,
        Match.NO,
        Match.MAYBE,
    )
    assert FirewallMatch().match_port(None) is Match.YES


def flow(**kw: Any) -> Flow:
    kw.setdefault("chain", FirewallChain.FORWARD)
    kw.setdefault("source_zones", {"lan"})
    kw.setdefault("destination_zones", {"wan"})
    kw.setdefault("protocol", TCP)
    kw.setdefault("port", 443)
    return Flow(**kw)


def test_rule_matches() -> None:
    r = fw_rule("accept", "lan", "wan", port=443, proto="tcp")
    assert r.matches(flow()) is Match.YES
    assert r.matches(flow(chain=FirewallChain.INPUT)) is Match.NO
    assert r.matches(flow(port=80)) is Match.NO
    assert r.matches(flow(port=None)) is Match.MAYBE
    assert r.matches(flow(protocol=UDP)) is Match.NO
    assert r.matches(flow(protocol=None)) is Match.MAYBE
    assert r.matches(flow(protocol=FirewallProtocol.ICMP)) is Match.NO
    assert r.model_copy(update={"enabled": False}).matches(flow()) is Match.NO
    assert r.model_copy(update={"exact": False}).matches(flow()) is Match.MAYBE
    assert r.model_copy(update={"family": 6}).matches(flow(family=4)) is Match.NO
    assert r.model_copy(update={"forwarded": True}).matches(flow()) is Match.NO
    assert r.model_copy(update={"forwarded": True}).matches(flow(forwarded=True)) is Match.YES
    other = FirewallRule(action=FirewallAction.DROP, protocols=[FirewallProtocol.OTHER])
    assert other.matches(flow()) is Match.MAYBE
    sport = FirewallRule(action=FirewallAction.DROP, source=FirewallMatch(ports=ports(1234)))
    assert sport.matches(flow()) is Match.MAYBE
    # a destination zone never matches traffic to the device itself
    assert fw_rule("drop", dest="lan", chain=None).matches(flow(chain=FirewallChain.INPUT)) is (
        Match.NO
    )
    assert r.label() == "rule None" or r.label().startswith("rule")
    assert fw_rule(name="x").label() == "rule 'x'"


def test_evaluate_first_match_policies_and_defaults() -> None:
    fw = home_firewall("gw", guest=GUEST)
    out = fw.evaluate(flow())
    assert (out.verdict, out.reason) == (A, "policy lan → wan (accept)")
    assert fw.evaluate(flow(source_zones={"guest"}, destination_zones={"lan"})).verdict is D
    dns = flow(chain=FirewallChain.INPUT, source_zones={"guest"}, protocol=UDP, port=53)
    assert fw.evaluate(dns).reason == "rule 'DNS' (accept)"
    # any port: DNS and DHCP may match (accept), the guest policy rejects
    anyport = fw.evaluate(dns.model_copy(update={"port": None}))
    assert anyport.verdict is U and "depends on rule 'DNS'" in anyport.reason
    # a may-match with the same outcome as what follows still decides
    same = fw.model_copy(update={"rules": [fw_rule("accept", "lan", exact=False)]})
    assert same.evaluate(flow()).verdict is A
    # no zone at all: the chain default
    assert fw.evaluate(flow(source_zones=set())).reason == "default forward policy (reject)"
    assert fw.evaluate(flow(source_zones=None)).verdict is U
    blind = fw.model_copy(update={"forward_policy": None})
    assert "no default forward policy" in blind.evaluate(flow(source_zones={"x"})).reason
    assert fw.model_copy(update={"enabled": False}).evaluate(flow()).verdict is A
    partial = fw.model_copy(update={"rules_complete": False})
    assert partial.evaluate(flow()).verdict is U
    assert fw.zone("lan") is not None and fw.zone("dmz") is None
    assert fw.zones_of(WAN) == {"wan"} and fw.uplink_zones() == {"wan"}


def test_port_forward_matching_and_target() -> None:
    pf = port_forward("192.168.1.10", 8443, target_port=443)
    assert pf.matches({"wan"}, TCP, 8443) is Match.YES
    assert pf.matches({"wan"}, UDP, 8443) is Match.NO
    assert pf.matches({"wan"}, None, 8443) is Match.MAYBE
    assert pf.matches({"wan"}, FirewallProtocol.ICMP, None) is Match.NO
    assert pf.target(8443) == 443 and pf.target(None) is None
    ranged = port_forward(
        "192.168.1.10", 5000, external_ports=ports((5000, 5010)), target_port=6000
    )
    assert ranged.target(5003) == 6003 and ranged.target(4000) == 6000
    dmz = PortForward(target_address=ip("192.168.1.10"))
    assert dmz.matches(None, None, None) is Match.YES and dmz.target(80) == 80
    assert pf.model_copy(update={"enabled": False}).matches({"wan"}, TCP, 8443) is Match.NO
    assert pf.model_copy(update={"exact": False}).matches({"wan"}, TCP, 8443) is Match.MAYBE
    limited = pf.model_copy(update={"sources": [cidr("203.0.113.0/24")]})
    assert limited.matches({"wan"}, TCP, 8443) is Match.MAYBE


def test_combinators() -> None:
    ok, no, eh = (FirewallVerdict(verdict=x, reason=x.value) for x in (A, D, U))
    assert any_of([no, eh, ok]) is ok and any_of([no, eh]) is eh and any_of([no]) is no
    assert in_series([ok, eh, no]) is no and in_series([ok, eh]) is eh and in_series([ok]) is ok
    assert any_of([]).verdict is U and in_series([]).verdict is U


# --- reachability -------------------------------------------------------------------------


def test_reach_between_networks() -> None:
    n = home()
    assert v(n, GUEST, "192.168.1.2", 443) is D  # guest → lan: forward default reject
    assert v(n, LAN, "192.168.30.50", 80) is D
    opened = with_fw(n, policies=[*n.firewalls[0].policies, policy("lan", "guest", "accept")])
    assert v(opened, LAN, "192.168.30.50", 80) is A
    assert v(n, LAN, "192.168.1.2", 22) is A  # same network, the switch filters nothing known
    assert reach(n, LAN, "192.168.1.2").reason == "same network, no router in between"


def test_reach_the_router_itself() -> None:
    n = home()
    assert v(n, GUEST, "192.168.30.1", 53, UDP) is A
    assert v(n, GUEST, "192.168.30.1", 443) is D
    assert v(n, GUEST, "192.168.30.1", None, None) is U
    # its LAN address from the guest network: still the input chain, from the guest zone
    out = reach(n, GUEST, "192.168.1.1", 443, TCP)
    assert (out.verdict, out.device_id) == (D, "gw")
    assert v(n, LAN, "192.168.1.1", 443) is A
    assert v(n, LAN, "2001:db8:1::1", 22) is A


def test_reach_from_the_internet() -> None:
    n = home()
    assert v(n, WAN, "198.51.100.23", 22) is D  # wan input reject
    assert v(n, WAN, "198.51.100.23", None, FirewallProtocol.ICMP) is A  # Allow-Ping
    out = reach(n, WAN, "192.168.1.2", 443, TCP)
    assert out.verdict is D and "forwards no port to it" in out.reason
    fwd = with_fw(n, port_forwards=[port_forward("192.168.1.2", 8443, target_port=443)])
    assert v(fwd, WAN, "192.168.1.2", 443) is A
    assert v(fwd, WAN, "192.168.1.2", 80) is D
    # a forward the filter must let through: the wan → lan policy rejects it ...
    strict = with_fw(n, port_forwards=[port_forward("192.168.1.2", 443, passes_filter=False)])
    assert v(strict, WAN, "192.168.1.2", 443) is D
    # ... unless a rule for forwarded connections accepts (MikroTik connection-nat-state)
    rule = fw_rule("accept", "wan", "lan", forwarded=True)
    opened = with_fw(strict, rules=[rule])
    assert v(opened, WAN, "192.168.1.2", 443) is A
    maybe = with_fw(n, port_forwards=[port_forward("192.168.1.2", 443, exact=False)])
    assert v(maybe, WAN, "192.168.1.2", 443) is U
    unread = with_fw(n, port_forwards_complete=False)
    assert v(unread, WAN, "192.168.1.2", 443) is U
    # a global IPv6 address is routed: the forward chain decides
    assert v(n, WAN, "2001:db8:1::5", 22) is D
    ssh = fw_rule("accept", "wan", "lan", port=22, proto="tcp")
    assert v(with_fw(n, rules=[ssh]), WAN, "2001:db8:1::5", 22) is A


def test_reach_unknown_cases() -> None:
    n = home()
    out = reach(n, GUEST, "203.0.113.9", 80, TCP)
    assert out.verdict is U and "no known network" in out.reason
    assert "not read" in reach(home(firewalls=[]), GUEST, "192.168.1.2", 443, TCP).reason
    other = Segment(id=segment_id(SITE.id, 40), site_id=SITE.id, vlan=40)
    lone = home(segments=[other], subnets=[sub("x", other.id, "192.168.40.1/24")])
    out = reach(lone, GUEST, "192.168.40.5", 80, TCP)
    assert out.verdict is U and "no single known router" in out.reason
    incomplete = with_fw(n, zones=[*n.firewalls[0].zones, zone("dmz", complete=False)])
    assert v(incomplete, segment_id(SITE.id, 99), "192.168.30.1", 443) is U


def test_target_device_with_its_own_firewall() -> None:
    sw_fw = firewall(
        "sw",
        zone("mgmt", LAN),
        policies=[policy("mgmt", None, "accept")],
        rules=[
            fw_rule(
                "drop",
                chain=FirewallChain.INPUT,
                source=FirewallMatch(networks=[cidr("192.168.30.0/24")]),
            )
        ],
    )
    n = home(firewalls=[home_firewall("gw", guest=GUEST), sw_fw])
    opened = with_fw(n, policies=[*n.firewalls[0].policies, policy("guest", "lan", "accept")])
    out = reach(opened, GUEST, "192.168.1.2", 443, TCP)
    assert (out.verdict, out.device_id) == (D, "sw")
    assert v(opened, LAN, "192.168.1.2", 443) is A


def test_address_helpers() -> None:
    n = home()
    assert address_owner(n, ip("192.168.30.1")) == "gw"
    assert address_owner(n, ip("198.51.100.23")) == "gw"
    assert address_owner(n, ip("192.168.1.99")) is None
    assert address_segment(n, ip("192.168.30.7")) == GUEST
    bad = n.model_copy(update={"devices": [*n.devices, device("ap", management_address="x")]})
    assert address_owner(bad, ip("192.168.1.99")) is None
    mgmt = home(devices=[device("ap", DeviceRole.AP, management_address="192.168.1.3")])
    assert address_owner(mgmt, ip("192.168.1.3")) == "ap"


# --- services -----------------------------------------------------------------------------


def test_service_reach_and_internet() -> None:
    n = home(services=[service("gw", "ssh")])
    ssh = service("gw", "ssh")
    assert service_reach(n, ssh, GUEST).verdict is D
    assert service_reach(n, ssh, LAN).verdict is A
    assert service_reach(n, service("gw", "ssh", enabled=False), LAN).verdict is D
    assert service_reach(n, service("gw", "mac-telnet"), GUEST).verdict is A
    assert service_from_internet(n, ssh).verdict is D
    rule = fw_rule("accept", "wan", port=22, proto="tcp", chain=FirewallChain.INPUT)
    opened = with_fw(n, rules=[rule])
    assert service_from_internet(opened, ssh).verdict is A
    # a port forward of 22 to another host takes the connection away
    away = with_fw(opened, port_forwards=[port_forward("192.168.1.10", 22)])
    out = service_from_internet(away, ssh)
    assert out.verdict is D and "sends it to 192.168.1.10" in out.reason
    maybe = with_fw(opened, port_forwards=[port_forward("192.168.1.10", 22, exact=False)])
    assert service_from_internet(maybe, ssh).verdict is U
    unread = with_fw(opened, port_forwards_complete=False)
    assert service_from_internet(unread, ssh).verdict is U
    assert service_from_internet(n, service("gw", "https", from_wan=True)).verdict is A
    assert service_from_internet(n, service("gw", "https", segments=[LAN])).verdict is D
    assert service_from_internet(n, service("gw", "mac-telnet")).verdict is U
    # a device without a known address towards the source: any of its addresses
    assert service_reach(n, ssh, segment_id(SITE.id, 99)).verdict is A  # default input accept


def double_nat(front_forwards: list[PortForward] | None, front_read: bool = True) -> Network:
    """``gw`` (uplink 192.168.178.2) behind ``fritz`` (LAN 192.168.178.0/24 in VLAN 5, public
    uplink 203.0.113.7); gw's firewall accepts SSH from its WAN."""
    outer = segment_id(SITE.id, 5)
    rule = fw_rule("accept", "wan", port=22, proto="tcp", chain=FirewallChain.INPUT)
    gw_fw = home_firewall("gw").model_copy(update={"rules": [rule]})
    fritz_up = uplink("fritz", addresses=[iface("203.0.113.7/24")])
    fritz_fw = firewall(
        "fritz",
        zone("lan", outer),
        zone("wan", fritz_up.id),
        policies=[policy("wan", None, "drop"), policy("wan", "lan", "drop")],
        port_forwards=front_forwards or [],
    )
    return home(
        devices=[device("fritz")],
        segments=[Segment(id=outer, site_id=SITE.id, vlan=5)],
        subnets=[sub("fritz", outer, "192.168.178.1/24")],
        uplinks=[fritz_up],
        firewalls=[gw_fw, fritz_fw] if front_read else [gw_fw],
    ).model_copy(
        update={"uplinks": [uplink("gw", addresses=[iface("192.168.178.2/24")]), fritz_up]}
    )


def test_double_nat_needs_the_router_in_front() -> None:
    ssh = service("gw", "ssh")
    out = service_from_internet(double_nat(None), ssh)
    assert out.verdict is D and "fritz in front does not let it through" in out.reason
    forwarded = double_nat([port_forward("192.168.178.2", 22)])
    assert service_from_internet(forwarded, ssh).verdict is A
    assert service_from_internet(double_nat(None, front_read=False), ssh).verdict is U
    # an inner address reached through both routers
    lan_fwd = double_nat([port_forward("192.168.178.2", 8022)])
    gw = lan_fwd.firewalls[0].model_copy(
        update={"port_forwards": [port_forward("192.168.1.2", 8022, target_port=22)]}
    )
    both = lan_fwd.model_copy(update={"firewalls": [gw, lan_fwd.firewalls[1]]})
    assert v(both, WAN, "192.168.1.2", 22) is A
    assert v(lan_fwd, WAN, "192.168.1.2", 22) is D


# --- merge, contract, schema ---------------------------------------------------------------


def test_merge_keeps_firewalls_and_moves_native_segments() -> None:
    from test_double_nat import ISP_LAN, MAIN, isp
    from test_double_nat import firewall as opnsense

    isp_fw = firewall("isp", zone("lan", MAIN), policies=[policy("lan", None, "accept")])
    fw_fw = firewall("fw", zone("lan", MAIN))
    n = merge([SITE], [isp(firewalls=[isp_fw]), opnsense(firewalls=[fw_fw])])
    isp_zone = n.firewall_of("isp")
    assert isp_zone is not None and isp_zone.zones[0].segments == [ISP_LAN]
    own = n.firewall_of("fw")
    assert own is not None and own.zones[0].segments == [MAIN]
    assert n.firewall_of("nobody") is None and n.knows("fw/firewall")


def test_firewall_problems() -> None:
    good = home_firewall("gw", guest=GUEST)
    assert firewall_problems(good, set(), {LAN, GUEST}, {WAN}, set()) == []
    bad = firewall(
        "gw",
        zone("lan", segment_id(SITE.id, 77), "gw/port/eth9", "gw/tunnel/wg9", "gw/uplink/x"),
        zone("lan"),
        policies=[
            policy("lan", None, "accept"),
            policy("lan", None, "drop"),
            policy("x", "y", "drop"),
        ],
        rules=[
            fw_rule("drop", "nowhere", name="r1"),
            fw_rule("drop", port=22, protocols=[FirewallProtocol.ICMP], name="r2"),
            fw_rule("drop", dest="lan", chain=FirewallChain.INPUT, name="r3"),
        ],
        port_forwards=[port_forward("192.168.1.2", 22, zones=["dmz"])],
        nat=[{"name": "n1", "zones": ["dmz"], "masquerade": False}],
    ).model_copy(update={"id": "gw/fw"})
    text = "\n".join(firewall_problems(bad, set(), {LAN}, set(), set()))
    for needle in [
        "firewall gw/fw is not gw/firewall",
        "lists a zone twice",
        f"has unknown segment {segment_id(SITE.id, 77)}",
        "has unknown port gw/port/eth9",
        "has unknown tunnel gw/tunnel/wg9",
        "has unknown uplink gw/uplink/x",
        "two policies for the same zone pair",
        "policy names unknown zone x",
        "rule r1 names unknown zone nowhere",
        "rule r2 has ports without TCP or UDP",
        "rule r3 is an input rule with a destination zone",
        "port forward fwd-22 names unknown zone dmz",
        "NAT rule n1 names unknown zone dmz",
        "NAT rule n1 has neither masquerade nor address",
    ]:
        assert needle in text, needle


class WithFirewall(Fake):
    """An adapter on API 1.4 that reads the firewall."""

    manifest = Fake.manifest.model_copy(
        update={
            "api_version": API_VERSION,
            "capabilities": frozenset({*Fake.manifest.capabilities, Capability.FIREWALL}),
        }
    )

    async def read_firewall(self) -> Observation:
        d = self.context.device_id
        return Observation(firewalls=[firewall(d, zone("lan", LAN), adapter="fake")])


async def test_observe_reads_the_firewall_and_passes_the_contract() -> None:
    from signalbox.testing import assert_contract

    snap = await assert_contract(WithFirewall(ctx()))
    (fw,) = snap.firewalls
    assert fw.source is not None and fw.observed_at == snap.observed_at


def test_contract_needs_the_capability_and_one_firewall() -> None:
    adapter = WithFirewall(ctx())
    good = asyncio.run(adapter.observe())
    twice = good.model_copy(update={"firewalls": [*good.firewalls, good.firewalls[0]]})
    assert any("reported twice" in p for p in problems(adapter, twice))
    no_caps = good.device.model_copy(update={"capabilities": ["interfaces"]})
    text = "\n".join(problems(adapter, good.model_copy(update={"device": no_caps})))
    assert "firewalls reported without declaring firewall" in text


def test_snapshot_and_schema() -> None:
    snap = snapshot(device("gw"), firewalls=[home_firewall()])
    assert snap.firewalls[0].id == "gw/firewall"
    defs = json_schema()["$defs"]
    assert {"Firewall", "FirewallRule", "PortForward", "ZonePolicy", "NatRule"} <= set(defs)


def test_firewall_needs_api_1_4() -> None:
    from signalbox.adapters import SINCE, AdapterContractError, check_manifest

    assert SINCE[Capability.FIREWALL] == "1.4"
    old = WithFirewall.manifest.model_copy(update={"api_version": "1.3"})
    with pytest.raises(
        AdapterContractError, match=r"declares firewall, which needs adapter API 1\.4"
    ):
        check_manifest(old)
