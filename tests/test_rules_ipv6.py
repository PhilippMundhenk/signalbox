from typing import Any

from factories import SITE, device, iface, ip
from signalbox.model import (
    Client,
    DeviceRole,
    Network,
    Security,
    Segment,
    Subnet,
    Wlan,
    segment_id,
)
from signalbox.rules import Finding, Rule, evaluate
from signalbox.rules.ipv6 import partial, prefix_64, unknown_prefix

LAN = segment_id(SITE.id, 10)
IOT = segment_id(SITE.id, 20)
GUEST = segment_id(SITE.id, 30)
NAMES = {LAN: "LAN", IOT: "IoT", GUEST: "Guest"}


def subnet(seg: str, address: str, dev: str = "gw", gateway: bool = True) -> Subnet:
    return Subnet(
        id=f"{dev}/subnet/{seg}/{address}",
        segment_id=seg,
        interface=iface(address),
        device_id=dev,
        gateway=gateway,
    )


def client(n: int, seg: str | None, *addresses: str) -> Client:
    return Client(
        id=f"gw/client/{n}",
        mac=f"02:00:00:00:00:{n:02x}",
        addresses=[ip(a) for a in addresses],
        segment_id=seg,
    )


def wlan(seg: str) -> Wlan:
    return Wlan(
        id=f"ap/wlan/{seg}",
        device_id="ap",
        ssid=f"Example-{NAMES[seg]}",
        radio_id="ap/radio/1",
        security=Security.WPA2,
        segment_id=seg,
    )


def network(**kw: Any) -> Network:
    vlans = {LAN: 10, IOT: 20, GUEST: 30}
    return Network(
        sites=[SITE],
        devices=[device("gw"), device("ap", DeviceRole.AP)],
        segments=[Segment(id=s, site_id=SITE.id, vlan=v, name=NAMES[s]) for s, v in vlans.items()],
        **kw,
    )


def run(r: Rule, net: Network) -> list[Finding]:
    return [f for f in evaluate(net, [r]) if f.rule_id == r.id]


LAN_V6 = [subnet(LAN, "192.0.2.1/24"), subnet(LAN, "2001:db8:1::1/64")]

# --- ipv6.unknown-prefix ------------------------------------------------------------------------


def test_unknown_prefix_passes_for_the_router_prefix_and_link_local() -> None:
    clients = [client(1, LAN, "192.0.2.10", "2001:db8:1::10", "fe80::10")]
    assert run(unknown_prefix, network(subnets=LAN_V6, clients=clients)) == []
    # a larger router prefix covers the client's /64 as well
    wide = [subnet(LAN, "2001:db8:1::1/56")]
    clients = [client(1, LAN, "2001:db8:1:5::10")]
    assert run(unknown_prefix, network(subnets=wide, clients=clients)) == []


def test_unknown_prefix_names_the_clients_of_a_rogue_prefix() -> None:
    clients = [
        client(1, LAN, "2001:db8:99::10"),
        client(2, LAN, "2001:db8:99::20", "2001:db8:1::20"),
        client(3, LAN, "fd00:db8::30"),
    ]
    found = run(unknown_prefix, network(subnets=LAN_V6, clients=clients))
    assert [f.message for f in found] == [
        "1 client on LAN (VLAN 10) uses addresses from fd00:db8::/64, which no router of "
        "LAN (VLAN 10) announces",
        "2 clients on LAN (VLAN 10) use addresses from 2001:db8:99::/64, which no router of "
        "LAN (VLAN 10) announces",
    ]
    assert found[1].severity == "warning" and found[1].fix
    assert found[1].objects == [LAN, "gw/client/1", "gw/client/2"]
    assert found[0].id != found[1].id


def test_unknown_prefix_on_a_network_without_ipv6_when_the_router_has_ipv6() -> None:
    subnets = [*LAN_V6, subnet(IOT, "198.51.100.1/24")]
    (f,) = run(unknown_prefix, network(subnets=subnets, clients=[client(1, IOT, "2001:db8:7::1")]))
    assert "IoT (VLAN 20)" in f.message and not f.incomplete


def test_unknown_prefix_stays_quiet_or_incomplete_without_router_ipv6() -> None:
    # the router reports no IPv6 at all: it may just not read it
    subnets = [subnet(LAN, "192.0.2.1/24")]
    (f,) = run(unknown_prefix, network(subnets=subnets, clients=[client(1, LAN, "2001:db8:9::1")]))
    assert f.incomplete and "LAN (VLAN 10)" in f.message
    # unknown network, no router subnet on it, client without network: silent
    clients = [client(1, GUEST, "2001:db8:9::1"), client(2, None, "2001:db8:9::2")]
    assert run(unknown_prefix, network(subnets=LAN_V6, clients=clients)) == []
    # a non-router (access point) subnet does not count as announced
    ap_only = [subnet(LAN, "2001:db8:9::2/64", dev="ap", gateway=False), *LAN_V6]
    rogue = [*clients[:1], client(3, LAN, "2001:db8:9::3")]
    assert len(run(unknown_prefix, network(subnets=ap_only, clients=rogue))) == 1


# --- ipv6.prefix-64 -----------------------------------------------------------------------------


def test_prefix_64_passes() -> None:
    assert run(prefix_64, network(subnets=LAN_V6, wlans=[wlan(LAN)])) == []


def test_prefix_64_reports_other_lengths_on_client_networks() -> None:
    subnets = [
        subnet(LAN, "2001:db8:1::1/60"),
        subnet(LAN, "2001:db8:1::1/60", dev="gw2"),  # the same prefix seen twice
        subnet(IOT, "2001:db8:2::1/80"),
    ]
    found = run(prefix_64, network(subnets=subnets, wlans=[wlan(LAN)], clients=[client(1, IOT)]))
    assert [f.message for f in found] == [
        "IoT (VLAN 20) uses 2001:db8:2::/80",
        "LAN (VLAN 10) uses 2001:db8:1::/60",
    ]
    assert found[0].severity == "warning" and "/64" in str(found[0].fix)


def test_prefix_64_skips_transit_and_link_local_networks() -> None:
    subnets = [subnet(GUEST, "2001:db8:ff::1/127"), subnet(LAN, "fe80::1/10")]
    assert run(prefix_64, network(subnets=subnets, wlans=[wlan(LAN)])) == []
    # a non-router subnet is not the router's prefix
    ap = [subnet(LAN, "2001:db8:1::2/60", dev="ap", gateway=False)]
    assert run(prefix_64, network(subnets=ap, wlans=[wlan(LAN)])) == []


# --- ipv6.partial -------------------------------------------------------------------------------


def test_partial_passes_with_ipv6_everywhere_or_nowhere() -> None:
    every = [*LAN_V6, subnet(IOT, "2001:db8:2::1/64")]
    used = [wlan(LAN), wlan(IOT)]
    assert run(partial, network(subnets=every, wlans=used)) == []
    nowhere = [subnet(LAN, "192.0.2.1/24"), subnet(IOT, "198.51.100.1/24")]
    assert run(partial, network(subnets=nowhere, wlans=used)) == []


def test_partial_reports_networks_without_ipv6_or_with_only_ula() -> None:
    subnets = [
        *LAN_V6,
        subnet(IOT, "198.51.100.1/24"),
        subnet(GUEST, "203.0.113.1/24"),
        subnet(GUEST, "fd00:db8:3::1/64"),
    ]
    used = [wlan(LAN), wlan(IOT), client(1, GUEST)]
    found = run(partial, network(subnets=subnets, wlans=used[:2], clients=used[2:]))
    assert [f.message for f in found] == [
        "Guest (VLAN 30) has only a local (ULA) IPv6 prefix while LAN (VLAN 10) has a global one",
        "IoT (VLAN 20) has no IPv6 while Guest (VLAN 30), LAN (VLAN 10) do",
    ]
    assert {f.severity for f in found} == {"info"}


def test_partial_ignores_networks_without_clients_or_router() -> None:
    # IoT has no SSID and no clients; Guest has clients but no router subnet
    subnets = [*LAN_V6, subnet(IOT, "198.51.100.1/24")]
    net = network(subnets=subnets, wlans=[wlan(LAN)], clients=[client(1, GUEST)])
    assert run(partial, net) == []
    # one network with IPv6 and one without, wording for a single other network
    net = network(subnets=subnets, wlans=[wlan(LAN), wlan(IOT)])
    (f,) = run(partial, net)
    assert f.message == "IoT (VLAN 20) has no IPv6 while LAN (VLAN 10) does"


def test_partial_finds_the_site_of_a_network_only_seen_as_a_subnet() -> None:
    lab = segment_id(SITE.id, 40)
    subnets = [*LAN_V6, subnet(lab, "198.51.100.129/25")]
    (f,) = run(partial, network(subnets=subnets, wlans=[wlan(LAN)], clients=[client(1, lab)]))
    assert f.message == f"{lab} has no IPv6 while LAN (VLAN 10) does"
