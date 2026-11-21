from typing import Any

from factories import SITE, device, iface, ip, snapshot
from signalbox.merge import merge
from signalbox.model import (
    Client,
    DeviceRole,
    DhcpPool,
    DhcpServer,
    DnsService,
    Network,
    ReadError,
    Reservation,
    Segment,
    Site,
    Snapshot,
    Subnet,
    segment_id,
)
from signalbox.rules import Finding, Rule, evaluate
from signalbox.rules.dhcp import (
    dns_option,
    duplicate_ip,
    one_server,
    pool_fixed_address,
    pools_overlap,
    reservation_in_pool,
    router_option,
    subnet_overlap,
)

LAN = segment_id(SITE.id, 10)
IOT = segment_id(SITE.id, 20)
DHCP = ["dhcp", "interfaces"]


def subnet(dev: str, seg: str, address: str, gateway: bool = True) -> Subnet:
    return Subnet(
        id=f"{dev}/subnet/{seg}/{address}",
        segment_id=seg,
        interface=iface(address),
        device_id=dev,
        gateway=gateway,
    )


def server(dev: str, seg: str = LAN, **kw: Any) -> DhcpServer:
    return DhcpServer(
        id=f"{dev}/dhcp/{seg}",
        device_id=dev,
        segment_id=seg,
        enabled=kw.pop("enabled", True),
        pools=kw.pop("pools", [pool("192.0.2.100", "192.0.2.199")]),
        router=kw.pop("router", ip("192.0.2.1")),
        dns_servers=kw.pop("dns_servers", [ip("192.0.2.1")]),
        **kw,
    )


def pool(start: str, end: str) -> DhcpPool:
    return DhcpPool(start=ip(start), end=ip(end))


def seg(vlan: int, name: str | None = None, site: str = SITE.id) -> Segment:
    return Segment(id=segment_id(site, vlan), site_id=site, vlan=vlan, name=name)


def gateway(**kw: Any) -> Snapshot:
    """A router serving LAN (192.0.2.0/24) with DHCP."""
    kw.setdefault("segments", [seg(10, "LAN")])
    kw.setdefault("subnets", [subnet("gw", LAN, "192.0.2.1/24")])
    kw.setdefault("dhcp_servers", [server("gw")])
    return snapshot(device("gw", capabilities=kw.pop("capabilities", DHCP)), **kw)


def run(r: Rule, *snaps: Snapshot, sites: list[Site] | None = None) -> list[Finding]:
    net = merge(sites or [SITE], snaps)
    return [f for f in evaluate(net, [r]) if f.rule_id == r.id]


def test_one_server_passes() -> None:
    assert run(one_server, gateway()) == []


def test_two_servers_are_an_error() -> None:
    other = snapshot(
        device("ap", DeviceRole.AP, capabilities=DHCP),
        dhcp_servers=[server("ap")],
    )
    (f,) = run(one_server, gateway(), other)
    assert f.severity == "error"
    assert f.message == "2 DHCP servers on LAN (VLAN 10): ap, gw"
    assert f.objects == [LAN, "ap/dhcp/" + LAN, "gw/dhcp/" + LAN]
    assert f.fix


def test_disabled_server_does_not_count_and_missing_is_a_warning() -> None:
    (f,) = run(one_server, gateway(dhcp_servers=[server("gw", enabled=False)]))
    assert f.severity == "warning" and f.message == "No DHCP server on LAN (VLAN 10)"
    assert not f.incomplete


def test_ipv6_only_network_needs_no_dhcp() -> None:
    snap = gateway(subnets=[subnet("gw", LAN, "2001:db8::1/64")], dhcp_servers=[])
    assert run(one_server, snap) == []


def test_unknown_dhcp_is_incomplete_not_a_finding() -> None:
    no_cap = gateway(dhcp_servers=[], capabilities=["interfaces"])
    (f,) = run(one_server, no_cap)
    assert f.incomplete and f.severity == "info"
    assert "site home" in f.message and "LAN (VLAN 10)" in f.message
    failed = gateway(
        dhcp_servers=[],
        errors=[ReadError(device_id="gw", capability="dhcp", message="timeout")],
    )
    assert [x.incomplete for x in run(one_server, failed)] == [True]


def test_segment_name_falls_back_to_vlan_and_id() -> None:
    snap = gateway(
        segments=[seg(10)],
        subnets=[subnet("gw", LAN, "192.0.2.1/24"), subnet("gw", IOT, "198.51.100.1/24")],
    )
    (f,) = run(one_server, snap)
    assert f.message == f"No DHCP server on {IOT}"
    (g,) = run(one_server, gateway(segments=[], dhcp_servers=[server("gw"), server("gw2")]))
    assert LAN in g.message
    native = Segment(id=segment_id(SITE.id, None), site_id=SITE.id)
    (h,) = run(
        one_server,
        gateway(
            segments=[native],
            subnets=[subnet("gw", native.id, "192.0.2.1/24")],
            dhcp_servers=[],
        ),
    )
    assert h.message == "No DHCP server on untagged network"


def test_pools_overlap() -> None:
    ok = server(
        "gw", pools=[pool("192.0.2.100", "192.0.2.149"), pool("192.0.2.150", "192.0.2.199")]
    )
    assert run(pools_overlap, gateway(dhcp_servers=[ok])) == []
    bad = server(
        "gw",
        pools=[
            pool("192.0.2.100", "192.0.2.160"),
            pool("192.0.2.199", "192.0.2.150"),
            pool("2001:db8::100", "2001:db8::1ff"),
        ],
    )
    (f,) = run(pools_overlap, gateway(dhcp_servers=[bad]))
    assert f.severity == "warning"
    assert "192.0.2.100-192.0.2.160 and 192.0.2.199-192.0.2.150 overlap" in f.message


def test_router_and_device_address_in_pool() -> None:
    iot = subnet("gw", IOT, "192.0.2.150/32")  # other segment: not in this pool
    assert run(pool_fixed_address, gateway(subnets=[subnet("gw", LAN, "192.0.2.1/24"), iot])) == []
    ap = snapshot(device("ap", DeviceRole.AP), subnets=[subnet("ap", LAN, "192.0.2.120/24", False)])
    (f,) = run(pool_fixed_address, gateway(), ap)
    assert (
        f.message
        == "192.0.2.120 of ap is inside the DHCP pool 192.0.2.100-192.0.2.199 on LAN (VLAN 10)"
    )
    assert f.severity == "warning"
    v6 = snapshot(device("ap"), subnets=[subnet("ap", LAN, "2001:db8::120/64", False)])
    assert run(pool_fixed_address, gateway(), v6) == []


def test_reservation_in_pool() -> None:
    outside = Reservation(mac="02:00:00:00:00:01", address=ip("192.0.2.20"), hostname="printer")
    assert (
        run(reservation_in_pool, gateway(dhcp_servers=[server("gw", reservations=[outside])])) == []
    )
    inside = Reservation(mac="02:00:00:00:00:02", address=ip("192.0.2.150"))
    (f,) = run(reservation_in_pool, gateway(dhcp_servers=[server("gw", reservations=[inside])]))
    assert f.message == (
        "Reservation 192.0.2.150 for 02:00:00:00:00:02 on LAN (VLAN 10) is inside the pool "
        "192.0.2.100-192.0.2.199"
    )


def test_router_option() -> None:
    assert run(router_option, gateway()) == []
    assert run(router_option, gateway(dhcp_servers=[server("gw", router=None)])) == []
    (f,) = run(router_option, gateway(dhcp_servers=[server("gw", router=ip("192.0.2.254"))]))
    assert f.severity == "warning"
    assert "router 192.0.2.254, but the router of this network is 192.0.2.1" in f.message
    assert "192.0.2.1" in (f.fix or "")


def test_router_option_without_known_router_is_incomplete() -> None:
    sw = snapshot(
        device("sw", DeviceRole.SWITCH),
        subnets=[subnet("sw", LAN, "192.0.2.2/24", gateway=False)],
        dhcp_servers=[server("sw")],
    )
    (f,) = run(router_option, sw)
    assert f.incomplete and "cannot be checked" in f.message


def test_subnet_of_gateway_device_counts_as_router_without_flag() -> None:
    snap = gateway(subnets=[subnet("gw", LAN, "192.0.2.1/24", gateway=False)])
    assert run(router_option, snap) == []
    assert run(one_server, snap) == []
    (f,) = run(one_server, gateway(subnets=snap.subnets, dhcp_servers=[]))
    assert f.message == "No DHCP server on LAN (VLAN 10)"


def test_dns_option() -> None:
    assert run(dns_option, gateway()) == []
    resolver = DnsService(id="pi/dns", device_id="pi", listen=[ip("192.0.2.53")])
    pi = snapshot(device("pi", DeviceRole.OTHER), dns_services=[resolver])
    ok = server("gw", dns_servers=[ip("192.0.2.53"), ip("192.0.2.1")])
    assert run(dns_option, gateway(dhcp_servers=[ok]), pi) == []
    # A resolver without listen addresses answers on every address of its device.
    anywhere = DnsService(id="pi/dns", device_id="pi")
    pi_all = snapshot(
        device("pi", DeviceRole.OTHER),
        dns_services=[anywhere],
        subnets=[subnet("pi", LAN, "192.0.2.53/24", False)],
    )
    assert run(dns_option, gateway(dhcp_servers=[ok]), pi_all) == []
    off = DnsService(id="pi/dns", device_id="pi", enabled=False, listen=[ip("192.0.2.53")])
    pi_off = snapshot(device("pi", DeviceRole.OTHER), dns_services=[off])
    (f,) = run(dns_option, gateway(dhcp_servers=[ok]), pi_off)
    assert "use DNS server 192.0.2.53, which is not a known resolver" in f.message
    public = server("gw", dns_servers=[ip("203.0.113.53")])
    (g,) = run(dns_option, gateway(dhcp_servers=[public]))
    assert "203.0.113.53" in g.message and g.severity == "warning"


def test_subnet_overlap_across_segments_and_sites() -> None:
    lan_and_iot = gateway(
        subnets=[subnet("gw", LAN, "192.0.2.1/25"), subnet("gw", IOT, "192.0.2.129/25")]
    )
    assert run(subnet_overlap, lan_and_iot) == []
    # The same subnet seen by two devices on one segment is fine.
    ap = snapshot(device("ap"), subnets=[subnet("ap", LAN, "192.0.2.2/25", False)])
    assert run(subnet_overlap, lan_and_iot, ap) == []
    overlap = gateway(
        subnets=[
            subnet("gw", LAN, "192.0.2.1/24"),
            subnet("gw", IOT, "192.0.2.129/25"),
            subnet("gw", IOT, "2001:db8::1/64"),
        ]
    )
    ap_iot = snapshot(device("ap"), subnets=[subnet("ap", IOT, "192.0.2.130/25", False)])
    (f,) = run(subnet_overlap, overlap, ap_iot)
    assert f.severity == "error" and f.objects == [LAN, IOT]
    assert "192.0.2.0/24 on LAN (VLAN 10) overlaps 192.0.2.128/25" in f.message

    cabin = Site(id="cabin", name="Cabin")
    remote = snapshot(
        device("gw2", site_id="cabin"),
        subnets=[subnet("gw2", segment_id("cabin", 10), "192.0.2.1/24")],
    )
    (g,) = run(subnet_overlap, gateway(), remote, sites=[SITE, cabin])
    assert g.objects == ["cabin/segment/10", LAN]


def client(mac: str, *addresses: str) -> Client:
    return Client(id=mac, mac=mac, addresses=[ip(a) for a in addresses])


def test_duplicate_ip() -> None:
    a = client("02:00:00:00:00:0a", "192.0.2.10", "fe80::1")
    b = client("02:00:00:00:00:0b", "192.0.2.11", "fe80::1")
    res = Reservation(mac="02:00:00:00:00:0a", address=ip("192.0.2.10"))
    snap = gateway(clients=[a, b], dhcp_servers=[server("gw", reservations=[res])])
    assert run(duplicate_ip, snap) == []

    clash = Reservation(mac="02:00:00:00:00:0c", address=ip("192.0.2.11"))
    snap = gateway(clients=[a, b], dhcp_servers=[server("gw", reservations=[clash])])
    (f,) = run(duplicate_ip, snap)
    assert f.severity == "error"
    assert f.message == "192.0.2.11 is used by 2 devices: 02:00:00:00:00:0b, 02:00:00:00:00:0c"
    assert f.objects == ["client/02:00:00:00:00:0b", "gw/dhcp/" + LAN]


def test_empty_network_is_clean() -> None:
    rules = [
        one_server,
        pools_overlap,
        pool_fixed_address,
        reservation_in_pool,
        router_option,
        dns_option,
        subnet_overlap,
        duplicate_ip,
    ]
    assert evaluate(Network(), rules) == []
