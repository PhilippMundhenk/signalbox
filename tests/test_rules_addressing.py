from typing import Any

from factories import SITE, device, iface, ip, port
from signalbox.model import (
    Band,
    Client,
    DeviceRole,
    DhcpPool,
    DhcpServer,
    DnsService,
    HostRecord,
    Network,
    PurposeSource,
    Radio,
    Reservation,
    Security,
    Segment,
    SegmentPurpose,
    Site,
    Subnet,
    Wlan,
    segment_id,
)
from signalbox.purpose import with_heuristics
from signalbox.rules import Finding, Rule, Severity, evaluate
from signalbox.rules.addressing import (
    client_subnet,
    dhcp_domain,
    dns_cross_network,
    duplicate_reservation,
    gateway_position,
    in_subnet,
    lease_time,
    management_address,
    one_gateway,
    pool_usage,
    prefix_consistent,
    reservation_hostname,
    self_assigned,
)

LAN = segment_id(SITE.id, 10)
IOT = segment_id(SITE.id, 20)
GUEST = segment_id(SITE.id, 30)
MAC = "02:00:00:00:00:10"


def subnet(dev: str, seg: str, address: str, gateway: bool = True) -> Subnet:
    return Subnet(
        id=f"{dev}/subnet/{seg}/{address}",
        segment_id=seg,
        interface=iface(address),
        device_id=dev,
        gateway=gateway,
    )


def pool(start: str, end: str) -> DhcpPool:
    return DhcpPool(start=ip(start), end=ip(end))


def server(dev: str = "gw", seg: str = LAN, **kw: Any) -> DhcpServer:
    return DhcpServer(
        id=f"{dev}/dhcp/{seg}",
        device_id=dev,
        segment_id=seg,
        enabled=kw.pop("enabled", True),
        pools=kw.pop("pools", [pool("192.0.2.100", "192.0.2.199")]),
        router=kw.pop("router", ip("192.0.2.1")),
        **kw,
    )


def res(address: str, mac: str = MAC, hostname: str | None = None) -> Reservation:
    return Reservation(mac=mac, address=ip(address), hostname=hostname)


def client(mac: str, *addresses: str, seg: str | None = LAN, **kw: Any) -> Client:
    return Client(
        id=f"client/{mac}",
        mac=mac,
        addresses=[ip(a) for a in addresses],
        segment_id=seg,
        **kw,
    )


SEGMENTS = [
    Segment(id=LAN, site_id=SITE.id, vlan=10, name="LAN"),
    Segment(id=IOT, site_id=SITE.id, vlan=20, name="IoT"),
    Segment(id=GUEST, site_id=SITE.id, vlan=30, name="Guest"),
]
GW_SUBNETS = [
    subnet("gw", LAN, "192.0.2.1/24"),
    subnet("gw", IOT, "198.51.100.1/24"),
]


def network(**kw: Any) -> Network:
    kw.setdefault("sites", [SITE])
    kw.setdefault("devices", [device("gw"), device("ap", DeviceRole.AP)])
    kw.setdefault("segments", SEGMENTS)
    kw.setdefault("subnets", GW_SUBNETS)
    kw.setdefault("dhcp_servers", [server()])
    return Network(**kw)


def run(r: Rule, net: Network) -> list[Finding]:
    return [f for f in evaluate(net, [r]) if f.rule_id == r.id]


def messages(r: Rule, net: Network) -> list[str]:
    return [f.message for f in run(r, net)]


# --- addr.client-subnet ---------------------------------------------------------------------------


def test_client_subnet_quiet_for_matching_and_link_local_addresses() -> None:
    clients = [
        client(MAC, "192.0.2.10", "fe80::1", "169.254.3.4"),
        client("02:00:00:00:00:11", "2001:db8::5"),  # no IPv6 subnet known: not compared
        client("02:00:00:00:00:12", "192.0.2.12", seg=None),
        client("02:00:00:00:00:13"),
    ]
    assert run(client_subnet, network(clients=clients)) == []


def test_client_subnet_reports_foreign_address() -> None:
    net = network(clients=[client(MAC, "203.0.113.23", hostname="tv")])
    (f,) = run(client_subnet, net)
    assert f.severity is Severity.WARNING
    assert "tv (02:00:00:00:00:10) uses 203.0.113.23" in f.message
    assert "LAN (VLAN 10) (192.0.2.0/24)" in f.message
    assert f.objects == [f"client/{MAC}", LAN]


def test_client_subnet_reports_addresses_in_two_networks() -> None:
    net = network(clients=[client(MAC, "192.0.2.10", "198.51.100.10")])
    (f,) = run(client_subnet, net)
    assert "addresses in 2 networks" in f.message
    assert f.objects == [f"client/{MAC}", LAN, IOT]


def test_client_subnet_incomplete_once_per_network_without_subnet() -> None:
    net = network(
        clients=[
            client(MAC, "203.0.113.5", seg=GUEST),
            client("02:00:00:00:00:11", "203.0.113.6", seg=GUEST),
        ]
    )
    (f,) = run(client_subnet, net)
    assert f.incomplete and "2 clients" in f.message


# --- dhcp.self-assigned ---------------------------------------------------------------------------


def test_self_assigned_reports_clients_per_network() -> None:
    clients = [
        client(MAC, "169.254.1.2", "fe80::2"),
        client("02:00:00:00:00:11", "169.254.1.3"),
        client("02:00:00:00:00:12", "169.254.1.4", "192.0.2.12"),  # also has a lease
        client("02:00:00:00:00:13", "2001:db8::13"),  # no IPv4 at all
    ]
    (f,) = run(self_assigned, network(clients=clients))
    assert f.message.startswith("2 clients on LAN (VLAN 10) have only a self-assigned")
    assert f.objects[0] == LAN


def test_self_assigned_single_client_and_quiet_without_server() -> None:
    (f,) = run(self_assigned, network(clients=[client(MAC, "169.254.1.2")]))
    assert f.message.startswith("1 client on LAN (VLAN 10) has only")
    quiet = network(clients=[client(MAC, "169.254.1.2", seg=IOT)])
    assert run(self_assigned, quiet) == []


# --- addr.prefix-consistent -----------------------------------------------------------------------


def test_prefix_consistent_quiet_for_matching_address() -> None:
    subs = [
        *GW_SUBNETS,
        subnet("gw", LAN, "192.0.2.254/24"),
        subnet("ap", LAN, "192.0.2.5/24", gateway=False),
        subnet("ap", LAN, "2001:db8:5::2/64", gateway=False),  # IPv6 is not compared
    ]
    assert run(prefix_consistent, network(subnets=subs)) == []


def test_prefix_consistent_reports_wrong_range_and_mask() -> None:
    subs = [*GW_SUBNETS, subnet("ap", LAN, "203.0.113.5/24", gateway=False)]
    (f,) = run(prefix_consistent, network(subnets=subs))
    assert f.severity is Severity.ERROR
    assert "ap has 203.0.113.5/24 on LAN (VLAN 10), outside the router's subnet" in f.message
    subs = [*GW_SUBNETS, subnet("ap", LAN, "192.0.2.5/16", gateway=False)]
    (f,) = run(prefix_consistent, network(subnets=subs))
    assert f.severity is Severity.WARNING
    assert "the router uses 192.0.2.1/24" in f.message and "/24" in str(f.fix)


def test_prefix_consistent_incomplete_without_router() -> None:
    subs = [subnet("ap", GUEST, "203.0.113.5/24", gateway=False)]
    (f,) = run(prefix_consistent, network(subnets=subs))
    assert f.incomplete and "No IPv4 router address is known for Guest" in f.message


# --- addr.gateway-position ------------------------------------------------------------------------


def test_gateway_position_quiet_when_consistent() -> None:
    assert run(gateway_position, network()) == []
    last = [subnet("gw", LAN, "192.0.2.254/24"), subnet("gw", IOT, "198.51.100.254/24")]
    assert run(gateway_position, network(subnets=last)) == []
    tiny = [
        *GW_SUBNETS,
        subnet("gw", GUEST, "203.0.113.0/31"),
        subnet("gw", GUEST, "2001:db8::9/64"),
    ]
    assert run(gateway_position, network(subnets=tiny)) == []


def test_gateway_position_reports_middle_and_mixed() -> None:
    subs = [*GW_SUBNETS, subnet("gw", GUEST, "203.0.113.77/24")]
    (f,) = run(gateway_position, network(subnets=subs))
    assert f.severity is Severity.INFO
    assert "203.0.113.77, neither the first nor the last" in f.message
    assert "203.0.113.1" in str(f.fix)
    subs = [*GW_SUBNETS, subnet("gw", GUEST, "203.0.113.254/24")]
    (f,) = run(gateway_position, network(subnets=subs))
    assert "the last usable address; the other networks of this site use the first" in f.message


# --- dhcp.pool-usage ------------------------------------------------------------------------------


def small(**kw: Any) -> DhcpServer:
    return server(pools=[pool("192.0.2.100", "192.0.2.109")], **kw)


def lan_clients(n: int, start: int = 100) -> list[Client]:
    return [client(f"02:00:00:00:01:{i:02x}", f"192.0.2.{start + i}") for i in range(n)]


def test_pool_usage_quiet_with_room() -> None:
    net = network(dhcp_servers=[small()], clients=lan_clients(5))
    assert run(pool_usage, net) == []


def test_pool_usage_warns_and_errors() -> None:
    (f,) = run(pool_usage, network(dhcp_servers=[small()], clients=lan_clients(9)))
    assert f.severity is Severity.WARNING
    assert f.message == "The pool of LAN (VLAN 10) has 10 free addresses and 9 are in use"
    (f,) = run(pool_usage, network(dhcp_servers=[small()], clients=lan_clients(10)))
    assert f.severity is Severity.ERROR and "is full" in f.message


def test_pool_usage_counts_reservations_and_overlapping_pools() -> None:
    srv = server(
        pools=[pool("192.0.2.100", "192.0.2.109"), pool("192.0.2.105", "192.0.2.109")],
        reservations=[res("192.0.2.100"), res("192.0.2.101", "02:00:00:00:00:11")],
    )
    clients = [client(MAC, "192.0.2.100"), *lan_clients(7, start=102)]
    (f,) = run(pool_usage, network(dhcp_servers=[srv], clients=clients))
    assert f.message == "The pool of LAN (VLAN 10) has 8 free addresses and 7 are in use"


def test_pool_usage_reports_more_clients_than_pool() -> None:
    clients = lan_clients(12, start=10)  # fixed addresses outside the pool
    (f,) = run(pool_usage, network(dhcp_servers=[small()], clients=clients))
    assert "12 clients without a reservation have been seen" in f.message


def test_pool_usage_incomplete_without_pool() -> None:
    (f,) = run(pool_usage, network(dhcp_servers=[server(pools=[])]))
    assert f.incomplete
    assert f.message.startswith("The DHCP server on gw for LAN (VLAN 10) did not report")


# --- dhcp.lease-time ------------------------------------------------------------------------------


def test_lease_time_quiet_for_normal_and_unknown() -> None:
    assert run(lease_time, network(dhcp_servers=[server(lease_seconds=43200)])) == []
    assert run(lease_time, network(dhcp_servers=[server()])) == []
    guest = server(seg=GUEST, lease_seconds=4 * 3600)
    assert run(lease_time, network(dhcp_servers=[guest])) == []


def test_lease_time_reports_short_and_long() -> None:
    (f,) = run(lease_time, network(dhcp_servers=[server(lease_seconds=90)]))
    assert f.severity is Severity.INFO
    assert "leases of 90 seconds on LAN (VLAN 10), which is very short" in f.message
    (f,) = run(lease_time, network(dhcp_servers=[server(lease_seconds=30 * 86400)]))
    assert "leases of 30 days" in f.message and "very long" in f.message
    (f,) = run(lease_time, network(dhcp_servers=[server(lease_seconds=120)]))
    assert "2 minutes" in f.message


def test_lease_time_guest_network_by_name_or_ssid() -> None:
    guest = server(seg=GUEST, lease_seconds=2 * 86400)
    (f,) = run(lease_time, with_heuristics(network(dhcp_servers=[guest])))
    assert "on the guest network Guest (VLAN 30)" in f.message
    segs = [Segment(id=IOT, site_id=SITE.id, vlan=20)]
    radio = Radio(id="ap/radio0", device_id="ap", name="radio0", band=Band.GHZ_5)
    wlan = Wlan(
        id="ap/wlan/v",
        device_id="ap",
        ssid="Visitor-Guest",
        radio_id=radio.id,
        security=Security.WPA2,
        segment_id=IOT,
    )
    srv = server(seg=IOT, lease_seconds=3600 * 48)
    net = network(segments=segs, dhcp_servers=[srv], radios=[radio], wlans=[wlan])
    (f,) = run(lease_time, with_heuristics(net))
    assert "guest network VLAN 20" in f.message
    # a declared purpose beats the name: an SSID that only looks like a guest network
    main = wlan.model_copy(
        update={"purpose": SegmentPurpose.MAIN, "purpose_source": PurposeSource.DECLARED}
    )
    net = network(segments=segs, dhcp_servers=[srv], radios=[radio], wlans=[main])
    assert run(lease_time, with_heuristics(net)) == []
    declared = segs[0].model_copy(update={"purpose": SegmentPurpose.MAIN})
    net = network(segments=[declared], dhcp_servers=[srv], radios=[radio], wlans=[wlan])
    assert run(lease_time, with_heuristics(net)) == []


def test_lease_time_escalates_with_full_pool_and_skips_all_reserved() -> None:
    srv = small(lease_seconds=30 * 86400)
    (f,) = run(lease_time, network(dhcp_servers=[srv], clients=lan_clients(9)))
    assert f.severity is Severity.WARNING
    reserved = server(lease_seconds=30 * 86400, reservations=[res("192.0.2.10")])
    net = network(dhcp_servers=[reserved], clients=[client(MAC, "192.0.2.10")])
    assert run(lease_time, net) == []


# --- dhcp.in-subnet -------------------------------------------------------------------------------


def test_in_subnet_quiet_for_valid_pools_and_reservations() -> None:
    srv = server(reservations=[res("192.0.2.10")])
    assert run(in_subnet, network(dhcp_servers=[srv])) == []


def test_in_subnet_reports_pool_beyond_subnet_and_reversed() -> None:
    srv = server(pools=[pool("192.0.2.100", "192.0.3.50"), pool("192.0.2.90", "192.0.2.80")])
    msgs = messages(in_subnet, network(dhcp_servers=[srv]))
    assert any(
        "192.0.2.100-192.0.3.50 of LAN (VLAN 10) extends beyond 192.0.2.0/24" in m for m in msgs
    )
    assert any("192.0.2.90-192.0.2.80 of LAN (VLAN 10) ends before it starts" in m for m in msgs)
    assert len(msgs) == 2


def test_in_subnet_reports_network_and_broadcast_addresses() -> None:
    srv = server(pools=[pool("192.0.2.0", "192.0.2.255"), pool("192.0.2.1", "192.0.2.20")])
    msgs = messages(in_subnet, network(dhcp_servers=[srv]))
    assert len(msgs) == 2  # the router address is dhcp.pool-fixed-address's
    assert any("includes 192.0.2.0, the network address" in m for m in msgs)
    assert any("includes 192.0.2.255, the broadcast address" in m for m in msgs)


def test_in_subnet_reports_bad_reservations() -> None:
    srv = server(
        reservations=[
            res("192.0.2.255"),
            res("192.0.2.1", "02:00:00:00:00:11", hostname="nas"),
            res("203.0.113.9", "02:00:00:00:00:12"),
        ]
    )
    msgs = messages(in_subnet, network(dhcp_servers=[srv]))
    assert any("192.0.2.255 for 02:00:00:00:00:10" in m and "broadcast address" in m for m in msgs)
    assert any("192.0.2.1 for nas" in m and "router address" in m for m in msgs)
    assert any("203.0.113.9" in m and "outside 192.0.2.0/24" in m for m in msgs)


def test_in_subnet_incomplete_for_relayed_network() -> None:
    srv = server(seg=GUEST, pools=[pool("203.0.113.100", "203.0.113.150")])
    (f,) = run(in_subnet, network(dhcp_servers=[srv]))
    assert f.incomplete and "relayed" in f.message
    srv6 = server(pools=[pool("2001:db8::100", "2001:db8::1ff")])
    (f,) = run(in_subnet, network(dhcp_servers=[srv6]))
    assert f.incomplete and "IPv6" in f.message


# --- addr.one-gateway -----------------------------------------------------------------------------


def test_one_gateway_quiet_for_one_router_and_plain_hosts() -> None:
    devices = [device("gw"), device("isp"), device("ap", DeviceRole.AP)]
    subs = [
        *GW_SUBNETS,
        subnet("gw", LAN, "192.0.2.2/24"),  # secondary address of the same router
        subnet("isp", LAN, "192.0.2.254/24", gateway=False),  # no DHCP: a plain host
        subnet("ap", LAN, "192.0.2.5/24", gateway=False),
        subnet("ap", LAN, "fe80::1/64"),
    ]
    assert run(one_gateway, network(devices=devices, subnets=subs)) == []


def test_one_gateway_reports_two_routers() -> None:
    devices = [device("gw"), device("isp", name="ISP router")]
    subs = [*GW_SUBNETS, subnet("isp", LAN, "192.0.2.254/24", gateway=False)]
    servers = [server(), server("isp", router=ip("192.0.2.254"))]
    (f,) = run(one_gateway, network(devices=devices, subnets=subs, dhcp_servers=servers))
    assert f.message == "LAN (VLAN 10) has 2 routers: gw (192.0.2.1), ISP router (192.0.2.254)"
    assert f.objects == [LAN, "gw", "isp"]


def test_one_gateway_counts_pair_sharing_an_address_once() -> None:
    devices = [device("gw"), device("gw2")]
    subs = [
        *GW_SUBNETS,
        subnet("gw", LAN, "192.0.2.10/24"),
        subnet("gw2", LAN, "192.0.2.11/24"),
        subnet("gw2", LAN, "192.0.2.1/24"),
    ]
    assert run(one_gateway, network(devices=devices, subnets=subs)) == []


# --- inventory.management-address -----------------------------------------------------------------


def managed(address: str, name: str = "sw", **kw: Any) -> Any:
    return device(name, DeviceRole.SWITCH, management_address=address, **kw)


def test_management_address_reports_dynamic_address() -> None:
    net = network(devices=[device("gw"), managed("192.0.2.120")])
    (f,) = run(management_address, net)
    assert f.severity is Severity.WARNING
    assert "sw is managed at 192.0.2.120, which is in the DHCP pool 192.0.2.100-192.0.2.199" in (
        f.message
    )


def test_management_address_quiet_cases() -> None:
    sw_port = port("sw", "eth0", mac=MAC)
    quiet = [
        network(devices=[device("gw"), managed("192.0.2.20")]),  # outside the pool
        network(  # reserved for the device's MAC
            devices=[device("gw"), managed("192.0.2.120:8443")],
            ports=[sw_port],
            dhcp_servers=[server(reservations=[res("192.0.2.120")])],
        ),
        network(  # MACs unknown, but the address is reserved
            devices=[device("gw"), managed("192.0.2.120")],
            dhcp_servers=[server(reservations=[res("192.0.2.120", "02:00:00:00:00:99")])],
        ),
        network(devices=[device("gw"), managed("switch.home.arpa")]),  # not resolvable
        network(devices=[device("gw"), managed("192.0.2.120", managed_by="ctl")]),
        network(devices=[device("gw"), managed("192.0.2.120", site_id="other")]),
        network(devices=[managed("127.0.0.1", "a"), managed("127.0.0.1", "b")]),
    ]
    for net in quiet:
        assert run(management_address, net) == []


def test_management_address_wrong_reservation_and_host_record() -> None:
    dns = DnsService(
        id="gw/dns",
        device_id="gw",
        host_records=[HostRecord(name="Switch.home.arpa", address=ip("192.0.2.130"))],
    )
    net = network(
        devices=[device("gw"), managed("switch.home.arpa.")],
        ports=[port("sw", "eth0", mac=MAC)],
        dns_services=[dns],
        dhcp_servers=[server(reservations=[res("192.0.2.130", "02:00:00:00:00:99")])],
    )
    (f,) = run(management_address, net)
    assert "managed at 192.0.2.130" in f.message


def test_management_address_reports_duplicates() -> None:
    net = network(
        devices=[
            managed("192.0.2.20", "a"),
            managed("[2001:db8::20]:443", "b"),
            managed("192.0.2.20", "c"),
        ]
    )
    (f,) = run(management_address, net)
    assert f.message == "a, c use the same management address 192.0.2.20"
    assert f.objects == ["a", "c"]


# --- dhcp.duplicate-reservation -------------------------------------------------------------------


def test_duplicate_reservation_quiet_cases() -> None:
    servers = [
        server(reservations=[res("192.0.2.10", hostname="nas")]),
        server(
            seg=IOT,
            router=ip("198.51.100.1"),
            pools=[],
            reservations=[res("198.51.100.10", hostname="nas")],
        ),
        server("old", enabled=False, reservations=[res("192.0.2.20")]),
    ]
    assert run(duplicate_reservation, network(dhcp_servers=servers)) == []


def test_duplicate_reservation_reports_two_addresses_on_two_servers() -> None:
    devices = [device("gw"), device("isp", name="ISP router")]
    servers = [
        server(reservations=[res("192.0.2.10")]),
        server("isp", reservations=[res("192.0.2.20")]),
    ]
    (f,) = run(duplicate_reservation, network(devices=devices, dhcp_servers=servers))
    assert f.message == (
        "02:00:00:00:00:10 has 2 reservations on LAN (VLAN 10): 192.0.2.10 (gw), "
        "192.0.2.20 (ISP router)"
    )
    assert f.severity is Severity.WARNING


def test_duplicate_reservation_same_entry_twice_is_info() -> None:
    srv = server(reservations=[res("192.0.2.10"), res("192.0.2.10")])
    (f,) = run(duplicate_reservation, network(dhcp_servers=[srv]))
    assert f.severity is Severity.INFO and "reserved 2 times" in f.message


def test_duplicate_reservation_reports_host_name_for_two_devices() -> None:
    srv = server(
        reservations=[
            res("192.0.2.10", hostname="Printer"),
            res("192.0.2.11", "02:00:00:00:00:11", hostname="printer.home.arpa"),
        ]
    )
    (f,) = run(duplicate_reservation, network(dhcp_servers=[srv]))
    assert "host name printer is reserved for 2 devices" in f.message


# --- dhcp.domain ----------------------------------------------------------------------------------


def iot_server(**kw: Any) -> DhcpServer:
    return server(seg=IOT, router=ip("198.51.100.1"), pools=[], **kw)


def test_domain_quiet_when_consistent_or_absent() -> None:
    assert run(dhcp_domain, network(dhcp_servers=[server(), iot_server()])) == []
    same = [server(domain="home.arpa"), iot_server(domain="Home.Arpa.")]
    dns = DnsService(
        id="gw/dns",
        device_id="gw",
        host_records=[
            HostRecord(name="nas.home.arpa", address=ip("192.0.2.10")),
            HostRecord(name="nas", address=ip("192.0.2.10")),
            HostRecord(name="vpn.example", address=ip("203.0.113.5")),  # no known network
        ],
    )
    assert run(dhcp_domain, network(dhcp_servers=same, dns_services=[dns])) == []


def test_domain_reports_missing_different_and_local() -> None:
    servers = [server(domain="home.arpa"), iot_server(domain="lan"), server(seg=GUEST, pools=[])]
    msgs = messages(dhcp_domain, network(dhcp_servers=servers))
    assert any("Guest (VLAN 30) gets no domain from DHCP" in m for m in msgs)
    assert any(
        "use different domains (LAN (VLAN 10): home.arpa; IoT (VLAN 20): lan)" in m for m in msgs
    )
    findings = run(dhcp_domain, network(dhcp_servers=[server(domain="home.local")]))
    (f,) = findings
    assert f.severity is Severity.WARNING and ".local is reserved for mDNS" in f.message


def test_domain_reports_host_record_with_other_suffix() -> None:
    dns = DnsService(
        id="gw/dns",
        device_id="gw",
        host_records=[HostRecord(name="nas.lan", address=ip("192.0.2.10"))],
    )
    off = DnsService(id="x/dns", device_id="x", enabled=False, host_records=dns.host_records)
    net = network(dhcp_servers=[server(domain="home.arpa")], dns_services=[dns, off])
    (f,) = run(dhcp_domain, net)
    assert "nas.lan (192.0.2.10) does not end in home.arpa" in f.message
    assert "nas.home.arpa" in str(f.fix)


# --- dhcp.reservation-hostname --------------------------------------------------------------------


def test_reservation_hostname_reports_different_name() -> None:
    srv = server(reservations=[res("192.0.2.10", hostname="printer")])
    net = network(dhcp_servers=[srv], clients=[client(MAC, "192.0.2.10", hostname="nas-1")])
    (f,) = run(reservation_hostname, net)
    assert f.severity is Severity.INFO
    assert "named printer, the device calls itself nas-1" in f.message


def test_reservation_hostname_quiet_cases() -> None:
    srv = server(
        reservations=[
            res("192.0.2.10", hostname="Printer.home.arpa"),
            res("192.0.2.11", "02:00:00:00:00:11", hostname="tv"),
            res("192.0.2.12", "02:00:00:00:00:12", hostname="phone"),
            res("192.0.2.13", "02:00:00:00:00:13"),
            res("192.0.2.14", "02:00:00:00:00:14", hostname="cam"),
            res("192.0.2.15", "02:00:00:00:00:15", hostname="tablet"),
        ]
    )
    clients = [
        client(MAC, hostname="printer"),
        client("02:00:00:00:00:11"),
        client("02:00:00:00:00:12", hostname="android-1a2b3c"),
        client("02:00:00:00:00:13", hostname="laptop"),
        client("02:00:00:00:00:14", hostname="02-00-00-00-00-14"),
        client("02:00:00:00:00:15", hostname="*"),
    ]
    assert run(reservation_hostname, network(dhcp_servers=[srv], clients=clients)) == []


# --- dhcp.dns-cross-network -----------------------------------------------------------------------


def test_dns_cross_network_reports_resolver_in_other_network() -> None:
    subs = [*GW_SUBNETS, subnet("pi", LAN, "192.0.2.53/24", gateway=False)]
    srv = iot_server(dns_servers=[ip("192.0.2.53")])
    (f,) = run(dns_cross_network, network(subnets=subs, dhcp_servers=[srv]))
    assert f.severity is Severity.INFO
    assert f.message == "Clients of IoT (VLAN 20) use 192.0.2.53 in LAN (VLAN 10) as DNS server"
    assert f.objects == [srv.id, LAN]


def test_dns_cross_network_quiet_cases() -> None:
    srv = iot_server(
        dns_servers=[
            ip("192.0.2.1"),  # a router address: answers on every interface
            ip("198.51.100.53"),  # own network
            ip("203.0.113.53"),  # unknown network (outside resolver: dhcp.dns-option)
        ]
    )
    assert run(dns_cross_network, network(dhcp_servers=[srv])) == []


def test_rules_of_other_sites_stay_apart() -> None:
    other = Site(id="cabin", name="Cabin")
    cabin = segment_id(other.id, 10)
    segs = [*SEGMENTS, Segment(id=cabin, site_id=other.id, vlan=10)]
    devices = [device("gw"), device("gw2", site_id=other.id)]
    subs = [*GW_SUBNETS, subnet("gw2", cabin, "203.0.113.254/24")]
    net = network(sites=[SITE, other], segments=segs, devices=devices, subnets=subs)
    assert run(gateway_position, net) == []
