from typing import Any

from factories import SITE, device, iface, ip
from signalbox.model import (
    Client,
    DeviceRole,
    DhcpPool,
    DhcpServer,
    DnsService,
    HostRecord,
    Network,
    ReadError,
    Reservation,
    Segment,
    Site,
    Subnet,
    segment_id,
)
from signalbox.rules import Finding, Rule, evaluate
from signalbox.rules.dns import (
    conflicting_records,
    forwarder_loop,
    forwarder_missing,
    host_record_dynamic,
    host_record_reservation,
    host_record_stale,
    single_forwarder,
)

LAN = segment_id(SITE.id, 10)
OTHER = Site(id="away", name="Away")
CAPS = ["interfaces", "dhcp", "dns", "clients"]


def subnet(dev: str, address: str, seg: str = LAN, gateway: bool = True) -> Subnet:
    return Subnet(
        id=f"{dev}/subnet/{address}",
        segment_id=seg,
        interface=iface(address),
        device_id=dev,
        gateway=gateway,
    )


def dns(dev: str, *records: tuple[str, str], **kw: Any) -> DnsService:
    return DnsService(
        id=f"{dev}/dns/{kw.get('name') or 'main'}",
        device_id=dev,
        listen=[ip(a) for a in kw.pop("listen", [])],
        # "192.0.2.1", or with a port: "192.0.2.1:5353", "[2001:db8::1]:5353"
        forwarders=list(kw.pop("forwarders", ["203.0.113.53", "198.51.100.53"])),
        host_records=[HostRecord(name=n, address=ip(a)) for n, a in records],
        **kw,
    )


def dhcp(dev: str = "gw", *reservations: tuple[str | None, str], **kw: Any) -> DhcpServer:
    return DhcpServer(
        id=f"{dev}/dhcp/lan",
        device_id=dev,
        segment_id=kw.pop("segment", LAN),
        enabled=kw.pop("enabled", True),
        pools=[DhcpPool(start=ip(s), end=ip(e)) for s, e in kw.pop("pools", [])],
        dns_servers=[ip(a) for a in kw.pop("dns_servers", [])],
        reservations=[
            Reservation(mac=f"02:00:00:00:01:{i:02x}", address=ip(a), hostname=h)
            for i, (h, a) in enumerate(reservations)
        ],
        **kw,
    )


def client(n: int, *addresses: str, seg: str | None = LAN) -> Client:
    return Client(
        id=f"gw/client/{n}",
        mac=f"02:00:00:00:00:{n:02x}",
        addresses=[ip(a) for a in addresses],
        segment_id=seg,
    )


def network(**kw: Any) -> Network:
    devices = kw.pop(
        "devices",
        [
            device("gw", capabilities=CAPS, management_address="192.0.2.1"),
            device("mt", DeviceRole.SWITCH, capabilities=CAPS, management_address="sw.example"),
        ],
    )
    return Network(
        sites=[SITE, OTHER],
        devices=devices,
        segments=[Segment(id=LAN, site_id=SITE.id, vlan=10, name="LAN")],
        subnets=kw.pop("subnets", [subnet("gw", "192.0.2.1/24"), subnet("mt", "192.0.2.2/24")]),
        **kw,
    )


def run(r: Rule, net: Network) -> list[Finding]:
    return [f for f in evaluate(net, [r]) if f.rule_id == r.id]


# --- dns.host-record-reservation ----------------------------------------------------------------


def test_host_record_matches_reservation() -> None:
    net = network(
        dns_services=[
            dns("gw", ("nas.home.example", "192.0.2.10"), ("NAS.home.example", "2001:db8:1::10"))
        ],
        dhcp_servers=[dhcp("mt", ("nas", "192.0.2.10"), (None, "192.0.2.11"))],
    )
    assert run(host_record_reservation, net) == []


def test_host_record_differs_from_reservation() -> None:
    net = network(
        dns_services=[dns("gw", ("nas.home.example", "192.0.2.20"))],
        dhcp_servers=[dhcp("mt", ("NAS", "192.0.2.10"))],
    )
    (f,) = run(host_record_reservation, net)
    assert f.severity == "warning"
    assert f.message == (
        "The DNS record nas points to 192.0.2.20, the DHCP reservation for nas is 192.0.2.10"
    )
    assert f.objects == ["gw/dns/main", "mt/dhcp/lan"] and f.fix


def test_round_robin_records_are_compared_as_sets() -> None:
    records = [("www", "192.0.2.30"), ("www", "192.0.2.31")]
    reservations = [("www", "192.0.2.30"), ("www", "192.0.2.31")]
    net = network(dns_services=[dns("gw", *records)], dhcp_servers=[dhcp("gw", *reservations)])
    assert run(host_record_reservation, net) == []
    net = network(dns_services=[dns("gw", *records)], dhcp_servers=[dhcp("gw", reservations[0])])
    assert len(run(host_record_reservation, net)) == 1


def test_host_record_on_a_reserved_address_with_another_name_is_info() -> None:
    net = network(
        dns_services=[dns("gw", ("files.home.example", "192.0.2.10"))],
        dhcp_servers=[dhcp("mt", ("nas", "192.0.2.10"))],
    )
    (f,) = run(host_record_reservation, net)
    assert f.severity == "info" and not f.incomplete
    assert f.message == (
        "The DNS record files.home.example points to 192.0.2.10, which is reserved in DHCP for nas"
    )


def test_host_record_reservation_stays_quiet_across_sites_and_for_disabled_servers() -> None:
    devices = [device("gw"), device("far", site_id=OTHER.id)]
    net = network(
        devices=devices,
        dns_services=[dns("gw", ("nas", "192.0.2.20")), dns("ghost", ("nas", "192.0.2.21"))],
        dhcp_servers=[
            dhcp("far", ("nas", "192.0.2.10")),
            dhcp("gw", ("nas", "192.0.2.11"), enabled=False),
            dhcp("ghost", ("nas", "192.0.2.12")),
        ],
    )
    assert run(host_record_reservation, net) == []


# --- dns.host-record-stale ----------------------------------------------------------------------


def test_host_records_that_point_to_known_addresses_pass() -> None:
    records = [
        ("nas", "192.0.2.10"),  # a client
        ("router", "192.0.2.1"),  # a router interface
        ("switch", "192.0.2.2"),  # a device interface
        ("printer", "192.0.2.50"),  # a reservation
        ("blocked", "0.0.0.0"),
        ("local", "127.0.0.1"),
    ]
    net = network(
        devices=[device("gw", capabilities=CAPS)],
        subnets=[subnet("gw", "192.0.2.1/24"), subnet("mt", "192.0.2.2/24")],
        dns_services=[dns("gw", *records)],
        dhcp_servers=[dhcp("gw", ("printer", "192.0.2.50"))],
        clients=[client(1, "192.0.2.10")],
    )
    net = net.model_copy(update={"devices": [*net.devices, device("mt")]})
    assert run(host_record_stale, net) == []


def test_host_record_to_an_unused_local_address_is_info() -> None:
    net = network(
        dns_services=[dns("gw", ("camera", "192.0.2.77"))], clients=[client(1, "192.0.2.10")]
    )
    (f,) = run(host_record_stale, net)
    assert f.severity == "info" and not f.incomplete
    assert f.message == (
        "The DNS record camera on gw points to 192.0.2.77 on LAN (VLAN 10), which no known "
        "device uses"
    )


def test_host_record_outside_every_network_is_a_warning() -> None:
    net = network(dns_services=[dns("gw", ("old", "198.51.100.7"))])
    (f,) = run(host_record_stale, net)
    assert f.severity == "warning"
    assert "198.51.100.7, which is not in any network Signalbox knows" in f.message


def test_host_record_stale_stays_quiet_without_client_data() -> None:
    no_clients = [device("gw", capabilities=["dns"]), device("mt", capabilities=["clients"])]
    errors = [ReadError(device_id="mt", capability="clients", message="timeout")]
    records = [("camera", "192.0.2.77"), ("cam6", "2001:db8:1::77")]
    subnets = [subnet("gw", "192.0.2.1/24"), subnet("gw", "2001:db8:1::1/64")]
    net = network(
        devices=no_clients, errors=errors, subnets=subnets, dns_services=[dns("gw", *records)]
    )
    assert run(host_record_stale, net) == []
    # IPv4 clients known, but no IPv6 neighbours: only the IPv4 record is checked
    net = network(
        subnets=subnets, dns_services=[dns("gw", *records)], clients=[client(1, "192.0.2.10")]
    )
    assert [f.message.split()[3] for f in run(host_record_stale, net)] == ["camera"]


# --- dns.host-record-dynamic --------------------------------------------------------------------


def test_host_record_outside_pool_or_reserved_passes() -> None:
    net = network(
        dns_services=[
            dns("gw", ("nas", "192.0.2.10"), ("tv", "192.0.2.150"), ("v6", "2001:db8::1"))
        ],
        dhcp_servers=[
            dhcp("gw", ("tv", "192.0.2.150"), pools=[("192.0.2.199", "192.0.2.100")]),
            dhcp("mt", pools=[("192.0.2.100", "192.0.2.199")], enabled=False),
        ],
    )
    assert run(host_record_dynamic, net) == []


def test_host_record_inside_pool_is_a_warning() -> None:
    net = network(
        dns_services=[dns("gw", ("printer", "192.0.2.150"))],
        dhcp_servers=[dhcp("mt", pools=[("192.0.2.100", "192.0.2.199")])],
    )
    (f,) = run(host_record_dynamic, net)
    assert f.severity == "warning"
    assert f.message == (
        "The DNS record printer points to 192.0.2.150, a dynamic address of LAN (VLAN 10) "
        "(pool 192.0.2.100-192.0.2.199)"
    )
    assert f.objects == ["gw/dns/main", "mt/dhcp/lan"] and "reservation" in str(f.fix)


def test_host_record_dynamic_compares_per_site() -> None:
    devices = [device("gw"), device("far", site_id=OTHER.id)]
    net = network(
        devices=devices,
        dns_services=[dns("gw", ("printer", "192.0.2.150"))],
        dhcp_servers=[
            dhcp("far", pools=[("192.0.2.100", "192.0.2.199")]),
            dhcp("ghost", pools=[("192.0.2.100", "192.0.2.199")]),
        ],
    )
    assert run(host_record_dynamic, net) == []


# --- dns.forwarder-loop -------------------------------------------------------------------------


def test_forwarders_to_upstream_or_recursive_resolver_pass() -> None:
    net = network(
        dns_services=[
            dns("gw", forwarders=["192.0.2.2"]),  # to mt
            dns("mt", forwarders=[]),  # recursive
        ]
    )
    assert run(forwarder_loop, net) == []


def test_two_resolvers_forwarding_to_each_other_loop() -> None:
    net = network(
        dns_services=[
            dns("gw", listen=["192.0.2.1"], forwarders=["192.0.2.2"]),
            dns("mt", forwarders=["192.0.2.1", "203.0.113.53"]),
        ]
    )
    (f,) = run(forwarder_loop, net)
    assert f.severity == "error"
    assert f.message == (
        "DNS lookups loop: gw forwards to 192.0.2.2 (mt), mt forwards to 192.0.2.1 (gw)"
    )
    assert f.objects == ["gw/dns/main", "mt/dns/main"] and f.fix


def test_a_resolver_forwarding_to_itself_loops() -> None:
    net = network(dns_services=[dns("gw", forwarders=["192.0.2.1"])])
    (f,) = run(forwarder_loop, net)
    assert f.message == "DNS lookups loop: gw forwards to 192.0.2.1, itself"


def test_disabled_services_do_not_count() -> None:
    net = network(
        dns_services=[
            dns("gw", forwarders=["192.0.2.2"]),
            dns("mt", forwarders=["192.0.2.1"], enabled=False),
        ]
    )
    assert run(forwarder_loop, net) == []


def test_adguard_home_and_unbound_on_one_router_are_not_a_loop() -> None:
    """#241, the reported setup: AdGuard Home (unread) on 53, Unbound on 53530 forwarding to
    the router's own address on port 53."""
    adguard = dns("gw", name="adguardhome", forwarders=[], config_read=False)
    unbound = dns("gw", name="unbound", port=53530, forwarders=["192.0.2.1"])
    net = network(dns_services=[adguard, unbound])
    (f,) = run(forwarder_loop, net)
    assert f.incomplete and f.severity == "info"
    assert f.message == (
        "gw (unbound) forwards DNS to 192.0.2.1, the DNS service gw (adguardhome) that "
        "Signalbox does not read: whether lookups come back in a loop cannot be checked"
    )
    assert f.objects == ["gw/dns/adguardhome", "gw/dns/unbound"]
    assert run(single_forwarder, net) == []  # AdGuard's upstreams are not known
    # AdGuard not even recognised: a port of the router where no known service listens
    (f,) = run(forwarder_loop, network(dns_services=[unbound]))
    assert f.incomplete and "port 53 of gw, where another DNS server" in f.message


def test_forward_to_another_port_of_the_device_is_another_service() -> None:
    for fwd in ("127.0.0.1:5353", "192.0.2.1:5353", "[::1]:5353"):
        net = network(dns_services=[dns("gw", forwarders=[fwd])])
        (f,) = run(forwarder_loop, net)
        assert f.incomplete, fwd
    # the same port is a loop, also through loopback
    for fwd in ("127.0.0.1", "192.0.2.1:53", "[::1]:53"):
        (f,) = run(forwarder_loop, network(dns_services=[dns("gw", forwarders=[fwd])]))
        assert not f.incomplete and f.message.endswith(", itself"), fwd


def test_two_services_on_one_router_can_still_loop() -> None:
    dnsmasq = dns("gw", name="dnsmasq", forwarders=["127.0.0.1:53530"])
    unbound = dns("gw", name="unbound", port=53530, forwarders=["192.0.2.1"])
    (f,) = run(forwarder_loop, network(dns_services=[dnsmasq, unbound]))
    assert not f.incomplete and f.message == (
        "DNS lookups loop: gw (dnsmasq) forwards to 127.0.0.1:53530 (gw (unbound)), "
        "gw (unbound) forwards to 192.0.2.1 (gw (dnsmasq))"
    )
    # Unbound resolving itself: a chain, not a loop
    unbound = dns("gw", name="unbound", port=53530, forwarders=[])
    assert run(forwarder_loop, network(dns_services=[dnsmasq, unbound])) == []
    assert run(single_forwarder, network(dns_services=[dnsmasq, unbound])) == []


def test_port_must_match_across_devices() -> None:
    net = network(
        dns_services=[
            dns("gw", listen=["192.0.2.1"], forwarders=["192.0.2.2:5353"]),
            dns("mt", forwarders=["192.0.2.1"]),
        ]
    )
    (f,) = run(forwarder_loop, net)
    assert f.incomplete and f.objects == ["gw/dns/main"]
    net = network(
        dns_services=[
            dns("gw", listen=["192.0.2.1"], forwarders=["192.0.2.2:5353"]),
            dns("mt", port=5353, forwarders=["192.0.2.1"]),
        ]
    )
    (f,) = run(forwarder_loop, net)
    assert f.message == (
        "DNS lookups loop: gw forwards to 192.0.2.2:5353 (mt), mt forwards to 192.0.2.1 (gw)"
    )


# --- dns.forwarder-missing ----------------------------------------------------------------------


def test_forwarder_and_dhcp_dns_that_exist_pass() -> None:
    net = network(
        dns_services=[dns("gw", forwarders=["192.0.2.53", "203.0.113.53"])],
        dhcp_servers=[dhcp("gw", dns_servers=["192.0.2.1", "192.0.2.2"])],
        clients=[client(1, "192.0.2.53")],
    )
    assert run(forwarder_missing, net) == []


def test_missing_local_forwarder_is_an_error_when_it_is_the_only_one() -> None:
    net = network(
        dns_services=[dns("gw", forwarders=["192.0.2.53"])],
        dhcp_servers=[dhcp("mt", dns_servers=["192.0.2.53", "192.0.2.1"])],
        clients=[client(1, "192.0.2.10")],
    )
    found = run(forwarder_missing, net)
    assert [(f.severity, f.message) for f in found] == [
        (
            "error",
            "gw forwards DNS to 192.0.2.53, but no device on LAN (VLAN 10) uses that address",
        ),
        (
            "warning",
            "mt hands out the DNS server 192.0.2.53, but no device on LAN (VLAN 10) uses that "
            "address",
        ),
    ]


def test_forwarder_missing_stays_quiet_without_client_data_or_outside() -> None:
    net = network(
        devices=[device("gw", capabilities=["dns"])],
        dns_services=[dns("gw", forwarders=["192.0.2.53", "2001:db8:1::53", "203.0.113.53"])],
        dhcp_servers=[dhcp("gw", dns_servers=["192.0.2.54"], enabled=False)],
        subnets=[subnet("gw", "192.0.2.1/24"), subnet("gw", "2001:db8:1::1/64")],
    )
    assert run(forwarder_missing, net) == []
    # clients known for IPv4 only: the IPv6 forwarder may be an unseen neighbour
    net = network(
        dns_services=[dns("gw", forwarders=["2001:db8:1::53"])],
        subnets=[subnet("gw", "192.0.2.1/24"), subnet("gw", "2001:db8:1::1/64")],
        clients=[client(1, "192.0.2.10")],
    )
    assert run(forwarder_missing, net) == []
    net = net.model_copy(update={"clients": [client(1, "2001:db8:1::10")]})
    assert len(run(forwarder_missing, net)) == 1


# --- dns.single-forwarder -----------------------------------------------------------------------


def test_two_upstreams_or_recursive_pass() -> None:
    assert run(single_forwarder, network(dns_services=[dns("gw")])) == []
    assert run(single_forwarder, network(dns_services=[dns("gw", forwarders=[])])) == []


def test_single_upstream_is_info() -> None:
    (f,) = run(single_forwarder, network(dns_services=[dns("gw", forwarders=["203.0.113.53"])]))
    assert f.severity == "info" and f.message == "gw forwards DNS only to 203.0.113.53" and f.fix


def test_forwarders_of_one_device_count_as_one() -> None:
    subnets = [subnet("gw", "192.0.2.1/24"), subnet("mt", "192.0.2.2/24")]
    subnets.append(subnet("mt", "2001:db8:1::2/64"))
    net = network(
        subnets=subnets, dns_services=[dns("gw", forwarders=["192.0.2.2", "2001:db8:1::2"])]
    )
    (f,) = run(single_forwarder, net)
    assert f.message == "gw forwards DNS only to mt (192.0.2.2, 2001:db8:1::2)"


def test_single_forwarder_follows_the_chain() -> None:
    # gw forwards only to mt, which has two upstreams: fine
    good = [dns("gw", forwarders=["192.0.2.2"]), dns("mt")]
    assert run(single_forwarder, network(dns_services=good)) == []
    # mt again has only one: both are reported
    bad = [dns("gw", forwarders=["192.0.2.2"]), dns("mt", forwarders=["203.0.113.53"])]
    assert [f.objects for f in run(single_forwarder, network(dns_services=bad))] == [
        ["gw/dns/main"],
        ["mt/dns/main"],
    ]
    # a loop is reported by dns.forwarder-loop, not here
    loop = [dns("gw", forwarders=["192.0.2.2"]), dns("mt", forwarders=["192.0.2.1"])]
    assert run(single_forwarder, network(dns_services=loop)) == []


# --- dns.conflicting-records --------------------------------------------------------------------


def test_same_records_on_every_resolver_pass() -> None:
    net = network(
        dns_services=[
            dns("gw", ("nas.home.example", "192.0.2.10"), ("nas", "2001:db8:1::10")),
            dns("mt", ("NAS", "192.0.2.10"), ("www", "192.0.2.30"), ("www", "192.0.2.31")),
            dns("far", ("nas", "192.0.2.99")),  # another site
        ],
        dhcp_servers=[dhcp("gw", domain="home.example")],
        devices=[device("gw"), device("mt"), device("far", site_id=OTHER.id)],
    )
    assert run(conflicting_records, net) == []


def test_name_with_different_addresses_on_two_resolvers() -> None:
    net = network(
        dns_services=[
            dns("gw", ("nas.home.example.", "192.0.2.10")),
            dns("mt", ("nas", "192.0.2.20")),
        ],
        dhcp_servers=[dhcp("gw", domain="Home.Example")],
    )
    (f,) = run(conflicting_records, net)
    assert f.severity == "warning"
    assert f.message == "nas resolves to 192.0.2.10 on gw and to 192.0.2.20 on mt"
    assert f.objects == ["gw/dns/main", "mt/dns/main"] and f.fix


def test_conflicting_records_stays_quiet_for_round_robin_on_one_resolver() -> None:
    net = network(dns_services=[dns("gw", ("nas", "192.0.2.10"), ("nas", "192.0.2.20"))])
    assert run(conflicting_records, net) == []
    # without the local domain known, nas and nas.home.example are different names
    net = network(
        dns_services=[
            dns("gw", ("nas", "192.0.2.10")),
            dns("mt", ("nas.home.example", "192.0.2.20")),
        ]
    )
    assert run(conflicting_records, net) == []


def test_host_record_to_a_network_of_another_site_is_not_stale_here() -> None:
    devices = [device("gw", capabilities=CAPS), device("far", site_id=OTHER.id)]
    subnets = [
        subnet("gw", "192.0.2.1/24"),
        subnet("far", "198.51.100.1/24", seg="away/segment/native"),
    ]
    net = network(
        devices=devices,
        subnets=subnets,
        dns_services=[dns("gw", ("remote", "198.51.100.9"))],
        clients=[client(1, "192.0.2.10")],
    )
    assert run(host_record_stale, net) == []
