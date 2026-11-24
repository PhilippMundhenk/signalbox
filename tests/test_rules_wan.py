"""WAN uplink rules (#148): passing, failing and silent cases."""

from typing import Any

from factories import SITE, device, iface, ip, uplink
from signalbox.model import (
    Client,
    DeviceRole,
    DnsService,
    Network,
    Segment,
    Site,
    Subnet,
    UplinkKind,
    segment_id,
)
from signalbox.rules import Finding, Rule, Severity, evaluate
from signalbox.rules.builtin import RULES as BUILTIN
from signalbox.rules.wan import RULES, cgnat, dns_mismatch, down, no_ipv6

LAN = segment_id(SITE.id, 10)
IOT = segment_id(SITE.id, 20)
OFFICE = Site(id="office", name="Office")


def subnet(seg: str, address: str, dev: str = "gw") -> Subnet:
    return Subnet(
        id=f"{dev}/subnet/{seg}/{address}",
        segment_id=seg,
        interface=iface(address),
        device_id=dev,
        gateway=True,
    )


def client(n: int, seg: str) -> Client:
    return Client(id=f"gw/client/{n}", mac=f"02:00:00:00:00:{n:02x}", segment_id=seg)


def network(**kw: Any) -> Network:
    values: dict[str, Any] = {
        "sites": [SITE, OFFICE],
        "devices": [device("gw", name="Router"), device("sw", DeviceRole.SWITCH)],
        "segments": [
            Segment(id=LAN, site_id=SITE.id, vlan=10, name="LAN"),
            Segment(id=IOT, site_id=SITE.id, vlan=20, name="IoT"),
        ],
    }
    return Network(**(values | kw))


def run(r: Rule, net: Network) -> list[Finding]:
    return evaluate(net, [r])


def test_registered_with_the_builtin_rules() -> None:
    ids = {r.id for r in BUILTIN}
    assert {r.id for r in RULES} <= ids
    assert [r.id for r in RULES] == ["wan.cgnat", "wan.down", "wan.dns-mismatch", "wan.no-ipv6"]


def test_no_uplinks_reported_all_quiet() -> None:
    net = network(subnets=[subnet(LAN, "192.0.2.1/24")], clients=[client(1, LAN)])
    assert evaluate(net, RULES) == []


# wan.cgnat


def test_cgnat_address_is_reported_with_ipv6_hint() -> None:
    up = uplink("gw", name="pppoe-out1", addresses=[iface("100.64.0.23/32")])
    [f] = run(cgnat, network(uplinks=[up]))
    assert f.severity is Severity.INFO
    assert f.objects == [up.id]
    assert f.message.startswith("The internet connection Router (pppoe-out1) is behind")
    assert "carrier-grade NAT" in f.message
    assert f.fix and "IPv6" in f.fix and f.fix.startswith("Reach")


def test_cgnat_without_ipv6_suggests_asking_the_provider() -> None:
    up = uplink("gw", addresses=[iface("100.100.1.2/10")], delegated_prefixes=[])
    [f] = run(cgnat, network(uplinks=[up]))
    assert f.fix and f.fix.startswith("Ask the provider")


def test_dslite_is_reported() -> None:
    up = uplink("gw", kind=UplinkKind.DSLITE, addresses=[iface("2001:db8:ffff::2/64")])
    [f] = run(cgnat, network(uplinks=[up]))
    assert "DS-Lite" in f.message


def test_public_private_map_e_and_ipv6_only_are_quiet() -> None:
    for up in [
        uplink("gw"),
        uplink("gw", addresses=[iface("10.0.0.2/24")]),
        uplink("gw", kind=UplinkKind.MAP_E),
        uplink("gw", addresses=[iface("2001:db8:ffff::2/64")]),
        uplink("gw", kind=UplinkKind.BRIDGE, addresses=[], delegated_prefixes=[]),
    ]:
        assert run(cgnat, network(uplinks=[up])) == []


def test_cgnat_backup_line_next_to_a_public_line_is_quiet() -> None:
    lte = uplink("gw", name="lte1", kind=UplinkKind.LTE, addresses=[iface("100.64.7.7/32")])
    assert run(cgnat, network(uplinks=[uplink("gw"), lte])) == []
    # ... but reported once the public line is down
    public_down = uplink("gw", up=False)
    [f] = run(cgnat, network(uplinks=[public_down, lte]))
    assert f.objects == [lte.id]


def test_down_cgnat_uplink_is_quiet() -> None:
    up = uplink("gw", up=False, addresses=[iface("100.64.0.23/32")])
    assert run(cgnat, network(uplinks=[up])) == []


def test_cgnat_range_used_by_a_known_router_is_double_nat_not_cgnat() -> None:
    upstream = subnet(LAN, "100.64.1.1/24", dev="isp-box")
    up = uplink("gw", addresses=[iface("100.64.1.20/24")])
    net = network(
        devices=[device("gw", name="Router"), device("isp-box")], subnets=[upstream], uplinks=[up]
    )
    assert run(cgnat, net) == []


def test_cgnat_per_site() -> None:
    office = device("ogw", site_id=OFFICE.id, name="Office router")
    net = network(
        devices=[device("gw", name="Router"), office],
        uplinks=[uplink("gw"), uplink("ogw", addresses=[iface("100.64.0.9/32")])],
    )
    [f] = run(cgnat, net)
    assert "Office router" in f.message


# wan.down


def test_down_without_other_line_is_a_warning() -> None:
    up = uplink("gw", up=False, since=None)
    [f] = run(down, network(uplinks=[up]))
    assert f.severity is Severity.WARNING
    assert f.message == "The internet connection Router (wan) is down"
    assert f.objects == [up.id]


def test_down_backup_line_is_info_and_names_the_working_one() -> None:
    lte = uplink("gw", name="lte1", up=False)
    [f] = run(down, network(uplinks=[uplink("gw"), lte]))
    assert f.severity is Severity.INFO
    assert f.message.endswith("is down; the internet works through wan")


def test_up_or_unknown_state_is_quiet() -> None:
    assert run(down, network(uplinks=[uplink("gw"), uplink("gw", name="b", up=None)])) == []


def test_down_uplink_without_name() -> None:
    up = uplink("gw", up=False, name=None)
    [f] = run(down, network(uplinks=[up]))
    assert f.message == "The internet connection Router is down"


# wan.dns-mismatch


def dns(*forwarders: str, dev: str = "gw", **kw: Any) -> DnsService:
    return DnsService(id=f"{dev}/dns", device_id=dev, forwarders=[ip(f) for f in forwarders], **kw)


def test_forwarder_on_the_wan_network_not_handed_out_is_reported() -> None:
    up = uplink("gw")  # 198.51.100.23/24, DNS 198.51.100.53
    [f] = run(dns_mismatch, network(uplinks=[up], dns_services=[dns("198.51.100.99")]))
    assert f.severity is Severity.INFO
    assert f.objects == ["gw/dns", up.id]
    assert "forwards DNS to 198.51.100.99" in f.message
    assert "hands out 198.51.100.53, 2001:db8:ffff::53" in f.message


def test_ipv6_forwarder_on_the_wan_network() -> None:
    up = uplink("gw")
    [f] = run(dns_mismatch, network(uplinks=[up], dns_services=[dns("2001:db8:ffff::99")]))
    assert "2001:db8:ffff::99" in f.message


def test_dns_choices_are_quiet() -> None:
    up = uplink("gw")
    for fwd in [
        "198.51.100.53",  # what the provider hands out
        "198.51.100.1",  # the upstream gateway (modem)
        "198.51.100.23",  # its own address
        "203.0.113.53",  # a public resolver of the user's choice
        "192.0.2.53",  # a local Pi-hole
        "198.51.100.2",  # a known device on the WAN side
    ]:
        net = network(
            devices=[
                device("gw", name="Router"),
                device("modem", management_address="198.51.100.2"),
            ],
            uplinks=[up],
            dns_services=[dns(fwd)],
        )
        assert run(dns_mismatch, net) == [], fwd


def test_dns_mismatch_quiet_without_provider_dns_or_when_down_or_other_device() -> None:
    fwd = dns("198.51.100.99")
    assert (
        run(dns_mismatch, network(uplinks=[uplink("gw", dns_servers=[])], dns_services=[fwd])) == []
    )
    assert run(dns_mismatch, network(uplinks=[uplink("gw", up=False)], dns_services=[fwd])) == []
    other = dns("198.51.100.99", dev="pihole")
    assert run(dns_mismatch, network(uplinks=[uplink("gw")], dns_services=[other])) == []
    off = dns("198.51.100.99", enabled=False)
    assert run(dns_mismatch, network(uplinks=[uplink("gw")], dns_services=[off])) == []


def test_dns_mismatch_ignores_bad_management_address() -> None:
    net = network(
        devices=[device("gw", name="Router", management_address="router.example")],
        uplinks=[uplink("gw")],
        dns_services=[dns("198.51.100.99")],
    )
    assert len(run(dns_mismatch, net)) == 1


# wan.no-ipv6


def lan_v4(**kw: Any) -> Network:
    subs = [subnet(LAN, "192.0.2.1/24"), subnet(IOT, "198.51.100.1/25"), *kw.pop("extra", [])]
    return network(subnets=subs, clients=[client(1, LAN), client(2, IOT)], **kw)


def test_delegated_prefix_unused_is_reported() -> None:
    up = uplink("gw")
    net = lan_v4(uplinks=[up], extra=[subnet(LAN, "fe80::1/64")])
    [f] = run(no_ipv6, net)
    assert f.severity is Severity.INFO and not f.incomplete
    assert f.objects == [up.id]
    assert "delegated IPv6 prefix (/56)" in f.message


def test_ula_only_counts_as_no_ipv6() -> None:
    net = lan_v4(uplinks=[uplink("gw")], extra=[subnet(LAN, "fd00:1::1/64")])
    assert len(run(no_ipv6, net)) == 1


def test_no_ipv6_reported_at_all_is_incomplete() -> None:
    [f] = run(no_ipv6, lan_v4(uplinks=[uplink("gw")]))
    assert f.incomplete
    assert "reported no IPv6 on its networks" in f.message


def test_ipv6_on_a_client_network_is_quiet() -> None:
    for extra in [
        subnet(LAN, "2001:db8:100:10::1/64"),  # from the delegated prefix
        subnet(IOT, "2001:db8:200::1/64"),  # another global prefix (tunnel)
        subnet(segment_id(SITE.id, 99), "2001:db8:100:99::1/64", dev="r2"),  # downstream router
    ]:
        devices = [device("gw", name="Router"), device("r2")]
        net = lan_v4(uplinks=[uplink("gw")], extra=[extra], devices=devices)
        assert run(no_ipv6, net) == [], extra.id


def test_no_ipv6_quiet_without_prefix_clients_or_when_down() -> None:
    assert run(no_ipv6, lan_v4(uplinks=[uplink("gw", delegated_prefixes=[])])) == []
    assert run(no_ipv6, lan_v4(uplinks=[uplink("gw", up=False)])) == []
    no_clients = network(subnets=[subnet(LAN, "192.0.2.1/24")], uplinks=[uplink("gw")])
    assert run(no_ipv6, no_clients) == []
    unknown = network(uplinks=[uplink("ghost")])
    assert run(no_ipv6, unknown) == []
