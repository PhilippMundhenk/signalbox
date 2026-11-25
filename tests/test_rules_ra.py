"""ipv6.ra-consistent (#72, #151): router advertisements and DHCPv6 settings agree."""

from __future__ import annotations

from datetime import UTC, datetime
from ipaddress import IPv6Network

from factories import SITE, device, dhcp_server, iface, ip
from signalbox.model import (
    DeviceRole,
    Dhcp6Mode,
    Dhcp6PrefixPool,
    Dhcp6Server,
    ForeignServer,
    Network,
    RaMode,
    RaPrefix,
    RouterAdvert,
    Segment,
    ServerKind,
    ServerOffer,
    SightingSource,
    Subnet,
    Uplink,
    segment_id,
)
from signalbox.rules import Finding, evaluate
from signalbox.rules.ra_consistency import ra_consistent

LAN = segment_id(SITE.id, 10)
NOW = datetime(2026, 1, 15, tzinfo=UTC)
P48 = IPv6Network("2001:db8:2::/48")


def adv(dev: str = "gw", mode: RaMode = RaMode.STATEFUL, **kw: object) -> RouterAdvert:
    return RouterAdvert(
        id=f"{dev}/ra/10",
        device_id=dev,
        segment_id=LAN,
        mode=mode,
        **kw,  # type: ignore[arg-type]
    )


def srv6(dev: str = "gw", mode: Dhcp6Mode = Dhcp6Mode.STATEFUL, **kw: object) -> Dhcp6Server:
    return Dhcp6Server(
        id=f"{dev}/dhcp6/lan",
        device_id=dev,
        segment_id=LAN,
        enabled=True,
        mode=mode,
        **kw,  # type: ignore[arg-type]
    )


def net(**kw: object) -> Network:
    return Network(
        sites=[SITE],
        devices=[device("gw"), device("rt2", DeviceRole.GATEWAY)],
        segments=[Segment(id=LAN, site_id=SITE.id, vlan=10, name="LAN")],
        **kw,  # type: ignore[arg-type]
    )


def run(n: Network) -> list[Finding]:
    return [f for f in evaluate(n, [ra_consistent]) if f.rule_id == ra_consistent.id]


def subnet(dev: str, address: str) -> Subnet:
    return Subnet(
        id=f"{dev}/subnet/{address}",
        segment_id=LAN,
        interface=iface(address),
        device_id=dev,
        gateway=True,
    )


def seen(kind: ServerKind, known: str | None = None, **offer: object) -> ForeignServer:
    return ForeignServer(
        id=f"home/foreign/{kind.value}/10/x",
        site_id=SITE.id,
        segment_id=LAN,
        kind=kind,
        server_address=ip("2001:db8:1::99"),
        offered=ServerOffer(**offer),  # type: ignore[arg-type]
        first_seen=NOW,
        last_seen=NOW,
        source=SightingSource.PROBE,
        known_as=known,
    )


def test_stays_quiet_without_router_advertisement_data() -> None:
    assert run(net()) == []
    assert run(net(dhcp6_servers=[srv6()])) == []


def test_managed_flag_without_a_dhcpv6_server() -> None:
    (f,) = run(net(router_adverts=[adv()]))
    assert "managed flag on LAN (VLAN 10)" in f.message and "no DHCPv6 server" in f.message
    assert f.severity == "warning" and f.fix
    assert f.message_id == "ra.noServer" and f.fix_id == "ra.noServer.fix"
    assert f.objects == [LAN, "gw/ra/10"]


def test_other_flag_alone_also_needs_a_server() -> None:
    (f,) = run(net(router_adverts=[adv(mode=RaMode.STATELESS)]))
    assert "other-config flag" in f.message


def test_a_prefix_delegation_only_server_answers_no_clients() -> None:
    pd = srv6(mode=Dhcp6Mode.STATELESS, prefix_pools=[Dhcp6PrefixPool(prefix=P48, length=56)])
    (f,) = run(net(router_adverts=[adv()], dhcp6_servers=[pd]))
    assert f.message_id == "ra.noServer"
    # and it needs no flag of its own
    assert run(net(router_adverts=[adv(mode=RaMode.SLAAC)], dhcp6_servers=[pd])) == []


def test_slaac_needs_no_server() -> None:
    assert run(net(router_adverts=[adv(mode=RaMode.SLAAC)])) == []
    assert run(net(router_adverts=[adv(mode=RaMode.OFF)])) == []


def test_a_server_seen_by_the_probe_or_a_server_read_counts() -> None:
    assert run(net(router_adverts=[adv()], dhcp6_servers=[srv6("rt2")])) == []
    assert run(net(router_adverts=[adv()], foreign_servers=[seen(ServerKind.DHCPV6)])) == []
    off = srv6().model_copy(update={"enabled": False})
    assert len(run(net(router_adverts=[adv()], dhcp6_servers=[off]))) == 1


def test_stateful_server_without_the_managed_flag() -> None:
    n = net(router_adverts=[adv(mode=RaMode.SLAAC)], dhcp6_servers=[srv6()])
    (f,) = run(n)
    assert "do not set the managed flag" in f.message
    assert f.message_id == "ra.flagOff"


def test_stateless_server_needs_the_other_flag_only() -> None:
    server = srv6(mode=Dhcp6Mode.STATELESS)
    assert run(net(router_adverts=[adv(mode=RaMode.STATELESS)], dhcp6_servers=[server])) == []
    (f,) = run(net(router_adverts=[adv(mode=RaMode.SLAAC)], dhcp6_servers=[server]))
    assert "other-config" in f.message


def test_server_without_any_advertisement() -> None:
    n = net(router_adverts=[adv(mode=RaMode.OFF)], dhcp6_servers=[srv6()])
    (f,) = run(n)
    assert f.message_id == "ra.noAdverts"


def test_a_server_of_a_segment_nobody_read_advertisements_for_is_quiet() -> None:
    assert run(net(dhcp6_servers=[srv6()])) == []


def test_dns_in_advertisements_differs_from_dhcpv6() -> None:
    a = adv(rdnss=[ip("2001:db8:1::1")])
    s = srv6(dns_servers=[ip("2001:db8:1::53")])
    (f,) = run(net(router_adverts=[a], dhcp6_servers=[s]))
    assert f.message_id == "ra.dnsDiffers" and "2001:db8:1::53" in f.message
    same = srv6(dns_servers=[ip("2001:db8:1::1")])
    assert run(net(router_adverts=[a], dhcp6_servers=[same])) == []
    assert run(net(router_adverts=[a], dhcp6_servers=[srv6()])) == []  # none handed out: no data


def test_two_routers_with_different_prefixes_or_flags() -> None:
    a = adv("gw", prefixes=[RaPrefix(prefix=IPv6Network("2001:db8:1::/64"), autonomous=True)])
    b = adv("rt2", prefixes=[RaPrefix(prefix=IPv6Network("2001:db8:2::/64"), autonomous=True)])
    n = net(router_adverts=[a, b], dhcp6_servers=[srv6()])
    found = run(n)
    assert [f.message_id for f in found] == ["ra.prefixesDiffer"]
    c = adv("rt2", mode=RaMode.SLAAC, prefixes=a.prefixes)
    found = run(net(router_adverts=[a, c], dhcp6_servers=[srv6()]))
    assert [f.message_id for f in found] == ["ra.flagsDiffer"]
    same = adv("rt2", prefixes=a.prefixes)
    assert run(net(router_adverts=[a, same], dhcp6_servers=[srv6()])) == []


def test_prefixes_default_to_the_routers_own_ipv6_networks() -> None:
    subnets = [subnet("gw", "2001:db8:1::1/64"), subnet("rt2", "2001:db8:2::1/64")]
    n = net(router_adverts=[adv("gw"), adv("rt2")], subnets=subnets, dhcp6_servers=[srv6()])
    assert [f.message_id for f in run(n)] == ["ra.prefixesDiffer"]


def test_probe_data_of_a_known_router_without_settings() -> None:
    a = adv("gw", prefixes=[RaPrefix(prefix=IPv6Network("2001:db8:1::/64"), autonomous=True)])
    heard = seen(ServerKind.RA, known="rt2", autonomous=[IPv6Network("2001:db8:7::/64")])
    n = net(router_adverts=[a], dhcp6_servers=[srv6()], foreign_servers=[heard])
    assert [f.message_id for f in run(n)] == ["ra.prefixesDiffer"]
    foreign = seen(ServerKind.RA, known=None, autonomous=[IPv6Network("2001:db8:7::/64")])
    assert run(net(router_adverts=[a], dhcp6_servers=[srv6()], foreign_servers=[foreign])) == []


def test_rdnss_of_the_provider_bypasses_the_local_resolver() -> None:
    subnets = [subnet("gw", "2001:db8:1::1/64"), subnet("gw", "192.0.2.1/24")]
    dhcp4 = dhcp_server("gw", 10, dns_servers=[ip("192.0.2.1")])
    a = adv(mode=RaMode.STATELESS, rdnss=[ip("2001:db8:ff::53")])
    uplink = Uplink(id="gw/uplink/wan", device_id="gw", dns_servers=[ip("2001:db8:ff::53")])
    n = net(
        router_adverts=[a],
        subnets=subnets,
        dhcp_servers=[dhcp4],
        uplinks=[uplink],
        dhcp6_servers=[srv6(mode=Dhcp6Mode.STATELESS)],
    )
    (f,) = run(n)
    assert f.message_id == "ra.dnsBypass"
    assert "2001:db8:ff::53" in f.message and "192.0.2.1" in f.message
    own = adv(mode=RaMode.STATELESS, rdnss=[ip("2001:db8:1::1")])
    n2 = n.model_copy(update={"router_adverts": [own]})
    assert run(n2) == []
    # IPv4 DHCP hands out a resolver outside the network: no claim about "local"
    far = dhcp_server("gw", 10, dns_servers=[ip("198.51.100.53")])
    n3 = n.model_copy(update={"dhcp_servers": [far]})
    assert run(n3) == []
