"""Foreign DHCP servers and routers (#184, #61): packets, the probe with a fake socket layer,
the prober, storage, matching, the checks and the API."""

from __future__ import annotations

import asyncio
import contextlib
import struct
from collections import deque
from collections.abc import Callable
from datetime import timedelta
from ipaddress import IPv4Address, IPv4Interface, IPv6Address, IPv6Interface, IPv6Network
from ipaddress import ip_address as ip
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from factories import SITE, T0, device, iface, snapshot
from signalbox import probehost
from signalbox.adapters import Adapter, AdapterConfig, Capability, Manifest, Observation, SystemInfo
from signalbox.config import ConfigError, load
from signalbox.foreign import attach, eui64_mac, foreign, known_server, view, where
from signalbox.model import (
    Client,
    DeviceRole,
    DhcpRelay,
    ForeignServer,
    Network,
    Port,
    Segment,
    ServerKind,
    ServerOffer,
    ServerSighting,
    SightingSource,
    Source,
    Subnet,
    foreign_server_id,
    object_id,
)
from signalbox.probehost import (
    HostInterface,
    ProbeError,
    advertisement,
    discover,
    offer,
    parse_advertisement,
    parse_offer,
    probe_sync,
    random_mac,
    router_solicitation,
)
from signalbox.prober import LEG, Prober, ProbeRunError, segment_of
from signalbox.rules import evaluate
from signalbox.rules.foreign import foreign_dhcp, foreign_ra
from signalbox.service import Services, build
from signalbox.store import DeviceRecord
from signalbox.web.app import create_app

PW = "probe-test-password"
SEG = f"{SITE.id}/segment/native"
ROGUE = IPv4Address("192.0.2.254")
ROGUE_MAC = "02:00:00:00:00:99"
GW_MAC = "02:00:00:00:00:01"
ETH0 = HostInterface(
    name="eth0",
    index=2,
    mac="02:00:00:00:00:50",
    ipv4=[IPv4Interface("192.0.2.50/24")],
    ipv6=[IPv6Interface("fe80::50/64"), IPv6Interface("2001:db8:1::50/64")],
)
ETH1 = HostInterface(name="eth1", index=3, ipv4=[IPv4Interface("198.51.100.50/24")])


# packets -----------------------------------------------------------------------------------------


def test_random_mac_is_locally_administered_unicast() -> None:
    for _ in range(20):
        first = int(random_mac().split(":")[0], 16)
        assert first & 0x02 and not first & 0x01


def test_discover_asks_for_a_broadcast_answer_and_never_requests() -> None:
    packet = discover(0x1234, "02:aa:bb:cc:dd:ee")
    assert packet[0] == 1 and struct.unpack("!I", packet[4:8])[0] == 0x1234
    assert struct.unpack("!H", packet[10:12])[0] == 0x8000  # broadcast flag
    assert packet[28:34] == bytes.fromhex("02aabbccddee")
    assert probehost._options(packet[240:])[53] == b"\x01"  # DISCOVER, not REQUEST (3)


def test_offer_round_trip() -> None:
    mac = "02:aa:bb:cc:dd:ee"
    packet = offer(
        7,
        mac,
        ROGUE,
        IPv4Address("192.0.2.123"),
        mask=IPv4Address("255.255.255.0"),
        routers=[ROGUE],
        dns=[IPv4Address("192.0.2.53"), IPv4Address("198.51.100.53")],
        domain="example.org",
        lease_seconds=3600,
    )
    answer = parse_offer(packet, 7, mac, "eth0")
    assert answer is not None
    assert (answer.kind, answer.interface, answer.server_address) == (
        ServerKind.DHCPV4,
        "eth0",
        ROGUE,
    )
    o = answer.offered
    assert o.address == IPv4Address("192.0.2.123") and o.routers == [ROGUE]
    assert [str(x) for x in o.dns_servers] == ["192.0.2.53", "198.51.100.53"]
    assert [str(p) for p in o.prefixes] == ["192.0.2.0/24"]
    assert (o.domain, o.lease_seconds, o.relay) == ("example.org", 3600, None)


def test_offer_parsing_rejects_everything_else() -> None:
    mac = "02:aa:bb:cc:dd:ee"
    good = offer(7, mac, ROGUE, IPv4Address("192.0.2.9"))
    assert parse_offer(good, 8, mac) is None  # another transaction
    assert parse_offer(good, 7, "02:00:00:00:00:01") is None  # another client
    assert parse_offer(good[:100], 7, mac) is None
    assert parse_offer(discover(7, mac), 7, mac) is None  # a request, not a reply
    ack = offer(7, mac, ROGUE, IPv4Address("192.0.2.9"), message=5)
    assert parse_offer(ack, 7, mac) is None
    broken = good[:236] + b"XXXX" + good[240:]
    assert parse_offer(broken, 7, mac) is None


def test_offer_through_a_relay_and_without_server_id() -> None:
    mac = "02:aa:bb:cc:dd:ee"
    relayed = offer(1, mac, ROGUE, IPv4Address("198.51.100.9"), relay=IPv4Address("198.51.100.1"))
    answer = parse_offer(relayed, 1, mac)
    assert answer is not None and answer.offered.relay == IPv4Address("198.51.100.1")
    # options with padding, an option cut short and no server identifier: siaddr is used
    raw = bytearray(offer(2, mac, ROGUE, IPv4Address("0.0.0.0")))
    end = raw.index(bytes([54, 4]))
    raw = raw[:end] + bytes([0, 0, 255])
    answer = parse_offer(bytes(raw), 2, mac)
    assert answer is not None and answer.server_address == ROGUE
    assert answer.offered.address is None
    assert probehost._options(bytes([1])) == {}


def test_router_solicitation_and_advertisement() -> None:
    assert router_solicitation(None) == bytes([133, 0, 0, 0, 0, 0, 0, 0])
    assert router_solicitation(GW_MAC)[8:] == bytes([1, 1]) + bytes.fromhex("020000000001")
    ra = advertisement(
        lifetime=1800,
        mac=GW_MAC,
        prefixes=[(IPv6Network("2001:db8:1::/64"), True), (IPv6Network("2001:db8:9::/64"), False)],
        routes=[IPv6Network("2001:db8:77::/48"), IPv6Network("2001:db8:78::/96")],
        dns=[IPv6Address("2001:db8:1::53")],
    )
    answer = parse_advertisement(ra, ip("fe80::1"), "eth0")
    assert answer is not None and answer.kind is ServerKind.RA
    assert (answer.server_address, answer.server_mac) == (ip("fe80::1"), GW_MAC)
    o = answer.offered
    assert o.router_lifetime == 1800 and o.routers == [ip("fe80::1")]
    assert [str(p) for p in o.prefixes] == ["2001:db8:1::/64", "2001:db8:9::/64"]
    assert [str(p) for p in o.autonomous] == ["2001:db8:1::/64"]
    assert [str(p) for p in o.routes] == ["2001:db8:77::/48", "2001:db8:78::/96"]
    assert o.dns_servers == [ip("2001:db8:1::53")]
    thread = parse_advertisement(advertisement(lifetime=0), ip("fe80::2"))
    assert thread is not None and thread.offered.routers == []
    assert parse_advertisement(router_solicitation(None) * 3, ip("fe80::1")) is None
    assert parse_advertisement(b"\x86\x00", ip("fe80::1")) is None
    cut = advertisement(mac=GW_MAC)[:-2] + bytes([3, 0])  # an option of length 0 ends parsing
    assert parse_advertisement(cut, ip("fe80::1")) is not None


# the probe with a fake socket layer --------------------------------------------------------------


class FakeDhcp:
    def __init__(self, fake: FakeSockets) -> None:
        self.fake = fake
        self.queue: deque[tuple[bytes, int]] = deque()
        self.closed = False

    def send(self, packet: bytes, interface: HostInterface) -> None:
        if interface.name in self.fake.send_fails:
            raise OSError("network unreachable")
        self.fake.sent.append((interface.name, packet))
        xid = struct.unpack("!I", packet[4:8])[0]
        mac = probehost._mac_text(packet[28:34])
        for make in self.fake.dhcp_servers.get(interface.name, []):
            self.queue.append((make(xid, mac), interface.index))
        self.queue.append((b"noise", interface.index))
        self.queue.append((offer(xid, mac, IPv4Address("203.0.113.1"), ROGUE), 99))

    def receive(self, timeout: float) -> tuple[bytes, int] | None:
        return self.queue.popleft() if self.queue else None

    def close(self) -> None:
        self.closed = True


class FakeIcmp:
    def __init__(self, fake: FakeSockets) -> None:
        self.fake = fake
        self.queue: deque[tuple[bytes, Any, int]] = deque()

    def send(self, packet: bytes, interface: HostInterface) -> None:
        if interface.name in self.fake.send_fails:
            raise OSError("no route")
        self.fake.sent.append((interface.name, packet))
        for source, packet_ in self.fake.routers.get(interface.name, []):
            self.queue.append((packet_, ip(source), interface.index))
            self.queue.append((packet_, ip(source), interface.index))  # twice: kept once
        self.queue.append((router_solicitation(None), ip("fe80::9"), interface.index))
        self.queue.append((advertisement(), ip("fe80::8"), 3 if interface.index != 3 else 2))

    def receive(self, timeout: float) -> tuple[bytes, Any, int] | None:
        return self.queue.popleft() if self.queue else None

    def close(self) -> None:
        pass


class FakeSockets:
    def __init__(self, interfaces: list[HostInterface] | None = None) -> None:
        self.ifaces = interfaces if interfaces is not None else [ETH0, ETH1]
        self.dhcp_servers: dict[str, list[Callable[[int, str], bytes]]] = {}
        self.routers: dict[str, list[tuple[str, bytes]]] = {}
        self.sent: list[tuple[str, bytes]] = []
        self.send_fails: set[str] = set()
        self.dhcp_error: str | None = None
        self.icmp_error: str | None = None
        self.arp: dict[Any, str] = {}
        self.list_error = False

    def interfaces(self) -> list[HostInterface]:
        if self.list_error:
            raise OSError("no netlink")
        return self.ifaces

    def dhcp(self) -> FakeDhcp:
        if self.dhcp_error:
            raise ProbeError(self.dhcp_error)
        return FakeDhcp(self)

    def icmp6(self) -> FakeIcmp:
        if self.icmp_error:
            raise ProbeError(self.icmp_error)
        return FakeIcmp(self)

    def neighbours(self) -> dict[Any, str]:
        return self.arp


def rogue_offer(server: IPv4Address = ROGUE) -> Callable[[int, str], bytes]:
    def make(xid: int, mac: str) -> bytes:
        return offer(
            xid,
            mac,
            server,
            IPv4Address("192.0.2.77"),
            mask=IPv4Address("255.255.255.0"),
            routers=[server],
            dns=[server],
        )

    return make


def clock() -> Callable[[], float]:
    ticks = iter(range(10_000))
    return lambda: float(next(ticks)) * 0.01


def test_probe_collects_offers_and_advertisements_per_interface() -> None:
    fake = FakeSockets()
    fake.dhcp_servers["eth0"] = [rogue_offer(), rogue_offer()]  # the same server twice
    fake.dhcp_servers["eth1"] = [rogue_offer(IPv4Address("198.51.100.1"))]
    fake.routers["eth0"] = [("fe80::1", advertisement(mac=GW_MAC))]
    fake.arp = {ROGUE: ROGUE_MAC}
    legs = probe_sync(fake, [ETH0, ETH1], 1.0, clock=clock())
    eth0, eth1 = legs["eth0"], legs["eth1"]
    assert [(a.kind, a.server_address, a.server_mac) for a in eth0.answers] == [
        (ServerKind.DHCPV4, ROGUE, ROGUE_MAC),
        (ServerKind.RA, ip("fe80::1"), GW_MAC),
    ]
    assert eth0.probed == {ServerKind.DHCPV4, ServerKind.RA} and eth0.errors == []
    assert [a.server_address for a in eth1.answers] == [IPv4Address("198.51.100.1")]
    assert eth1.probed == {ServerKind.DHCPV4}  # no link-local address: no RS
    assert [name for name, _ in fake.sent] == ["eth0", "eth1", "eth0"]


def test_probe_reports_missing_permissions_per_leg() -> None:
    fake = FakeSockets()
    fake.dhcp_error = "no port 68"
    fake.icmp_error = "needs CAP_NET_RAW"
    legs = probe_sync(fake, [ETH0, ETH1], 0.1, clock=clock())
    assert legs["eth0"].errors == ["no port 68", "needs CAP_NET_RAW"]
    assert legs["eth1"].errors == ["no port 68"] and not legs["eth1"].probed


def test_probe_send_failures_and_missing_addresses() -> None:
    fake = FakeSockets()
    fake.send_fails = {"eth0"}
    bare = HostInterface(name="eth9", index=9)
    legs = probe_sync(fake, [ETH0, bare], 0.1, clock=clock())
    assert legs["eth0"].errors == [
        "DHCPDISCOVER not sent: network unreachable",
        "router solicitation not sent: no route",
    ]
    assert legs["eth9"].errors == ["no IPv4 address on this interface: DHCP not probed"]
    only_ra = probe_sync(FakeSockets(), [ETH0], 0.1, dhcp=False, clock=clock())
    assert only_ra["eth0"].probed == {ServerKind.RA}


def test_probe_async_wrapper() -> None:
    fake = FakeSockets()
    fake.dhcp_servers["eth1"] = [rogue_offer()]
    legs = asyncio.run(probehost.probe(fake, [ETH1], 0.05, ra=False))
    assert [a.server_address for a in legs["eth1"].answers] == [ROGUE]


# the real socket layer, as far as it runs without privileges -------------------------------------


def test_host_interfaces_include_the_loopback() -> None:
    found = probehost.HostSockets().interfaces()
    lo = next(i for i in found if i.loopback)
    assert lo.up and any(a.ip == IPv4Address("127.0.0.1") for a in lo.ipv4)
    assert isinstance(probehost.HostSockets().neighbours(), dict)


def test_proc_tables(tmp_path: Path) -> None:
    arp = tmp_path / "arp"
    arp.write_text(
        "IP address HW type Flags HW address Mask Device\n"
        "192.0.2.254 0x1 0x2 02:00:00:00:00:99 * eth0\n"
        "192.0.2.9 0x1 0x0 00:00:00:00:00:00 * eth0\n"
        "bad 0x1 0x2 02:00:00:00:00:98 * eth0\n"
        "short\n"
    )
    assert probehost.arp_table(arp) == {ROGUE: ROGUE_MAC}
    assert probehost.arp_table(tmp_path / "missing") == {}
    inet6 = tmp_path / "if_inet6"
    inet6.write_text(
        "fe800000000000000000000000000050 02 40 20 80 eth0\n"
        "20010db8000100000000000000000050 02 40 00 80 eth0\nshort\n"
    )
    assert probehost._inet6(inet6) == {
        "eth0": [IPv6Interface("fe80::50/64"), IPv6Interface("2001:db8:1::50/64")]
    }


def test_udp_socket_errors_explain_what_to_do(monkeypatch: pytest.MonkeyPatch) -> None:
    class Refusing:
        def __init__(self, *a: Any) -> None:
            pass

        def setsockopt(self, *a: Any) -> None:
            pass

        def bind(self, address: Any) -> None:
            raise error

        def close(self) -> None:
            pass

    monkeypatch.setattr(probehost.socket, "socket", Refusing)
    error: OSError = PermissionError(13, "Permission denied")
    with pytest.raises(ProbeError, match="CAP_NET_BIND_SERVICE"):
        probehost.HostSockets().dhcp()
    error = OSError(98, "Address already in use")
    with pytest.raises(ProbeError, match="DHCP client"):
        probehost.HostSockets().dhcp()


def test_raw_socket_errors_explain_what_to_do(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*a: Any) -> None:
        raise error

    monkeypatch.setattr(probehost.socket, "socket", refuse)
    error: OSError = PermissionError(1, "Operation not permitted")
    with pytest.raises(ProbeError, match="CAP_NET_RAW"):
        probehost.HostSockets().icmp6()
    error = OSError(97, "Address family not supported")
    with pytest.raises(ProbeError, match="no IPv6"):
        probehost.HostSockets().icmp6()


def test_udp_socket_on_a_free_port(monkeypatch: pytest.MonkeyPatch) -> None:
    """The real DHCP socket (on a free port instead of 68): IP_PKTINFO on send and receive."""
    monkeypatch.setattr(probehost, "DHCP_CLIENT_PORT", 0)
    sock = probehost._UdpDhcp()
    try:
        port = sock.sock.getsockname()[1]
        assert sock.receive(0.01) is None
        lo = next(i for i in probehost.HostSockets().interfaces() if i.loopback)
        sock.sock.sendmsg(
            [b"hello"],
            [
                (
                    probehost.socket.IPPROTO_IP,
                    probehost._IP_PKTINFO,
                    struct.pack("@i4s4s", lo.index, b"\0" * 4, b"\0" * 4),
                )
            ],
            0,
            ("127.0.0.1", port),
        )
        got = sock.receive(1.0)
        assert got is not None and got[0] == b"hello" and got[1] == lo.index
        with contextlib.suppress(OSError):  # a broadcast: sent, or no route in a sandbox
            sock.send(b"x", lo)
    finally:
        sock.close()


# matching ----------------------------------------------------------------------------------------


def sub(device_id: str, address: str, segment: str = SEG, gateway: bool = True) -> Subnet:
    return Subnet(
        id=object_id(device_id, "subnet", address.replace("/", "_")),
        segment_id=segment,
        interface=iface(address),
        device_id=device_id,
        gateway=gateway,
    )


def network(**kw: Any) -> Network:
    """gw: router of the untagged network 192.0.2.0/24 and 2001:db8:1::/64, port MAC known;
    sw: a switch that sees ROGUE_MAC on its port 7."""
    values: dict[str, Any] = {
        "sites": [SITE],
        "devices": [device("gw"), device("sw", DeviceRole.SWITCH)],
        "segments": [Segment(id=SEG, site_id=SITE.id)],
        "subnets": [sub("gw", "192.0.2.1/24"), sub("gw", "2001:db8:1::1/64")],
        "ports": [
            Port(id="gw/port/lan", device_id="gw", name="lan", mac=GW_MAC),
            Port(id="sw/port/7", device_id="sw", name="7"),
        ],
        "clients": [
            Client(
                id="sw/client/02:00:00:00:00:99",
                mac=ROGUE_MAC,
                addresses=[ROGUE],
                seen_on="sw/port/7",
                source=Source(adapter="test", device_id="sw"),
            )
        ],
    }
    values.update(kw)
    return Network(**values)


def probed(
    address: str | None,
    mac: str | None = None,
    kind: ServerKind = ServerKind.DHCPV4,
    **offered: Any,
) -> ForeignServer:
    return ForeignServer(
        id=foreign_server_id(SITE.id, kind, SEG, mac or str(address)),
        site_id=SITE.id,
        segment_id=SEG,
        kind=kind,
        server_address=ip(address) if address else None,
        server_mac=mac,
        offered=ServerOffer(**offered),
        first_seen=T0,
        last_seen=T0,
        source=SightingSource.PROBE,
        seen_by=[LEG + "eth0"],
    )


def test_known_by_address_mac_eui64_relay_and_prefix() -> None:
    net = network(
        dhcp_relays=[
            DhcpRelay(
                id="gw/dhcp-relay/20", device_id="gw", segment_id=SEG, servers=[ip("192.0.2.53")]
            )
        ]
    )
    v4 = ServerKind.DHCPV4
    assert known_server(net, v4, SEG, ip("192.0.2.1"), None) == ("gw", "address")
    assert known_server(net, v4, SEG, None, GW_MAC) == ("gw", "mac")
    assert known_server(net, v4, SEG, ip("192.0.2.53"), None) == ("gw", "relay")
    relayed = ServerOffer(relay=ip("192.0.2.1"))
    assert known_server(net, v4, SEG, ip("203.0.113.9"), None, relayed) == ("gw", "relay")
    assert known_server(net, v4, SEG, ROGUE, ROGUE_MAC) == (None, None)
    ra = ServerKind.RA
    eui = ip("fe80::ff:fe00:1")  # 02:00:00:ff:fe:00:00:01 -> MAC 02:00:00:00:00:01? no: see below
    assert eui64_mac(ip("fe80::ff:fe00:1")) == "02:00:00:00:00:01"
    assert known_server(net, ra, SEG, eui, None) == ("gw", "mac")
    assert eui64_mac(ip("fe80::1")) is None and eui64_mac(ip("192.0.2.1")) is None
    own = ServerOffer(prefixes=[IPv6Network("2001:db8:1::/64")])
    assert known_server(net, ra, SEG, ip("fe80::7"), None, own) == ("gw", "prefix")
    other = ServerOffer(prefixes=[IPv6Network("2001:db8:66::/64")])
    assert known_server(net, ra, SEG, ip("fe80::7"), None, other) == (None, None)
    assert known_server(net, ra, None, ip("fe80::7"), None, own) == (None, None)


def test_attach_combines_sightings_and_probe_answers() -> None:
    sighting = ServerSighting(
        id="sw/server-seen/alert",
        device_id="sw",
        segment_id=SEG,
        server_mac=ROGUE_MAC,
        origin=SightingSource.DEVICE_ALERT,
        source=Source(adapter="test", device_id="sw"),
        observed_at=T0 - timedelta(hours=1),
    )
    lost = ServerSighting(
        id="ghost/server-seen/x",
        device_id="ghost",
        server_address=ip("203.0.113.9"),
        observed_at=T0,
    )
    lease = ServerSighting(
        id="sw/server-seen/lease",
        device_id="sw",
        server_address=ip("192.0.2.1"),
        seen_at=T0,
    )
    net = attach(network(server_sightings=[sighting, lost, lease]), [probed(str(ROGUE), ROGUE_MAC)])
    servers = {s.id: s for s in net.foreign_servers}
    rogue = servers[foreign_server_id(SITE.id, ServerKind.DHCPV4, SEG, ROGUE_MAC)]
    assert rogue.source is SightingSource.PROBE and rogue.known_as is None
    assert rogue.seen_by == ["signalbox/eth0", "sw"] and rogue.first_seen == T0 - timedelta(hours=1)
    assert rogue.server_address == ROGUE
    gw = servers[foreign_server_id(SITE.id, ServerKind.DHCPV4, None, "192.0.2.1")]
    assert (gw.known_as, gw.known_by, gw.source) == ("gw", "address", SightingSource.CLIENT_LEASE)
    assert len(servers) == 2  # the sighting of an unknown device has no site
    assert foreign(net) == [rogue] and foreign(net, ServerKind.RA) == []
    assert where(net, rogue) == ["port 7 of sw"]
    rows = {r["id"]: r for r in view(net)}
    assert rows[rogue.id]["where"] == ["port 7 of sw"]
    assert rows[rogue.id]["seen_by"] == ["Signalbox on eth0", "sw"]
    assert rows[gw.id]["known_name"] == "gw" and rows[gw.id]["segment_name"] is None


def test_mac_from_a_client_with_the_address() -> None:
    net = attach(network(), [probed(str(ROGUE))])
    [server] = foreign(net)
    assert server.server_mac is None
    assert view(net)[0]["server_mac"] == ROGUE_MAC and view(net)[0]["segment_name"] == "untagged"
    alone = attach(network(clients=[]), [probed(str(ROGUE)), probed(None, "02:00:00:00:00:77")])
    assert [where(alone, s) for s in alone.foreign_servers] == [[], []]


# checks ------------------------------------------------------------------------------------------


def messages(net: Network) -> dict[str, list[tuple[str, str | None]]]:
    out: dict[str, list[tuple[str, str | None]]] = {}
    for f in evaluate(net, [foreign_dhcp, foreign_ra]):
        out.setdefault(f.rule_id, []).append((f.message, f.fix))
    return out


def test_foreign_dhcp_server_finding() -> None:
    net = attach(
        network(),
        [
            probed(str(ROGUE), routers=[ROGUE], dns_servers=[ROGUE]),
            probed("192.0.2.1"),  # the router itself: known
        ],
    )
    [(message, fix)] = messages(net)["dhcp.foreign-server"]
    assert message == (
        "Unknown DHCP server (192.0.2.254, MAC 02:00:00:00:00:99) on untagged network, "
        "handing out gateway 192.0.2.254 and DNS 192.0.2.254; it answered Signalbox's probe"
    )
    assert fix is not None and "seen on port 7 of sw" in fix and "router mode" in fix


def test_foreign_dhcp_from_alerts_and_leases() -> None:
    alert = probed(None, "02:00:00:00:00:77").model_copy(
        update={"source": SightingSource.DEVICE_ALERT, "seen_by": ["sw"]}
    )
    lease = probed("203.0.113.9").model_copy(
        update={"source": SightingSource.CLIENT_LEASE, "seen_by": ["sw"], "segment_id": None}
    )
    found = messages(attach(network(clients=[]), [alert, lease]))["dhcp.foreign-server"]
    assert sorted(m for m, _ in found) == [
        "Unknown DHCP server (203.0.113.9) on site home; it gave an address to sw",
        "Unknown DHCP server (MAC 02:00:00:00:00:77) on untagged network; it reported as "
        "unknown by sw",
    ]
    fixes = {m.split(" ")[3]: f for m, f in found}
    assert "MAC address tables" in (fixes["(MAC"] or "")
    assert "ARP table" in (fixes["(203.0.113.9)"] or "")


def test_foreign_router_finding_and_thread_border_routers() -> None:
    rogue_ra = probed(
        "fe80::99",
        "02:00:00:00:00:98",
        ServerKind.RA,
        router_lifetime=1800,
        autonomous=[IPv6Network("2001:db8:66::/64")],
        prefixes=[IPv6Network("2001:db8:66::/64")],
    )
    thread = probed(
        "fe80::77",
        "02:00:00:00:00:97",
        ServerKind.RA,
        router_lifetime=0,
        routes=[IPv6Network("fd00:77::/64")],
    )
    gateway = probed("fe80::1", GW_MAC, ServerKind.RA, router_lifetime=1800)
    found = messages(attach(network(clients=[]), [rogue_ra, thread, gateway]))
    assert list(found) == ["ra.foreign-router"]
    [(message, fix)] = found["ra.foreign-router"]
    assert message == (
        "Unknown IPv6 router (fe80::99, MAC 02:00:00:00:00:98) advertises on untagged network "
        "(as a default router, prefix 2001:db8:66::/64); it answered Signalbox's probe"
    )
    assert fix is not None and "RA guard" in fix
    unknown_lifetime = probed("fe80::5", "02:00:00:00:00:96", ServerKind.RA)
    [(message, _)] = messages(attach(network(clients=[]), [unknown_lifetime]))["ra.foreign-router"]
    assert message.endswith("advertises on untagged network; it answered Signalbox's probe")


def test_checks_are_quiet_without_evidence() -> None:
    assert messages(attach(network())) == {}
    assert messages(Network()) == {}


# prober, store, runner, API ----------------------------------------------------------------------


class Plain(Adapter):
    manifest = Manifest(
        id="plain",
        name="Plain",
        version="1",
        api_version="1.4",
        vendor="Test",
        roles=frozenset({DeviceRole.GATEWAY}),
        capabilities=frozenset({Capability.DHCP}),
        config=AdapterConfig,
    )

    async def read_system(self) -> SystemInfo:
        return SystemInfo()

    async def read_dhcp(self) -> Observation:
        return Observation()


def services_for(tmp_path: Path, **env: str) -> Services:
    svc = build(
        tmp_path,
        env={"SIGNALBOX_AUTH_PASSWORD": PW, "SIGNALBOX_PROBES_MIN_GAP_SECONDS": "0", **env},
        adapters={"plain": Plain},
        rules=[foreign_dhcp, foreign_ra],
        link_sources=[],
    )
    svc.store.put_site(SITE)
    rec = DeviceRecord(
        id="gw", site_id=SITE.id, name="GW", role=DeviceRole.GATEWAY, adapter="plain"
    )
    svc.store.put_device(rec, {}, Plain.manifest.config)
    net = network()
    svc.store.save_snapshot(
        snapshot(
            device("gw", adapter="plain"),
            segments=net.segments,
            subnets=net.subnets,
            ports=[p for p in net.ports if p.device_id == "gw"],
        )
    )
    return svc


def prober(svc: Services, fake: FakeSockets) -> Prober:
    return Prober(svc.store, svc.runner, svc.config, sockets=fake)


def run(p: Prober) -> dict[str, Any]:
    async def go() -> dict[str, Any]:
        status = p.start()
        assert p._task is not None
        await p._task
        return status

    return asyncio.run(go())


def test_segment_of_a_host_interface(tmp_path: Path) -> None:
    net = network()
    assert segment_of(net, ETH0) == (SEG, SITE.id)
    assert segment_of(net, ETH1) == (None, None)
    v6 = HostInterface(name="v6", index=5, ipv6=[IPv6Interface("2001:db8:1::9/64")])
    assert segment_of(net, v6) == (SEG, SITE.id)


def test_prober_runs_stores_and_forgets(tmp_path: Path) -> None:
    svc = services_for(tmp_path, SIGNALBOX_PROBES_ENABLED="true")
    try:
        down = HostInterface(name="eth2", index=4, ipv4=[IPv4Interface("192.0.2.60/24")], up=False)
        lo = HostInterface(name="lo", index=1, loopback=True, ipv4=[IPv4Interface("127.0.0.1/8")])
        fake = FakeSockets([ETH0, ETH1, down, lo])
        fake.dhcp_servers["eth0"] = [rogue_offer(), rogue_offer(IPv4Address("192.0.2.1"))]
        fake.routers["eth0"] = [("fe80::1", advertisement(mac=GW_MAC))]
        fake.arp = {ROGUE: ROGUE_MAC}
        p = prober(svc, fake)
        p.settings.wait_seconds = 0.05
        status = run(p)
        assert status["running"] and status["legs"][0]["interface"] == "eth0"
        state = p.status()
        assert not state["running"] and state["finished_at"]
        legs = {x["interface"]: x for x in state["legs"]}
        assert legs["eth0"]["state"] == "done" and legs["eth0"]["answers"] == 3
        assert legs["eth1"]["errors"] == ["not on a network Signalbox knows"]
        assert legs["eth2"]["errors"] == ["interface is down"] and "lo" not in legs
        stored = svc.store.foreign_servers()
        assert {(s.kind, str(s.server_address)) for s in stored} == {
            (ServerKind.DHCPV4, "192.0.2.254"),
            (ServerKind.DHCPV4, "192.0.2.1"),
            (ServerKind.RA, "fe80::1"),
        }
        net = svc.runner.network()
        assert [s.server_address for s in foreign(net)] == [ROGUE]
        assert [f.rule_id for f in svc.runner.evaluate()[1]] == ["dhcp.foreign-server"]
        first = next(s for s in stored if s.server_address == ROGUE).first_seen
        # the rogue is gone: the next run forgets it, the router stays; first_seen is kept
        fake.dhcp_servers["eth0"] = [rogue_offer(IPv4Address("192.0.2.1"))]
        run(p)
        stored = svc.store.foreign_servers()
        assert ROGUE not in {s.server_address for s in stored} and len(stored) == 2
        assert svc.runner.evaluate()[1] == []
        # a failing DHCP leg keeps what it heard before
        fake.dhcp_servers["eth0"] = [rogue_offer()]
        run(p)
        fake.dhcp_error = "no port 68"
        fake.dhcp_servers["eth0"] = []
        run(p)
        kept = next(s for s in svc.store.foreign_servers() if s.server_address == ROGUE)
        assert kept.first_seen >= first
        legs = {x["interface"]: x for x in p.status()["legs"]}
        assert legs["eth0"]["errors"] == ["no port 68"] and legs["eth0"]["state"] == "done"
    finally:
        svc.close()


def test_prober_refusals(tmp_path: Path) -> None:
    svc = services_for(tmp_path)
    try:
        p = prober(svc, FakeSockets())
        with pytest.raises(ProbeRunError, match="turned off") as off:
            p.start()
        assert off.value.status == 403 and p.status()["next_run"] is None
        p.config.probes.enabled = True
        p.config.probes.dhcp = p.config.probes.router_solicitation = False
        with pytest.raises(ProbeRunError, match="Both"):
            p.start()
        p.config.probes.dhcp = True
        p.running = True
        with pytest.raises(ProbeRunError) as busy:
            p.start()
        assert busy.value.status == 409
        p.running = False
        p.config.probes.min_gap_seconds = 300
        p.started_at = p.finished_at = None
        p.config.probes.interval_hours = 6
        p.started_at = __import__("datetime").datetime.now(T0.tzinfo)
        with pytest.raises(ProbeRunError) as soon:
            p.start()
        assert soon.value.status == 429 and p.status()["next_run"]
        p.started_at = None
        p.sockets = FakeSockets([ETH1])
        with pytest.raises(ProbeRunError, match="host networking") as nothing:
            asyncio.run(_start(p))
        assert nothing.value.status == 422
        p.config.probes.interfaces = ["eth7"]
        p.sockets = FakeSockets([ETH0])
        with pytest.raises(ProbeRunError, match="host networking"):
            asyncio.run(_start(p))
        broken = FakeSockets()
        broken.list_error = True
        p.sockets = broken
        with pytest.raises(ProbeRunError, match="cannot be listed"):
            asyncio.run(_start(p))
    finally:
        svc.close()


async def _start(p: Prober) -> None:
    p.start()


def test_prober_survives_a_broken_run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    svc = services_for(tmp_path, SIGNALBOX_PROBES_ENABLED="true")
    try:
        p = prober(svc, FakeSockets())

        async def boom(*a: Any, **kw: Any) -> None:
            raise RuntimeError("boom")

        monkeypatch.setattr(probehost, "probe", boom)
        run(p)
        assert [x["state"] for x in p.status()["legs"]] == ["failed", "skipped"]
        assert not p.running
    finally:
        svc.close()


def test_schedule_and_stop(tmp_path: Path) -> None:
    svc = services_for(tmp_path, SIGNALBOX_PROBES_ENABLED="true")
    try:
        p = prober(svc, FakeSockets())

        async def go() -> None:
            await p.run_forever()  # interval 0: returns at once
            p.config.probes.interval_hours = 1
            calls: list[bool] = []
            p.start = lambda scheduled=False: (
                calls.append(scheduled)
                or (_ for _ in ()).throw(  # type: ignore[method-assign]
                    ProbeRunError(409, "running", "busy")
                )
            )
            task = asyncio.create_task(p.run_forever())
            await asyncio.sleep(0)
            await p.stop()
            await task
            assert calls == []

        asyncio.run(go())
    finally:
        svc.close()


def test_store_keeps_first_seen_and_prunes(tmp_path: Path) -> None:
    svc = services_for(tmp_path)
    try:
        s = svc.store
        old = probed(str(ROGUE))
        s.put_foreign(old)
        later = old.model_copy(
            update={"first_seen": T0 + timedelta(days=1), "last_seen": T0 + timedelta(days=1)}
        )
        assert s.put_foreign(later).first_seen == T0
        assert s.foreign_servers()[0].last_seen == T0 + timedelta(days=1)
        assert s.prune_foreign(T0) == 0 and s.prune_foreign(T0 + timedelta(days=2)) == 1
        s.put_foreign(old)
        assert s.delete_foreign(["nope"]) == 0 and s.delete_foreign() == 1
    finally:
        svc.close()


def test_api(tmp_path: Path) -> None:
    svc = services_for(tmp_path, SIGNALBOX_PROBES_ENABLED="true")
    try:
        app = create_app(svc, run_background=False)
        fake = FakeSockets([ETH0])
        fake.dhcp_servers["eth0"] = [rogue_offer()]
        app.state.prober.sockets = fake
        app.state.prober.config.probes.wait_seconds = 0.05
        with TestClient(app) as c:
            assert c.post("/api/login", json={"password": PW}).status_code == 200
            state = c.get("/api/probes").json()
            assert state["status"]["enabled"] and state["servers"] == []
            r = c.post("/api/probes")
            assert r.status_code == 202 and r.json()["legs"][0]["interface"] == "eth0"
            for _ in range(200):
                state = c.get("/api/probes").json()
                if not state["status"]["running"]:
                    break
            [server] = state["servers"]
            assert server["server_address"] == "192.0.2.254" and server["known_as"] is None
            ids = [f["finding"]["rule_id"] for f in c.get("/api/findings").json()]
            assert "dhcp.foreign-server" in ids
            assert c.delete("/api/probes").status_code == 204
            assert c.get("/api/probes").json()["servers"] == []
    finally:
        svc.close()


def test_api_when_off(tmp_path: Path) -> None:
    svc = services_for(tmp_path)
    try:
        svc.store.put_foreign(probed(str(ROGUE)))
        with TestClient(create_app(svc, run_background=False)) as c:
            c.post("/api/login", json={"password": PW})
            state = c.get("/api/probes").json()
            assert not state["status"]["enabled"] and state["servers"] == []  # kept, not used
            r = c.post("/api/probes")
            assert r.status_code == 403 and r.json()["error"] == "disabled"
    finally:
        svc.close()


def test_config_bounds(tmp_path: Path) -> None:
    assert load(tmp_path, env={"SIGNALBOX_PROBES_ENABLED": "true"}).probes.enabled
    (tmp_path / "signalbox.yaml").write_text("probes:\n  wait_seconds: 60\n")
    with pytest.raises(ConfigError):
        load(tmp_path, env={})
