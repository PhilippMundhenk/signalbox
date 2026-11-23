"""Signalbox's own probe for foreign DHCP servers and routers (#184, docs/adr/0015).

On each network interface of Signalbox's host it sends one DHCPDISCOVER and one router
solicitation and listens for a few seconds; nothing else:

- **DHCPv4**: a DHCPDISCOVER from a random, locally administered client MAC with the
  broadcast flag set, so every server answers with a broadcast OFFER. Signalbox never sends a
  REQUEST: no server hands out (commits) a lease, an offered address is only held back for the
  server's offer timeout. Needs a UDP socket bound to port 68 (``CAP_NET_BIND_SERVICE`` or
  ``net.ipv4.ip_unprivileged_port_start`` ≤ 68); the interface is chosen per packet with
  ``IP_PKTINFO``, so no ``SO_BINDTODEVICE`` and no raw socket.
- **IPv6 router solicitation**: an ICMPv6 RS to ff02::2 with hop limit 255, then the router
  advertisements. ICMPv6 other than echo needs a raw socket: ``CAP_NET_RAW``. Without it the
  leg reports that and the DHCP leg still runs.

Only the networks the host itself is attached to can be probed (host networking, or a VLAN
interface per network). Linux only. Everything that touches a socket goes through
:class:`Sockets`, so tests replace it with a fake (``tests/test_probes.py``).
"""

from __future__ import annotations

import asyncio
import contextlib
import fcntl
import os
import secrets
import select
import socket
import struct
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field, replace
from ipaddress import (
    IPv4Address,
    IPv4Interface,
    IPv6Address,
    IPv6Interface,
    IPv6Network,
    ip_address,
)
from pathlib import Path
from typing import Protocol, TypeVar

from signalbox.model import IPAddress, IPNetwork, ServerKind, ServerOffer

T = TypeVar("T")
MAGIC = b"\x63\x82\x53\x63"
DHCP_SERVER_PORT = 67
DHCP_CLIENT_PORT = 68
ALL_ROUTERS = "ff02::2"
_IP_PKTINFO = getattr(socket, "IP_PKTINFO", 8)
_IPV6_RECVPKTINFO = getattr(socket, "IPV6_RECVPKTINFO", 49)
_IPV6_PKTINFO = getattr(socket, "IPV6_PKTINFO", 50)
_SIOCGIFFLAGS, _SIOCGIFADDR, _SIOCGIFNETMASK, _SIOCGIFHWADDR = 0x8913, 0x8915, 0x891B, 0x8927
_IFF_UP, _IFF_LOOPBACK = 0x1, 0x8


class ProbeError(Exception):
    """A leg could not run; the message says why and what to do (shown to the user)."""


# packets -----------------------------------------------------------------------------------


def random_mac() -> str:
    """A random, locally administered unicast MAC (``x2:``, ``x6:``, ``xa:``, ``xe:``)."""
    raw = bytearray(secrets.token_bytes(6))
    raw[0] = (raw[0] & 0xFC) | 0x02
    return ":".join(f"{b:02x}" for b in raw)


def _mac_bytes(mac: str) -> bytes:
    return bytes(int(x, 16) for x in mac.split(":"))


def _mac_text(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw[:6])


def discover(xid: int, mac: str) -> bytes:
    """A DHCPDISCOVER: broadcast flag, client MAC ``mac``, asking for router, DNS, domain."""
    head = struct.pack(
        "!BBBBIHH4s4s4s4s16s64s128s",
        1,  # BOOTREQUEST
        1,  # Ethernet
        6,
        0,
        xid,
        0,
        0x8000,  # broadcast: answer by broadcast, the client has no address
        b"\0" * 4,
        b"\0" * 4,
        b"\0" * 4,
        b"\0" * 4,
        _mac_bytes(mac) + b"\0" * 10,
        b"\0" * 64,
        b"\0" * 128,
    )
    options = (
        bytes([53, 1, 1])  # DHCPDISCOVER
        + bytes([61, 7, 1])
        + _mac_bytes(mac)  # client identifier
        + bytes([55, 5, 1, 3, 6, 15, 51])  # subnet mask, router, DNS, domain, lease time
        + bytes([255])
    )
    return head + MAGIC + options


def offer(
    xid: int,
    client_mac: str,
    server: IPv4Address,
    address: IPv4Address,
    *,
    mask: IPv4Address | None = None,
    routers: list[IPv4Address] | None = None,
    dns: list[IPv4Address] | None = None,
    domain: str | None = None,
    lease_seconds: int | None = None,
    relay: IPv4Address | None = None,
    message: int = 2,
) -> bytes:
    """A DHCPOFFER (for the fake socket layer and the tests; Signalbox never sends one)."""
    head = struct.pack(
        "!BBBBIHH4s4s4s4s16s64s128s",
        2,
        1,
        6,
        0,
        xid,
        0,
        0x8000,
        b"\0" * 4,
        address.packed,
        server.packed,
        relay.packed if relay else b"\0" * 4,
        _mac_bytes(client_mac) + b"\0" * 10,
        b"\0" * 64,
        b"\0" * 128,
    )
    opts = bytes([53, 1, message, 54, 4]) + server.packed
    if mask is not None:
        opts += bytes([1, 4]) + mask.packed
    if routers:
        opts += bytes([3, 4 * len(routers)]) + b"".join(r.packed for r in routers)
    if dns:
        opts += bytes([6, 4 * len(dns)]) + b"".join(d.packed for d in dns)
    if domain:
        opts += bytes([15, len(domain)]) + domain.encode()
    if lease_seconds is not None:
        opts += bytes([51, 4]) + struct.pack("!I", lease_seconds)
    return head + MAGIC + opts + bytes([255])


@dataclass(frozen=True)
class Answer:
    """One server that answered a probe."""

    kind: ServerKind
    interface: str
    server_address: IPAddress | None
    server_mac: str | None
    offered: ServerOffer


def _options(raw: bytes) -> dict[int, bytes]:
    out: dict[int, bytes] = {}
    i = 0
    while i < len(raw):
        code = raw[i]
        if code == 255:
            break
        if code == 0:
            i += 1
            continue
        if i + 1 >= len(raw):
            break
        size = raw[i + 1]
        out[code] = out.get(code, b"") + raw[i + 2 : i + 2 + size]
        i += 2 + size
    return out


def _v4_list(raw: bytes | None) -> list[IPAddress]:
    if not raw:
        return []
    return [IPv4Address(raw[i : i + 4]) for i in range(0, len(raw) - len(raw) % 4, 4)]


def parse_offer(data: bytes, xid: int, mac: str, interface: str = "") -> Answer | None:
    """The answer in a DHCPOFFER to our DISCOVER (``xid`` and client MAC match); None for
    anything else (other clients' traffic, ACKs, broken packets)."""
    if len(data) < 240 or data[0] != 2 or data[236:240] != MAGIC:
        return None
    if struct.unpack("!I", data[4:8])[0] != xid or _mac_text(data[28:34]) != mac:
        return None
    opts = _options(data[240:])
    if opts.get(53) != b"\x02":
        return None
    yiaddr = IPv4Address(data[16:20])
    giaddr = IPv4Address(data[24:28])
    server_ids = _v4_list(opts.get(54))
    server = server_ids[0] if server_ids else IPv4Address(data[20:24])
    prefixes: list[IPNetwork] = []
    mask = opts.get(1)
    if mask and len(mask) == 4 and int(yiaddr):
        with contextlib.suppress(ValueError):
            prefixes.append(IPv4Interface(f"{yiaddr}/{IPv4Address(mask)}").network)
    lease = opts.get(51)
    domain = opts.get(15)
    return Answer(
        kind=ServerKind.DHCPV4,
        interface=interface,
        server_address=server if int(server) else None,
        server_mac=None,
        offered=ServerOffer(
            address=yiaddr if int(yiaddr) else None,
            routers=_v4_list(opts.get(3)),
            dns_servers=_v4_list(opts.get(6)),
            prefixes=prefixes,
            domain=domain.decode(errors="replace").strip("\0") or None if domain else None,
            lease_seconds=struct.unpack("!I", lease)[0] if lease and len(lease) == 4 else None,
            relay=giaddr if int(giaddr) else None,
        ),
    )


def router_solicitation(mac: str | None) -> bytes:
    """ICMPv6 type 133; the kernel fills in the checksum. With the source link-layer option
    when the interface has a MAC."""
    body = struct.pack("!BBHI", 133, 0, 0, 0)
    if mac:
        body += bytes([1, 1]) + _mac_bytes(mac)
    return body


def advertisement(
    *,
    lifetime: int = 1800,
    mac: str | None = None,
    prefixes: list[tuple[IPv6Network, bool]] | None = None,
    routes: list[IPv6Network] | None = None,
    dns: list[IPv6Address] | None = None,
) -> bytes:
    """A router advertisement (for the fake socket layer and the tests)."""
    out = struct.pack("!BBHBBHII", 134, 0, 0, 64, 0, lifetime, 0, 0)
    if mac:
        out += bytes([1, 1]) + _mac_bytes(mac)
    for net, auto in prefixes or []:
        flags = 0x80 | (0x40 if auto else 0)
        out += struct.pack("!BBBBIII", 3, 4, net.prefixlen, flags, 86400, 14400, 0)
        out += net.network_address.packed
    for net in routes or []:
        size = 3 if net.prefixlen > 64 else 2
        out += struct.pack("!BBBBI", 24, size, net.prefixlen, 0, 1800)
        out += net.network_address.packed[: 8 * (size - 1)]
    if dns:
        out += struct.pack("!BBHI", 25, 1 + 2 * len(dns), 0, 1800)
        out += b"".join(d.packed for d in dns)
    return out


def parse_advertisement(data: bytes, source: IPAddress, interface: str = "") -> Answer | None:
    """The router in a router advertisement; None for any other ICMPv6 message."""
    if len(data) < 16 or data[0] != 134 or data[1] != 0:
        return None
    lifetime = struct.unpack("!H", data[6:8])[0]
    mac: str | None = None
    prefixes: list[IPNetwork] = []
    autonomous: list[IPv6Network] = []
    routes: list[IPNetwork] = []
    dns: list[IPAddress] = []
    i = 16
    while i + 2 <= len(data):
        kind, size = data[i], data[i + 1] * 8
        if size == 0 or i + size > len(data):
            break
        opt = data[i : i + size]
        if kind == 1 and size >= 8:
            mac = _mac_text(opt[2:8])
        elif kind == 3 and size == 32:
            with contextlib.suppress(ValueError):
                net = IPv6Network((IPv6Address(opt[16:32]), opt[2]), strict=False)
                prefixes.append(net)
                if opt[3] & 0x40:
                    autonomous.append(net)
        elif kind == 24 and size >= 8 and opt[2] <= 128:
            raw = (opt[8:size] + b"\0" * 16)[:16]
            with contextlib.suppress(ValueError):
                routes.append(IPv6Network((IPv6Address(raw), opt[2]), strict=False))
        elif kind == 25 and size >= 24:
            dns += [IPv6Address(opt[j : j + 16]) for j in range(8, size - 15, 16)]
        i += size
    return Answer(
        kind=ServerKind.RA,
        interface=interface,
        server_address=source,
        server_mac=mac,
        offered=ServerOffer(
            routers=[source] if lifetime else [],
            dns_servers=dns,
            prefixes=prefixes,
            routes=routes,
            router_lifetime=lifetime,
            autonomous=autonomous,
        ),
    )


# the socket layer ------------------------------------------------------------------------------


@dataclass(frozen=True)
class HostInterface:
    """A network interface of Signalbox's host."""

    name: str
    index: int
    mac: str | None = None
    ipv4: list[IPv4Interface] = field(default_factory=list)
    ipv6: list[IPv6Interface] = field(default_factory=list)
    up: bool = True
    loopback: bool = False

    def link_local(self) -> IPv6Interface | None:
        return next((a for a in self.ipv6 if a.is_link_local), None)


class DhcpSocket(Protocol):
    def send(self, packet: bytes, interface: HostInterface) -> None: ...
    def receive(self, timeout: float) -> tuple[bytes, int] | None:
        """One datagram and the index of the interface it arrived on; None: nothing."""

    def close(self) -> None: ...


class Icmp6Socket(Protocol):
    def send(self, packet: bytes, interface: HostInterface) -> None: ...
    def receive(self, timeout: float) -> tuple[bytes, IPAddress, int] | None:
        """One ICMPv6 message, its source address and arriving interface; None: nothing."""

    def close(self) -> None: ...


class Sockets(Protocol):
    """Everything the probe needs from the operating system."""

    def interfaces(self) -> list[HostInterface]: ...
    def dhcp(self) -> DhcpSocket: ...
    def icmp6(self) -> Icmp6Socket: ...
    def neighbours(self) -> dict[IPAddress, str]:
        """The host's ARP table (address -> MAC), read only: nothing is sent for it."""


def _ioctl(sock: socket.socket, request: int, name: str) -> bytes | None:
    try:
        return fcntl.ioctl(sock.fileno(), request, struct.pack("256s", name.encode()[:15]))
    except OSError:
        return None


def _inet6(path: Path = Path("/proc/net/if_inet6")) -> dict[str, list[IPv6Interface]]:
    out: dict[str, list[IPv6Interface]] = {}
    with contextlib.suppress(OSError):
        for line in path.read_text().splitlines():
            parts = line.split()
            if len(parts) < 6:
                continue
            raw, plen, name = parts[0], int(parts[2], 16), parts[5]
            address = IPv6Address(bytes.fromhex(raw))
            out.setdefault(name, []).append(IPv6Interface((address, plen)))
    return out


def arp_table(path: Path = Path("/proc/net/arp")) -> dict[IPAddress, str]:
    out: dict[IPAddress, str] = {}
    with contextlib.suppress(OSError):
        for line in path.read_text().splitlines()[1:]:
            parts = line.split()
            if len(parts) < 4 or parts[3] == "00:00:00:00:00:00":
                continue
            with contextlib.suppress(ValueError):
                out[ip_address(parts[0])] = parts[3].lower()
    return out


class _UdpDhcp:
    def __init__(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.setsockopt(socket.IPPROTO_IP, _IP_PKTINFO, 1)
            sock.bind(("0.0.0.0", DHCP_CLIENT_PORT))
        except PermissionError:
            sock.close()
            raise ProbeError(
                "Signalbox may not use UDP port 68 (the DHCP client port): give it "
                "CAP_NET_BIND_SERVICE or set net.ipv4.ip_unprivileged_port_start=68 "
                "(docs/PROBES.md)"
            ) from None
        except OSError as exc:
            sock.close()
            raise ProbeError(
                f"UDP port 68 cannot be used ({exc.strerror or exc}): a DHCP client on "
                "Signalbox's host may hold it (docs/PROBES.md)"
            ) from None
        self.sock = sock

    def send(self, packet: bytes, interface: HostInterface) -> None:
        source = interface.ipv4[0].ip.packed if interface.ipv4 else b"\0" * 4
        info = struct.pack("@i4s4s", interface.index, source, b"\0" * 4)
        self.sock.sendmsg(
            [packet],
            [(socket.IPPROTO_IP, _IP_PKTINFO, info)],
            0,
            ("255.255.255.255", DHCP_SERVER_PORT),
        )

    def receive(self, timeout: float) -> tuple[bytes, int] | None:
        ready, _, _ = select.select([self.sock], [], [], max(timeout, 0))
        if not ready:
            return None
        data, ancillary, _, _ = self.sock.recvmsg(4096, socket.CMSG_SPACE(12))
        index = 0
        for level, kind, value in ancillary:
            if level == socket.IPPROTO_IP and kind == _IP_PKTINFO and len(value) >= 4:
                index = struct.unpack("@i", value[:4])[0]
        return data, index

    def close(self) -> None:
        self.sock.close()


class _RawIcmp6:
    def __init__(self) -> None:
        try:
            sock = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
        except PermissionError:
            raise ProbeError(
                "router solicitations need a raw ICMPv6 socket: give Signalbox CAP_NET_RAW, "
                "or turn probes.router_solicitation off (docs/PROBES.md)"
            ) from None
        except OSError as exc:
            raise ProbeError(f"no IPv6 on this host ({exc.strerror or exc})") from None
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 255)
        sock.setsockopt(socket.IPPROTO_IPV6, _IPV6_RECVPKTINFO, 1)
        self.sock = sock

    def send(self, packet: bytes, interface: HostInterface) -> None:
        self.sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, interface.index)
        self.sock.sendto(packet, (ALL_ROUTERS, 0, 0, interface.index))

    def receive(self, timeout: float) -> tuple[bytes, IPAddress, int] | None:
        ready, _, _ = select.select([self.sock], [], [], max(timeout, 0))
        if not ready:
            return None
        data, ancillary, _, addr = self.sock.recvmsg(4096, socket.CMSG_SPACE(20))
        index = int(addr[3]) if len(addr) > 3 else 0
        for level, kind, value in ancillary:
            if level == socket.IPPROTO_IPV6 and kind == _IPV6_PKTINFO and len(value) >= 20:
                index = struct.unpack("@I", value[16:20])[0]
        source = ip_address(str(addr[0]).split("%", 1)[0])
        return data, source, index

    def close(self) -> None:
        self.sock.close()


class HostSockets:
    """The real socket layer (Linux)."""

    def interfaces(self) -> list[HostInterface]:
        v6 = _inet6()
        out: list[HostInterface] = []
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            for index, name in socket.if_nameindex():
                flags_raw = _ioctl(sock, _SIOCGIFFLAGS, name)
                flags = struct.unpack("H", flags_raw[16:18])[0] if flags_raw else 0
                hw = _ioctl(sock, _SIOCGIFHWADDR, name)
                mac = _mac_text(hw[18:24]) if hw else None
                addr = _ioctl(sock, _SIOCGIFADDR, name)
                mask = _ioctl(sock, _SIOCGIFNETMASK, name)
                v4: list[IPv4Interface] = []
                if addr and mask:
                    ip, netmask = IPv4Address(addr[20:24]), IPv4Address(mask[20:24])
                    v4.append(IPv4Interface(f"{ip}/{netmask}"))
                out.append(
                    HostInterface(
                        name=name,
                        index=index,
                        mac=mac if mac and mac != "00:00:00:00:00:00" else None,
                        ipv4=v4,
                        ipv6=v6.get(name, []),
                        up=bool(flags & _IFF_UP),
                        loopback=bool(flags & _IFF_LOOPBACK),
                    )
                )
        return out

    def dhcp(self) -> DhcpSocket:
        return _UdpDhcp()

    def neighbours(self) -> dict[IPAddress, str]:
        return arp_table()

    def icmp6(self) -> Icmp6Socket:
        return _RawIcmp6()


# the probe ---------------------------------------------------------------------------------------


@dataclass
class Leg:
    """What one interface's probe found, or why it could not run."""

    interface: str
    answers: list[Answer] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    #: The kinds that were sent and listened for (their answers are complete).
    probed: set[ServerKind] = field(default_factory=set)


def _drain(
    receive: Callable[[float], T | None], wait: float, clock: Callable[[], float]
) -> Iterator[T]:
    end = clock() + wait
    while (left := end - clock()) > 0:
        got = receive(left)
        if got is None:
            return
        yield got


def probe_sync(
    sockets: Sockets,
    interfaces: list[HostInterface],
    wait: float,
    *,
    dhcp: bool = True,
    ra: bool = True,
    clock: Callable[[], float] = time.monotonic,
) -> dict[str, Leg]:
    """One DISCOVER and one RS per interface, then ``wait`` seconds of listening each.

    Never raises for socket problems: they become the legs' errors.
    """
    legs = {i.name: Leg(i.name) for i in interfaces}
    if dhcp:
        v4 = [i for i in interfaces if i.ipv4]
        for i in interfaces:
            if not i.ipv4:
                legs[i.name].errors.append("no IPv4 address on this interface: DHCP not probed")
        try:
            sock = sockets.dhcp() if v4 else None
        except ProbeError as exc:
            sock = None
            for i in v4:
                legs[i.name].errors.append(str(exc))
        if sock is not None:
            try:
                for iface in v4:
                    xid, mac = struct.unpack("!I", os.urandom(4))[0], random_mac()
                    try:
                        sock.send(discover(xid, mac), iface)
                    except OSError as exc:
                        legs[iface.name].errors.append(f"DHCPDISCOVER not sent: {exc}")
                        continue
                    legs[iface.name].probed.add(ServerKind.DHCPV4)
                    seen: set[tuple[object, ...]] = set()
                    for got in _drain(sock.receive, wait, clock):
                        raw, index = got
                        if index and index != iface.index:
                            continue
                        answer = parse_offer(raw, xid, mac, iface.name)
                        if answer is None:
                            continue
                        key = (answer.server_address, answer.offered.relay)
                        if key not in seen:
                            seen.add(key)
                            legs[iface.name].answers.append(answer)
            finally:
                sock.close()
        arp = sockets.neighbours()
        for leg in legs.values():
            leg.answers = [
                replace(a, server_mac=arp.get(a.server_address)) if a.server_address else a
                for a in leg.answers
            ]
    if ra:
        v6 = [i for i in interfaces if i.link_local() is not None]
        try:
            icmp = sockets.icmp6() if v6 else None
        except ProbeError as exc:
            icmp = None
            for i in v6:
                legs[i.name].errors.append(str(exc))
        if icmp is not None:
            try:
                for iface in v6:
                    try:
                        icmp.send(router_solicitation(iface.mac), iface)
                    except OSError as exc:
                        legs[iface.name].errors.append(f"router solicitation not sent: {exc}")
                        continue
                    legs[iface.name].probed.add(ServerKind.RA)
                    routers: set[object] = set()
                    for heard in _drain(icmp.receive, wait, clock):
                        data, source, index = heard
                        if index and index != iface.index:
                            continue
                        answer = parse_advertisement(data, source, iface.name)
                        if answer is not None and source not in routers:
                            routers.add(source)
                            legs[iface.name].answers.append(answer)
            finally:
                icmp.close()
    return legs


async def probe(
    sockets: Sockets,
    interfaces: list[HostInterface],
    wait: float,
    *,
    dhcp: bool = True,
    ra: bool = True,
) -> dict[str, Leg]:
    """:func:`probe_sync` in a worker thread (the sockets block)."""
    return await asyncio.to_thread(probe_sync, sockets, interfaces, wait, dhcp=dhcp, ra=ra)


def interface_networks(iface: HostInterface) -> list[IPNetwork]:
    """The networks of an interface's global addresses (to find its Signalbox network)."""
    nets: list[IPNetwork] = [a.network for a in iface.ipv4]
    nets += [a.network for a in iface.ipv6 if not a.is_link_local]
    return nets
