"""Traceroute from Signalbox's own host without root (#253, docs/adr/0014).

The way ``tracepath`` does it: one ordinary UDP socket per hop with the TTL (IPv6: hop limit)
set and ``IP_RECVERR`` on, a datagram to a high port of the target, and the ICMP error the
kernel queues for that socket (``MSG_ERRQUEUE``) names the router that answered: *time
exceeded* from a router on the way, *port unreachable* from the target itself. No raw socket,
no ``CAP_NET_RAW``, no extra package in the container; Linux only (other systems: an error).

Each probe is a few bytes to UDP port 33434 + TTL, as classic traceroute sends; one probe per
hop, ``wait`` seconds per hop.
"""

from __future__ import annotations

import asyncio
import errno
import select
import socket
import struct
import sys
import time
from ipaddress import IPv4Address, IPv6Address, ip_address

from signalbox.adapters import AdapterError, TraceAnswer
from signalbox.model import TraceHop

#: Linux values; the socket module has them on newer Pythons only.
IP_RECVERR = getattr(socket, "IP_RECVERR", 11)
IPV6_RECVERR = getattr(socket, "IPV6_RECVERR", 25)
MSG_ERRQUEUE = getattr(socket, "MSG_ERRQUEUE", 0x2000)
BASE_PORT = 33434
_ORIGIN_ICMP, _ORIGIN_ICMP6 = 2, 3
#: struct sock_extended_err: errno, origin, type, code, pad, info, data
_EXT_ERR = struct.Struct("=IBBBBII")


def _offender(data: bytes, v6: bool) -> tuple[int, int, int, str | None]:
    """(origin, ICMP type, code, offender address) from an ``IP_RECVERR`` control message."""
    _, origin, icmp_type, code, _, _, _ = _EXT_ERR.unpack_from(data)
    rest = data[_EXT_ERR.size :]
    address: str | None = None
    if v6 and len(rest) >= 24:
        address = socket.inet_ntop(socket.AF_INET6, rest[8:24])
    elif not v6 and len(rest) >= 8:
        address = socket.inet_ntop(socket.AF_INET, rest[4:8])
    return origin, icmp_type, code, address


def classify(v6: bool, origin: int, icmp_type: int, code: int) -> str | None:
    """``hop`` (time exceeded), ``reached`` (port unreachable), ``unreachable`` (another
    destination unreachable: a router refused it), None: not an ICMP error."""
    if origin != (_ORIGIN_ICMP6 if v6 else _ORIGIN_ICMP):
        return None
    if (v6 and icmp_type == 3) or (not v6 and icmp_type == 11):
        return "hop"
    if (v6 and icmp_type == 1 and code == 4) or (not v6 and icmp_type == 3 and code == 3):
        return "reached"
    if (v6 and icmp_type == 1) or (not v6 and icmp_type == 3):
        return "unreachable"
    return None


def probe(target: IPv4Address | IPv6Address, ttl: int, wait: float) -> tuple[str, TraceHop]:
    """Send one probe with this TTL; (``hop``/``reached``/``unreachable``/``none``, the hop)."""
    v6 = target.version == 6
    family = socket.AF_INET6 if v6 else socket.AF_INET
    level = socket.IPPROTO_IPV6 if v6 else socket.IPPROTO_IP
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(level, IPV6_RECVERR if v6 else IP_RECVERR, 1)
        sock.setsockopt(level, socket.IPV6_UNICAST_HOPS if v6 else socket.IP_TTL, ttl)
        sock.setblocking(False)
        start = time.monotonic()
        try:
            sock.connect((str(target), BASE_PORT + ttl))
            sock.send(b"signalbox-trace")
        except OSError as exc:
            if exc.errno in (errno.ENETUNREACH, errno.EHOSTUNREACH) and ttl > 1:
                return "unreachable", TraceHop(ttl=ttl)
            raise AdapterError(
                f"this host cannot send to {target}: {exc.strerror or exc}",
                fix="Check that Signalbox's host has a route (and an address of this IP "
                "version) to it.",
            ) from None
        poller = select.poll()
        poller.register(sock, select.POLLERR)
        deadline = start + wait
        while (left := deadline - time.monotonic()) > 0:
            if not poller.poll(left * 1000):
                break
            try:
                _, ancdata, _, _ = sock.recvmsg(512, 512, MSG_ERRQUEUE)
            except BlockingIOError:
                continue
            rtt = round((time.monotonic() - start) * 1000, 3)
            for cmsg_level, cmsg_type, data in ancdata:
                if cmsg_level != level or cmsg_type != (IPV6_RECVERR if v6 else IP_RECVERR):
                    continue
                origin, icmp_type, code, address = _offender(data, v6)
                kind = classify(v6, origin, icmp_type, code)
                if kind is None:
                    continue
                addr = ip_address(address) if address else None
                return kind, TraceHop(ttl=ttl, address=addr, rtt_ms=rtt)
    return "none", TraceHop(ttl=ttl)


def trace_blocking(target: IPv4Address | IPv6Address, max_hops: int, wait: float) -> TraceAnswer:
    if not sys.platform.startswith("linux"):
        raise AdapterError(
            "tracing from Signalbox's host needs Linux (IP_RECVERR)",
            fix="Run Signalbox in its container or on Linux, or trace from a router only "
            "(traces.from_signalbox: false).",
        )
    hops: list[TraceHop] = []
    silent = 0
    for ttl in range(1, max_hops + 1):
        kind, hop = probe(target, ttl, wait)
        hops.append(hop)
        if kind == "reached" or (kind == "hop" and hop.address == target):
            return TraceAnswer(hops=hops, reached=True)
        if kind == "unreachable":
            break
        silent = silent + 1 if kind == "none" else 0
        if silent >= 5:  # five silent hops in a row: the rest will not answer either
            break
    while hops and hops[-1].address is None:
        hops.pop()
    return TraceAnswer(hops=hops, reached=False)


async def trace(target: IPv4Address | IPv6Address, max_hops: int, wait: float) -> TraceAnswer:
    """Trace from this host in a worker thread (the probes block for ``wait`` at most)."""
    return await asyncio.to_thread(trace_blocking, target, max_hops, wait)
