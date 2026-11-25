"""Optional name resolution of dynamic DNS names (#450, ``ddns.resolve``, off by default).

A resolved name is what the world sees: the check ``ddns.mismatch`` compares it with the public
address of the internet connection, also when the device does not say which address it
announced. Resolving **sends a DNS query for each host name** from the host Signalbox runs on
(to the resolver that host uses, which can see the name); nothing is sent while the option is
off. Only the answer is kept, in memory, and it replaces ``published_address`` of the entries.
"""

from __future__ import annotations

import asyncio
import socket
from ipaddress import IPv4Address, ip_address

from signalbox.model import Network


async def resolve_one(name: str, timeout: float) -> list[IPv4Address]:
    """The IPv4 addresses of ``name`` (empty when it does not resolve or the lookup is slow)."""
    loop = asyncio.get_running_loop()
    try:
        infos = await asyncio.wait_for(
            loop.getaddrinfo(name, None, family=socket.AF_INET, type=socket.SOCK_STREAM), timeout
        )
    except (OSError, TimeoutError):
        return []
    found: list[IPv4Address] = []
    for info in infos:
        addr = ip_address(str(info[4][0]))
        if isinstance(addr, IPv4Address) and addr not in found:
            found.append(addr)
    return found


async def resolve_names(
    names: set[str], timeout: float, limit: int = 32
) -> dict[str, list[IPv4Address]]:
    """Resolve each name once (at most ``limit`` names per round)."""
    chosen = sorted(names)[:limit]
    answers = await asyncio.gather(*(resolve_one(n, timeout) for n in chosen))
    return dict(zip(chosen, answers, strict=True))


def hostnames(net: Network) -> set[str]:
    """The names to resolve: enabled clients that announce IPv4 (or do not say)."""
    return {
        d.hostname.lower().rstrip(".")
        for d in net.ddns
        if d.enabled and (not d.families or 4 in d.families)
    }


def apply(net: Network, resolved: dict[str, list[IPv4Address]]) -> Network:
    """The network with ``published_address`` taken from the resolved name where the name
    resolved. Of several answers, one that the internet connection has is preferred."""
    if not resolved:
        return net
    out = []
    for d in net.ddns:
        answers = resolved.get(d.hostname.lower().rstrip("."))
        if not d.enabled or not answers:
            out.append(d)
            continue
        ups = net.uplinks_of(d.device_id)
        own = {a.ip for up in ups for a in up.ipv4()}
        own |= {up.public_ipv4 for up in ups if up.public_ipv4}
        pick = next((a for a in answers if a in own), answers[0])
        out.append(d.model_copy(update={"published_address": pick}))
    return net.model_copy(update={"ddns": out})
