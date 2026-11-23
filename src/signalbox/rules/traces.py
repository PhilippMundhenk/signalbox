"""Checks on path traces (#253): the routed path disagrees with what the model says.

Both are information only and conservative: they look only at complete traces (the target
answered, every hop answered, no error), stay quiet when the model does not know enough to
predict the path, and are silent without traces (path traces off, the desired and predicted
states).
"""

from __future__ import annotations

from collections.abc import Iterator
from ipaddress import IPv4Address

from signalbox.model import (
    SIGNALBOX_SOURCE,
    NatClass,
    Network,
    PathTrace,
    TraceHop,
    Tunnel,
    TunnelPeer,
    address_nat_class,
)
from signalbox.rules import Result, Severity, found, rule
from signalbox.rules._names import device_name
from signalbox.traces import complete, hop_kind, tunnel_of


def _routing_peer(net: Network, trace: PathTrace) -> tuple[Tunnel, TunnelPeer] | None:
    """A tunnel of the source with an enabled peer that routes the target's network (not a
    default route): the model says the trace should go through it."""
    for tunnel in net.tunnels_of(trace.source):
        if not tunnel.enabled or tunnel.up is False:
            continue
        for peer in tunnel.site_peers():
            if not peer.enabled:
                continue
            for n in tunnel.remote_networks(peer):
                if n.prefixlen and n.version == trace.target.version and trace.target in n:
                    return tunnel, peer
    return None


def _in_tunnel(net: Network, peer: TunnelPeer, hop: TraceHop) -> bool:
    if tunnel_of(net, hop) is not None:
        return True
    return hop.address is not None and any(
        n.version == hop.address.version and hop.address in n for n in peer.allowed_ips
    )


@rule(
    "trace.not-via-tunnel",
    "Traffic to the other site does not take the tunnel",
    Severity.INFO,
    "A VPN tunnel of the device routes the network of the traced address to the other site, "
    "but the trace from the device went somewhere else first: the first router that answered "
    "is neither the tunnel's other end nor the target. The traffic may leave unencrypted "
    "over the internet (a missing route, a policy route, a tunnel that is down).",
)
def not_via_tunnel(net: Network) -> Iterator[Result]:
    for trace in net.traces:
        if trace.source == SIGNALBOX_SOURCE or not complete(trace) or len(trace.hops) < 2:
            continue
        routing = _routing_peer(net, trace)
        if routing is None:
            continue
        tunnel, peer = routing
        first = trace.hops[0]
        if first.address == trace.target or _in_tunnel(net, peer, first):
            continue
        where = device_name(net, first.device_id) if first.device_id else str(first.address)
        yield found(
            f"{device_name(net, trace.source)} reaches {trace.target} through {where} first, "
            f"not through the tunnel {tunnel.description or tunnel.name} that routes it",
            [trace.id, trace.source, tunnel.id],
            fix="Check the route to that network on the device (it should point into the "
            "tunnel) and whether the tunnel is up; trace again afterwards.",
        )


def _predicted_private(net: Network, device_id: str) -> int | None:
    """Routers with private addresses the model expects in front of a gateway: the known
    gateways in front of it (``upstream_router``), and one unknown router where the last
    uplink has a private address and no known router holds it. None: not known."""
    count, seen, current = 0, set(), device_id
    while current not in seen:
        seen.add(current)
        uplinks = [u for u in net.uplinks_of(current) if u.up is not False]
        if not uplinks:
            return None if current == device_id else count
        classes = {u.nat_class() for u in uplinks}
        if None in classes:
            return None
        if NatClass.PRIVATE not in classes:
            return count
        uplink = next(u for u in uplinks if u.nat_class() is NatClass.PRIVATE)
        front = net.upstream_router(uplink)
        count += 1
        if front is None:
            return count
        current = front.device_id
    return count


@rule(
    "trace.extra-nat",
    "More routers with private addresses on the way out than known",
    Severity.INFO,
    "A trace from the gateway to the internet passed more routers with private (RFC 1918) "
    "addresses before the first public one than Signalbox expects from the uplinks it knows: "
    "there is a router in front of the site that Signalbox does not know about (double NAT "
    "by an ISP box in router mode, a forgotten travel router). Some providers number their own "
    "routers privately; then this is expected.",
)
def extra_nat(net: Network) -> Iterator[Result]:
    for trace in net.traces:
        if trace.purpose != "internet" or trace.source == SIGNALBOX_SOURCE:
            continue
        if not complete(trace) or not isinstance(trace.target, IPv4Address):
            continue
        leading = []
        for hop in trace.hops:
            kind = hop_kind(hop)
            if kind == "device" and isinstance(hop.address, IPv4Address):
                kind = {NatClass.PRIVATE: "private", NatClass.CGNAT: "cgnat"}.get(
                    address_nat_class(hop.address), "public"
                )
            if kind not in ("private", "cgnat"):
                break
            if kind == "private":
                leading.append(hop)
        else:
            continue  # never reached a public address: nothing to compare
        expected = _predicted_private(net, trace.source)
        if expected is None or len(leading) <= expected:
            continue
        unknown = [str(h.address) for h in leading if not h.device_id]
        yield found(
            f"{device_name(net, trace.source)} reaches the internet through {len(leading)} "
            f"router(s) with private addresses, Signalbox expects {expected}"
            + (f" (unknown: {', '.join(unknown)})" if unknown else ""),
            [trace.id, trace.source],
            fix="Find the router at that address: put an ISP box into bridge or exposed-host "
            "mode, or add the router to Signalbox; acknowledge this if the provider numbers "
            "its routers privately.",
        )


RULES = [not_via_tunnel, extra_nat]
