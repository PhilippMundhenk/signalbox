"""VPN tunnel rules: stale handshakes, overlapping or unrouted allowed IPs, keepalive behind NAT,
ends that disagree (#152).

They read :class:`~signalbox.model.Tunnel` (WireGuard, adapter API 1.3) and stay quiet where a
device did not report what a rule needs: no handshake counters, no uplinks, no routes, no
subnets at the other end. Public keys are shown shortened; endpoints are never put in a message
(they are household data).
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import timedelta
from ipaddress import IPv4Network, IPv6Network

from signalbox.model import IPNetwork, NatClass, Network, Tunnel, TunnelPeer, Uplink
from signalbox.rules import Result, Severity, found, rule
from signalbox.rules._names import device_name, site_of_device

#: A peer that should be up and has not handshaken for this long is reported. WireGuard
#: re-handshakes about every 2 minutes while traffic flows (a keepalive makes sure it does).
STALE_AFTER = timedelta(minutes=5)


def _tunnel(net: Network, t: Tunnel) -> str:
    return f"tunnel {t.name} of {device_name(net, t.device_id)}"


def _peer(p: TunnelPeer) -> str:
    return f"peer {p.name}" if p.name else f"the peer with the key {p.public_key[:8]}…"


def _overlap(a: IPNetwork, b: IPNetwork) -> bool:
    if a.version != b.version:
        return False
    if isinstance(a, IPv4Network) and isinstance(b, IPv4Network):
        return a.subnet_of(b) or b.subnet_of(a)
    assert isinstance(a, IPv6Network) and isinstance(b, IPv6Network)
    return a.subnet_of(b) or b.subnet_of(a)


def _covered(a: IPNetwork, by: list[IPNetwork]) -> bool:
    return any(a.version == b.version and a.subnet_of(b) for b in by)  # type: ignore[arg-type]


def _local_networks(net: Network, device_id: str) -> list[IPNetwork]:
    """The networks of the site of a device (subnets of its devices); empty when none known."""
    site = site_of_device(net, device_id)
    return [
        s.interface.network
        for s in net.subnets
        if site is not None and site_of_device(net, s.device_id) == site
    ]


def _active(t: Tunnel, p: TunnelPeer) -> bool:
    return t.enabled and t.up is not False and p.enabled


@rule(
    "vpn.handshake-stale",
    "A VPN peer has not been reached for a while",
    Severity.WARNING,
    "WireGuard peers that are meant to stay connected (a persistent keepalive is set) complete "
    "a handshake about every two minutes. Without a handshake for five minutes, or none since "
    "the tunnel came up, the other end is not answering: the site behind it is cut off.",
)
def handshake_stale(net: Network) -> Iterator[Result]:
    for t in sorted(net.tunnels, key=lambda t: t.id):
        if t.observed_at is None:
            continue
        for p in t.peers:
            keeps = bool(p.keepalive_seconds)
            if not _active(t, p) or not (keeps or p.endpoint_host):
                continue  # a phone that connects to us is not expected to be there
            if p.latest_handshake is None:
                if p.rx_bytes is None:
                    continue  # the device did not report the running state
                age = None
            else:
                age = p.handshake_age(t.observed_at)
                if age is None or age < STALE_AFTER.total_seconds():
                    continue
            when = (
                "has not completed a handshake since the tunnel came up"
                if age is None
                else f"has not completed a handshake for {int(age // 60)} minutes"
            )
            yield found(
                f"On {_tunnel(net, t)}, {_peer(p)} {when}",
                [t.id],
                fix="Check that the other end is running and reachable (its public address or "
                "name, the port, the firewall in front of it) and that both ends have the "
                "other's public key. Without a persistent keepalive an idle tunnel stays "
                "quiet by design."
                if not keeps
                else "Check that the other end is running and reachable (its public address or "
                "name, the port, the firewall in front of it) and that both ends have the "
                "other's public key.",
                severity=Severity.WARNING if keeps else Severity.INFO,
                key=p.public_key,
            )


@rule(
    "vpn.allowed-ips-overlap",
    "Allowed IPs of VPN peers overlap each other or a local network",
    Severity.WARNING,
    "A WireGuard peer receives the traffic for its allowed IPs. Two peers of one tunnel with "
    "the same network leave the traffic to only one of them; a peer that routes a network "
    "that also exists locally cuts the site off from its own devices or sends their traffic "
    "through the tunnel.",
)
def allowed_ips_overlap(net: Network) -> Iterator[Result]:
    for t in sorted(net.tunnels, key=lambda t: t.id):
        peers = [p for p in t.peers if p.enabled]
        for i, p in enumerate(peers):
            for q in peers[i + 1 :]:
                same = sorted(set(p.allowed_ips) & set(q.allowed_ips), key=str)
                for shared in (n for n in same if n.num_addresses > 1):
                    yield found(
                        f"On {_tunnel(net, t)}, {_peer(p)} and {_peer(q)} both route {shared}: "
                        "only one of them gets that traffic",
                        [t.id],
                        fix="Give each peer its own networks in its allowed IPs; remove the "
                        "network from the peer that should not carry it.",
                        key=f"{shared}/{min(p.public_key, q.public_key)}/"
                        f"{max(p.public_key, q.public_key)}",
                    )
        local = _local_networks(net, t.device_id)
        for p in peers:
            for network in t.remote_networks(p):
                if network.prefixlen == 0:
                    continue  # a full tunnel (exit node): all traffic, by design
                clash = next((n for n in local if _overlap(network, n)), None)
                if clash is not None:
                    yield found(
                        f"On {_tunnel(net, t)}, {_peer(p)} routes {network}, which overlaps the "
                        f"local network {clash}: the two cannot be told apart",
                        [t.id],
                        fix="Use different address ranges at the two ends (a VPN between two "
                        "sites with the same network cannot route), or narrow the allowed IPs "
                        "of the peer.",
                        key=f"{p.public_key}/{network}",
                    )


@rule(
    "vpn.allowed-ips-unrouted",
    "A VPN peer's networks are not routed into the tunnel",
    Severity.WARNING,
    "The allowed IPs of a WireGuard peer only say what the tunnel accepts. For traffic to use "
    "the tunnel, the device needs a route for each network through the tunnel interface. If "
    "the configuration has none, the networks behind the peer cannot be reached.",
)
def allowed_ips_unrouted(net: Network) -> Iterator[Result]:
    for t in sorted(net.tunnels, key=lambda t: t.id):
        if t.routes is None:
            continue  # the integration does not read routes
        for p in t.peers:
            if not _active(t, p):
                continue
            for network in t.remote_networks(p):
                if _covered(network, t.routes):
                    continue
                yield found(
                    f"On {_tunnel(net, t)}, {_peer(p)} accepts {network}, but the device has no "
                    "route for it through the tunnel",
                    [t.id],
                    fix="Let the device add the routes of the allowed IPs (OpenWrt: route "
                    "allowed IPs on the peer) or add a static route for the network through the "
                    "tunnel interface. A route set by a script is not seen: acknowledge the "
                    "finding then.",
                    key=f"{p.public_key}/{network}",
                )


def _behind_nat(net: Network, device_id: str) -> list[Uplink] | None:
    """The connected uplinks of the device when none has a public IPv4; None otherwise."""
    live = [u for u in net.uplinks_of(device_id) if u.up is not False]
    classes = [u.nat_class() for u in live]
    if not live or any(c is None or c is NatClass.PUBLIC for c in classes):
        return None
    return live


@rule(
    "vpn.keepalive-behind-nat",
    "A VPN peer behind NAT has no persistent keepalive",
    Severity.WARNING,
    "A router behind NAT (a private or carrier-grade NAT address on its internet connection) "
    "keeps the NAT entry of a WireGuard tunnel only while packets flow. Without a persistent "
    "keepalive (usually 25 seconds) the entry expires when the tunnel is idle and the other end "
    "can no longer reach this one.",
)
def keepalive_behind_nat(net: Network) -> Iterator[Result]:
    for t in sorted(net.tunnels, key=lambda t: t.id):
        if _behind_nat(net, t.device_id) is None:
            continue
        for p in t.peers:
            if _active(t, p) and p.endpoint_host and p.keepalive_seconds == 0:
                yield found(
                    f"{_tunnel(net, t).capitalize()} is behind NAT and has no persistent "
                    f"keepalive for {_peer(p)}: the tunnel stops working when it is idle",
                    [t.id],
                    fix="Set the persistent keepalive of the peer to 25 seconds.",
                    key=p.public_key,
                )


@rule(
    "vpn.ends-disagree",
    "The two ends of a VPN tunnel do not match",
    Severity.WARNING,
    "When both ends of a WireGuard tunnel are known, each must list the other as a peer, and "
    "the networks one end routes to the other must exist there. Otherwise the tunnel cannot "
    "work in one direction or at all.",
)
def ends_disagree(net: Network) -> Iterator[Result]:
    for t in sorted(net.tunnels, key=lambda t: t.id):
        if t.public_key is None:
            continue
        for p in t.peers:
            other = net.tunnel_with_key(p.public_key)
            if other is None or other.id == t.id or not _active(t, p):
                continue  # the other end is not read (a remote site): nothing to compare
            there = other.peer(t.public_key)
            if there is None or not there.enabled:
                yield found(
                    f"On {_tunnel(net, t)}, {_peer(p)} is {_tunnel(net, other)}, but that "
                    f"tunnel does not list {t.name} of {device_name(net, t.device_id)} as a "
                    "peer",
                    [t.id, other.id],
                    fix="Add the public key of this tunnel as a peer on the other end (with "
                    "the networks of this site as its allowed IPs), or remove the peer here.",
                    key=p.public_key,
                )
                continue
            theirs = _local_networks(net, other.device_id)
            if not theirs:
                continue  # the other site's networks are not known
            for network in t.remote_networks(p):
                if network.prefixlen == 0 or any(_overlap(network, n) for n in theirs):
                    continue
                yield found(
                    f"On {_tunnel(net, t)}, {_peer(p)} ({_tunnel(net, other)}) is sent {network}, "
                    "but no network like it exists at the other end",
                    [t.id, other.id],
                    fix="Correct the allowed IPs of the peer to the networks that really lie "
                    "behind the other end, or add the network there.",
                    key=f"{p.public_key}/{network}",
                )


RULES = [
    handshake_stale,
    allowed_ips_overlap,
    allowed_ips_unrouted,
    keepalive_behind_nat,
    ends_disagree,
]
