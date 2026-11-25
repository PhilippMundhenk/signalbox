"""IPsec and OpenVPN tunnel rules (#153): weak proposals, IKEv1 aggressive mode, tunnels and
child SAs that are down, OpenVPN without tls-auth, selectors that overlap local networks or
do not mirror the other end.

They read :class:`~signalbox.model.Tunnel` of kind ``ipsec`` and ``openvpn`` and stay quiet
where a device did not report what a rule needs. Secrets are not in the model; partner
gateways and endpoints are household data and never put into a message.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from ipaddress import ip_address

from signalbox.foreign import addresses
from signalbox.model import (
    WEAK_DH_BELOW,
    Network,
    Tunnel,
    TunnelAuth,
    TunnelKind,
    TunnelRole,
)
from signalbox.rules import Result, RuleParams, Severity, ctx, found, param, rule
from signalbox.rules._names import device_name
from signalbox.rules.vpn import _local_networks, _overlap

#: OpenVPN data ciphers that are broken or obsolete (64-bit blocks, DES family, RC4).
WEAK_OPENVPN_CIPHERS = ("bf", "blowfish", "des", "3des", "des-ede", "rc2", "rc4", "cast5", "idea")

WEAK_FIX = (
    "Remove the weak algorithms from the proposal of this connection and the other end "
    "(AES-256 or AES-128-GCM, SHA-256 or better, DH group 14 or higher, 19 for elliptic "
    "curves)."
)
DOWN_FIX = (
    "Check that the other gateway is running and reachable, that both ends agree on "
    "identities, authentication and proposals, and read the log of the VPN service."
)


def _tunnel(net: Network, t: Tunnel) -> str:
    return f"{device_name(net, t.device_id)}/{t.description or t.name}"


def _active(t: Tunnel) -> bool:
    return t.enabled and t.up is not False


class WeakCryptoParams(RuleParams):
    min_dh_group: int = param(
        WEAK_DH_BELOW,
        unit="count",
        ge=1,
        le=40,
        description="Diffie-Hellman groups with a lower number are reported as weak "
        "(1, 2 and 5 are 768 to 1536 bit).",
    )


def _label(weak: list[str]) -> str:
    names = {"encryption": "", "integrity": "", "dh": "DH group "}
    return ", ".join(f"{names[k.split(':')[0]]}{k.split(':', 1)[1]}" for k in weak)


@rule(
    "vpn.weak-crypto",
    "An IPsec or OpenVPN tunnel allows weak cryptography",
    Severity.WARNING,
    "Weak algorithms in an IPsec proposal (DES, 3DES, MD5, SHA1, Diffie-Hellman groups below "
    "the parameter min_dh_group, 14 by default), IKEv1 aggressive mode with a pre-shared key, "
    "or an old OpenVPN cipher such as BF-CBC can be broken. The tunnel often still works "
    "because the other end offers them.",
    params=WeakCryptoParams,
)
def weak_crypto(net: Network) -> Iterator[Result]:
    for t in sorted(net.tunnels, key=lambda t: t.id):
        if not t.enabled:
            continue
        if t.kind is TunnelKind.IPSEC:
            limit = ctx.params(WeakCryptoParams, t).min_dh_group
            weak: list[str] = []
            for prop in t.proposals:
                weak += [w for w in prop.weaknesses(limit) if w not in weak]
            if weak:
                yield found(
                    f"Tunnel {_tunnel(net, t)} allows weak cryptography: {_label(weak)}",
                    [t.id],
                    fix=WEAK_FIX,
                    key="proposal",
                    mid="vpn.weakCrypto",
                    fix_id="vpn.weakCrypto.fix",
                    params={"tunnel": _tunnel(net, t), "what": _label(weak)},
                )
            if t.ike_version == 1 and t.aggressive and t.auth is not TunnelAuth.CERTIFICATE:
                yield found(
                    f"Tunnel {_tunnel(net, t)} uses IKEv1 aggressive mode",
                    [t.id],
                    fix="Switch the connection to IKEv2, or to IKEv1 main mode with "
                    "certificates, and use a long random pre-shared key if one must stay.",
                    key="aggressive",
                    mid="vpn.aggressive",
                    fix_id="vpn.aggressive.fix",
                    params={"tunnel": _tunnel(net, t)},
                )
        elif t.kind is TunnelKind.OPENVPN and t.cipher:
            weak_ciphers = [
                c
                for c in re.split(r"[,:\s]+", t.cipher.strip())
                if c and re.match(rf"(?i)({'|'.join(WEAK_OPENVPN_CIPHERS)})(-|\d|$)", c)
            ]
            if weak_ciphers:
                what = ", ".join(weak_ciphers)
                yield found(
                    f"Tunnel {_tunnel(net, t)} allows weak cryptography: {what}",
                    [t.id],
                    fix=WEAK_FIX,
                    key="cipher",
                    mid="vpn.weakCrypto",
                    fix_id="vpn.weakCrypto.fix",
                    params={"tunnel": _tunnel(net, t), "what": what},
                )


def _fixed_partner(t: Tunnel) -> bool:
    """A connection that this device is expected to bring up: it names the other gateway."""
    return bool(t.remote_gateway) and t.remote_gateway not in ("any", "%any", "0.0.0.0", "::")


def _no_child_up(t: Tunnel) -> bool:
    enabled = [c for c in t.children if c.enabled]
    return bool(enabled) and all(c.established is False for c in enabled)


@rule(
    "vpn.tunnel-down",
    "A site-to-site or client VPN tunnel is down",
    Severity.WARNING,
    "An IPsec connection to a fixed partner gateway, or an OpenVPN client, is enabled but not "
    "established: the networks behind it cannot be reached. Roadwarrior servers are not "
    "reported, they are idle without clients.",
)
def tunnel_down(net: Network) -> Iterator[Result]:
    for t in sorted(net.tunnels, key=lambda t: t.id):
        if not t.enabled or t.observed_at is None:
            continue
        down = False
        if t.kind is TunnelKind.IPSEC and _fixed_partner(t):
            down = t.up is False or (t.up is None and _no_child_up(t))
        elif t.kind is TunnelKind.OPENVPN and t.role is TunnelRole.CLIENT:
            down = t.up is False
        if down:
            yield found(
                f"Tunnel {_tunnel(net, t)} is down",
                [t.id],
                fix=DOWN_FIX,
                mid="vpn.tunnelDown",
                fix_id="vpn.tunnelDown.fix",
                params={"tunnel": _tunnel(net, t)},
            )


@rule(
    "vpn.child-down",
    "An IPsec connection is up but a child SA is not established",
    Severity.WARNING,
    "The first phase of an IPsec connection is up, but a child security association (phase 2, "
    "traffic selector pair) is not. The partners agree on who they are but not on the "
    "networks or the proposal, so that traffic is dropped.",
)
def child_down(net: Network) -> Iterator[Result]:
    for t in sorted(net.tunnels, key=lambda t: t.id):
        if t.kind is not TunnelKind.IPSEC or not _active(t) or t.up is not True:
            continue
        for c in t.children:
            if c.enabled and c.established is False:
                yield found(
                    f"On tunnel {_tunnel(net, t)} the connection is up, but the child "
                    f"{c.name} is not established",
                    [t.id],
                    fix="Compare the networks (traffic selectors) and the phase 2 proposals "
                    "of both ends; they must mirror each other exactly.",
                    key=c.name,
                    mid="vpn.childDown",
                    fix_id="vpn.childDown.fix",
                    params={"tunnel": _tunnel(net, t), "child": c.name},
                )


@rule(
    "vpn.openvpn-no-tls-auth",
    "An OpenVPN instance has no tls-auth or tls-crypt",
    Severity.WARNING,
    "tls-crypt or tls-auth makes an OpenVPN server drop every packet without the shared key "
    "before the TLS handshake. Without it anyone on the internet can talk to the TLS stack. "
    "Clients are reported as info.",
)
def openvpn_no_tls_auth(net: Network) -> Iterator[Result]:
    for t in sorted(net.tunnels, key=lambda t: t.id):
        if t.kind is TunnelKind.OPENVPN and t.enabled and t.tls_auth is False:
            yield found(
                f"OpenVPN {_tunnel(net, t)} has no tls-auth or tls-crypt",
                [t.id],
                fix="Generate a static key for the instance, set it as tls-crypt (or "
                "tls-auth) on the server and give the same key to every client.",
                severity=Severity.WARNING if t.role is TunnelRole.SERVER else Severity.INFO,
                mid="vpn.noTlsAuth",
                fix_id="vpn.noTlsAuth.fix",
                params={"tunnel": _tunnel(net, t)},
            )


@rule(
    "vpn.selector-overlap-local",
    "A VPN tunnel routes a network that also exists locally",
    Severity.WARNING,
    "A remote network of an IPsec connection, or a route an OpenVPN client receives, that "
    "overlaps a network of the site makes both unreachable or sends local traffic into the "
    "tunnel.",
)
def selector_overlap_local(net: Network) -> Iterator[Result]:
    for t in sorted(net.tunnels, key=lambda t: t.id):
        if t.kind is TunnelKind.WIREGUARD or not t.enabled:
            continue
        if t.kind is TunnelKind.OPENVPN and t.role is not TunnelRole.CLIENT:
            continue  # a server's pushed routes are its own networks
        local = _local_networks(net, t.device_id)
        for network in t.all_remote_networks():
            if network.prefixlen == 0:
                continue
            clash = next((n for n in local if _overlap(network, n)), None)
            if clash is not None:
                yield found(
                    f"Tunnel {_tunnel(net, t)} routes {network} to the remote site, which "
                    f"overlaps the local network {clash}",
                    [t.id],
                    fix="Use different address ranges at the two sites, or narrow the "
                    "networks of the connection (NAT between the sites also works).",
                    key=str(network),
                    mid="vpn.selectorOverlap",
                    fix_id="vpn.selectorOverlap.fix",
                    params={
                        "tunnel": _tunnel(net, t),
                        "network": str(network),
                        "local": str(clash),
                    },
                )


def _gateway_of(t: Tunnel) -> str | None:
    if not t.remote_gateway:
        return None
    try:
        return str(ip_address(t.remote_gateway))
    except ValueError:
        return None


@rule(
    "vpn.selector-mismatch",
    "The networks of the two ends of an IPsec tunnel do not mirror each other",
    Severity.WARNING,
    "When both ends of a site-to-site IPsec connection are read, the local networks of one "
    "end must be the remote networks of the other. Otherwise the child security association "
    "is not established or only part of the traffic passes. The ends are found by the remote "
    "gateway address of each.",
)
def selector_mismatch(net: Network) -> Iterator[Result]:
    owner = addresses(net)
    ipsec = [
        t
        for t in sorted(net.tunnels, key=lambda t: t.id)
        if t.kind is TunnelKind.IPSEC and _active(t)
    ]
    for t in ipsec:
        gw = _gateway_of(t)
        other_device = owner.get(ip_address(gw)) if gw else None
        if other_device is None or other_device == t.device_id:
            continue
        for o in ipsec:
            ogw = _gateway_of(o)
            if o.device_id != other_device or o.id <= t.id or ogw is None:
                continue
            if owner.get(ip_address(ogw)) != t.device_id:
                continue
            mine = [c for c in t.children if c.enabled and c.local_networks and c.remote_networks]
            theirs = [c for c in o.children if c.enabled and c.local_networks and c.remote_networks]
            if not mine or not theirs:
                continue
            sent = {n for c in mine for n in c.remote_networks}
            expected = {n for c in theirs for n in c.local_networks}
            back = {n for c in mine for n in c.local_networks}
            there = {n for c in theirs for n in c.remote_networks}
            if sent == expected and back == there:
                continue
            diff = ", ".join(str(n) for n in sorted((sent ^ expected) | (back ^ there), key=str))
            yield found(
                f"IPsec tunnels {_tunnel(net, t)} and {_tunnel(net, o)} do not mirror each "
                f"other's networks ({diff})",
                [t.id, o.id],
                fix="Make the local networks of each end the remote networks of the other "
                "(and the other way round); both sides of a connection must list the same "
                "pairs.",
                key=o.id,
                mid="vpn.selectorMismatch",
                fix_id="vpn.selectorMismatch.fix",
                params={"tunnel": _tunnel(net, t), "other": _tunnel(net, o), "networks": diff},
            )


RULES = [
    weak_crypto,
    tunnel_down,
    child_down,
    openvpn_no_tls_auth,
    selector_overlap_local,
    selector_mismatch,
]
