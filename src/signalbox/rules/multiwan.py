"""Multi-WAN and dynamic DNS rules: failover groups (#150) and DDNS clients (#154).

They read :class:`~signalbox.model.GatewayGroup` and :class:`~signalbox.model.DynamicDns` and
stay quiet where a gateway did not report the state of a member or the address a name was
given: unknown is not down, and not different.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import timedelta
from ipaddress import IPv4Address, IPv6Address

from signalbox.model import (
    DdnsResult,
    DynamicDns,
    GatewayGroup,
    GatewayGroupMember,
    NatClass,
    Network,
    Uplink,
    UplinkState,
    address_nat_class,
)
from signalbox.rules import (
    Result,
    Rule,
    RuleParams,
    Severity,
    ctx,
    found,
    history_rule,
    param,
    rule,
)
from signalbox.rules._names import device_name
from signalbox.sightings import History

#: A dynamic DNS name that was not updated for this long (#440).
STALE_DAYS = 30


def _is_down(net: Network, member: GatewayGroupMember) -> bool | None:
    """True/False as the member's monitor or its uplink says; None: not known."""
    if member.state is not None:
        return member.state is UplinkState.DOWN
    up = net.uplink(member.uplink_id) if member.uplink_id else None
    if up is not None:
        if up.health is not None:
            return up.health.state is UplinkState.DOWN
        if up.up is not None:
            return not up.up
    return None


def _split(
    net: Network, group: GatewayGroup
) -> tuple[list[GatewayGroupMember], list[GatewayGroupMember]] | None:
    """(down, not down) members; None when any member's state is unknown."""
    down: list[GatewayGroupMember] = []
    alive: list[GatewayGroupMember] = []
    for m in group.members:
        state = _is_down(net, m)
        if state is None:
            return None
        (down if state else alive).append(m)
    return down, alive


def _names(members: list[GatewayGroupMember]) -> str:
    return ", ".join(sorted(m.name for m in members))


@rule(
    "wan.group-member-down",
    "A line of a failover group is down",
    Severity.WARNING,
    "One member of a group of internet connections (failover or load balancing) is reported "
    "down by the gateway's monitor, while at least two others work. The site stays online, but "
    "it has lost a line it was meant to have, and a second failure may hurt more than expected.",
)
def member_down(net: Network) -> Iterator[Result]:
    for group in sorted(net.gateway_groups, key=lambda g: g.id):
        split = _split(net, group)
        if split is None:
            continue
        down, alive = split
        if not down or len(alive) < 2:
            continue
        device = device_name(net, group.device_id)
        yield found(
            f"{_names(down)} of the gateway group {group.name} on {device} is down; "
            f"{_names(alive)} still work",
            [group.id],
            fix="Check the cable, the modem or the mobile signal of this line, and the "
            "address the gateway pings to judge it. Turn the rule off for a line that is "
            "down on purpose.",
            mid="wan.groupMemberDown",
            fix_id="wan.groupMemberDown.fix",
            params={
                "down": _names(down),
                "group": group.name,
                "device": device,
                "working": _names(alive),
            },
        )


@rule(
    "wan.group-last-member",
    "Only one line of a failover group is left",
    Severity.WARNING,
    "All but one member of a group of internet connections are down. The site is still online, "
    "but there is nothing left to fail over to: the next failure takes it offline.",
)
def last_member(net: Network) -> Iterator[Result]:
    for group in sorted(net.gateway_groups, key=lambda g: g.id):
        split = _split(net, group)
        if split is None:
            continue
        down, alive = split
        if not down or len(alive) != 1:
            continue
        device = device_name(net, group.device_id)
        yield found(
            f"Only {alive[0].name} is left in the gateway group {group.name} on {device}: "
            f"{_names(down)} down",
            [group.id],
            fix="Bring the lines that are down back, or expect the site to go offline when "
            "the remaining one fails.",
            mid="wan.groupLastMember",
            fix_id="wan.groupLastMember.fix",
            params={
                "left": alive[0].name,
                "down": _names(down),
                "group": group.name,
                "device": device,
            },
        )


@rule(
    "wan.monitor-local",
    "A line is monitored by pinging its own gateway",
    Severity.INFO,
    "A member of a group of internet connections is judged by pinging the address of its own "
    "next hop (the modem or the provider's router). That device answers even when the "
    "provider's network behind it is dead, so the gateway never sees the line fail and never "
    "switches to the backup.",
)
def monitor_local(net: Network) -> Iterator[Result]:
    for group in sorted(net.gateway_groups, key=lambda g: g.id):
        if len(group.members) < 2:
            continue
        for m in group.members:
            up = net.uplink(m.uplink_id) if m.uplink_id else None
            hop = m.gateway or (up.upstream_gateway if up else None)
            targets = m.monitor_targets or (list(up.monitor.targets) if up and up.monitor else [])
            if hop is None or not targets or any(t != hop for t in targets):
                continue
            device = device_name(net, group.device_id)
            yield found(
                f"{m.name} of the gateway group {group.name} on {device} is monitored by "
                f"pinging its own gateway {hop}",
                [group.id],
                fix="Let the gateway ping an address on the internet through this line (a "
                "public DNS server, for example) instead of the modem or router in front.",
                key=m.name,
                mid="wan.monitorLocal",
                fix_id="wan.monitorLocal.fix",
                params={"member": m.name, "group": group.name, "device": device, "hop": str(hop)},
            )


def _uplink_of(net: Network, entry: DynamicDns) -> Uplink | None:
    if entry.uplink_id:
        return net.uplink(entry.uplink_id)
    own = net.uplinks_of(entry.device_id)
    return own[0] if len(own) == 1 else None


@rule(
    "ddns.mismatch",
    "Dynamic DNS name points to another address than the internet connection has",
    Severity.WARNING,
    "A dynamic DNS client announced an IPv4 address that is not the public address the "
    "internet connection has now. Remote access by that name goes to the old address (or to "
    "someone else) until the next update works. Quiet when the gateway does not say which "
    "address was announced, when the line is down and when its public address is not known "
    "(behind carrier-grade NAT).",
)
def mismatch(net: Network) -> Iterator[Result]:
    for entry in sorted(net.ddns, key=lambda d: d.id):
        pub = entry.published_address
        if not entry.enabled or pub is None or pub.version != 4:
            continue
        up = _uplink_of(net, entry)
        if up is None or up.up is False:
            continue
        own = [a.ip for a in up.ipv4() if address_nat_class(a.ip) is NatClass.PUBLIC]
        current = [up.public_ipv4] if up.public_ipv4 else own
        if not current or pub in current:
            continue
        device = device_name(net, entry.device_id)
        yield found(
            f"The dynamic DNS name {entry.hostname} on {device} points to {pub}, but the "
            f"internet connection has {current[0]}",
            [entry.id, up.id],
            fix="Run an update of the dynamic DNS client, and check that it uses this "
            "internet connection and that its account still works.",
            mid="ddns.mismatch",
            fix_id="ddns.mismatch.fix",
            params={
                "hostname": entry.hostname,
                "device": device,
                "published": str(pub),
                "current": str(current[0]),
            },
        )


@rule(
    "ddns.update-failed",
    "Dynamic DNS update fails",
    Severity.WARNING,
    "A dynamic DNS client reports that its last update failed (wrong account, expired "
    "subscription, provider outage). The name keeps the address of the last success, which "
    "becomes wrong the next time the provider changes the line's address.",
)
def update_failed(net: Network) -> Iterator[Result]:
    for entry in sorted(net.ddns, key=lambda d: d.id):
        if not entry.enabled or entry.last_result is not DdnsResult.ERROR:
            continue
        device = device_name(net, entry.device_id)
        yield found(
            f"The dynamic DNS update of {entry.hostname} on {device} fails",
            [entry.id],
            fix="Check the account, the password or token and the provider's status page, "
            "then start an update. Turn the client off if the name is no longer used.",
            mid="ddns.updateFailed",
            fix_id="ddns.updateFailed.fix",
            params={"hostname": entry.hostname, "device": device},
        )


def _unreachable(address: IPv4Address | IPv6Address) -> bool:
    """A private, shared (carrier-grade NAT), loopback or link-local address: nobody on the
    internet can use it. Documentation prefixes count as public (see address_nat_class)."""
    if isinstance(address, IPv4Address):
        return address_nat_class(address) is not NatClass.PUBLIC
    return address.is_link_local or address.is_loopback or address.packed[0] & 0xFE == 0xFC


def _shared_address(up: Uplink) -> IPv4Address | None:
    """The line's IPv4 address when it is not public and no public one is known."""
    if up.public_ipv4:
        return None if address_nat_class(up.public_ipv4) is NatClass.PUBLIC else up.public_ipv4
    own = [a.ip for a in up.ipv4()]
    if own and not any(address_nat_class(a) is NatClass.PUBLIC for a in own):
        return own[0]
    return None


@rule(
    "ddns.private-address",
    "Dynamic DNS name leads to an address that is not reachable from the internet",
    Severity.WARNING,
    "A dynamic DNS client announced a private, shared (carrier-grade NAT), loopback or "
    "link-local address, or, where the gateway does not say which address was announced, its "
    "internet connection has a shared address. Remote access by that name cannot work from "
    "outside. Quiet for clients that are off, and when neither address is known.",
)
def private_address(net: Network) -> Iterator[Result]:
    for entry in sorted(net.ddns, key=lambda d: d.id):
        if not entry.enabled:
            continue
        up = _uplink_of(net, entry)
        if entry.published_address is not None:
            bad: IPv4Address | IPv6Address | None = (
                entry.published_address if _unreachable(entry.published_address) else None
            )
        elif up is not None and up.up is not False and 6 not in entry.families:
            bad = _shared_address(up)
        else:
            bad = None
        if bad is None:
            continue
        device = device_name(net, entry.device_id)
        yield found(
            f"The dynamic DNS name {entry.hostname} on {device} leads to {bad}, which cannot be "
            "reached from the internet",
            [entry.id],
            fix="Use a client that announces the public address of the internet connection. "
            "Behind carrier-grade NAT, ask the provider for a public address, or use a VPN "
            "that connects outwards.",
            mid="ddns.privateAddress",
            fix_id="ddns.privateAddress.fix",
            params={"hostname": entry.hostname, "device": device, "address": str(bad)},
        )


@rule(
    "ddns.plain-http",
    "Dynamic DNS updates are sent without encryption",
    Severity.WARNING,
    "A dynamic DNS client sends its updates over plain HTTP. The account name and password "
    "(or token) can be read on the way, and anyone on the path can change where the name "
    "points. Only where the gateway says it: quiet when it does not.",
)
def plain_http(net: Network) -> Iterator[Result]:
    for entry in sorted(net.ddns, key=lambda d: d.id):
        if not entry.enabled or entry.tls is not False:
            continue
        device = device_name(net, entry.device_id)
        yield found(
            f"The dynamic DNS client for {entry.hostname} on {device} sends its updates "
            "without encryption",
            [entry.id],
            fix="Turn on HTTPS for the client, or use an update address that starts with "
            "https://. Change the password or token if it was sent in plain text.",
            mid="ddns.plainHttp",
            fix_id="ddns.plainHttp.fix",
            params={"hostname": entry.hostname, "device": device},
        )


@rule(
    "ddns.vpn-endpoint",
    "VPN peer is reached by a dynamic DNS name that is not kept up to date",
    Severity.WARNING,
    "The endpoint of a VPN peer is the name of a dynamic DNS client that is turned off or "
    "whose last update failed. When the provider changes the address of that site, the tunnel "
    "stays down. Quiet when no client is known for the name (it may be kept elsewhere).",
)
def vpn_endpoint(net: Network) -> Iterator[Result]:
    broken = {
        e.hostname.lower().rstrip("."): e
        for e in sorted(net.ddns, key=lambda d: d.id)
        if not e.enabled or e.last_result is DdnsResult.ERROR
    }
    for tun in sorted(net.tunnels, key=lambda t: t.id):
        for peer in tun.peers:
            host = (peer.endpoint_host or "").lower().rstrip(".")
            entry = broken.get(host)
            if entry is None or not peer.enabled:
                continue
            device = device_name(net, tun.device_id)
            yield found(
                f"The VPN tunnel {tun.name} on {device} reaches its peer through the name "
                f"{entry.hostname}, whose dynamic DNS client is off or failing",
                [tun.id, entry.id],
                fix="Turn the dynamic DNS client on and fix its updates, or use a name that "
                "is kept up to date as the endpoint.",
                key=f"{tun.id}/{peer.public_key}",
                mid="ddns.vpnEndpoint",
                fix_id="ddns.vpnEndpoint.fix",
                params={"tunnel": tun.name, "device": device, "hostname": entry.hostname},
            )


class StaleParams(RuleParams):
    days: int = param(
        STALE_DAYS, unit="d", ge=1, le=3650, description="Days without an update of the name."
    )


@history_rule(
    "ddns.stale",
    "Dynamic DNS name was not updated for a long time",
    Severity.INFO,
    "An enabled dynamic DNS client whose last successful update is older than the parameter "
    f"days ({STALE_DAYS} by default). Some providers drop a name that is not updated for a "
    "while, and the client may have stopped working without an error. Quiet when the "
    "gateway does not say when the last update was, and without the observation clock.",
    params=StaleParams,
)
def stale(net: Network, history: History) -> Iterator[Result]:
    now = history.now
    if now is None:
        return
    for entry in sorted(net.ddns, key=lambda d: d.id):
        if not entry.enabled or entry.last_update is None:
            continue
        days = ctx.params(StaleParams, entry).days
        if entry.last_update > now - timedelta(days=days):
            continue
        age = (now - entry.last_update).days
        device = device_name(net, entry.device_id)
        yield found(
            f"The dynamic DNS name {entry.hostname} on {device} was not updated for {age} days",
            [entry.id],
            fix="Start an update of the client and check that it still runs. Turn it off if "
            "the name is no longer used.",
            mid="ddns.stale",
            fix_id="ddns.stale.fix",
            params={"hostname": entry.hostname, "device": device, "age": age, "days": days},
        )


RULES: list[Rule] = [
    member_down,
    last_member,
    monitor_local,
    mismatch,
    update_failed,
    private_address,
    plain_http,
    vpn_endpoint,
    stale,
]
