"""Multi-WAN and dynamic DNS rules: failover groups (#150) and DDNS clients (#154).

They read :class:`~signalbox.model.GatewayGroup` and :class:`~signalbox.model.DynamicDns` and
stay quiet where a gateway did not report the state of a member or the address a name was
given: unknown is not down, and not different.
"""

from __future__ import annotations

from collections.abc import Iterator

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
from signalbox.rules import Result, Rule, Severity, found, rule
from signalbox.rules._names import device_name


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


RULES: list[Rule] = [member_down, last_member, monitor_local, mismatch, update_failed]
