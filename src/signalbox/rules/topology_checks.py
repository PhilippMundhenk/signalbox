"""Topology and inventory rules: link aggregation, hidden and unknown devices, duplicates,
single points of failure, and where devices are managed.

Like the VLAN rules these work on :attr:`Network.links` and stay quiet when the data they need
is missing or ambiguous.
"""

from __future__ import annotations

import re
from collections import deque
from collections.abc import Iterable, Iterator
from ipaddress import ip_address

from signalbox.model import (
    UNTRUSTED_PURPOSES,
    Client,
    Device,
    DeviceRole,
    FdbKind,
    LagGroup,
    LinkKind,
    Membership,
    Neighbour,
    Network,
    Port,
    PortKind,
    SegmentPurpose,
    client_target,
    normalise_mac,
)
from signalbox.rules import Result, Severity, found, incomplete, rule
from signalbox.rules._names import device_name, segment_name
from signalbox.rules.vlan import INFRASTRUCTURE, address_segment


def _device_of(net: Network, port: str) -> str:
    p = net.port(port)
    return p.device_id if p is not None else port.split("/port/", 1)[0]


def _port_name(net: Network, port: str) -> str:
    p = net.port(port)
    name = p.name if p else port.split("/port/", 1)[-1]
    return f"{device_name(net, _device_of(net, port))} port {name}"


def _names(items: Iterable[str]) -> str:
    """``a``, ``a and b``, ``a, b and c``."""
    items = list(items)
    return ", ".join(items)


def _mac(value: str | None) -> str | None:
    try:
        return normalise_mac(value or "")
    except ValueError:
        return None


def _address(value: str | None) -> str | None:
    """A comparable management address; None for none, loopback or a bare ``localhost``."""
    text = (value or "").strip().strip("[]").lower()
    if not text or text == "localhost":
        return None
    try:
        addr = ip_address(text)
    except ValueError:
        return text
    return None if addr.is_loopback else str(addr)


def _peers(net: Network) -> dict[str, list[str]]:
    """Port id -> the ports it is linked to."""
    out: dict[str, list[str]] = {}
    for link in net.links:
        out.setdefault(link.a, []).append(link.b)
        out.setdefault(link.b, []).append(link.a)
    return out


# --- lag.consistent ------------------------------------------------------------------------


def _memberships(net: Network) -> dict[str, dict[str, Membership]]:
    out: dict[str, dict[str, Membership]] = {}
    for seg in net.segments:
        for m in seg.members:
            out.setdefault(m.port_id, {})[seg.id] = m.mode
    return out


@rule(
    "lag.consistent",
    "Link aggregation differs between members or ends",
    Severity.ERROR,
    "All member ports of a link aggregation (LAG, bond) must have the same speed, duplex and "
    "VLANs, and must be cabled to ports of one other device that form a LAG there too. A LAG "
    "on one end and single ports on the other end loops or drops traffic; members with "
    "different VLANs lose frames of some connections only. A LAG with only one working member "
    "has lost its redundancy and part of its bandwidth.",
)
def lag_consistent(net: Network) -> Iterator[Result]:
    groups = net.lag_groups()
    members_of = _memberships(net)
    peers = _peers(net)
    for (dev, lag), group in groups.items():
        members = list(group.members)
        ids = [p.id for p in members]
        label = f"{device_name(net, dev)} {lag} [{_names([p.name for p in members])}]"
        up = [p for p in members if p.up is not False]
        speeds = {p.speed_mbps for p in up if p.speed_mbps is not None}
        if len(speeds) > 1:
            speed_text = ", ".join(f"{p.name}: {p.speed_mbps} Mbit/s" for p in up if p.speed_mbps)
            yield found(
                f"{label}: the members run at different speeds ({speed_text}).",
                [dev, *ids],
                fix="Set all members to auto-negotiation and check their cables.",
                severity=Severity.WARNING,
                key=f"{lag}\x00speed",
                mid="topology.lagSpeeds",
                fix_id="topology.lagAuto.fix",
                params={"label": label, "speeds": speed_text},
            )
        duplex = {p.full_duplex for p in up if p.full_duplex is not None}
        if len(duplex) > 1:
            yield found(
                f"{label}: some members run in half duplex.",
                [dev, *ids],
                fix="Set all members to auto-negotiation and full duplex.",
                severity=Severity.WARNING,
                key=f"{lag}\x00duplex",
                mid="topology.lagDuplex",
                fix_id="topology.lagDuplex.fix",
                params={"label": label},
            )
        vlans = [members_of.get(p.id) for p in members]
        if all(vlans) and any(v != vlans[0] for v in vlans):
            yield found(
                f"{label}: the members carry different VLANs.",
                [dev, *ids],
                fix="Configure the VLANs on the LAG itself, or the same VLANs on every member.",
                key=f"{lag}\x00vlans",
                mid="topology.lagVlans",
                fix_id="topology.lagVlans.fix",
                params={"label": label},
            )
        states = [p.up for p in members]
        if len(members) > 1 and None not in states and states.count(True) == 1:
            yield found(
                f"{label}: only one member is up.",
                [dev, *ids],
                fix="Check the cables and the far end of the members that are down.",
                severity=Severity.INFO,
                key=f"{lag}\x00single",
                mid="topology.lagSingle",
                fix_id="topology.lagSingle.fix",
                params={"label": label},
            )
        elif len(members) > 1 and None not in states and _carrying(group) == 1:
            # #157: all members are up, but LACP aggregates only one of them
            yield found(
                f"{label}: only one member carries traffic.",
                [dev, *ids],
                fix="See the finding about the members that are not aggregated.",
                severity=Severity.INFO,
                key=f"{lag}\x00single",
                mid="topology.lagSingleActive",
                fix_id="topology.lagSingleActive.fix",
                params={"label": label},
            )
        yield from _lag_far_end(net, label, dev, lag, members, peers)


def _carrying(group: LagGroup) -> int | None:
    """Members that are up and carry traffic, where every member that is up says (#157);
    ``None``: not reported."""
    up = [p for p in group.members if p.up is True]
    if group.mode is None or not group.mode.lacp:
        return None
    states = [p.lag_member_state for p in up]
    if any(s is None or (s.selected is None and s.collecting_distributing is None) for s in states):
        return None
    return sum(
        1
        for s in states
        if s is not None and s.selected is not False and s.collecting_distributing is not False
    )


def _lag_far_end(
    net: Network, label: str, dev: str, lag: str, members: list[Port], peers: dict[str, list[str]]
) -> Iterator[Result]:
    remote = sorted({r for p in members for r in peers.get(p.id, []) if _device_of(net, r) != dev})
    if len(remote) < 2:
        return  # nothing (or one cable) known about the far end
    ids = [p.id for p in members]
    devices = sorted({_device_of(net, r) for r in remote})
    if len(devices) > 1:
        yield found(
            f"{label} is connected to several devices: "
            f"{_names(_port_name(net, r) for r in remote)}.",
            [dev, *ids],
            fix="Connect all members of the LAG to one device (or one switch stack).",
            key=f"{lag}\x00devices",
            mid="topology.lagDevices",
            fix_id="topology.lagDevices.fix",
            params={"label": label, "ports": _names(_port_name(net, r) for r in remote)},
        )
        return
    ports = [net.port(r) for r in remote]
    if any(p is None for p in ports):
        yield incomplete(
            f"{device_name(net, devices[0])} does not report its ports, so the far end of "
            f"{label} could not be checked.",
            [dev, *ids],
            key=f"{lag}\x00far-end",
            mid="topology.lagFarUnknown",
            params={"device": device_name(net, devices[0]), "label": label},
        )
        return
    groups = net.lag_groups()
    lag_of = {m.id: name for (_, name), g in groups.items() for m in g.members}
    far = {lag_of.get(p.id) for p in ports if p is not None}
    if far == {None}:
        yield found(
            f"{label} is connected to {_names(_port_name(net, r) for r in remote)}, which are "
            "not in a LAG.",
            [dev, *ids],
            fix=f"Configure a LAG on {device_name(net, devices[0])} or remove all but one cable.",
            key=f"{lag}\x00far-end",
            mid="topology.lagFarNoLag",
            fix_id="topology.lagFarNoLag.fix",
            params={
                "label": label,
                "ports": _names(_port_name(net, r) for r in remote),
                "device": device_name(net, devices[0]),
            },
        )
    elif len(far) > 1:
        yield found(
            f"{label} is connected to {_names(_port_name(net, r) for r in remote)}, which are "
            "not all in the same LAG.",
            [dev, *ids],
            fix=f"Put all of these ports on {device_name(net, devices[0])} into one LAG.",
            key=f"{lag}\x00far-end",
            mid="topology.lagFarMixed",
            fix_id="topology.lagFarMixed.fix",
            params={
                "label": label,
                "ports": _names(_port_name(net, r) for r in remote),
                "device": device_name(net, devices[0]),
            },
        )


# --- topology.hidden-device ----------------------------------------------------------------

#: More client devices than this on one port suggest a switch behind it.
HIDDEN_THRESHOLD = 3


def _device_macs(net: Network) -> set[str]:
    """Port MACs and the addresses devices report as their own in their MAC table (#160)."""
    return {p.mac for p in net.ports if p.mac} | {e.mac for e in net.fdb if e.kind is FdbKind.SELF}


def _device_addresses(net: Network) -> set[str]:
    out = {a for d in net.devices if (a := _address(d.management_address))}
    out |= {str(sn.interface.ip) for sn in net.subnets}
    return out


def _segments_behind(client: Client, device_id: str) -> set[str]:
    """The networks the device that owns the port puts the client in (its own sighting, #511);
    the merged network where that device did not say."""
    own = {s.segment_id for s in client.sightings if s.device_id == device_id and s.segment_id}
    if own:
        return own
    return {client.segment_id} if client.segment_id else set()


@rule(
    "topology.hidden-device",
    "Unknown switch or access point behind a port",
    Severity.INFO,
    "Many devices, or devices of several networks, are seen behind one port that has no known "
    "neighbour. Usually an unmanaged switch or a travel router is connected there. Signalbox "
    "cannot see through it: VLAN checks through it may be wrong, it may strip or leak tagged "
    "VLANs, and a loop behind it is invisible.",
)
def hidden_device(net: Network) -> Iterator[Result]:
    ends = set(_peers(net))
    macs = _device_macs(net)
    addresses = _device_addresses(net)
    by_port: dict[str, list[Client]] = {}
    for c in net.clients:
        if c.seen_on:
            by_port.setdefault(c.seen_on, []).append(c)
    tagged = {m.port_id for s in net.segments for m in s.members if m.mode is Membership.TAGGED}
    roles = {d.id: d.role for d in net.devices}
    for port_id, clients in sorted(by_port.items()):
        p = net.port(port_id)
        if p is None or p.kind is not PortKind.ETHERNET or port_id in ends:
            continue
        if p.external is False:
            continue  # a CPU port (#252) sees every client of the switch
        if roles.get(p.device_id) not in INFRASTRUCTURE:
            continue
        if any(c.mac in macs or {str(a) for a in c.addresses} & addresses for c in clients):
            continue  # a known device is behind the port
        segments = {s for c in clients for s in _segments_behind(c, p.device_id)}
        if len(clients) <= HIDDEN_THRESHOLD and len(segments) < 2:
            continue
        several = f" in {len(segments)} networks" if len(segments) > 1 else ""
        on_tagged = port_id in tagged
        yield found(
            f"{len(clients)} devices{several} are seen behind {_port_name(net, port_id)}, which "
            "has no known neighbour.",
            [port_id],
            fix="If a switch or access point is connected there, add it under Devices or enter "
            "it on the Topology page."
            + (
                " An unmanaged switch should not be on a port with tagged VLANs."
                if on_tagged
                else ""
            ),
            severity=Severity.WARNING if on_tagged else None,
            mid="topology.hiddenNets" if several else "topology.hidden",
            fix_id="topology.hidden.taggedFix" if on_tagged else "topology.hidden.fix",
            params={
                "count": len(clients),
                "networks": len(segments),
                "port": _port_name(net, port_id),
            },
        )


# --- inventory.unknown-neighbour -----------------------------------------------------------


@rule(
    "inventory.unknown-neighbour",
    "Network device seen by LLDP is not in Signalbox",
    Severity.INFO,
    "A device announces itself by LLDP (or a similar protocol) with a management address, but "
    "it is not one of the devices Signalbox reads. If it is a switch or access point, VLAN "
    "paths through it stay incomplete and its SSIDs and firmware are not checked.",
)
def unknown_neighbour(net: Network) -> Iterator[Result]:
    macs = _device_macs(net)
    names = {d.name.lower() for d in net.devices}
    addresses = _device_addresses(net)
    own = {p.id: p.device_id for p in net.ports}
    seen: dict[str, list[tuple[str, str, str | None]]] = {}
    for nb in net.neighbours:
        addr = _address(nb.management_address)
        if addr is None or addr in addresses:
            continue
        if nb.capabilities or _is_gear_description(nb.description):
            continue  # inventory.unknown-network-device judges what it announces
        chassis = _mac(nb.chassis_id)
        if chassis in macs or (nb.system_name or "").lower() in names:
            continue
        if nb.local_port_id not in own:
            continue
        if chassis is not None and net.expected(client_target(chassis)).known_neighbour:
            continue  # the user knows it and left it out of Signalbox on purpose
        key = chassis or nb.chassis_id
        seen.setdefault(key, []).append((nb.local_port_id, addr, nb.system_name))
    for key, entries in sorted(seen.items()):
        entries.sort()
        ports = [e[0] for e in entries]
        name = next((e[2] for e in entries if e[2]), None)
        who = f"{name} ({entries[0][1]})" if name else entries[0][1]
        yield found(
            f"{_names(_port_name(net, p) for p in ports)} "
            f"{'sees' if len(ports) == 1 else 'see'} a device announcing itself as {who} that "
            "is not in Signalbox.",
            ports,
            fix="If it is a router, switch or access point, add it under Devices. Phones and "
            "computers that send LLDP can be ignored.",
            key=key,
            mid="topology.unknownNeighbour",
            fix_id="topology.unknownNeighbour.fix",
            params={
                "count": len(ports),
                "ports": _names(_port_name(net, p) for p in ports),
                "who": who,
            },
        )


# --- inventory.unknown-network-device ------------------------------------------------------

#: LLDP system capabilities of network gear; a telephone or station is an end device.
NETWORK_CAPABILITIES = ("bridge", "router", "wlan-access-point")
_GEAR = re.compile(
    r"\b(switch|router|routeros|access[ -]point|gateway|firewall|openwrt|opnsense|pfsense|"
    r"edgeswitch|edgerouter|unifi|omada|mikrotik|ubiquiti|tp-link|netgear|aruba|juniper|"
    r"fortigate|catalyst|procurve|zyxel|d-link|draytek|fritz!?box)\b",
    re.IGNORECASE,
)


def _is_gear_description(description: str | None) -> bool:
    return bool(description and _GEAR.search(description))


def _network_kinds(nb: Neighbour) -> list[str] | None:
    """What makes the neighbour network gear (its capabilities, or ``[]`` for a description that
    names network equipment); None for an end device or when it says nothing."""
    kinds = [c for c in nb.capabilities if c in NETWORK_CAPABILITIES]
    if kinds:
        return kinds
    if "telephone" in nb.capabilities or "station" in nb.capabilities:
        return None
    return [] if _is_gear_description(nb.description) else None


@rule(
    "inventory.unknown-network-device",
    "Switch, router or access point seen by LLDP is not in Signalbox",
    Severity.WARNING,
    "A neighbour announces itself by LLDP, MNDP or CDP as a bridge (switch), router or WLAN "
    "access point, or describes itself as network equipment, but it is not one of the devices "
    "Signalbox reads: its chassis MAC and management address match no device or port. Without "
    "it VLAN paths through it stay incomplete and its SSIDs and firmware are not checked. "
    "Phones and stations are not reported.",
)
def unknown_network_device(net: Network) -> Iterator[Result]:
    macs = _device_macs(net)
    names = {d.name.lower() for d in net.devices}
    addresses = _device_addresses(net)
    own = {p.id for p in net.ports}
    seen: dict[str, list[tuple[str, str | None, str | None, list[str]]]] = {}
    for nb in net.neighbours:
        kinds = _network_kinds(nb)
        if kinds is None or nb.local_port_id not in own:
            continue
        addr = _address(nb.management_address)
        chassis = _mac(nb.chassis_id)
        if addr in addresses or chassis in macs or (nb.system_name or "").lower() in names:
            continue
        if chassis is not None and net.expected(client_target(chassis)).known_neighbour:
            continue  # the user knows it and left it out of Signalbox on purpose
        seen.setdefault(chassis or nb.chassis_id, []).append(
            (nb.local_port_id, addr, nb.system_name, kinds)
        )
    for key, entries in sorted(seen.items()):
        entries.sort(key=lambda e: e[0])
        ports = [e[0] for e in entries]
        name = next((e[2] for e in entries if e[2]), None)
        addr = next((e[1] for e in entries if e[1]), None)
        kinds = next((e[3] for e in entries if e[3]), [])
        detail = ", ".join(([addr] if name and addr else []) + kinds)
        who = (name or addr or key) + (f" ({detail})" if detail else "")
        yield found(
            f"{_names(_port_name(net, p) for p in ports)} "
            f"{'sees' if len(ports) == 1 else 'see'} a network device announcing itself as {who} "
            "that is not in Signalbox.",
            ports,
            fix="Add it under Devices so that Signalbox reads it."
            + (" Find devices on that page can look for it at its address." if addr else ""),
            key=key,
            mid="topology.unknownNetworkDevice",
            fix_id="topology.unknownNetworkDevice.fixFind"
            if addr
            else "topology.unknownNetworkDevice.fix",
            params={
                "count": len(ports),
                "ports": _names(_port_name(net, p) for p in ports),
                "who": who,
            },
        )


# --- vlan.management-separate --------------------------------------------------------------


@rule(
    "vlan.management-separate",
    "Devices are managed in a network with clients",
    Severity.INFO,
    "The management addresses of routers, switches and access points lie in a network that "
    "also has user devices or an SSID, while the site already uses VLANs. Every compromised "
    "laptop or IoT device can then reach the login pages of the network devices. A separate "
    "management VLAN, reachable only from admin devices, is the usual next step. A network "
    "with the purpose management is that VLAN and is not reported; guest and IoT networks "
    "are security.management-exposure's finding. Off unless enabled: this is a "
    "recommendation, not a fault.",
    enabled=False,
)
def management_separate(net: Network) -> Iterator[Result]:
    macs = _device_macs(net)
    addresses = _device_addresses(net)
    for site in sorted({d.site_id for d in net.devices}):
        if not any(s.vlan is not None and s.site_id == site for s in net.segments):
            continue  # no VLANs at this site
        managed: dict[str, list[Device]] = {}
        for d in net.devices:
            if d.site_id == site and d.role in INFRASTRUCTURE:
                seg = address_segment(net, d)
                if seg is not None:
                    managed.setdefault(seg, []).append(d)
        mgmt = sorted(
            s.id
            for s in net.segments
            if s.site_id == site and s.purpose is SegmentPurpose.MANAGEMENT
        )
        for seg, devices in sorted(managed.items()):
            purpose = next((s.purpose for s in net.segments if s.id == seg), None)
            if purpose is SegmentPurpose.MANAGEMENT or purpose in UNTRUSTED_PURPOSES:
                continue
            clients = [
                c
                for c in net.clients
                if c.segment_id == seg
                and c.mac not in macs
                and not {str(a) for a in c.addresses} & addresses
            ]
            ssids = sorted({w.ssid for w in net.wlans if w.enabled and w.segment_id == seg})
            if not clients and not ssids:
                continue
            users = []
            if clients:
                users.append(f"clients: {len(clients)}")
            if ssids:
                users.append(f"SSIDs: {_names(ssids)}")
            names = sorted(d.name for d in devices)
            yield found(
                f"{_names(names)} {'is' if len(names) == 1 else 'are'} managed in "
                f"{segment_name(net, seg)}, which also has {'; '.join(users)}.",
                [seg],
                fix="Move the management addresses to "
                f"{_names(segment_name(net, m) for m in mgmt)}, the management network."
                if mgmt
                else "Consider a management VLAN that only admin devices can reach, and move the "
                "management addresses there.",
                mid="topology.mgmtShared.both"
                if clients and ssids
                else "topology.mgmtShared.clients"
                if clients
                else "topology.mgmtShared.ssids",
                fix_id="topology.mgmtShared.fix" if mgmt else "topology.mgmtShared.fixNone",
                params={
                    "count": len(names),
                    "names": _names(names),
                    "segment": segment_name(net, seg),
                    "clients": len(clients),
                    "ssids": _names(ssids),
                    "management": _names(segment_name(net, m) for m in mgmt),
                },
            )


# --- inventory.duplicate-device ------------------------------------------------------------


def _virtual_mac(mac: str) -> bool:
    """VRRP/CARP virtual router MACs, shared on purpose by several devices."""
    return mac.startswith(("00:00:5e:00:01:", "00:00:5e:00:02:"))


@rule(
    "inventory.duplicate-device",
    "Device is in the inventory twice",
    Severity.WARNING,
    "Two devices in Signalbox have the same management address or the same port MAC address, "
    "for example a switch added directly and also reported by its controller. Every check "
    "then sees it twice: duplicate SSIDs, VLAN differences with itself, doubled clients.",
)
def duplicate_device(net: Network) -> Iterator[Result]:
    owners: dict[tuple[str, str], set[str]] = {}
    for d in net.devices:
        if (addr := _address(d.management_address)) is not None:
            owners.setdefault(("address", addr), set()).add(d.id)
    for p in net.ports:
        if p.mac and not _virtual_mac(p.mac) and net.device(p.device_id):
            owners.setdefault(("MAC", p.mac), set()).add(p.device_id)
    parent = {d.id: d.id for d in net.devices}

    def root(x: str) -> str:
        while parent[x] != x:
            x = parent[x]
        return x

    for ids in owners.values():
        first, *rest = sorted(ids)
        for other in rest:
            parent[root(other)] = root(first)
    groups: dict[str, list[str]] = {}
    for dev_id in sorted(parent):
        groups.setdefault(root(dev_id), []).append(dev_id)
    for members in groups.values():
        if len(members) < 2:
            continue
        reasons = sorted(
            value for (_kind, value), ids in owners.items() if len(ids & set(members)) > 1
        )
        names = [_full_name(net, d) for d in members]
        yield found(
            f"{_names(names)} look like the same device (shared: {_names(reasons)}).",
            members,
            fix="Remove all but one of them from Signalbox (keep the one read through the "
            "controller if it is managed by one).",
            mid="topology.duplicate",
            fix_id="topology.duplicate.fix",
            params={"names": _names(names), "reasons": _names(reasons)},
        )


def _full_name(net: Network, device_id: str) -> str:
    d = net.device(device_id)
    if d is None or d.managed_by is None:
        return device_name(net, device_id)
    return f"{device_name(net, d.managed_by)}/{d.name}"


# --- redundancy.single-point ---------------------------------------------------------------


def _adjacency(net: Network) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for link in net.links:
        a, b = _device_of(net, link.a), _device_of(net, link.b)
        if a != b:
            out.setdefault(a, set()).add(b)
            out.setdefault(b, set()).add(a)
    return out


def _reach(
    adjacent: dict[str, set[str]], start: Iterable[str], *, without: str = "", cut: frozenset[str]
) -> set[str]:
    seen = {s for s in start if s != without}
    queue = deque(sorted(seen))
    while queue:
        here = queue.popleft()
        for there in sorted(adjacent.get(here, ())):
            if there != without and frozenset((here, there)) != cut and there not in seen:
                seen.add(there)
                queue.append(there)
    return seen


def _affected(net: Network, ids: Iterable[str]) -> str:
    roles = {d.id: d.role for d in net.devices}
    aps = sum(1 for d in ids if roles.get(d) is DeviceRole.AP)
    switches = sum(1 for d in ids if roles.get(d) is DeviceRole.SWITCH)
    parts = []
    if aps:
        parts.append(f"{aps} AP")
    if switches:
        parts.append(f"{switches} SW")
    return ", ".join(parts)


#: A failure that cuts off at least this many switches and access points is reported.
SPOF_MINIMUM = 2


@rule(
    "redundancy.single-point",
    "Single point of failure",
    Severity.INFO,
    "One switch or one cable carries the connection of several access points or switches to "
    "the router. If it fails, all of them are offline. A spare, a better switch or a second "
    "uplink (with LAG or spanning tree) helps. A wireless hop (mesh backhaul, repeater, WDS) is "
    "such a cable too and is marked (Wi-Fi), because it is the likeliest to fail. Checked only "
    "for sites with at least three network devices whose links to the router are all known.",
)
def single_point(net: Network) -> Iterator[Result]:
    adjacent = _adjacency(net)
    cables: dict[frozenset[str], int] = {}
    wired: set[frozenset[str]] = set()  # pairs with at least one link that is not wireless
    for link in net.links:
        pair = frozenset((_device_of(net, link.a), _device_of(net, link.b)))
        if len(pair) == 2:
            cables[pair] = cables.get(pair, 0) + 1
            if link.kind is not LinkKind.WIRELESS:
                wired.add(pair)
    for site in sorted({d.site_id for d in net.devices}):
        infra = [d for d in net.devices if d.site_id == site and d.role in INFRASTRUCTURE]
        roots = {d.id for d in infra if d.role is DeviceRole.GATEWAY}
        if len(infra) < 3 or not roots:
            continue
        others = {d.id for d in infra} - roots
        none: frozenset[str] = frozenset()
        if not others <= _reach(adjacent, roots, cut=none):
            continue  # the topology is incomplete: some device has no known path to the router
        gateway = _names(sorted(device_name(net, r) for r in roots))
        lines: list[str] = []
        objects: set[str] = set()
        for d in sorted(others, key=lambda i: device_name(net, i)):
            lost = others - {d} - _reach(adjacent, roots, without=d, cut=none)
            if len(lost) >= SPOF_MINIMUM:
                lines.append(f"{device_name(net, d)}: {_affected(net, lost)}")
                objects.add(d)
        for pair, count in sorted(cables.items(), key=lambda t: sorted(t[0])):
            if count > 1 or not pair <= {d.id for d in infra}:
                continue  # several links (a LAG) are redundant
            lost = others - _reach(adjacent, roots, cut=pair)
            if len(lost) >= SPOF_MINIMUM:
                a, b = sorted(device_name(net, d) for d in pair)
                # a hop that is only wireless (a mesh backhaul, #459) is named as such
                how = "" if pair in wired else " (Wi-Fi)"
                lines.append(f"{a} \u2194 {b}{how}: {_affected(net, lost)}")
        if not lines:
            continue
        points = "; ".join(lines)
        yield found(
            f"Single points of failure towards {gateway} (what is cut off): {points}.",
            [site, *sorted(objects)],
            fix="Consider a second uplink (with LAG or spanning tree) for these devices, or "
            "keep a spare.",
            mid="topology.spof",
            fix_id="topology.spof.fix",
            params={"gateway": gateway, "points": points},
        )


RULES = [
    lag_consistent,
    hidden_device,
    unknown_neighbour,
    unknown_network_device,
    management_separate,
    duplicate_device,
    single_point,
]
