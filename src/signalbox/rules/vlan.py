"""VLAN and link rules: segments reach the gateway, both ends of a link agree.

These rules work on :attr:`Network.links` (each joins two port ids) and on the segment
memberships of the ports. Devices are the nodes of the link graph; a port belongs to its
``device_id``. Ports of a device that reports no VLAN memberships at all are treated as
unknown, not as "carries nothing", so an unmanaged or unread switch never produces errors.

The same holds for a device that was not fully read (#205: unreachable, or its ``interfaces``
read failed): its ports are unknown, and checks that need them are incomplete. A link inferred
from a MAC table may run through devices Signalbox does not read, so a disagreement between its
ends is incomplete too, not an error. A gateway's uplink (WAN) port carries the network of the
router in front of it untagged (``Network.upstream_router``); where the integration does not
report uplinks, a gateway port in no segment that is cabled to another gateway is taken for one.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Iterator
from dataclasses import dataclass
from ipaddress import ip_address

from signalbox.model import (
    Device,
    DeviceRole,
    DeviceStatus,
    Link,
    LinkKind,
    LinkOrigin,
    Membership,
    Neighbour,
    Network,
    PortKind,
)
from signalbox.rules import Result, Severity, found, incomplete, rule


@dataclass(frozen=True)
class _View:
    """Indexes over a network that the rules below share."""

    net: Network
    #: port id -> segment id -> membership mode
    members: dict[str, dict[str, Membership]]
    #: devices with at least one reported membership on one of their own ports
    reporting: frozenset[str]
    #: devices whose ports were not fully read (unreachable, ``interfaces`` failed)
    unread: frozenset[str]

    @classmethod
    def of(cls, net: Network) -> _View:
        members: dict[str, dict[str, Membership]] = {}
        for seg in net.segments:
            for m in seg.members:
                members.setdefault(m.port_id, {})[seg.id] = m.mode
        reporting = frozenset(_device_of(net, p) for p in members)
        return cls(net, members, reporting, not_fully_read(net))

    def known(self, port: str) -> bool:
        """True when the VLANs of this port are known: its device reports memberships and was
        fully read."""
        device = _device_of(self.net, port)
        return device in self.reporting and device not in self.unread

    def is_unread(self, port: str) -> bool:
        return _device_of(self.net, port) in self.unread

    def carries(self, port: str, segment: str) -> bool:
        return segment in self.members.get(port, {})

    def tagged(self, port: str) -> set[str]:
        return {s for s, m in self.members.get(port, {}).items() if m is Membership.TAGGED}

    def untagged(self, port: str) -> frozenset[str]:
        return frozenset(
            s for s, m in self.members.get(port, {}).items() if m is Membership.UNTAGGED
        )


_MAC_LINK = (
    "{} is only inferred from a MAC table and may run through devices that are not read, so "
    "this could not be checked. Enable LLDP on both devices or enter the cable by hand."
)
_UNREAD = frozenset({DeviceStatus.UNREACHABLE, DeviceStatus.AUTH_FAILED, DeviceStatus.UNTRUSTED})


def not_fully_read(net: Network) -> frozenset[str]:
    """Devices whose ports and VLANs are not known from this round: not reachable, or the
    ``interfaces`` capability failed (a partly read device keeps what it did read)."""
    failed = {e.device_id for e in net.errors if e.capability == "interfaces"}
    return frozenset(
        d.id for d in net.devices if net.statuses.get(d.id) in _UNREAD or d.id in failed
    )


def uplink_end(net: Network, view: _View, link: Link, port: str) -> tuple[bool, str | None]:
    """Is ``port`` (an end of ``link``) a gateway's uplink, and which segment does it carry
    untagged: the upstream router's network (None: not known)?

    An uplink reported on the port counts (#148); without one, a gateway port that is in no
    segment and is cabled to another gateway's port is taken for an uplink (#205).
    """
    if view.members.get(port):
        return False, None
    uplink = net.uplink_at(port)
    if uplink is not None:
        sub = net.upstream_router(uplink)
        return True, sub.segment_id if sub else None
    other = link.b if port == link.a else link.a
    here, there = net.device(_device_of(net, port)), net.device(_device_of(net, other))
    gateways = (
        here is not None
        and there is not None
        and here.id != there.id
        and here.role is DeviceRole.GATEWAY
        and there.role is DeviceRole.GATEWAY
    )
    return gateways, None


def _device_of(net: Network, port: str) -> str:
    p = net.port(port)
    if p is not None:
        return p.device_id
    return port.split("/port/", 1)[0]


def _device_name(net: Network, device_id: str) -> str:
    d = net.device(device_id)
    return d.name if d else device_id


def _port_name(net: Network, port: str) -> str:
    p = net.port(port)
    name = p.label() if p else port.split("/port/", 1)[-1]
    return f"{_device_name(net, _device_of(net, port))} port {name}"


def _link_name(net: Network, link: Link) -> str:
    return f"{_port_name(net, link.a)} \u2194 {_port_name(net, link.b)}"


def _segment_name(net: Network, segment: str) -> str:
    seg = net.segment(segment)
    if seg is None:
        return segment
    if seg.name:
        return f"{seg.name} (VLAN {seg.vlan})" if seg.vlan else seg.name
    return f"VLAN {seg.vlan}" if seg.vlan else "the untagged network"


def _gateways(net: Network) -> dict[str, set[str]]:
    """segment id -> devices that route it (a gateway device or a subnet marked as gateway)."""
    roles = {d.id: d.role for d in net.devices}
    out: dict[str, set[str]] = {}
    for sn in net.subnets:
        if sn.gateway or roles.get(sn.device_id) is DeviceRole.GATEWAY:
            out.setdefault(sn.segment_id, set()).add(sn.device_id)
    return out


def internal(net: Network, port: str) -> bool:
    """The port is known to be internal (CPU port, bridge, VLAN interface; #252): no cable
    ends there, so link and VLAN checks that compare cable ends leave it out."""
    p = net.port(port)
    return p is not None and p.external is False


def _link_ends(net: Network) -> set[str]:
    return {p for link in net.links for p in (link.a, link.b)}


def _used_segments(net: Network) -> dict[str, set[str]]:
    """device id -> segments it serves to clients: SSIDs on APs, access ports on APs/switches."""
    roles = {d.id: d.role for d in net.devices}
    out: dict[str, set[str]] = {}
    for w in net.wlans:
        if w.enabled and w.segment_id and roles.get(w.device_id) is DeviceRole.AP:
            out.setdefault(w.device_id, set()).add(w.segment_id)
    uplinks = _link_ends(net)
    for seg in net.segments:
        for m in seg.members:
            dev = _device_of(net, m.port_id)
            if (
                m.mode is Membership.UNTAGGED
                and m.port_id not in uplinks
                and not internal(net, m.port_id)
                and roles.get(dev) in (DeviceRole.AP, DeviceRole.SWITCH)
            ):
                out.setdefault(dev, set()).add(seg.id)
    return out


def _paths(net: Network, start: str) -> dict[str, list[Link]]:
    """Shortest link path from ``start`` to every device it reaches (breadth first, stable)."""
    adjacent: dict[str, list[tuple[str, Link]]] = {}
    for link in net.links:
        a, b = _device_of(net, link.a), _device_of(net, link.b)
        if a != b:
            adjacent.setdefault(a, []).append((b, link))
            adjacent.setdefault(b, []).append((a, link))
    paths: dict[str, list[Link]] = {start: []}
    queue = deque([start])
    while queue:
        here = queue.popleft()
        for there, link in sorted(adjacent.get(here, []), key=lambda t: (t[0], t[1].id)):
            if there not in paths:
                paths[there] = [*paths[here], link]
                queue.append(there)
    return paths


@rule(
    "vlan.path-to-gateway",
    "VLAN does not reach the gateway",
    Severity.ERROR,
    "Every network (VLAN) that an access point offers on an SSID, or that a switch or access "
    "point puts on an access port, has to be carried on every cable between that device and the "
    "router that serves its addresses. If one switch on the way does not carry it, clients on "
    "that network get no address and no internet.",
)
def path_to_gateway(net: Network) -> Iterator[Result]:
    view = _View.of(net)
    gateways = _gateways(net)
    # (segment, link) -> names of the devices whose clients need it
    missing: dict[tuple[str, str], set[str]] = {}
    links = {link.id: link for link in net.links}
    unknown_ends: set[tuple[str, str]] = set()
    for dev, used in sorted(_used_segments(net).items()):
        # segments routed elsewhere; one without a router is a plain layer-2 VLAN
        segments = sorted(s for s in used if s in gateways and dev not in gateways[s])
        if not segments:
            continue
        paths = _paths(net, dev)
        unconnected = False
        for seg in segments:
            reached = sorted(g for g in gateways[seg] if g in paths)
            if not reached:
                unconnected = True
                continue
            target = min(reached, key=lambda g: (len(paths[g]), g))
            for link in paths[target]:
                for end in (link.a, link.b):
                    if uplink_end(net, view, link, end)[0] or internal(net, end):
                        continue  # a router's uplink, or an internal port (#252)
                    if not view.known(end):
                        unknown_ends.add((link.id, end))
                    elif not view.carries(end, seg):
                        missing.setdefault((seg, link.id), set()).add(_device_name(net, dev))
        if unconnected:
            yield incomplete(
                f"{_device_name(net, dev)} is not connected to the gateway in the known "
                "topology, so the path of its VLANs could not be checked. Add the missing "
                "link (cable or wireless uplink) or enable LLDP on the devices in between.",
                [dev],
                key="unconnected",
                mid="vlan.unconnected",
                params={"name": _device_name(net, dev)},
            )
    for link_id, end in sorted(unknown_ends):
        what = "was not fully read" if view.is_unread(end) else "does not report VLAN memberships"
        yield incomplete(
            f"{_device_name(net, _device_of(net, end))} {what}, so "
            f"{_link_name(net, links[link_id])} could not be checked.",
            [link_id, end],
            key="unknown-port",
            mid="vlan.unread" if view.is_unread(end) else "vlan.noMemberships",
            params={
                "device": _device_name(net, _device_of(net, end)),
                "link": _link_name(net, links[link_id]),
            },
        )
    for (seg, link_id), users in sorted(missing.items()):
        link = links[link_id]
        lacking = [e for e in (link.a, link.b) if not view.carries(e, seg)]
        ports = ", ".join(_port_name(net, e) for e in lacking)
        if link.origin is LinkOrigin.MAC:
            yield incomplete(
                f"{_segment_name(net, seg)}, used on {', '.join(sorted(users))}, is not "
                f"configured on {ports}. {_MAC_LINK.format(f'The link {_link_name(net, link)}')}",
                [seg, link_id, *lacking],
                key="mac-link",
                mid="vlan.missingMac",
                params={
                    "segment": _segment_name(net, seg),
                    "users": ", ".join(sorted(users)),
                    "ports": ports,
                    "link": _link_name(net, link),
                },
            )
            continue
        yield found(
            f"{_segment_name(net, seg)}, used on {', '.join(sorted(users))}, is not carried on "
            f"the link {_link_name(net, link)} (missing on {ports}).",
            [seg, link_id, *lacking],
            fix=f"Add {_segment_name(net, seg)} as tagged VLAN to {ports}.",
            mid="vlan.missing",
            fix_id="vlan.missing.fix",
            params={
                "segment": _segment_name(net, seg),
                "users": ", ".join(sorted(users)),
                "link": _link_name(net, link),
                "ports": ports,
            },
        )


def _comparable(net: Network, view: _View) -> Iterator[Link]:
    """Links whose two ends both report VLAN memberships and are not internal ports."""
    for link in net.links:
        if internal(net, link.a) or internal(net, link.b):
            continue
        if view.known(link.a) and view.known(link.b):
            yield link


@rule(
    "vlan.native-mismatch",
    "Untagged VLAN differs between the ends of a link",
    Severity.ERROR,
    "Both ends of a cable must agree on which network travels untagged (the native VLAN). "
    "If they differ, devices on one network suddenly appear on the other one, or lose their "
    "connection.",
)
def native_mismatch(net: Network) -> Iterator[Result]:
    view = _View.of(net)
    for link in _comparable(net, view):
        ends: list[frozenset[str]] = []
        for end in (link.a, link.b):
            is_uplink, carries = uplink_end(net, view, link, end)
            if is_uplink and carries is None:
                break  # the uplink to a router whose network is not known
            ends.append(frozenset({carries}) if carries else view.untagged(end))
        if len(ends) < 2 or ends[0] == ends[1]:
            continue
        a, b = ends

        def describe(segs: frozenset[str]) -> str:
            return ", ".join(sorted(_segment_name(net, s) for s in segs)) or "\u2013"

        values = {
            "link": _link_name(net, link),
            "a_port": _port_name(net, link.a),
            "a": describe(a),
            "b_port": _port_name(net, link.b),
            "b": describe(b),
        }
        message = (
            f"{_link_name(net, link)}: {_port_name(net, link.a)} sends {describe(a)} untagged, "
            f"{_port_name(net, link.b)} sends {describe(b)} untagged."
        )
        if link.origin is LinkOrigin.MAC:
            yield incomplete(
                f"{message} {_MAC_LINK.format('It')}",
                [link.id, link.a, link.b],
                key="mac-link",
                mid="vlan.nativeMac",
                params=values,
            )
            continue
        yield found(
            message,
            [link.id, link.a, link.b],
            fix="Set the same untagged (native) VLAN on both ports, or none on both.",
            mid="vlan.native",
            fix_id="vlan.native.fix",
            params=values,
        )


@rule(
    "vlan.tagged-both-ends",
    "VLAN tagged on only one end of a link",
    Severity.WARNING,
    "A VLAN that one end of a cable sends tagged must also be configured on the other end, "
    "otherwise its traffic is dropped there.",
)
def tagged_both_ends(net: Network) -> Iterator[Result]:
    view = _View.of(net)
    for link in _comparable(net, view):
        if any(uplink_end(net, view, link, e)[0] for e in (link.a, link.b)):
            continue
        for here, there in ((link.a, link.b), (link.b, link.a)):
            for seg in sorted(view.tagged(here)):
                if view.carries(there, seg):
                    continue
                values = {
                    "segment": _segment_name(net, seg),
                    "here": _port_name(net, here),
                    "there": _port_name(net, there),
                    "link": _link_name(net, link),
                }
                message = (
                    f"{_segment_name(net, seg)} is tagged on {_port_name(net, here)} but not "
                    f"configured on {_port_name(net, there)} ({_link_name(net, link)})."
                )
                if link.origin is LinkOrigin.MAC:
                    yield incomplete(
                        f"{message} {_MAC_LINK.format('The link')}",
                        [seg, link.id, there],
                        key="mac-link",
                        mid="vlan.taggedMac",
                        params=values,
                    )
                    continue
                yield found(
                    message,
                    [seg, link.id, there],
                    fix=f"Add {_segment_name(net, seg)} as tagged VLAN to "
                    f"{_port_name(net, there)}, or remove it from {_port_name(net, here)}.",
                    mid="vlan.tagged",
                    fix_id="vlan.tagged.fix",
                    params=values,
                )


@rule(
    "vlan.unused",
    "VLAN is not used",
    Severity.INFO,
    "The router has an address range for this network, but no switch port and no SSID uses it. "
    "It may be left over from an earlier setup.",
)
def unused(net: Network) -> Iterator[Result]:
    gateways = _gateways(net)
    used_by_wlan = {w.segment_id for w in net.wlans if w.segment_id}
    for seg_id in sorted(gateways):
        if seg_id in used_by_wlan:
            continue
        seg = net.segment(seg_id)
        own = gateways[seg_id]
        members = seg.members if seg else []
        if any(_device_of(net, m.port_id) not in own for m in members):
            continue
        names = ", ".join(sorted(_device_name(net, g) for g in own))
        yield found(
            f"{_segment_name(net, seg_id)} has a subnet on {names} but no other port and no "
            "SSID uses it.",
            [seg_id],
            fix="Remove the VLAN and its subnet if it is no longer needed, or add it to the "
            "ports and SSIDs that should use it.",
            mid="vlan.unused",
            fix_id="vlan.unused.fix",
            params={"segment": _segment_name(net, seg_id), "names": names},
        )


@rule(
    "link.speed-duplex",
    "Link ends disagree on speed or duplex",
    Severity.WARNING,
    "The two ends of a cable report a different speed or duplex mode. This usually means a "
    "fixed setting on one side and auto-negotiation on the other, or a damaged cable, and "
    "causes slow or unreliable connections.",
)
def speed_duplex(net: Network) -> Iterator[Result]:
    for link in net.links:
        if link.kind is LinkKind.WIRELESS:
            continue
        a, b = net.port(link.a), net.port(link.b)
        if a is None or b is None or a.up is False or b.up is False:
            continue
        if a.external is False or b.external is False:
            continue  # an internal port (#252): its speed is not the cable's
        objects = [link.id, link.a, link.b]
        if a.speed_mbps is not None and b.speed_mbps is not None and a.speed_mbps != b.speed_mbps:
            yield found(
                f"{_link_name(net, link)}: {_port_name(net, link.a)} runs at "
                f"{a.speed_mbps} Mbit/s, {_port_name(net, link.b)} at {b.speed_mbps} Mbit/s.",
                objects,
                fix="Set both ports to auto-negotiation; if it stays, replace the cable.",
                key="speed",
                mid="vlan.speed",
                fix_id="vlan.speed.fix",
                params={
                    "link": _link_name(net, link),
                    "a": _port_name(net, link.a),
                    "a_speed": a.speed_mbps,
                    "b": _port_name(net, link.b),
                    "b_speed": b.speed_mbps,
                },
            )
        if (
            a.full_duplex is not None
            and b.full_duplex is not None
            and a.full_duplex != b.full_duplex
        ):

            def mode(full: bool) -> str:
                return "FDX" if full else "HDX"

            yield found(
                f"{_link_name(net, link)}: {_port_name(net, link.a)} runs "
                f"{mode(a.full_duplex)}, {_port_name(net, link.b)} {mode(b.full_duplex)}.",
                objects,
                fix="Set both ports to auto-negotiation (or the same fixed speed and duplex).",
                key="duplex",
                mid="vlan.duplex",
                fix_id="vlan.duplex.fix",
                params={
                    "link": _link_name(net, link),
                    "a": _port_name(net, link.a),
                    "a_mode": mode(a.full_duplex),
                    "b": _port_name(net, link.b),
                    "b_mode": mode(b.full_duplex),
                },
            )


#: Roles of network equipment (everything but end devices).
INFRASTRUCTURE = (DeviceRole.GATEWAY, DeviceRole.SWITCH, DeviceRole.AP)


def address_segment(net: Network, device: Device) -> str | None:
    """Segment of a subnet at the device's site that contains its management address."""
    try:
        addr = ip_address((device.management_address or "").strip("[]"))
    except ValueError:
        return None
    sites = {s.id: s.site_id for s in net.segments}
    for sn in sorted(net.subnets, key=lambda sn: sn.id):
        site = sites.get(sn.segment_id, sn.segment_id.split("/segment/", 1)[0])
        if site == device.site_id and addr in sn.interface.network:
            return sn.segment_id
    return None


def _announces(net: Network, nb: Neighbour, devices: set[str]) -> bool:
    """True when an LLDP neighbour is one of ``devices`` (by port MAC or system name)."""
    chassis = nb.chassis_id.lower()
    for d in devices:
        dev = net.device(d)
        if dev and nb.system_name and nb.system_name.lower() == dev.name.lower():
            return True
        if any(p.mac == chassis for p in net.ports if p.device_id == d):
            return True
    return False


def _and(items: list[str]) -> str:
    return ", ".join(items)


def _ap_segments(net: Network, ap: Device, uplink: Link) -> set[str] | None:
    """Every segment the access point uses itself, or None when that is not fully known."""
    if ap.managed_by is not None:
        return None  # a controller may move SSIDs between access points
    if any(e.device_id == ap.id and e.capability == "wireless" for e in net.errors):
        return None
    if ap.id in not_fully_read(net):
        return None
    wlans = [w for w in net.wlans if w.device_id == ap.id and w.enabled]
    if not wlans or any(w.segment_id is None for w in wlans):
        return None
    for link in net.links:
        if link.id != uplink.id and ap.id in (_device_of(net, link.a), _device_of(net, link.b)):
            return None  # it forwards to further devices
    ends = {_device_of(net, uplink.a), _device_of(net, uplink.b)}
    for nb in net.neighbours:
        here = _device_of(net, nb.local_port_id)
        if nb.local_port_id in (uplink.a, uplink.b):
            if not _announces(net, nb, ends - {here}):
                return None  # something else (perhaps a switch) sits on the cable
        elif here == ap.id:
            return None  # a neighbour behind another port of the access point
    own = {sn.segment_id for sn in net.subnets if sn.device_id == ap.id}
    management = address_segment(net, ap)
    if management is None and not own:
        return None  # the VLAN it is managed in is unknown
    used = _used_segments(net).get(ap.id, set()) | own
    used |= {w.segment_id for w in wlans if w.segment_id}
    if management is not None:
        used.add(management)
    return used


@rule(
    "vlan.trunk-scope",
    "Link to an access point carries networks it does not use",
    Severity.INFO,
    "The cable to an access point should carry only the networks (VLANs) the access point uses "
    "for its SSIDs, its own access ports and its management address. Every extra VLAN on the "
    "cable can be reached by anyone who unplugs the access point (in a hallway or outdoors), "
    "and its broadcasts flood the access point.",
)
def trunk_scope(net: Network) -> Iterator[Result]:
    view = _View.of(net)
    devices = {d.id: d for d in net.devices}
    for link in net.links:
        if link.kind is LinkKind.WIRELESS:
            continue
        for ap_end, up_end in ((link.a, link.b), (link.b, link.a)):
            ap = devices.get(_device_of(net, ap_end))
            upstream = devices.get(_device_of(net, up_end))
            if ap is None or ap.role is not DeviceRole.AP or upstream is None:
                continue
            if upstream.role is DeviceRole.AP or not view.known(up_end):
                continue
            used = _ap_segments(net, ap, link)
            if used is None:
                continue
            extra = sorted(view.tagged(up_end) - used)
            if not extra:
                continue
            names = _and([_segment_name(net, s) for s in extra])
            uses = _and(sorted(_segment_name(net, s) for s in used))
            yield found(
                f"The link to {ap.name} carries {names}, but {ap.name} only uses {uses}.",
                [link.id, up_end],
                fix=f"Remove {names} from {_port_name(net, up_end)}.",
                mid="vlan.trunkScope",
                fix_id="vlan.trunkScope.fix",
                params={
                    "ap": ap.name,
                    "names": names,
                    "uses": uses,
                    "port": _port_name(net, up_end),
                },
            )


_SLOW_MBPS = 1000


@rule(
    "link.slow",
    "Slow or half-duplex link",
    Severity.WARNING,
    "A cable between two network devices (router, switch, access point) runs at 10 or 100 "
    "Mbit/s, or a port runs in half duplex. A slow uplink caps every client behind it, which "
    "looks like slow internet or slow Wi-Fi; half duplex causes collisions. Common causes are a "
    "damaged cable or connector that uses only two pairs, an old patch panel, or a port set to "
    "a fixed speed. A link slower than both ports support (1 Gbit/s on two 2.5 Gbit/s ports) is "
    "reported as info.",
)
def slow(net: Network) -> Iterator[Result]:
    devices = {d.id: d for d in net.devices}
    ends: set[str] = set()
    for link in net.links:
        if link.kind is LinkKind.WIRELESS:
            continue
        ends |= {link.a, link.b}
        known = [devices[d] for e in (link.a, link.b) if (d := _device_of(net, e)) in devices]
        if not known or any(d.role not in INFRASTRUCTURE for d in known):
            continue
        ports = [p for e in (link.a, link.b) if (p := net.port(e)) is not None]
        if any(p.kind is not PortKind.ETHERNET or p.up is False for p in ports):
            continue  # an end is down, or an aggregate or virtual port
        if any(p.external is False for p in ports):
            continue  # an internal port (#252)
        speeds = [p.speed_mbps for p in ports if p.speed_mbps is not None]
        maxima = [p.max_speed_mbps for p in ports if p.max_speed_mbps is not None]
        if speeds and maxima and min(speeds) >= min(maxima):
            pass  # as fast as the slower port can go (a 100 Mbit/s-only device)
        elif speeds and min(speeds) < _SLOW_MBPS:
            yield found(
                f"The link {_link_name(net, link)} runs at {min(speeds)} Mbit/s.",
                [link.id],
                fix="Replace the cable (it may use only two pairs) or check that both ports are "
                "set to auto-negotiation.",
                key="speed",
                mid="vlan.slowLink",
                fix_id="vlan.slowLink.fix",
                params={"link": _link_name(net, link), "speed": min(speeds)},
            )
        elif speeds and len(ports) == 2 and len(maxima) == 2 and min(speeds) < min(maxima):
            yield found(
                f"The link {_link_name(net, link)} runs at {min(speeds)} Mbit/s, but both "
                f"ports support {min(maxima)} Mbit/s.",
                [link.id],
                fix="Use a cable rated for the higher speed (Cat 5e or better for 2.5 Gbit/s, "
                "Cat 6a for 10 Gbit/s), check that both ports advertise it in "
                "auto-negotiation, and replace a damaged cable.",
                severity=Severity.INFO,
                key="max-speed",
                mid="vlan.belowMax",
                fix_id="vlan.belowMax.fix",
                params={"link": _link_name(net, link), "speed": min(speeds), "max": min(maxima)},
            )
        half = [p for p in ports if p.full_duplex is False]
        if half:
            yield found(
                f"The link {_link_name(net, link)} runs in half duplex on "
                f"{', '.join(_port_name(net, p.id) for p in half)}.",
                [link.id],
                fix="Set both ports to auto-negotiation (or the same fixed speed and full "
                "duplex); if it stays, replace the cable.",
                key="duplex",
                mid="vlan.halfDuplex",
                fix_id="vlan.halfDuplex.fix",
                params={
                    "link": _link_name(net, link),
                    "ports": ", ".join(_port_name(net, p.id) for p in half),
                },
            )
    for p in net.ports:
        dev = devices.get(p.device_id)
        if p.id in ends or dev is None or dev.role not in INFRASTRUCTURE:
            continue
        if p.kind is not PortKind.ETHERNET or p.up is not True or p.external is False:
            continue  # not a wired port with link, or an internal one (CPU port, #252)
        if p.full_duplex is False:
            yield found(
                f"{_port_name(net, p.id)} runs in half duplex.",
                [p.id],
                fix="Set the port and the connected device to auto-negotiation; if it stays, "
                "replace the cable.",
                key="duplex",
                mid="vlan.portHalfDuplex",
                fix_id="vlan.portHalfDuplex.fix",
                params={"port": _port_name(net, p.id)},
            )
        elif (
            p.speed_mbps is not None
            and p.speed_mbps <= 10
            and (p.max_speed_mbps is None or p.max_speed_mbps > p.speed_mbps)
        ):
            yield found(
                f"{_port_name(net, p.id)} runs at {p.speed_mbps} Mbit/s.",
                [p.id],
                fix="Check the cable and the connected device; almost every device today "
                "reaches at least 100 Mbit/s.",
                severity=Severity.INFO,
                key="speed",
                mid="vlan.portSlow",
                fix_id="vlan.portSlow.fix",
                params={"port": _port_name(net, p.id), "speed": p.speed_mbps},
            )


RULES = [
    path_to_gateway,
    native_mismatch,
    tagged_both_ends,
    unused,
    speed_duplex,
    trunk_scope,
    slow,
]
