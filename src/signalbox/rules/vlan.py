"""VLAN and link rules: segments reach the gateway, both ends of a link agree.

These rules work on :attr:`Network.links` (each joins two port ids) and on the segment
memberships of the ports. Devices are the nodes of the link graph; a port belongs to its
``device_id``. Ports of a device that reports no VLAN memberships at all are treated as
unknown, not as "carries nothing", so an unmanaged or unread switch never produces errors.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Iterator
from dataclasses import dataclass

from signalbox.model import DeviceRole, Link, LinkKind, Membership, Network
from signalbox.rules import Result, Severity, found, incomplete, rule


@dataclass(frozen=True)
class _View:
    """Indexes over a network that the rules below share."""

    net: Network
    #: port id -> segment id -> membership mode
    members: dict[str, dict[str, Membership]]
    #: devices with at least one reported membership on one of their own ports
    reporting: frozenset[str]

    @classmethod
    def of(cls, net: Network) -> _View:
        members: dict[str, dict[str, Membership]] = {}
        for seg in net.segments:
            for m in seg.members:
                members.setdefault(m.port_id, {})[seg.id] = m.mode
        reporting = frozenset(_device_of(net, p) for p in members)
        return cls(net, members, reporting)

    def known(self, port: str) -> bool:
        """True when the VLANs of this port are known (its device reports memberships)."""
        return _device_of(self.net, port) in self.reporting

    def carries(self, port: str, segment: str) -> bool:
        return segment in self.members.get(port, {})

    def tagged(self, port: str) -> set[str]:
        return {s for s, m in self.members.get(port, {}).items() if m is Membership.TAGGED}

    def untagged(self, port: str) -> frozenset[str]:
        return frozenset(
            s for s, m in self.members.get(port, {}).items() if m is Membership.UNTAGGED
        )


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
    name = p.name if p else port.split("/port/", 1)[-1]
    return f"{_device_name(net, _device_of(net, port))} port {name}"


def _link_name(net: Network, link: Link) -> str:
    return f"{_port_name(net, link.a)} to {_port_name(net, link.b)}"


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
            )
    for link_id, end in sorted(unknown_ends):
        yield incomplete(
            f"{_device_name(net, _device_of(net, end))} does not report VLAN memberships, so "
            f"{_link_name(net, links[link_id])} could not be checked.",
            [link_id, end],
            key="unknown-port",
        )
    for (seg, link_id), users in sorted(missing.items()):
        link = links[link_id]
        lacking = [e for e in (link.a, link.b) if not view.carries(e, seg)]
        ports = " and ".join(_port_name(net, e) for e in lacking)
        yield found(
            f"{_segment_name(net, seg)}, used on {', '.join(sorted(users))}, is not carried on "
            f"the link {_link_name(net, link)} (missing on {ports}).",
            [seg, link_id, *lacking],
            fix=f"Add {_segment_name(net, seg)} as tagged VLAN to {ports}.",
        )


def _comparable(net: Network, view: _View) -> Iterator[Link]:
    """Links whose two ends both report VLAN memberships."""
    for link in net.links:
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
        a, b = view.untagged(link.a), view.untagged(link.b)
        if a == b:
            continue

        def describe(segs: frozenset[str]) -> str:
            return " and ".join(sorted(_segment_name(net, s) for s in segs)) or "nothing"

        yield found(
            f"{_link_name(net, link)}: {_port_name(net, link.a)} sends {describe(a)} untagged, "
            f"{_port_name(net, link.b)} sends {describe(b)} untagged.",
            [link.id, link.a, link.b],
            fix="Set the same untagged (native) VLAN on both ports, or none on both.",
        )


@rule(
    "vlan.tagged-both-ends",
    "VLAN tagged on only one end of a link",
    Severity.ERROR,
    "A VLAN that one end of a cable sends tagged must also be configured on the other end, "
    "otherwise its traffic is dropped there.",
)
def tagged_both_ends(net: Network) -> Iterator[Result]:
    view = _View.of(net)
    for link in _comparable(net, view):
        for here, there in ((link.a, link.b), (link.b, link.a)):
            for seg in sorted(view.tagged(here)):
                if view.carries(there, seg):
                    continue
                yield found(
                    f"{_segment_name(net, seg)} is tagged on {_port_name(net, here)} but not "
                    f"configured on {_port_name(net, there)} ({_link_name(net, link)}).",
                    [seg, link.id, there],
                    fix=f"Add {_segment_name(net, seg)} as tagged VLAN to "
                    f"{_port_name(net, there)}, or remove it from {_port_name(net, here)}.",
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
        objects = [link.id, link.a, link.b]
        if a.speed_mbps is not None and b.speed_mbps is not None and a.speed_mbps != b.speed_mbps:
            yield found(
                f"{_link_name(net, link)}: {_port_name(net, link.a)} runs at "
                f"{a.speed_mbps} Mbit/s, {_port_name(net, link.b)} at {b.speed_mbps} Mbit/s.",
                objects,
                fix="Set both ports to auto-negotiation; if it stays, replace the cable.",
                key="speed",
            )
        if (
            a.full_duplex is not None
            and b.full_duplex is not None
            and a.full_duplex != b.full_duplex
        ):

            def mode(full: bool) -> str:
                return "full duplex" if full else "half duplex"

            yield found(
                f"{_link_name(net, link)}: {_port_name(net, link.a)} runs "
                f"{mode(a.full_duplex)}, {_port_name(net, link.b)} {mode(b.full_duplex)}.",
                objects,
                fix="Set both ports to auto-negotiation (or the same fixed speed and duplex).",
                key="duplex",
            )


RULES = [path_to_gateway, native_mismatch, tagged_both_ends, unused, speed_duplex]
