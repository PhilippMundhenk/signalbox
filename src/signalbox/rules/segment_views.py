"""Rules that compare what several devices say about one network or client (#165).

They use ``Segment.views`` and ``Client.sightings``, which ``merge`` keeps per device.
"""

from __future__ import annotations

from collections.abc import Iterator

from signalbox.model import DeviceRole, Network
from signalbox.rules import Result, Severity, found, rule
from signalbox.rules._names import device_name, segment_name
from signalbox.rules.vlan import not_fully_read

_LISTING_LIMIT = 4


@rule(
    "clients.segment-disagreement",
    "The router and a switch or access point place a client in different networks",
    Severity.WARNING,
    "The router sees a client in one network, the switch port or SSID it is connected to in "
    "another. Usual causes: a wrong untagged VLAN on the port, a bridge between two VLANs, or "
    "a device that tags its own frames. Only a router's sighting is compared with that of a "
    "switch or access point, and only where both name a network; devices that were not fully "
    "read this round are left out.",
)
def segment_disagreement(net: Network) -> Iterator[Result]:
    unread = not_fully_read(net)
    roles = {d.id: d.role for d in net.devices}
    for client in sorted(net.clients, key=lambda c: c.mac):
        seen = [
            s
            for s in client.sightings
            if s.segment_id and s.device_id in roles and s.device_id not in unread
        ]
        routers = [s for s in seen if roles[s.device_id] is DeviceRole.GATEWAY]
        others = [s for s in seen if roles[s.device_id] is not DeviceRole.GATEWAY]
        for router in routers:
            for other in others:
                if router.segment_id is None or other.segment_id is None:
                    continue
                if router.segment_id == other.segment_id:
                    continue
                names = {
                    "client": client.hostname or client.mac,
                    "router": device_name(net, router.device_id),
                    "router_segment": segment_name(net, router.segment_id),
                    "other": device_name(net, other.device_id),
                    "other_segment": segment_name(net, other.segment_id),
                }
                yield found(
                    f"{names['client']} is in {names['router_segment']} according to "
                    f"{names['router']}, but in {names['other_segment']} according to "
                    f"{names['other']}.",
                    [client.id, router.device_id, other.device_id],
                    fix="Check the untagged VLAN of the port (or the SSID's VLAN) the client is "
                    "on, and whether a device bridges the two networks.",
                    key=f"{router.device_id}:{other.device_id}",
                    mid="clients.segmentDisagreement",
                    fix_id="clients.segmentDisagreement.fix",
                    params=names,
                )


@rule(
    "segment.name-missing",
    "A VLAN has no name on any device",
    Severity.INFO,
    "A VLAN that no device names is hard to recognise in findings, the segments page and "
    "logs. Names derived from the id (vlan20, ether1.20) count as names here. A VLAN that at "
    "least one device names is never reported, and neither is the untagged network.",
)
def name_missing(net: Network) -> Iterator[Result]:
    for seg in sorted(net.segments, key=lambda s: s.id):
        if seg.vlan is None or seg.name or any(v.name for v in seg.views):
            continue
        reporting = ", ".join(
            sorted(device_name(net, v.device_id) for v in seg.views)[:_LISTING_LIMIT]
        )
        yield found(
            f"VLAN {seg.vlan} has no name on any device ({reporting}).",
            [seg.id],
            fix="Give the network a name on the router, for example its purpose (IoT, Guest).",
            mid="segment.nameMissing",
            fix_id="segment.nameMissing.fix",
            params={"vlan": seg.vlan, "devices": reporting},
        )


RULES = [segment_disagreement, name_missing]
