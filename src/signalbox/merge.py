"""Join device snapshots into one :class:`~signalbox.model.Network`."""

from __future__ import annotations

from collections.abc import Iterable

from signalbox.model import (
    Client,
    DeviceRole,
    Link,
    Network,
    PortMembership,
    Segment,
    Site,
    Snapshot,
)


def _merge_segments(snaps: list[Snapshot]) -> list[Segment]:
    """One segment per id; a port's membership is taken from the device that owns the port.

    Other devices may report foreign ports (for example a controller that knows its switches);
    their view only fills gaps.
    """
    merged: dict[str, Segment] = {}
    members: dict[str, dict[str, tuple[bool, PortMembership]]] = {}
    for snap in snaps:
        own = f"{snap.device.id}/"
        for seg in snap.segments:
            old = merged.get(seg.id)
            merged[seg.id] = (
                seg.model_copy(update={"source": None, "vendor_extra": {}})
                if old is None
                else old.model_copy(update={"name": old.name or seg.name})
            )
            known = members.setdefault(seg.id, {})
            for m in seg.members:
                owned = m.port_id.startswith(own)
                if m.port_id not in known or (owned and not known[m.port_id][0]):
                    known[m.port_id] = (owned, m)
    result = []
    for sid in sorted(merged):
        by_port = members[sid]
        result.append(
            merged[sid].model_copy(update={"members": [by_port[p][1] for p in sorted(by_port)]})
        )
    return result


def _merge_clients(snapshots: list[Snapshot]) -> list[Client]:
    """One client per MAC address.

    Addresses are joined. Where it was seen comes from the most specific device: an access point
    or switch knows the port, a gateway only knows the client exists.
    """
    rank = {DeviceRole.AP: 0, DeviceRole.SWITCH: 1, DeviceRole.OTHER: 2, DeviceRole.GATEWAY: 3}
    ordered = sorted(snapshots, key=lambda s: (rank[s.device.role], s.device.id))
    merged: dict[str, Client] = {}
    for snap in ordered:
        for c in snap.clients:
            old = merged.get(c.mac)
            if old is None:
                merged[c.mac] = c.model_copy(update={"id": f"client/{c.mac}"})
                continue
            addresses = list(dict.fromkeys([*old.addresses, *c.addresses]))
            last_seen = max(
                (t for t in (old.last_seen, c.last_seen) if t is not None), default=None
            )
            merged[c.mac] = old.model_copy(
                update={
                    "addresses": addresses,
                    "hostname": old.hostname or c.hostname,
                    "segment_id": old.segment_id or c.segment_id,
                    "seen_on": old.seen_on or c.seen_on,
                    "last_seen": last_seen,
                }
            )
    return sorted(merged.values(), key=lambda c: c.mac)


def merge(
    sites: Iterable[Site],
    snapshots: Iterable[Snapshot],
    links: Iterable[Link] = (),
) -> Network:
    """Merge snapshots (one per device) and the known links into a network."""
    snaps = sorted(snapshots, key=lambda s: s.device.id)
    ids = [s.device.id for s in snaps]
    duplicates = sorted({i for i in ids if ids.count(i) > 1})
    if duplicates:
        raise ValueError(f"more than one snapshot for device(s) {', '.join(duplicates)}")

    def every(attr: str) -> list[object]:
        return [item for s in snaps for item in getattr(s, attr)]

    return Network.model_validate(
        {
            "sites": sorted(sites, key=lambda s: s.id),
            "devices": [d for s in snaps for d in (s.device, *s.extra_devices)],
            "statuses": {
                d.id: s.extra_status.get(d.id, s.status) if d is not s.device else s.status
                for s in snaps
                for d in (s.device, *s.extra_devices)
            },
            "ports": every("ports"),
            "segments": _merge_segments(snaps),
            "subnets": every("subnets"),
            "dhcp_servers": every("dhcp_servers"),
            "dns_services": every("dns_services"),
            "radios": every("radios"),
            "wlans": every("wlans"),
            "clients": _merge_clients(snaps),
            "neighbours": every("neighbours"),
            "links": sorted(links, key=lambda link: link.id),
            "errors": every("errors"),
        }
    )
