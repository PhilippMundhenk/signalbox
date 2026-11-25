"""What the forwarding databases (MAC address tables, #160, ADR 0015) say about where things
are plugged in: which ports are uplinks, the port a client sits behind, and links between
managed devices, also through switches Signalbox does not read.

Core logic only: adapters report :class:`~signalbox.model.FdbEntry` objects as the device
keeps them; everything here is derived on the merged :class:`~signalbox.model.Network`.

- A *sighting* is a MAC address learned on a port: every dynamic or static entry on a port
  that is not internal (``Port.external`` is not False). A device that reports no table at all
  contributes the port its clients were seen on (``Client.seen_on``), as integrations without a
  table (ARP-based routers, Fritz!Box) say it.
- A port is an *uplink* when it learns the MAC address of another managed device (one of its
  ports' MACs or a device's own table entry), or when it is the end of a cable link.
- A wired client sits behind the port among its sightings that is not an uplink and learns the
  fewest addresses (an access port beats the uplinks of every switch in front of it); with
  only uplinks, the one with the fewest addresses.
- A port that learns another managed device's address is linked to that device, unless a third
  managed device that the port also learns sits between them: the far device learns the third
  one on the same port as this one, and the third one learns the two on different ports (or
  has no table), or the third one's table learns the two on different ports. With no table
  of either to tell, a switch is taken to sit before a device that is no switch (#378).
  Devices joined by an unmanaged switch are all linked to each other. The far end is the port
  where the far device learns this device's addresses, else the jack that owns the learned
  address; for a device without a table and without a MAC per port (NETGEAR Plus, Easy Smart)
  the port is guessed from PVID, VLANs and speed, and the link is *inferred*.
- The addresses of a managed device are its ports' MACs, its own table entries, ``Device.mac``
  and the MAC an ARP/NDP table gives for its management address (#378).
- Sightings on a VLAN interface count for the jack below it (an ARP table names ``igb1.10``).
- A *coarse* port (``Port.coarse``: a host list that puts every wired host on one port, as the
  FRITZ!Box ``lan``) is no per-port table: it is linked only to devices that report no table
  or whose own table learns it on a wired port, never to one whose bridge uplink is wireless
  (#529). When several devices learned on one port are told apart by nothing and one of them
  lacks a per-port table, the one holding their default next hop (the gateway) is the nearest:
  a LAN is taken as a star around its gateway.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from signalbox.model import (
    Client,
    DeviceRole,
    EvidenceSource,
    FdbKind,
    LinkEvidence,
    LinkKind,
    Membership,
    MeshPeerRole,
    MeshUplink,
    Network,
    Port,
    PortKind,
    PortRole,
)


@dataclass(frozen=True)
class Sighting:
    device_id: str
    port_id: str
    mac: str


@dataclass
class Index:
    """Lookups over the sightings of a network."""

    sightings: list[Sighting]
    #: MAC → device id, for the addresses of managed devices.
    owner: dict[str, str]
    #: MAC → the port that owns it.
    port_of_mac: dict[str, str]
    #: Device id → its addresses.
    macs: dict[str, set[str]]
    #: Port id → MAC addresses learned there.
    learned: dict[str, set[str]] = field(default_factory=dict)
    uplinks: set[str] = field(default_factory=set)
    #: MAC → sightings of it.
    where: dict[str, list[Sighting]] = field(default_factory=dict)
    #: Device id → port id → MACs learned there, by the devices' own tables.
    tables: dict[str, dict[str, set[str]]] = field(default_factory=dict)
    #: MAC → the port of the ARP/NDP entry that gave it to a device by its management address.
    by_address: dict[str, str] = field(default_factory=dict)
    #: Devices that report a MAC address table (even one with nothing usable in it).
    reporting: set[str] = field(default_factory=set)
    #: Coarse ports (``Port.coarse``, #529): their sightings are no per-port table.
    coarse: set[str] = field(default_factory=set)

    def count(self, port_id: str) -> int:
        return len(self.learned.get(port_id, ()))

    def ports_learning(self, device_id: str, macs: set[str]) -> Counter[str]:
        """Ports of a device where it learns any of ``macs``, with how many of them."""
        table = self.tables.get(device_id, {})
        return Counter({p: n for p, learned in table.items() if (n := len(learned & macs))})


def index(net: Network, held: bool = False) -> Index:
    """The sightings of a network; ``held``: also those of earlier rounds the runner added
    (``Network.held_sightings``, #378), for the link inference."""
    ports = {p.id: p for p in net.ports}

    def usable(port_id: str) -> Port | None:
        port = ports.get(port_id)
        return port if port is not None and port.external is not False else None

    owner: dict[str, str] = {}
    port_of_mac: dict[str, str] = {}
    for p in net.ports:
        if p.mac:
            owner.setdefault(p.mac, p.device_id)
            port_of_mac.setdefault(p.mac, p.id)
    for e in net.fdb:
        if e.kind is FdbKind.SELF:
            owner.setdefault(e.mac, e.device_id)
            port_of_mac.setdefault(e.mac, e.port_id)
    for d in net.devices:
        if d.mac:
            owner.setdefault(d.mac, d.id)
    by_address: dict[str, str] = {}
    managed = {d.management_address: d.id for d in net.devices if d.management_address}
    for c in net.clients:
        if c.mac in owner:
            continue
        dev = next((managed[a] for a in map(str, c.addresses) if a in managed), None)
        if dev is not None:
            owner[c.mac] = dev
            if c.seen_on:
                by_address[c.mac] = c.seen_on
    macs: dict[str, set[str]] = {}
    for mac, dev in owner.items():
        macs.setdefault(dev, set()).add(mac)
    with_table = {e.device_id for e in net.fdb}
    earlier = net.held_sightings if held else []
    with_table |= {
        hp.device_id
        for h in earlier
        if h.source is EvidenceSource.FDB and (hp := ports.get(h.port_id)) is not None
    }
    sightings: dict[Sighting, None] = {}
    for e in net.fdb:
        if e.kind is not FdbKind.SELF and usable(e.port_id):
            sightings[Sighting(e.device_id, e.port_id, e.mac)] = None
    for c in net.clients:
        # an ARP table names a VLAN interface (internal): the cable is on the jack below it
        port = usable(_jack(net, c.seen_on or ""))
        if port is not None and port.device_id not in with_table:
            sightings[Sighting(port.device_id, port.id, c.mac)] = None
    for h in earlier:
        port = usable(_jack(net, h.port_id))
        if port is not None and owner.get(h.mac) not in (None, port.device_id):
            sightings[Sighting(port.device_id, port.id, h.mac)] = None
    coarse = {p.id for p in net.ports if p.coarse}
    ix = Index(
        list(sightings),
        owner,
        port_of_mac,
        macs,
        by_address=by_address,
        reporting=with_table,
        coarse=coarse,
    )
    for s in ix.sightings:
        ix.learned.setdefault(s.port_id, set()).add(s.mac)
        ix.where.setdefault(s.mac, []).append(s)
        if s.device_id in with_table and s.port_id not in coarse:
            ix.tables.setdefault(s.device_id, {}).setdefault(s.port_id, set()).add(s.mac)
        if owner.get(s.mac, s.device_id) != s.device_id:
            ix.uplinks.add(s.port_id)
    for link in net.links:
        if link.kind is not LinkKind.VPN:
            ix.uplinks |= {link.a, link.b}
    return ix


def _wireless(net: Network, seen_on: str | None) -> bool:
    """Seen on an SSID or a Wi-Fi interface: the access point knows better than any table."""
    if not seen_on:
        return False
    port = net.port(seen_on)
    return port is None or port.kind is PortKind.WIRELESS


def placement(net: Network, ix: Index, client: Client) -> str | None:
    """The port a client sits behind by the tables, or its reported ``seen_on``."""
    if _wireless(net, client.seen_on):
        return client.seen_on
    own = ix.owner.get(client.mac)
    ports = {s.port_id for s in ix.where.get(client.mac, ()) if s.device_id != own}
    if not ports:
        return client.seen_on
    access = {p for p in ports if p not in ix.uplinks}
    best = min(access or ports, key=lambda p: (ix.count(p), p))
    if client.seen_on and best == _jack(net, client.seen_on):
        return client.seen_on  # the VLAN interface it was seen on stays
    if client.seen_on and client.seen_on not in ports and not access:
        return client.seen_on  # a device without a table said more than an uplink would
    return best


def place_clients(net: Network) -> Network:
    """The network with each wired client's ``seen_on`` taken from the tables."""
    if not net.fdb:
        return net
    ix = index(net)
    clients = []
    for c in net.clients:
        where = placement(net, ix, c)
        clients.append(c if where == c.seen_on else c.model_copy(update={"seen_on": where}))
    return net.model_copy(update={"clients": clients})


@dataclass(frozen=True)
class Adjacent:
    """A port of one device that leads to another managed device, and the far port."""

    local: str
    remote: str
    wireless: bool
    #: The far port is a guess, or no table of either device confirms the cable (#378).
    inferred: bool = False
    evidence: tuple[LinkEvidence, ...] = ()


def _jack(net: Network, port_id: str) -> str:
    """The port a VLAN interface runs on: an ARP table names ``igb1.10``, the cable is on
    ``igb1``."""
    port = net.port(port_id)
    for _ in range(4):
        if port is None or port.role is not PortRole.VLAN or len(port.lower) != 1:
            break
        below = net.port(port.lower[0])
        if below is None:
            break
        port = below
    return port.id if port is not None else port_id


def _wired(net: Network, port_id: str, depth: int = 0) -> list[str]:
    """The cable ends at or below a port: the wired members of a bridge or VLAN interface,
    else the port itself (not a Wi-Fi interface or a CPU port)."""
    port = net.port(port_id)
    if port is None:
        return []
    if port.role in (PortRole.BRIDGE, PortRole.VLAN) and port.lower and depth < 4:
        return sorted({j for low in port.lower for j in _wired(net, low, depth + 1)})
    if port.kind is PortKind.WIRELESS or port.role in (PortRole.CPU, PortRole.WIRELESS):
        return []
    return [port_id]


def _jacks(net: Network, device_id: str) -> list[str]:
    """Ports of a device a cable can be plugged into (for a guess)."""
    return [
        p.id
        for p in net.ports
        if p.device_id == device_id
        and p.kind is PortKind.ETHERNET
        and p.role in (None, PortRole.JACK, PortRole.SWITCH_PORT)
        and p.external is not False
        and p.up is not False
    ]


def managed_sightings(net: Network) -> list[tuple[str, str, EvidenceSource]]:
    """(port, MAC, source) of every managed device's MAC seen on another device's port this
    round, for the history (#378)."""
    ix = index(net)
    return sorted(
        {
            (s.port_id, s.mac, _kind(ix, s.device_id))
            for s in ix.sightings
            if ix.owner.get(s.mac) not in (None, s.device_id)
        }
    )


def _segments_of_ports(net: Network) -> dict[str, set[str]]:
    """Jack -> the segments it and the VLAN interfaces on it carry, and those of the clients
    seen there (what an ARP table says about a router's port)."""
    out: dict[str, set[str]] = {}
    for seg in net.segments:
        for m in seg.members:
            out.setdefault(_jack(net, m.port_id), set()).add(seg.id)
    for c in net.clients:
        if c.seen_on and c.segment_id:
            out.setdefault(_jack(net, c.seen_on), set()).add(c.segment_id)
    return out


def _segments_of_devices(net: Network) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for seg in net.segments:
        for m in seg.members:
            if (p := net.port(m.port_id)) is not None:
                out.setdefault(p.device_id, set()).add(seg.id)
    for d in net.devices:
        if (native := net.native_segment(d.id)) is not None:
            out.setdefault(d.id, set()).add(native)
    return out


def _may_sit_between(ix: Index, here: str, dev: str, switch: str) -> bool:
    """Nothing says the switch is beside the path from ``here`` to ``dev``: its own table does
    not learn the two on one port, and ``dev``'s table does not learn it on another port than
    ``here``."""
    a = ix.ports_learning(switch, ix.macs.get(here, set()))
    b = ix.ports_learning(switch, ix.macs.get(dev, set()))
    if a and b:
        return not set(a) & set(b)
    toward_here = ix.ports_learning(dev, ix.macs.get(here, set()))
    toward_switch = ix.ports_learning(dev, ix.macs.get(switch, set()))
    return not (toward_here and toward_switch and not set(toward_here) & set(toward_switch))


def adjacencies(net: Network) -> list[Adjacent]:
    """Ports that learn another managed device's address, with the nearest such device.

    A router without a bridge table only says that a device is in the same layer-2 network
    as one of its ports (ARP/NDP, #378): when a known switch, or another bridging device that
    reports where hosts are (#529), may sit between, no cable is drawn from it to a device
    that is no switch, and one to a switch is inferred.
    """
    ix = index(net, held=True)
    roles = {d.id: d.role for d in net.devices}
    bridging = _bridging(net, ix)
    wireless_up = _wireless_uplinks(net, ix)
    hops = _next_hops(net)
    port_segments = _segments_of_ports(net)
    device_segments = _segments_of_devices(net)
    learned: dict[str, set[str]] = {}
    for port_id, macs in ix.learned.items():
        learned.setdefault(_jack(net, port_id), set()).update(macs)
    out: dict[tuple[str, str], Adjacent] = {}
    #: (local port, far device, the far ports to choose from, evidence) of a guess
    open_ends: list[tuple[str, str, list[str], tuple[LinkEvidence, ...]]] = []
    for port_id, macs in sorted(learned.items()):
        port = net.port(port_id)
        if port is None:
            continue
        here = port.device_id
        seen: dict[str, str] = {}  # device -> one of its MACs learned here
        for mac in sorted(macs):
            dev = ix.owner.get(mac)
            if dev is not None and dev != here:
                seen.setdefault(dev, mac)
        coarse = port_id in ix.coarse
        if coarse:  # a host list of the whole LAN: only what the far tables allow (#529)
            seen = {
                dev: mac
                for dev, mac in seen.items()
                if dev not in wireless_up and _wired_toward(net, ix, dev, here)
            }
        nearest = [
            dev
            for dev in seen
            if not any(
                other != dev
                and (
                    _between(ix, here, dev, other, coarse)
                    or (not coarse and _switch_first(ix, roles, dev, other))
                )
                for other in seen
            )
        ]
        wireless = port.kind is PortKind.WIRELESS
        # nothing tells them apart: a star around the gateway (#529); over Wi-Fi the nearest
        # is the access point, not the gateway
        gateway = None if wireless else _gateway(ix, hops, here, nearest)
        if gateway is not None:
            nearest = [gateway]
        arp_only = roles.get(here) is DeviceRole.GATEWAY and here not in ix.tables
        here_segments = port_segments.get(port_id, set())
        for dev in nearest:
            unsure = False
            if arp_only:
                # any bridging device may sit in between; before the gateway only where its
                # own table says so (#529)
                between = _separates if dev == gateway else _may_sit_between
                unsure = any(
                    sw not in (here, dev)
                    and device_segments.get(sw, set()) & here_segments
                    and between(ix, here, dev, sw)
                    for sw in bridging
                )
                if unsure and roles.get(dev) is not DeviceRole.SWITCH:
                    continue  # same network, not a cable: a switch may be in between
            evidence = _evidence(ix, port_id, here, dev, seen[dev])
            if dev == gateway:
                evidence += (LinkEvidence(port_id=port_id, source=EvidenceSource.GATEWAY),)
            inferred = unsure or dev == gateway or (coarse and dev not in ix.reporting)
            remote, choices = _far_port(net, ix, here, dev, seen[dev])
            if remote is None:
                if choices:
                    open_ends.append((port_id, dev, choices, evidence))
                continue
            if remote == port_id:
                continue
            out.setdefault(
                (port_id, remote),
                Adjacent(port_id, remote, wireless, inferred, evidence),
            )
    for local, remote, evidence in _guess(net, open_ends, out):
        port = net.port(local)
        wireless = port is not None and port.kind is PortKind.WIRELESS
        out.setdefault((local, remote), Adjacent(local, remote, wireless, True, evidence))
    return list(out.values())


def _switch_first(ix: Index, roles: dict[str, DeviceRole], dev: str, other: str) -> bool:
    """No table of either says where they are: a switch is taken to sit before a device that
    is none (an AP behind a switch the gateway's ARP table sees on the same port, #378)."""
    return (
        roles.get(other) is DeviceRole.SWITCH
        and roles.get(dev) is not DeviceRole.SWITCH
        and dev not in ix.tables
        and other not in ix.tables
    )


def _between(ix: Index, here: str, far: str, other: str, coarse: bool = False) -> bool:
    """``other`` sits between ``here`` and ``far``: its own table learns the two on different
    ports; or ``far`` learns ``other`` on the same port as ``here``, and ``other`` learns them
    on different ports (or reports no table, so nothing says it is beside the path: an
    unmanaged switch joining all three). From a ``coarse`` port (#529) a device without a
    table is no such switch: the coarse device's own LAN switch joins them."""
    a = ix.ports_learning(other, ix.macs.get(here, set()))
    b = ix.ports_learning(other, ix.macs.get(far, set()))
    if a and b and not set(a) & set(b):
        return True
    toward_here = ix.ports_learning(far, ix.macs.get(here, set()))
    toward_other = ix.ports_learning(far, ix.macs.get(other, set()))
    if not set(toward_here) & set(toward_other):
        return False
    if other not in ix.tables:
        return not coarse
    return not a or not b


def _separates(ix: Index, here: str, dev: str, sw: str) -> bool:
    """``sw``'s own table learns ``here`` and ``dev`` on different ports."""
    a = ix.ports_learning(sw, ix.macs.get(here, set()))
    b = ix.ports_learning(sw, ix.macs.get(dev, set()))
    return bool(a and b and not set(a) & set(b))


def _bridging(net: Network, ix: Index) -> list[str]:
    """Devices that may sit between a router and what its ARP table sees (#529): every switch,
    and any other device that bridges and says where hosts are, by a MAC address table (an
    access point, a router with LAN ports) or a host list (``Port.coarse``). A device that says
    nothing about its ports is not taken to sit in between (it would hide every cable)."""
    out = {d.id for d in net.devices if d.role is DeviceRole.SWITCH}
    out |= {p.device_id for p in net.ports if p.id in ix.coarse}
    return sorted(out | ix.reporting)


def _wireless_port(net: Network, port_id: str) -> bool:
    port = net.port(port_id)
    return port is not None and (port.kind is PortKind.WIRELESS or port.role is PortRole.WIRELESS)


def _wireless_uplinks(net: Network, ix: Index) -> set[str]:
    """Devices whose bridge uplink is wireless (#529): a repeater or mesh node by its mesh
    membership (wireless uplink, wireless hops to the controller), a bridge whose STP root port
    is a Wi-Fi/WDS/mesh interface, the station end of a wireless backhaul (a peer reported as
    uplink, or the station of a WDS access point's downlink)."""
    out: set[str] = set()
    for d in net.devices:
        if d.mesh is not None and (d.mesh.uplink is MeshUplink.WIRELESS or (d.mesh.hop or 0) > 0):
            out.add(d.id)
        for bridge in d.stp_bridges or []:
            if bridge.root_port_id and _wireless_port(net, bridge.root_port_id):
                out.add(d.id)
    for peer in net.mesh_peers:
        if peer.role is MeshPeerRole.UPLINK:
            out.add(peer.device_id)
        elif peer.role is MeshPeerRole.DOWNLINK and (o := ix.owner.get(peer.peer_mac)):
            out.add(o)
    return out


def _wired_toward(net: Network, ix: Index, dev: str, here: str) -> bool:
    """``dev`` may be cabled to ``here`` by its own table: it reports none, or it learns
    ``here`` on a port that is no Wi-Fi interface."""
    if dev not in ix.reporting:
        return True
    toward = ix.ports_learning(dev, ix.macs.get(here, set()))
    return any(not _wireless_port(net, p) for p in toward)


def _next_hops(net: Network) -> dict[str, set[str]]:
    """Device -> the devices holding its default next hop (default routes, uplinks)."""
    owner: dict[str, str] = {}
    for d in net.devices:
        if d.management_address:
            owner.setdefault(str(d.management_address), d.id)
    for sub in net.subnets:
        owner.setdefault(str(sub.interface.ip), sub.device_id)
    hops: dict[str, set[str]] = {}

    def add(device_id: str, address: object) -> None:
        dev = owner.get(str(address))
        if dev is not None and dev != device_id:
            hops.setdefault(device_id, set()).add(dev)

    for r in net.routes:
        if r.default and r.gateway is not None and r.enabled and r.active is not False:
            add(r.device_id, r.gateway)
    for u in net.uplinks:
        if u.upstream_gateway is not None:
            add(u.device_id, u.upstream_gateway)
    return hops


def _gateway(ix: Index, hops: dict[str, set[str]], here: str, nearest: list[str]) -> str | None:
    """Of several devices learned on one port, none between the others, the one that holds the
    default next hop of this device or of the others (#529). Only where one of them reports no
    per-port table: with real tables an unmanaged switch joins them all."""
    if len(nearest) < 2 or all(d in ix.tables for d in nearest):
        return None
    found: set[str] = set()
    for d in (here, *nearest):
        found |= hops.get(d, set())
    found &= set(nearest)
    return found.pop() if len(found) == 1 else None


def _far_port(
    net: Network, ix: Index, here: str, far: str, mac: str
) -> tuple[str | None, list[str]]:
    """The far end, else the ports to guess it from: the far device's table where it learns
    this device, else the jack that owns the learned address."""
    toward = ix.ports_learning(far, ix.macs.get(here, set()))
    if toward:
        return min(toward, key=lambda p: (-toward[p], p)), []
    owners = [p.id for p in net.ports if p.device_id == far and p.mac == mac]
    if not owners and (entry := ix.port_of_mac.get(mac)) is not None:
        owners = [entry]  # the device's own entry in its table
    if not owners:
        return None, _jacks(net, far)
    # DSA user ports, the CPU port and the bridge often share one MAC
    wired = sorted({j for o in owners for j in _wired(net, o)})
    if len(wired) == 1:
        return wired[0], []
    if not wired:
        return (owners[0], []) if len(owners) == 1 else (None, _jacks(net, far))
    return None, wired


def _evidence(ix: Index, port_id: str, here: str, far: str, mac: str) -> tuple[LinkEvidence, ...]:
    """What supports a link: this port's sighting, the far device's table, third devices
    whose tables see both ends behind one port, an ARP entry that named the far MAC."""
    out = [LinkEvidence(port_id=port_id, source=_kind(ix, here))]
    for p in sorted(ix.ports_learning(far, ix.macs.get(here, set()))):
        out.append(LinkEvidence(port_id=p, source=EvidenceSource.FDB))
    for other in sorted(ix.tables):
        if other in (here, far):
            continue
        a = ix.ports_learning(other, ix.macs.get(here, set()))
        b = ix.ports_learning(other, ix.macs.get(far, set()))
        out += [LinkEvidence(port_id=p, source=EvidenceSource.FDB) for p in sorted(set(a) & set(b))]
    for m in sorted(ix.macs.get(far, set())):
        if m in ix.by_address:
            out.append(LinkEvidence(port_id=ix.by_address[m], source=EvidenceSource.ADDRESS))
            break
    return tuple(dict.fromkeys(out))


def _kind(ix: Index, device_id: str) -> EvidenceSource:
    return EvidenceSource.FDB if device_id in ix.tables else EvidenceSource.ARP


def _memberships(net: Network) -> dict[str, frozenset[tuple[str, Membership]]]:
    out: dict[str, set[tuple[str, Membership]]] = {}
    for seg in net.segments:
        for m in seg.members:
            out.setdefault(m.port_id, set()).add((seg.id, m.mode))
    return {k: frozenset(v) for k, v in out.items()}


def _guess(
    net: Network,
    open_ends: list[tuple[str, str, list[str], tuple[LinkEvidence, ...]]],
    known: dict[tuple[str, str], Adjacent],
) -> list[tuple[str, str, tuple[LinkEvidence, ...]]]:
    """The far port of each open end (#378): the free port of the far device whose VLANs,
    PVID and speed match the near port best, the best matches first. Ports at the end of a
    known link are not free."""
    if not open_ends:
        return []
    members = _memberships(net)
    taken = {e for link in net.links for e in (link.a, link.b)}
    taken |= {e for adj in known.values() for e in (adj.local, adj.remote)}

    def score(near: str, far: str) -> tuple[int, int, int, int, int]:
        a, b = net.port(near), net.port(far)
        va, vb = members.get(near, frozenset()), members.get(far, frozenset())
        return (
            int(bool(va) and va == vb),
            len(va & vb),
            int(a is not None and b is not None and a.pvid is not None and a.pvid == b.pvid),
            int(
                a is not None
                and b is not None
                and a.speed_mbps is not None
                and a.speed_mbps == b.speed_mbps
            ),
            int(b is not None and b.up is True),
        )

    options = sorted(
        (
            (score(local, far_port), local, dev, far_port, evidence)
            for local, dev, choices, evidence in open_ends
            for far_port in choices
        ),
        key=lambda o: (tuple(-x for x in o[0]), o[1], o[3]),
    )
    out: list[tuple[str, str, tuple[LinkEvidence, ...]]] = []
    done: set[tuple[str, str]] = set()
    for _, local, dev, far_port, evidence in options:
        if (local, dev) in done or far_port in taken or local == far_port:
            continue
        done.add((local, dev))
        taken.add(far_port)
        out.append((local, far_port, evidence))
    return out


def fdb_access_ports(net: Network) -> dict[str, str]:
    """MAC address → the wired access port the device tables put it behind (#298).

    Only addresses a device's own table reports (not ``seen_on`` of an ARP-based router);
    uplinks, wireless ports and the addresses of managed devices are left out. With several
    access ports the one that learns the fewest addresses wins, as in :func:`placement`.
    """
    ix = index(net)
    out: dict[str, str] = {}
    for mac, seen in ix.where.items():
        own = ix.owner.get(mac)
        ports = {
            s.port_id
            for s in seen
            if s.device_id != own
            and s.device_id in ix.tables
            and s.port_id not in ix.uplinks
            and (p := net.port(s.port_id)) is not None
            and p.kind is not PortKind.WIRELESS
        }
        if ports:
            out[mac] = min(ports, key=lambda p: (ix.count(p), p))
    return out
