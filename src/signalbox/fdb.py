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
  has no table). Devices joined by an unmanaged switch are all linked to each other. The far
  end is the port where the far device learns this device's addresses, else the port that
  owns the learned address.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from signalbox.model import (
    Client,
    FdbKind,
    LinkKind,
    Network,
    Port,
    PortKind,
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

    def count(self, port_id: str) -> int:
        return len(self.learned.get(port_id, ()))

    def ports_learning(self, device_id: str, macs: set[str]) -> Counter[str]:
        """Ports of a device where it learns any of ``macs``, with how many of them."""
        table = self.tables.get(device_id, {})
        return Counter({p: n for p, learned in table.items() if (n := len(learned & macs))})


def index(net: Network) -> Index:
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
    macs: dict[str, set[str]] = {}
    for mac, dev in owner.items():
        macs.setdefault(dev, set()).add(mac)
    with_table = {e.device_id for e in net.fdb}
    sightings: dict[Sighting, None] = {}
    for e in net.fdb:
        if e.kind is not FdbKind.SELF and usable(e.port_id):
            sightings[Sighting(e.device_id, e.port_id, e.mac)] = None
    for c in net.clients:
        port = usable(c.seen_on or "")
        if port is not None and port.device_id not in with_table:
            sightings[Sighting(port.device_id, port.id, c.mac)] = None
    ix = Index(list(sightings), owner, port_of_mac, macs)
    for s in ix.sightings:
        ix.learned.setdefault(s.port_id, set()).add(s.mac)
        ix.where.setdefault(s.mac, []).append(s)
        if s.device_id in with_table:
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


def adjacencies(net: Network) -> list[Adjacent]:
    """Ports that learn another managed device's address, with the nearest such device."""
    ix = index(net)
    out: dict[tuple[str, str], Adjacent] = {}
    for port_id, learned in sorted(ix.learned.items()):
        port = net.port(port_id)
        if port is None:
            continue
        here = port.device_id
        seen: dict[str, str] = {}  # device -> one of its MACs learned here
        for mac in sorted(learned):
            dev = ix.owner.get(mac)
            if dev is not None and dev != here:
                seen.setdefault(dev, mac)
        nearest = [
            dev
            for dev in seen
            if not any(other != dev and _between(ix, here, dev, other) for other in seen)
        ]
        for dev in nearest:
            remote = _far_port(ix, here, dev, seen[dev])
            if remote is None or remote == port_id:
                continue
            out.setdefault(
                (port_id, remote),
                Adjacent(port_id, remote, port.kind is PortKind.WIRELESS),
            )
    return list(out.values())


def _between(ix: Index, here: str, far: str, other: str) -> bool:
    """``other`` sits between ``here`` and ``far``: ``far`` learns ``other`` on the same port
    as ``here``, and ``other`` learns them on different ports (or reports no table, so nothing
    says it is beside the path: an unmanaged switch joining all three)."""
    toward_here = ix.ports_learning(far, ix.macs.get(here, set()))
    toward_other = ix.ports_learning(far, ix.macs.get(other, set()))
    if not set(toward_here) & set(toward_other):
        return False
    if other not in ix.tables:
        return True
    a = ix.ports_learning(other, ix.macs.get(here, set()))
    b = ix.ports_learning(other, ix.macs.get(far, set()))
    return not a or not b or not set(a) & set(b)


def _far_port(ix: Index, here: str, far: str, mac: str) -> str | None:
    toward = ix.ports_learning(far, ix.macs.get(here, set()))
    if toward:
        return min(toward, key=lambda p: (-toward[p], p))
    return ix.port_of_mac.get(mac)


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
