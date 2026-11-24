"""Rules on the MAC address tables (forwarding databases, #160, ADR 0016; checks #298).

``mac.flapping`` and ``mac.static-stale`` use the observation history; ``mac.table-full`` the
current tables. All stay quiet for devices that report no table.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterator
from datetime import timedelta

from signalbox.fdb import fdb_access_ports
from signalbox.model import FDB_LIMIT, FdbKind, Network, client_target
from signalbox.rules import Result, Rule, Severity, found, history_rule, rule
from signalbox.rules._names import device_name, site_of_device
from signalbox.rules.history_checks import FLAP_COUNT, FLAP_PERIOD, _client_sites
from signalbox.sightings import History

#: A static entry for an address not seen anywhere for this long is stale.
STALE_AFTER = timedelta(days=14)
#: A table with this many entries is near the ``FDB_LIMIT`` Signalbox keeps per device.
NEAR_LIMIT = FDB_LIMIT * 9 // 10


def _port_text(net: Network, port_id: str | None) -> str:
    p = net.port(port_id) if port_id else None
    if p is None:
        return port_id or "an unknown port"
    return f"{device_name(net, p.device_id)} port {p.label()}"


@history_rule(
    "mac.flapping",
    "MAC address keeps moving between ports",
    Severity.WARNING,
    "The same MAC address is learned on different ports or switches again and again. That is "
    "the sign of a loop in the cabling (spanning tree off or misconfigured), two devices with "
    "the same address, or a virtual machine or bonded NIC that switches between links. It "
    "causes short outages and packet loss for the device. Counted from the MAC address tables "
    "of each observation round, so only moves that last until a round are seen. Wireless "
    "roaming between access points, uplinks and addresses of network "
    "devices are ignored.",
)
def mac_flapping(net: Network, history: History) -> Iterator[Result]:
    if history.now is None or not net.fdb:
        return
    since = history.now - FLAP_PERIOD
    current = fdb_access_ports(net)
    for mac, port_id in sorted(current.items()):
        past = history.fdb.get(mac)
        moves = [c for c in past.changes if c.at >= since] if past else []
        if len(moves) < FLAP_COUNT:
            continue
        ports = Counter(c.new for c in moves)
        ports.update(c.old for c in moves)
        shown = sorted(ports)[:3]
        names = ", ".join(_port_text(net, p) for p in shown)
        who = next((c.hostname for c in net.clients if c.mac == mac and c.hostname), None)
        yield found(
            f"{who + ' (' + mac + ')' if who else mac} moved {len(moves)} times in the last 24 "
            f"hours between {len(ports)} ports, among them {names}; now behind "
            f"{_port_text(net, port_id)}",
            [port_id],
            fix="Look for a loop in the cabling (two cables between the same switches, a "
            "switch plugged into itself) and turn on spanning tree; check that no two devices "
            "use the same MAC address and that a bonded or virtual NIC is set up consistently.",
            key=mac,
        )


@history_rule(
    "mac.static-stale",
    "Static MAC table entry for a device that is gone",
    Severity.INFO,
    "A static entry in a switch's MAC address table pins an address to a port. When the device "
    "is gone, the entry stays, and a new device that later gets the address (or is plugged "
    "into another port) is cut off or flooded. Reported when the address has not been seen "
    "anywhere (clients, any device) for 14 days, and only at sites where a device reports "
    "clients and Signalbox has observed for at least that long.",
)
def static_stale(net: Network, history: History) -> Iterator[Result]:
    now = history.now
    if now is None:
        return
    sites = _client_sites(net)
    present = {c.mac for c in net.clients}
    own = {p.mac for p in net.ports if p.mac} | {e.mac for e in net.fdb if e.kind is FdbKind.SELF}
    by_mac: dict[str, list[str]] = {}
    for e in net.fdb:
        if (
            e.kind is FdbKind.STATIC
            and e.mac not in own
            and e.mac not in present
            and site_of_device(net, e.device_id) in sites
        ):
            by_mac.setdefault(e.mac, []).append(e.id)
    for mac, ids in sorted(by_mac.items()):
        past = history.clients.get(mac)
        if past is not None:
            if now - past.last_seen < STALE_AFTER:
                continue
            ago = f"since {past.last_seen:%Y-%m-%d}"
        elif history.covers(STALE_AFTER):
            ago = f"for more than {STALE_AFTER.days} days"
        else:
            continue
        if net.expected(client_target(mac)).may_be_unreachable:
            continue
        entries = [e for e in net.fdb if e.id in ids]
        where = ", ".join(sorted({_port_text(net, e.port_id) for e in entries}))
        yield found(
            f"The static MAC address table entry for {mac} on {where} is for a device not seen "
            f"{ago}",
            [e.port_id for e in entries],
            fix="Remove the entry if the device is gone. A device that is rarely on keeps it; "
            "mark it as may be unreachable or turn the rule off.",
            key=mac,
        )


@rule(
    "mac.table-full",
    "MAC address table is (nearly) full",
    Severity.INFO,
    "A device's MAC address table has as many entries as Signalbox keeps per device "
    f"({FDB_LIMIT}) or close to it (90 %). Entries beyond that are dropped, so the placement of "
    "clients and the links found through unmanaged switches may be incomplete or wrong. A "
    "large table also means a switch that floods when its own table is full: check for a "
    "loop or a device sending frames with random source addresses.",
)
def table_full(net: Network) -> Iterator[Result]:
    counts = Counter(e.device_id for e in net.fdb)
    for dev_id, n in sorted(counts.items()):
        if n < NEAR_LIMIT:
            continue
        yield found(
            f"{device_name(net, dev_id)} has {n} entries in its MAC address table "
            f"(Signalbox keeps at most {FDB_LIMIT}); the topology it shows may be incomplete",
            [dev_id],
            fix="Check for a loop or a device flooding random addresses; on a large network the "
            "devices behind a full table are placed by their other sightings only.",
        )


RULES: list[Rule] = [mac_flapping, static_stale, table_full]
