"""Rules that need the observation history (issue #185; checks #64, #85, #115, #128).

They receive a read-only :class:`~signalbox.sightings.History` and stay silent where it is
empty or too short (a fresh installation, the desired or the predicted state of a plan).
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import datetime, timedelta

from signalbox.adapters import Capability
from signalbox.model import DeviceStatus, Network, PortKind, client_target
from signalbox.rules import Result, Rule, Severity, found, history_rule
from signalbox.rules._names import device_name, segment_name, site_of_device
from signalbox.rules.clients import is_randomised
from signalbox.sightings import ANSWERED, History

#: A device that did not answer for this long is reported; after ``DOWN_ERROR`` as an error.
DOWN_WARNING = timedelta(hours=1)
DOWN_ERROR = timedelta(hours=24)
#: Period and number of outages or link losses that count as flapping.
FLAP_PERIOD = timedelta(hours=24)
FLAP_COUNT = 3
#: How long a client's move to another network is reported.
MOVE_WINDOW = timedelta(days=7)
#: A client that moves this often within ``MOVE_WINDOW`` roams between networks by design.
ROAMING_MOVES = 3


def _when(at: datetime) -> str:
    return f"{at:%Y-%m-%d %H:%M} UTC"


def _span(delta: timedelta) -> str:
    """``45 minutes``, ``5 hours`` or ``3 days``."""
    minutes = int(delta.total_seconds() // 60)
    if minutes < 120:
        return f"{minutes} minutes"
    if minutes < 48 * 60:
        return f"{minutes // 60} hours"
    return f"{minutes // (24 * 60)} days"


@history_rule(
    "device.down-long",
    "Device unreachable for a long time",
    Severity.WARNING,
    "A device that does not answer for hours is not a missed poll: it is off, was replaced (new "
    "address or certificate), or its password changed. Every check involving it uses data from "
    "before the outage or is incomplete. Reported after an hour, as an error after a day; the "
    "per-round read finding stays, this one says for how long.",
)
def down_long(net: Network, history: History) -> Iterator[Result]:
    now = history.now
    if now is None:
        return
    for dev in net.devices:
        if net.statuses.get(dev.id) not in (DeviceStatus.UNREACHABLE, DeviceStatus.AUTH_FAILED):
            continue
        if (
            net.statuses.get(dev.id) is DeviceStatus.UNREACHABLE
            and net.expected(dev.id).may_be_unreachable
        ):
            continue  # off on purpose (a lab switch, a seasonal access point)
        past = history.devices.get(dev.id)
        if past is None:
            continue
        since = past.last_ok or past.first_seen
        down = now - since
        if down < DOWN_WARNING:
            continue
        if past.last_ok is None:
            when = f"since Signalbox first saw it ({_when(since)})"
        else:
            when = f"for {_span(down)} (last read {_when(since)})"
        yield found(
            f"{dev.name} has not answered {when}",
            [dev.id],
            fix="Check its power and cabling, its address and password; remove it from Signalbox "
            "(or disable it) if it was replaced or retired.",
            severity=Severity.ERROR if down >= DOWN_ERROR else None,
        )


@history_rule(
    "device.flapping",
    "Device keeps dropping out",
    Severity.WARNING,
    "A device that stops answering several times a day and comes back has a power problem "
    "(PoE budget, failing power supply), overheats, restarts by itself, or sits behind a "
    "flapping link. Users notice short outages but rarely connect them to one device.",
)
def device_flapping(net: Network, history: History) -> Iterator[Result]:
    if history.now is None:
        return
    since = history.now - FLAP_PERIOD
    for dev in net.devices:
        past = history.devices.get(dev.id)
        n = past.outages(since) if past else 0
        if n >= FLAP_COUNT:
            yield found(
                f"{dev.name} stopped answering {n} times in the last 24 hours",
                [dev.id],
                fix="Check its power supply or PoE budget, its temperature and its uplink cable.",
            )


@history_rule(
    "port.flapping",
    "Link goes down and up repeatedly",
    Severity.WARNING,
    "A cable link that keeps going down and up (a bad cable or connector, a duplex or "
    "auto-negotiation problem, a failing port) causes short outages for everything behind it. "
    "Counted from the link state of each observation round, so only losses that last until a "
    "round are seen. Warning on links between network devices, info on other ports (a computer "
    "that sleeps and wakes also does this).",
)
def port_flapping(net: Network, history: History) -> Iterator[Result]:
    if history.now is None:
        return
    since = history.now - FLAP_PERIOD
    linked: dict[str, str] = {}
    for link in net.links:
        linked[link.a], linked[link.b] = link.b, link.a
    for port in net.ports:
        if port.kind not in (PortKind.ETHERNET, PortKind.LAG):
            continue
        past = history.ports.get(port.id)
        n = past.downs(since) if past else 0
        if n < FLAP_COUNT:
            continue
        other = linked.get(port.id)
        to = ""
        if other is not None:
            peer = net.port(other)
            to = f" (to {device_name(net, peer.device_id)})" if peer else f" (to {other})"
        yield found(
            f"{device_name(net, port.device_id)} port {port.name}{to} lost its link {n} times "
            "in the last 24 hours",
            [port.id],
            fix="Replace or re-terminate the cable, check the connectors, and leave both ends on "
            "auto-negotiation.",
            severity=None if other is not None else Severity.INFO,
        )


def _client_sites(net: Network) -> set[str]:
    """Sites where a device that reports clients answered and reported them this round."""
    failed = {e.device_id for e in net.errors if e.capability == Capability.CLIENTS}
    return {
        d.site_id
        for d in net.devices
        if Capability.CLIENTS in d.capabilities
        and net.statuses.get(d.id) in ANSWERED
        and d.id not in failed
    }


@history_rule(
    "dhcp.stale-reservation",
    "DHCP reservation for a device that is gone",
    Severity.INFO,
    "A reservation whose device has not been seen for weeks blocks an address, keeps DNS names "
    "and port forwards pointing to it, and the address may later be handed to another device. "
    "Checked once Signalbox has observed the network for the whole history period "
    "(history.days, default 30 days), and only at sites where a device reports clients.",
)
def stale_reservation(net: Network, history: History) -> Iterator[Result]:
    if not history.covers(timedelta(days=history.days)):
        return
    sites = _client_sites(net)
    present = {c.mac for c in net.clients} | set(history.clients)
    for srv in net.dhcp_servers:
        if site_of_device(net, srv.device_id) not in sites:
            continue
        for res in srv.reservations:
            if res.mac in present or net.expected(client_target(res.mac)).may_be_unreachable:
                continue
            host = f" ({res.hostname})" if res.hostname else ""
            yield found(
                f"The reservation {res.address}{host} on {segment_name(net, srv.segment_id)} is "
                f"for {res.mac}, which has not been seen for more than {history.days} days",
                [srv.id],
                fix="Remove the reservation if the device is gone. A device that is rarely on "
                "(a camera in the garden in winter) keeps it; turn the rule off if needed.",
                key=f"{res.mac}:{res.address}",
            )


@history_rule(
    "clients.network-changed",
    "Client moved to another network",
    Severity.INFO,
    "A device that suddenly appears in the guest or main network usually joined the wrong SSID "
    "or was plugged into another port; a server that moves between VLANs breaks firewall "
    "rules. A mis-tagged port often shows up like this first. Reported for a week after the "
    "move. Randomised MAC addresses and clients that move back and forth often are ignored.",
)
def network_changed(net: Network, history: History) -> Iterator[Result]:
    if history.now is None:
        return
    since = history.now - MOVE_WINDOW
    for client in net.clients:
        if client.segment_id is None or is_randomised(client.mac):
            continue
        if net.expected(client_target(client.mac)).segment is not None:
            continue  # clients.unexpected-network knows where it belongs
        past = history.clients.get(client.mac)
        recent = [m for m in past.moves if m.at >= since] if past else []
        if not recent or len(recent) >= ROAMING_MOVES or recent[-1].new != client.segment_id:
            continue
        move = recent[-1]
        name = client.hostname or client.mac
        yield found(
            f"{name} ({client.mac}) moved from {segment_name(net, move.old)} to "
            f"{segment_name(net, move.new)} at {_when(move.at)}",
            [client.id, move.old, move.new],
            fix="If this was not intended, check the SSID it joined or the switch port it is "
            "plugged into (and that port's VLAN).",
            key=move.at.isoformat(),
        )


RULES: list[Rule] = [down_long, device_flapping, port_flapping, stale_reservation, network_changed]
