"""Port error counters (issues #115, #158).

A slowly dying cable, a bad connector or a duplex mismatch shows up as rising CRC and error
counters long before anything breaks. The rule looks at what the counters did between the last
two reads (:mod:`signalbox.counters`), never at lifetime totals: a port with a few old errors
is quiet, a port that collects errors now is reported.
"""

from __future__ import annotations

from collections.abc import Iterator

from signalbox.counters import CounterDelta
from signalbox.model import FrameTypes, Membership, Network, Port, PortKind, PortRole
from signalbox.rules import Result, Rule, RuleParams, Severity, ctx, found, history_rule, param
from signalbox.rules._names import device_name
from signalbox.sightings import History


class PortErrorParams(RuleParams):
    error_ratio: float = param(
        0.001,
        unit="ratio",
        ge=0,
        le=1,
        description="Report a port (information) when the errors between two reads are at "
        "least this share of its packets (0.001: one in a thousand).",
    )
    crc_ratio: float = param(
        0.0001,
        unit="ratio",
        ge=0,
        le=1,
        description="Warn when the CRC/FCS errors received between two reads are at least this "
        "share of the packets received (0.0001: one in ten thousand).",
    )
    min_packets: int = param(
        1000,
        unit="count",
        ge=1,
        description="Reads with fewer packets than this on a port are too small to judge.",
    )
    min_errors: int = param(
        5,
        unit="count",
        ge=1,
        description="Fewer errors than this between two reads are never reported (a single "
        "bad frame).",
    )


@history_rule(
    "port.errors",
    "Port collects errors",
    Severity.WARNING,
    "Rising CRC (FCS) or error counters on a port are the early sign of a bad cable or "
    "connector, a duplex or speed mismatch, or a failing port, long before the link drops. "
    "Judged on what happened between the last two reads relative to the packets in that time, "
    "not on lifetime totals: a warning when the CRC errors received exceed a small share of the "
    "packets (parameter crc_ratio), information for other errors above error_ratio. "
    "Ports that are down, reads with few packets or errors, and counters that were reset by a "
    "reboot are ignored. The thresholds are the rule's parameters (they replace the "
    "deprecated counters section of the configuration).",
    params=PortErrorParams,
)
def port_errors(net: Network, history: History) -> Iterator[Result]:
    for port in net.ports:
        if port.kind not in (PortKind.ETHERNET, PortKind.LAG) or port.up is False:
            continue
        if port.admin_up is False or port.external is False:
            continue
        record = history.counters.get(port.id)
        delta = record.delta if record else None
        if delta is None or delta.reset:
            continue
        packets = delta.packets
        errors = delta.errors
        limits = ctx.params(PortErrorParams, port)
        if not packets or packets < limits.min_packets or not errors:
            continue
        crc = delta.rx_crc_errors or 0
        rx = delta.rx_packets or packets
        crc_bad = crc >= limits.min_errors and crc / rx >= limits.crc_ratio
        any_bad = errors >= limits.min_errors and errors / packets >= limits.error_ratio
        if not crc_bad and not any_bad:
            continue
        name = device_name(net, port.device_id)
        minutes = max(1, round(delta.seconds / 60))
        if crc_bad:
            share = f"{crc / rx:.2%}"
            message = (
                f"{name} port {port.name} received {crc} frames with a bad checksum (CRC) in "
                f"the last {minutes} min ({share} of {rx} packets)"
            )
            mid = "counters.portCrc"
            params: dict[str, str | int] = {"count": crc, "packets": rx, "share": share}
        else:
            share = f"{errors / packets:.2%}"
            message = (
                f"{name} port {port.name} counted {errors} errors in the last {minutes} min "
                f"({share} of {packets} packets)"
            )
            mid = "counters.portErrors"
            params = {"count": errors, "packets": packets, "share": share}
        yield found(
            message,
            [port.id],
            fix="Replace or re-terminate the cable, check the connectors and the SFP, and leave "
            "both ends on auto-negotiation (a forced speed or duplex on one end causes this).",
            severity=None if crc_bad else Severity.INFO,
            mid=mid,
            fix_id="counters.portErrors.fix",
            params={"device": name, "port": port.name, "minutes": minutes, **params},
        )


# --- follow-ups of #434 ---------------------------------------------------------------------


def _live(net: Network, history: History) -> Iterator[tuple[Port, CounterDelta]]:
    """Ethernet ports and LAGs that are up and have a usable delta (no reset) of the last reads."""
    for port in net.ports:
        if port.kind not in (PortKind.ETHERNET, PortKind.LAG) or port.up is not True:
            continue
        if port.admin_up is False or port.external is False:
            continue
        record = history.counters.get(port.id)
        delta = record.delta if record else None
        if delta is None or delta.reset:
            continue
        yield port, delta


def _minutes(delta: CounterDelta) -> int:
    return max(1, round(delta.seconds / 60))


class PortDropParams(RuleParams):
    drop_ratio: float = param(
        0.01,
        unit="ratio",
        ge=0,
        le=1,
        description="Report a port when the packets dropped between two reads are at least this "
        "share of its packets (0.01: one in a hundred).",
    )
    min_packets: int = param(
        1000,
        unit="count",
        ge=1,
        description="Reads with fewer packets than this on a port are too small to judge.",
    )
    min_drops: int = param(
        20,
        unit="count",
        ge=1,
        description="Fewer drops than this between two reads are never reported.",
    )


@history_rule(
    "port.drops",
    "Port drops packets",
    Severity.INFO,
    "A port that drops packets (full queues, a congested uplink, a speed mismatch between the "
    "ends or a CPU that cannot keep up) makes connections slow and video or calls stutter, "
    "without any error counter rising. Judged on what happened between the last two reads "
    "relative to the packets in that time (parameter drop_ratio), never on lifetime totals. "
    "Ports that are down, reads with few packets or drops and the read after a counter reset "
    "are ignored.",
    params=PortDropParams,
)
def port_drops(net: Network, history: History) -> Iterator[Result]:
    for port, delta in _live(net, history):
        limits = ctx.params(PortDropParams, port)
        packets, drops = delta.packets, delta.drops
        if not packets or packets < limits.min_packets or not drops:
            continue
        if drops < limits.min_drops or drops / packets < limits.drop_ratio:
            continue
        name = device_name(net, port.device_id)
        share = f"{drops / packets:.2%}"
        yield found(
            f"{name} port {port.name} dropped {drops} packets in the last {_minutes(delta)} min "
            f"({share} of {packets} packets)",
            [port.id],
            fix="Look for a link that is slower than the traffic (a 100 Mbit/s link or a "
            "congested uplink), a loop, or a device that floods the port; a faster link or "
            "traffic shaping helps.",
            mid="counters.portDrops",
            fix_id="counters.portDrops.fix",
            params={
                "device": name,
                "port": port.name,
                "minutes": _minutes(delta),
                "count": drops,
                "packets": packets,
                "share": share,
            },
        )


class PortUtilisationParams(RuleParams):
    utilisation_pct: float = param(
        90,
        unit="%",
        ge=1,
        le=100,
        description="Report a port when it carried at least this share of its link speed, in "
        "either direction, between the last two reads.",
    )
    min_seconds: int = param(
        20,
        unit="s",
        ge=1,
        description="Reads closer together than this are too short to judge a rate.",
    )


@history_rule(
    "port.utilisation",
    "Port is close to its link speed",
    Severity.INFO,
    "A port that carries nearly its whole link speed (parameter utilisation_pct, default 90 %) "
    "is a bottleneck: everything behind it slows down and queues fill up (see port.drops). "
    "The rate is the traffic between the last two reads divided by their distance, in the "
    "busier direction, so a short burst between the reads counts as sustained. Needs the link "
    "speed and byte counters; ports that are down and the read after a counter reset are "
    "ignored.",
    params=PortUtilisationParams,
)
def port_utilisation(net: Network, history: History) -> Iterator[Result]:
    for port, delta in _live(net, history):
        limits = ctx.params(PortUtilisationParams, port)
        if not port.speed_mbps or delta.seconds < limits.min_seconds:
            continue
        if delta.rx_bytes is None and delta.tx_bytes is None:
            continue
        rx = (delta.rx_bytes or 0) * 8 / delta.seconds / 1e6
        tx = (delta.tx_bytes or 0) * 8 / delta.seconds / 1e6
        busiest = max(rx, tx)
        share = busiest / port.speed_mbps * 100
        if share < limits.utilisation_pct:
            continue
        name = device_name(net, port.device_id)
        direction = "received" if rx >= tx else "sent"
        yield found(
            f"{name} port {port.name} {direction} {busiest:.0f} Mbit/s of its "
            f"{port.speed_mbps} Mbit/s link ({share:.0f} %) in the last {_minutes(delta)} min",
            [port.id],
            fix="Move heavy devices to another port, aggregate several links (LAG) or use a "
            "faster link or port.",
            mid="counters.portUtilisationRx" if rx >= tx else "counters.portUtilisationTx",
            fix_id="counters.portUtilisation.fix",
            params={
                "device": name,
                "port": port.name,
                "minutes": _minutes(delta),
                "rate": round(busiest),
                "speed": port.speed_mbps,
                "percent": round(share),
            },
        )


def _is_trunk(net: Network, port: Port) -> bool:
    if port.frame_types is FrameTypes.TAGGED_ONLY:
        return True
    return any(
        m.port_id == port.id and m.mode is Membership.TAGGED
        for segment in net.segments
        for m in segment.members
    )


class IdleTrunkParams(RuleParams):
    idle_kbps: float = param(
        2,
        unit="kbit/s",
        ge=0,
        le=1000,
        description="A trunk that carries no more than this between two reads (in both "
        "directions together) counts as idle; spanning tree and LLDP frames alone are below "
        "a kilobit per second.",
    )
    min_seconds: int = param(
        20,
        unit="s",
        ge=1,
        description="Reads closer together than this are too short to judge.",
    )


@history_rule(
    "port.idle-trunk",
    "Trunk port carries no traffic",
    Severity.INFO,
    "A port that is configured as a trunk (it carries tagged VLANs) and has a link, but "
    "carries almost nothing between the last two reads (parameter idle_kbps), usually leads to "
    "nothing: a forgotten uplink, an access point that is off or a cable to an unused device. "
    "Unused trunks widen the VLAN exposure of the switch. One read can fall into a quiet "
    "moment, so treat it as a hint.",
    params=IdleTrunkParams,
)
def port_idle_trunk(net: Network, history: History) -> Iterator[Result]:
    for port, delta in _live(net, history):
        limits = ctx.params(IdleTrunkParams, port)
        if port.role not in (None, PortRole.JACK) or delta.seconds < limits.min_seconds:
            continue
        if delta.rx_bytes is None and delta.tx_bytes is None:
            continue
        if not _is_trunk(net, port):
            continue
        kbps = ((delta.rx_bytes or 0) + (delta.tx_bytes or 0)) * 8 / delta.seconds / 1000
        if kbps > limits.idle_kbps:
            continue
        name = device_name(net, port.device_id)
        yield found(
            f"{name} port {port.name} is a trunk with a link but carried almost no traffic in "
            f"the last {_minutes(delta)} min",
            [port.id],
            fix="Check what is plugged in. If nothing uses the trunk, disable the port or remove "
            "the tagged VLANs from it.",
            mid="counters.idleTrunk",
            fix_id="counters.idleTrunk.fix",
            params={"device": name, "port": port.name, "minutes": _minutes(delta)},
        )


class CollisionParams(RuleParams):
    min_collisions: int = param(
        10,
        unit="count",
        ge=1,
        description="Fewer collisions than this between two reads are never reported.",
    )


@history_rule(
    "port.collisions",
    "Port counts collisions on a full-duplex link",
    Severity.WARNING,
    "Collisions only happen on half-duplex links. A port that negotiated full duplex (or "
    "runs at 1 Gbit/s or more, which is always full duplex) and still counts collisions has a "
    "duplex mismatch with the other end: one side forces half duplex or a speed, the other "
    "negotiates. Throughput collapses under load. Judged on the collisions between the last "
    "two reads (parameter min_collisions).",
    params=CollisionParams,
)
def port_collisions(net: Network, history: History) -> Iterator[Result]:
    for port, delta in _live(net, history):
        collisions = delta.collisions
        if not collisions or collisions < ctx.params(CollisionParams, port).min_collisions:
            continue
        if not (port.full_duplex is True or (port.speed_mbps or 0) >= 1000):
            continue
        name = device_name(net, port.device_id)
        yield found(
            f"{name} port {port.name} counted {collisions} collisions in the last "
            f"{_minutes(delta)} min although the link is full duplex",
            [port.id],
            fix="Leave both ends on auto-negotiation, or force the same speed and duplex on "
            "both; replace the cable if it persists.",
            mid="counters.collisions",
            fix_id="counters.collisions.fix",
            params={
                "device": name,
                "port": port.name,
                "minutes": _minutes(delta),
                "count": collisions,
            },
        )


class CounterResetParams(RuleParams):
    min_ports: int = param(
        3,
        unit="count",
        ge=1,
        description="A device counts as restarted when its counters restarted from zero on all "
        "its ports that report counters, and there are at least this many.",
    )


@history_rule(
    "device.reboot-by-counters",
    "Device restarted (seen from its port counters)",
    Severity.INFO,
    "Devices that report no uptime cannot be checked by device.reboot. When the counters of "
    "all their ports start again from zero between two reads (and at least min_ports ports "
    "report counters), the device restarted or cleared its statistics. Devices whose boot time "
    "is known are left to device.reboot.",
    params=CounterResetParams,
)
def reboot_by_counters(net: Network, history: History) -> Iterator[Result]:
    for dev in net.devices:
        if history.boots.get(dev.id) is not None:
            continue
        deltas = []
        for port in net.ports_of(dev.id):
            record = history.counters.get(port.id)
            if record is not None and record.delta is not None:
                deltas.append(record.delta)
        if len(deltas) < ctx.params(CounterResetParams, dev).min_ports:
            continue
        if not all(d.reset for d in deltas):
            continue
        yield found(
            f"{dev.name} restarted or cleared its counters (all {len(deltas)} ports counted from "
            "zero again)",
            [dev.id],
            fix="If nobody restarted it, check its power supply or PoE budget and its temperature.",
            mid="counters.deviceReset",
            fix_id="counters.deviceReset.fix",
            params={"device": dev.name, "count": len(deltas)},
        )


RULES: list[Rule] = [
    port_errors,
    port_drops,
    port_utilisation,
    port_idle_trunk,
    port_collisions,
    reboot_by_counters,
]
