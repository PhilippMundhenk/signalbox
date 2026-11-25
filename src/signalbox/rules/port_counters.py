"""Port error counters (issues #115, #158).

A slowly dying cable, a bad connector or a duplex mismatch shows up as rising CRC and error
counters long before anything breaks. The rule looks at what the counters did between the last
two reads (:mod:`signalbox.counters`), never at lifetime totals: a port with a few old errors
is quiet, a port that collects errors now is reported.
"""

from __future__ import annotations

from collections.abc import Iterator

from signalbox.model import Network, PortKind
from signalbox.rules import Result, Rule, Severity, found, history_rule
from signalbox.rules._names import device_name
from signalbox.sightings import History


@history_rule(
    "port.errors",
    "Port collects errors",
    Severity.WARNING,
    "Rising CRC (FCS) or error counters on a port are the early sign of a bad cable or "
    "connector, a duplex or speed mismatch, or a failing port, long before the link drops. "
    "Judged on what happened between the last two reads relative to the packets in that time, "
    "not on lifetime totals: a warning when the CRC errors received exceed a small share of the "
    "packets (counters.crc_ratio), information for other errors above counters.error_ratio. "
    "Ports that are down, reads with few packets or errors, and counters that were reset by a "
    "reboot are ignored. The thresholds are in the configuration under counters.",
)
def port_errors(net: Network, history: History) -> Iterator[Result]:
    limits = history.counter_limits
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


RULES: list[Rule] = [port_errors]
