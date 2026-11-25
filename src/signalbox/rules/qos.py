"""Traffic shaping and smart queue management (#166): whether the shaper of a gateway matches
the line it sits on, and whether a line that suffers from bufferbloat has one at all.

They read :class:`~signalbox.model.Shaper` (OpenWrt sqm-scripts, OPNsense pipes, MikroTik queues,
UniFi Smart Queues) with the line rates of :class:`~signalbox.model.Uplink` (DSL sync, LTE). A
rate the device does not report is never judged.
"""

from __future__ import annotations

from collections.abc import Iterator

from signalbox.model import Device, Network, Shaper, Uplink, UplinkKind
from signalbox.rules import Result, Rule, RuleParams, Severity, ctx, found, param, rule
from signalbox.rules._names import device_name

#: Adapters that read shapers: the check "no shaper" is only made for their gateways.
READERS = frozenset({"openwrt", "opnsense", "mikrotik", "unifi"})
#: Line kinds that are prone to bufferbloat besides those with a modem rate.
_PRONE = frozenset({UplinkKind.LTE, UplinkKind.PPPOE})


class AboveLineParams(RuleParams):
    tolerance_pct: float = param(
        5,
        unit="%",
        ge=0,
        le=100,
        description="How far the shaper rate may exceed the line rate before it is reported.",
    )


class BelowLineParams(RuleParams):
    below_pct: float = param(
        50,
        unit="%",
        ge=1,
        le=99,
        description="Shaper rate below this share of the line rate is reported as wasteful.",
    )


def _directions(sh: Shaper, up: Uplink) -> Iterator[tuple[str, int, int]]:
    """``(direction, shaper rate, line rate)`` for the directions both are known for."""
    if sh.download_kbps and up.downstream_kbps:
        yield "download", sh.download_kbps, up.downstream_kbps
    if sh.upload_kbps and up.upstream_kbps:
        yield "upload", sh.upload_kbps, up.upstream_kbps


def _mbit(kbps: int) -> str:
    return f"{kbps / 1000:g} Mbit/s"


def _active(net: Network) -> Iterator[tuple[Shaper, Uplink]]:
    for sh in sorted(net.shapers, key=lambda s: s.id):
        up = net.uplink(sh.uplink_id) if sh.uplink_id else None
        if sh.enabled and up is not None:
            yield sh, up


@rule(
    "qos.shaper-above-line",
    "Shaper rate above the line rate",
    Severity.WARNING,
    "A shaper (SQM, Smart Queues, queue) is set to a rate higher than the line the modem "
    "reports. The line, not the shaper, is then the bottleneck: the queue in front of the modem "
    "fills up and the shaper does nothing against bufferbloat. Set the rate a few percent below "
    "the real line speed (parameter tolerance_pct allows for a slightly higher setting).",
    params=AboveLineParams,
)
def above_line(net: Network) -> Iterator[Result]:
    for sh, up in _active(net):
        tol = ctx.params(AboveLineParams, sh).tolerance_pct
        for way, rate, line in _directions(sh, up):
            if rate <= line * (1 + tol / 100):
                continue
            dev = device_name(net, sh.device_id)
            yield found(
                f"The {way} rate of the shaper {sh.name!r} on {dev} is {_mbit(rate)}, above "
                f"the line rate of {_mbit(line)}",
                [sh.id, up.id],
                fix="Set the shaper to about 90 to 95 % of the real line speed.",
                key=way,
                mid=f"qos.aboveLine.{way}",
                fix_id="qos.aboveLine.fix",
                params={
                    "shaper": repr(sh.name),
                    "device": dev,
                    "rate": _mbit(rate),
                    "line": _mbit(line),
                },
            )


@rule(
    "qos.shaper-far-below-line",
    "Shaper rate far below the line rate",
    Severity.INFO,
    "A shaper is set far below the line rate the modem reports, so part of the bandwidth you "
    "pay for is never used. A few percent below the line is right for a smart queue; much "
    "lower is usually a value that was never updated after a speed upgrade (parameter "
    "below_pct).",
    params=BelowLineParams,
)
def far_below_line(net: Network) -> Iterator[Result]:
    for sh, up in _active(net):
        share = ctx.params(BelowLineParams, sh).below_pct
        for way, rate, line in _directions(sh, up):
            if rate >= line * share / 100:
                continue
            dev = device_name(net, sh.device_id)
            yield found(
                f"The {way} rate of the shaper {sh.name!r} on {dev} is {_mbit(rate)}, far below "
                f"the line rate of {_mbit(line)}",
                [sh.id, up.id],
                fix="Check whether the line got faster and raise the shaper rate to about 90 "
                "to 95 % of it.",
                key=way,
                mid=f"qos.farBelowLine.{way}",
                fix_id="qos.farBelowLine.fix",
                params={
                    "shaper": repr(sh.name),
                    "device": dev,
                    "rate": _mbit(rate),
                    "line": _mbit(line),
                },
            )


@rule(
    "qos.shaper-on-down-uplink",
    "Shaper on an internet connection that is down",
    Severity.INFO,
    "An enabled shaper belongs to an internet connection that is currently down. It does "
    "nothing until the line is back, and it may be a leftover of a connection that was removed "
    "or renamed.",
)
def on_down_uplink(net: Network) -> Iterator[Result]:
    for sh, up in _active(net):
        if up.up is not False:
            continue
        dev = device_name(net, sh.device_id)
        yield found(
            f"The shaper {sh.name!r} on {dev} belongs to the connection {up.name or up.id}, "
            "which is down",
            [sh.id, up.id],
            fix="Bring the connection up, or disable or remove the shaper if it is no longer used.",
            mid="qos.downUplink",
            fix_id="qos.downUplink.fix",
            params={"shaper": repr(sh.name), "device": dev, "uplink": up.name or up.id},
        )


def _prone(up: Uplink) -> bool:
    """A line type that suffers from bufferbloat: LTE, PPPoE (DSL, mostly) and a line with a
    modem rate below gigabit (DSL, cable)."""
    if up.kind in _PRONE:
        return True
    line = [r for r in (up.downstream_kbps, up.upstream_kbps) if r]
    return bool(line) and max(line) < 1_000_000


def _reads_shapers(dev: Device) -> bool:
    return dev.adapter in READERS and "interfaces" in dev.capabilities


@rule(
    "qos.no-shaper",
    "No smart queue on an internet connection",
    Severity.INFO,
    "A gateway has an internet connection of a type that suffers from bufferbloat (DSL or "
    "PPPoE, cable, LTE) and no shaper is set up on the gateway. Without a smart queue (SQM with "
    "cake or fq_codel, Smart Queues, an OPNsense pipe with FQ-CoDel) video calls and games lag "
    "while someone uploads. Only gateways whose integration reads shapers are checked, and "
    "only connections that are up; a gateway with any enabled shaper that is not tied to a "
    "connection is not reported.",
)
def no_shaper(net: Network) -> Iterator[Result]:
    for dev in sorted(net.devices, key=lambda d: d.id):
        if not _reads_shapers(dev):
            continue
        mine = [s for s in net.shapers_of(dev.id) if s.enabled]
        if any(s.uplink_id is None for s in mine):
            continue
        covered = {s.uplink_id for s in mine}
        for up in sorted(net.uplinks_of(dev.id), key=lambda u: u.id):
            if up.up is not True or up.id in covered or not _prone(up):
                continue
            dev_name = device_name(net, dev.id)
            yield found(
                f"The internet connection {up.name or up.id} of {dev_name} has no smart queue",
                [up.id],
                fix="Set up SQM (cake) or Smart Queues at about 90 to 95 % of the line speed.",
                key=up.id,
                mid="qos.noShaper",
                fix_id="qos.noShaper.fix",
                params={"uplink": up.name or up.id, "device": dev_name},
            )


RULES: list[Rule] = [above_line, far_below_line, on_down_uplink, no_shaper]
