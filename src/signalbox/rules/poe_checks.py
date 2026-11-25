"""Power over Ethernet: the switch's budget and the powered devices (issue #116, model #159).

The check uses what a switch reports about its PSE: ``Device.poe`` (budget and used power) and
``Port.poe`` (state, class, power per port). Everything stays quiet where a switch reports no
budget or no PoE data.
"""

from __future__ import annotations

from collections.abc import Iterator

from signalbox.model import (
    POE_CLASS_PSE_W,
    Device,
    MessageValue,
    Network,
    PoeStatus,
    Port,
    PortKind,
)
from signalbox.power import powered_by
from signalbox.rules import Result, Rule, RuleParams, Severity, ctx, found, param, rule
from signalbox.rules._names import device_name

#: Share of the budget from which the draw counts as near the limit (warning); 100 % is an error.
WARN_SHARE = 0.8
#: Tolerance above the class limit (measurement error) before a port counts as overdrawing.
CLASS_MARGIN = 1.05


class PoeParams(RuleParams):
    warn_pct: float = param(
        WARN_SHARE * 100,
        unit="%",
        ge=1,
        le=100,
        description="Share of the budget in use from which it is a warning (100 % is an error).",
    )


def _used_w(net: Network, device: Device) -> float | None:
    """Power in use: the switch's own figure, else the sum of the ports that report power."""
    if device.poe is not None and device.poe.used_w is not None:
        return device.poe.used_w
    drawn = [p.poe.power_w for p in net.ports_of(device.id) if p.poe and p.poe.power_w is not None]
    return sum(drawn) if drawn else None


def _watts(value: float) -> str:
    return f"{value:.1f}".removesuffix(".0")


def _budget(net: Network, device: Device) -> Iterator[Result]:
    supply = device.poe
    if supply is None or not supply.budget_w:
        return
    used = _used_w(net, device)
    if used is None:
        return
    share = used / supply.budget_w
    if share * 100 < ctx.params(PoeParams, device).warn_pct:
        return
    over = share >= 1.0
    params: dict[str, MessageValue] = {
        "device": device.name,
        "used": _watts(used),
        "budget": _watts(supply.budget_w),
        "percent": round(share * 100),
    }
    yield found(
        f"{device.name} delivers {params['used']} W of its {params['budget']} W PoE budget "
        f"({params['percent']} %)" + (": the budget is used up." if over else "."),
        [device.id],
        fix="Move a device to another PoE switch, use a PoE injector, or lower the priority of "
        "ports that can wait: when the budget is exceeded the switch cuts power to the "
        "lowest-priority ports and those devices reboot.",
        severity=Severity.ERROR if over else Severity.WARNING,
        key="budget",
        mid="poe.budgetOver" if over else "poe.budgetNear",
        fix_id="poe.budget.fix",
        params=params,
    )


def _overdraw(net: Network, device: Device) -> Iterator[Result]:
    for port in net.ports_of(device.id):
        poe = port.poe
        if poe is None or poe.power_w is None or poe.power_class is None:
            continue
        limit = POE_CLASS_PSE_W[poe.power_class]
        if poe.power_w <= limit * CLASS_MARGIN:
            continue
        params: dict[str, MessageValue] = {
            "device": device.name,
            "port": port.name,
            "power": _watts(poe.power_w),
            "class": poe.power_class,
            "limit": _watts(limit),
        }
        yield found(
            f"{device.name} port {port.name}: the powered device draws {params['power']} W, more "
            f"than PoE class {poe.power_class} allows ({params['limit']} W).",
            [port.id],
            fix="The device is faulty or reports the wrong class. Check it, or connect it to a "
            "port of a higher class.",
            severity=Severity.WARNING,
            key=f"class:{port.id}",
            mid="poe.classExceeded",
            fix_id="poe.classExceeded.fix",
            params=params,
        )


def _idle(net: Network, device: Device) -> Iterator[Result]:
    names = sorted(
        p.name
        for p in net.ports_of(device.id)
        if p.poe
        and p.poe.enabled is not False
        and p.poe.status is PoeStatus.SEARCHING
        and p.up is not True  # with a link and no powered device it is poe.unneeded
    )
    if not names:
        return
    params: dict[str, MessageValue] = {
        "device": device.name,
        "ports": ", ".join(names),
        "count": len(names),
    }
    yield found(
        f"{device.name}: PoE is on but no powered device is detected on {params['ports']}.",
        [device.id],
        fix="Turn PoE off on ports without a powered device, or check the cable of the device "
        "that should be powered.",
        severity=Severity.INFO,
        key="idle",
        mid="poe.idle",
        fix_id="poe.idle.fix",
        params=params,
    )


@rule(
    "poe.budget",
    "PoE draw within the switch's budget and the powered devices' class",
    Severity.WARNING,
    "A PoE switch has a power budget (40 to 120 W for small ones). When the devices draw more "
    "than that, the switch cuts power to the lowest-priority ports and access points or cameras "
    "reboot at random. The check warns when the draw reaches 80 % of the budget (parameter "
    "warn_pct), reports an "
    "error from 100 %, warns about a port whose powered device draws more than its PoE class "
    "allows, and notes ports with PoE on where no powered device is detected. Switches that "
    "report no budget are not checked.",
    params=PoeParams,
)
def poe_budget(net: Network) -> Iterator[Result]:
    for device in net.devices:
        yield from _budget(net, device)
        yield from _overdraw(net, device)
        yield from _idle(net, device)


def _label(net: Network, port: Port) -> str:
    return f"{device_name(net, port.device_id)} port {port.name}"


@rule(
    "poe.fault",
    "A PoE port reports a fault or an overload",
    Severity.ERROR,
    "The switch reports a fault (short circuit, over-current, a power supply problem) or an "
    "overload on a PoE port. The powered device gets no or too little power and restarts or "
    "stays off. An overload is a warning, a fault an error. Quiet where the switch reports no "
    "PoE state per port.",
)
def poe_fault(net: Network) -> Iterator[Result]:
    powered = {p.port_id: p for p in powered_by(net).values()}
    for port in net.ports:
        poe = port.poe
        if poe is None or poe.status not in (PoeStatus.FAULT, PoeStatus.OVERLOAD):
            continue
        name = _label(net, port)
        overload = poe.status is PoeStatus.OVERLOAD
        objects = [port.id]
        known = powered.get(port.id)
        if known is not None:
            objects.append(known.device_id)
        yield found(
            f"{name}: PoE reports an overload." if overload else f"{name}: PoE reports a fault.",
            objects,
            fix="Check the cable and the powered device (a short circuit, a damaged connector or "
            "a device that draws more than the port allows); unplug it and plug it in again.",
            severity=Severity.WARNING if overload else Severity.ERROR,
            key=port.id,
            mid="poe.faultOverload" if overload else "poe.fault",
            fix_id="poe.fault.fix",
            params={"port": name},
        )


@rule(
    "poe.class-mismatch",
    "The PoE class of a port and of its device disagree",
    Severity.WARNING,
    "The switch detected another PoE class on a port than the powered device announces (LLDP "
    "power TLV). One of them is wrong: the device may get less power than it needs, or the "
    "switch reserves more of its budget than necessary. Needs a neighbour that announces its "
    "class and a switch that reports the detected class.",
)
def poe_class_mismatch(net: Network) -> Iterator[Result]:
    for nb in net.neighbours:
        port = net.port(nb.local_port_id)
        if nb.wireless or port is None or port.poe is None or nb.poe_class is None:
            continue
        seen = port.poe.power_class
        if seen is None or seen == nb.poe_class:
            continue
        name = _label(net, port)
        yield found(
            f"{name}: the switch detects PoE class {seen} but the device announces class "
            f"{nb.poe_class}.",
            [port.id, nb.id],
            fix="Check the cable and the power supply of the device. If it keeps announcing "
            "another class, set the class or the power limit of the port by hand.",
            key=nb.id,
            mid="poe.classMismatch",
            fix_id="poe.classMismatch.fix",
            params={"port": name, "detected": seen, "announced": nb.poe_class},
        )


@rule(
    "poe.unneeded",
    "PoE is on for a device that has its own power",
    Severity.INFO,
    "A port has PoE switched on and a link, but the switch detects no powered device: what is "
    "connected has its own power supply. PoE on such a port is harmless with a standard "
    "(802.3af/at/bt) switch, but passive PoE can damage equipment, and PoE off on that port is "
    "the safer default. One finding per switch.",
)
def poe_unneeded(net: Network) -> Iterator[Result]:
    for device in net.devices:
        names = sorted(
            p.name
            for p in net.ports_of(device.id)
            if p.kind is PortKind.ETHERNET
            and p.up is True
            and p.poe
            and p.poe.enabled is True
            and p.poe.status is PoeStatus.SEARCHING
        )
        if not names:
            continue
        params: dict[str, MessageValue] = {
            "device": device.name,
            "ports": ", ".join(names),
            "count": len(names),
        }
        yield found(
            f"{device.name}: PoE is on but nothing is powered over it on {params['ports']}.",
            [device.id],
            fix="Turn PoE off on these ports; the devices there have their own power supply.",
            key=device.id,
            mid="poe.unneeded",
            fix_id="poe.unneeded.fix",
            params=params,
        )


RULES: list[Rule] = [poe_budget, poe_fault, poe_class_mismatch, poe_unneeded]
