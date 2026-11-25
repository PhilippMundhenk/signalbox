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
)
from signalbox.rules import Result, Rule, Severity, found, rule

#: Share of the budget from which the draw counts as near the limit (warning); 100 % is an error.
WARN_SHARE = 0.8
#: Tolerance above the class limit (measurement error) before a port counts as overdrawing.
CLASS_MARGIN = 1.05


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
    if share < WARN_SHARE:
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
        if p.poe and p.poe.enabled is not False and p.poe.status is PoeStatus.SEARCHING
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
    "reboot at random. The check warns when the draw reaches 80 % of the budget, reports an "
    "error from 100 %, warns about a port whose powered device draws more than its PoE class "
    "allows, and notes ports with PoE on where no powered device is detected. Switches that "
    "report no budget are not checked.",
)
def poe_budget(net: Network) -> Iterator[Result]:
    for device in net.devices:
        yield from _budget(net, device)
        yield from _overdraw(net, device)
        yield from _idle(net, device)


RULES: list[Rule] = [poe_budget]
