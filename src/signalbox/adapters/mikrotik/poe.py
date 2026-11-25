"""PoE-out of RouterOS ethernet ports (#159).

``/interface/ethernet/poe`` lists the ports with PoE-out (``poe-out``: ``auto-on``,
``forced-on``, ``off``; RouterOS 7). ``monitor once`` adds ``poe-out-status``,
``poe-out-voltage``, ``poe-out-current`` (mA) and ``poe-out-power`` (W). Numbers come as text with a
unit (``48.3V``, ``120mA``, ``5.8W``).
"""

from __future__ import annotations

import re
from typing import Any

from signalbox.model import PoeStatus, PortPoe

_STATUS = {
    "powered-on": PoeStatus.DELIVERING,
    "waiting-for-load": PoeStatus.SEARCHING,
    "current-too-low": PoeStatus.SEARCHING,
    "off": PoeStatus.DISABLED,
    "short-circuit": PoeStatus.FAULT,
    "voltage-too-low": PoeStatus.FAULT,
    "hardware-failure": PoeStatus.FAULT,
    "controller-error": PoeStatus.FAULT,
    "overload": PoeStatus.OVERLOAD,
}
_NUMBER = re.compile(r"-?\d+(?:\.\d+)?")


def number(value: Any) -> float | None:
    """The number in ``5.8W`` / ``120mA`` / ``48.3V``; None for anything else."""
    match = _NUMBER.match(str(value or "").strip())
    return float(match.group()) if match else None


def port(row: dict[str, Any], monitor: dict[str, Any]) -> PortPoe:
    """One port from its ``/interface/ethernet/poe`` row and its monitor answer (maybe empty)."""
    mode = str(row.get("poe-out") or "").strip()
    status = _STATUS.get(str(monitor.get("poe-out-status") or "").strip())
    if mode == "off":
        status = PoeStatus.DISABLED
    power = number(monitor.get("poe-out-power"))
    return PortPoe(
        enabled=None if not mode else mode != "off",
        status=status,
        power_w=power if power is not None and power >= 0 else None,
        voltage_v=number(monitor.get("poe-out-voltage")),
        current_ma=number(monitor.get("poe-out-current")),
    )
