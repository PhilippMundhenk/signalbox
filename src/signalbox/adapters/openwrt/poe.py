"""PoE of OpenWrt switches with the ``realtek-poe`` daemon (#159).

``ubus call poe info`` answers ``{"budget": 65, "consumption": 12.3, "ports": {"lan1":
{"priority": 2, "mode": "PoE+", "status": "Delivering power", "consumption": 3450}}}``. The
object exists only on switches with the daemon (``realtek-poe``, OpenWrt 21.02 and later;
older ``poemgr`` builds are not read). The units are a guess (#21): the total in watts, the
port consumption in milliwatts as the daemon's README shows; a port value above the budget is
read as milliwatts, otherwise as watts.
"""

from __future__ import annotations

from typing import Any

from signalbox.model import PoeMode, PoeStatus, PoeSupply, PortPoe

_MODES = {"poe": PoeMode.AF, "poe+": PoeMode.AT, "poe++": PoeMode.BT}


def _number(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    return float(value) if value >= 0 else None


def _status(text: str) -> PoeStatus | None:
    low = text.strip().lower()
    if not low:
        return None
    if low.startswith("deliver"):
        return PoeStatus.DELIVERING
    if low.startswith("search"):
        return PoeStatus.SEARCHING
    if low.startswith("disabled"):
        return PoeStatus.DISABLED
    if "overload" in low:
        return PoeStatus.OVERLOAD
    if "fault" in low or "error" in low:
        return PoeStatus.FAULT
    return None


def read(info: Any) -> tuple[PoeSupply | None, dict[str, PortPoe]]:
    """The budget and the ports (by interface name) of a ``poe info`` answer; empty when the
    answer has no PoE data."""
    if not isinstance(info, dict):
        return None, {}
    budget = _number(info.get("budget"))
    used = _number(info.get("consumption"))
    supply = PoeSupply(budget_w=budget, used_w=used) if budget or used else None
    out: dict[str, PortPoe] = {}
    rows = info.get("ports")
    for name, row in rows.items() if isinstance(rows, dict) else []:
        if not isinstance(row, dict):
            continue
        raw = _number(row.get("consumption"))
        power = None if raw is None else raw / 1000 if raw > (budget or 100) else raw
        status = _status(str(row.get("status") or ""))
        mode_text = str(row.get("mode") or "").strip().lower()
        out[str(name)] = PortPoe(
            enabled=None if status is None else status is not PoeStatus.DISABLED,
            status=status,
            mode=_MODES.get(mode_text),
            power_w=power,
        )
    return supply, out
