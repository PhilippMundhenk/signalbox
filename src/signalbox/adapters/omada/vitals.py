"""Omada health and time: the device list's vital signs and the site's time zone.

The Open API lists every managed device with ``cpuUtil`` and ``memUtil`` (percent; the device
details call the latter ``memoryUtil``), the uptime as text (``uptime``, ``"3day(s) 4h 5m
6s"``) and, in the details, as seconds (``uptimeLong``). ``cpuUtil``, ``memoryUtil`` and
``uptimeLong`` are in the controller's own API description of the device details (Omada
Software Controller 6.3 in CI, #140); the list's ``memUtil`` and ``uptime`` text and every
value are not confirmed (the CI site has no devices). *Guess*: ``temp``/``temperature``
(°C), ``fanStatus`` and ``powerStatus`` on switches and gateways that have them, read only
when they are words that leave no doubt (``normal``, ``abnormal``, ...; a number could mean either).
Memory is only there as a percentage (``memUtil``): without the total there are no bytes to
report, so it is left out.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from email.utils import parsedate_to_datetime
from typing import Any

from signalbox.model import DeviceHealth, DeviceTime, Fan, PowerSupply, TemperatureSensor

_PART = re.compile(r"(\d+)\s*(day\(s\)|days?|d|h|m|s)\b", re.IGNORECASE)
_CLOCK = re.compile(r"(\d+):(\d\d):(\d\d)")
_UNIT = {"d": 86400, "h": 3600, "m": 60, "s": 1}
#: words of a fan or power state that clearly mean "fine" or "failed"
_OK = {"normal": True, "ok": True, "good": True, "abnormal": False, "fault": False}
_OK |= {"failed": False, "error": False}


def _number(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, int | float | str):
        return None
    try:
        return float(value)
    except ValueError:
        return None


def uptime(row: dict[str, Any]) -> int | None:
    """``uptimeLong`` (seconds), else ``uptime`` text: ``3day(s) 4h 5m 6s``, ``2 days
    04:05:06``, ``45m 2s``."""
    seconds = _number(row.get("uptimeLong"))
    if seconds is not None and seconds >= 0:
        return int(seconds)
    text = row.get("uptime")
    if isinstance(text, int | float) and not isinstance(text, bool) and text >= 0:
        return int(text)
    if not isinstance(text, str) or not text.strip():
        return None
    total, rest = 0, text
    if (m := _CLOCK.search(rest)) is not None:
        total += int(m.group(1)) * 3600 + int(m.group(2)) * 60 + int(m.group(3))
        rest = rest[: m.start()] + rest[m.end() :]
    parts = _PART.findall(rest)
    if not parts and m is None:
        return None
    for amount, unit in parts:
        total += int(amount) * _UNIT[unit[0].lower()]
    return total


def _percent(value: Any) -> float | None:
    number = _number(value)
    return number if number is not None and 0 <= number <= 100 else None


def _state(value: Any) -> bool | None:
    return _OK.get(value.strip().lower()) if isinstance(value, str) else None


def health_of(row: dict[str, Any]) -> DeviceHealth:
    temp = _number(row.get("temp", row.get("temperature")))
    fans = []
    if (fan := _state(row.get("fanStatus"))) is not None:
        fans.append(Fan(name="fan", ok=fan))
    power = []
    if (psu := _state(row.get("powerStatus"))) is not None:
        power.append(PowerSupply(name="power", ok=psu))
    return DeviceHealth(
        uptime_seconds=uptime(row),
        cpu_load_pct=_percent(row.get("cpuUtil")),
        temperatures=[TemperatureSensor(name="device", value_c=temp)] if temp is not None else [],
        fans=fans,
        power_supplies=power,
    )


def time_of(date_header: str | None, zone: Any, start: datetime, end: datetime) -> DeviceTime:
    """The controller's clock from the ``Date`` header of an answer (whole seconds, read
    between ``start`` and ``end``) and the site's ``timeZone`` (``UTC``, ``Europe/Berlin``,
    as the sites list gives it: the zone the site's devices are set to)."""
    clock = None
    if date_header:
        try:
            clock = parsedate_to_datetime(date_header)
        except (TypeError, ValueError, IndexError):
            clock = None
    if clock is not None and clock.tzinfo is None:
        clock = None
    half = (end - start) / 2
    name = zone.strip() if isinstance(zone, str) and zone.strip() else None
    return DeviceTime(
        clock=clock.astimezone(UTC) + timedelta(seconds=0.5) if clock else None,
        read_at=start + half if clock else None,
        uncertainty_seconds=half.total_seconds() + 0.5 if clock else None,
        timezone=name,
    )
