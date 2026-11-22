"""OpenWrt health and time: ``system info``, thermal zones and the ``system`` UCI config.

``system info`` (rpcd) answers memory in bytes, ``root`` and ``tmp`` in KiB, ``load`` as the
kernel's fixed-point numbers (65536 is a load of 1.0) and ``localtime`` as the local wall clock
in seconds since the epoch (UTC seconds plus the zone's offset). The zone OpenWrt runs on is the
POSIX string in ``system.@system[0].timezone`` (written to ``/etc/TZ``); ``zonename`` is the
IANA name LuCI shows. Both shapes are documented in ``docs/adapters/openwrt.md``.
"""

from __future__ import annotations

import calendar
import re
from datetime import UTC, datetime, timedelta, timezone
from typing import Any

from signalbox.model import (
    DeviceHealth,
    DeviceTime,
    NtpClient,
    NtpServer,
    StorageKind,
    StorageUsage,
    TemperatureSensor,
)

KIB = 1024
LOAD_SCALE = 65536
#: thermal zones tried, ``/sys/class/thermal/thermal_zone<N>/temp`` (stops at the first missing)
THERMAL_ZONES = 8


def _int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _part(values: Any, key: str) -> int | None:
    found = _int(values.get(key)) if isinstance(values, dict) else None
    return found if found is not None and found >= 0 else None


def _disk(name: str, kind: StorageKind, values: Any) -> StorageUsage | None:
    total = _part(values, "total")
    if not total:
        return None
    used = _part(values, "used")
    if used is None and (free := _part(values, "free")) is not None:
        used = max(total - free, 0)
    if used is not None:
        used = min(used, total)
    return StorageUsage(
        name=name,
        kind=kind,
        total_bytes=total * KIB,
        used_bytes=used * KIB if used is not None else None,
    )


def health_of(info: dict[str, Any], temperatures: list[TemperatureSensor]) -> DeviceHealth:
    """``system info`` (and the thermal zones) as :class:`DeviceHealth`.

    Memory used is total minus ``available`` (the kernel's estimate, without page cache); where
    rpcd has no ``available`` (before 21.02) total minus free, buffers and cache. ``root`` is
    where the configuration lives (the overlay on squashfs images): storage of kind
    ``system``; ``tmp`` is RAM: ``temporary``.
    """
    memory = info.get("memory") if isinstance(info.get("memory"), dict) else {}
    total = _part(memory, "total")
    used = None
    if total:
        available = _part(memory, "available")
        if available is None and (free := _part(memory, "free")) is not None:
            available = free + (_part(memory, "buffered") or 0) + (_part(memory, "cached") or 0)
        if available is not None:
            used = max(total - min(available, total), 0)
    load = info.get("load")
    average = None
    if isinstance(load, list) and len(load) >= 3:
        numbers = [_int(x) for x in load[:3]]
        if all(n is not None and n >= 0 for n in numbers):
            average = tuple(round((n or 0) / LOAD_SCALE, 2) for n in numbers)
    uptime = _int(info.get("uptime"))
    storage = [
        s
        for s in (
            _disk("/", StorageKind.SYSTEM, info.get("root")),
            _disk("/tmp", StorageKind.TEMPORARY, info.get("tmp")),
        )
        if s is not None
    ]
    return DeviceHealth(
        uptime_seconds=uptime if uptime is not None and uptime >= 0 else None,
        load_average=average,
        memory_total_bytes=total or None,
        memory_used_bytes=used,
        storage=storage,
        temperatures=temperatures,
    )


def thermal(zone: int, temp: Any, kind: Any) -> TemperatureSensor | None:
    """A thermal zone: ``temp`` in milli-degrees Celsius, ``type`` its name."""
    value = _int(str(temp).strip()) if isinstance(temp, str) else None
    if value is None:
        return None
    name = kind.strip() if isinstance(kind, str) and kind.strip() else f"thermal_zone{zone}"
    return TemperatureSensor(name=name, value_c=value / 1000)


# --- POSIX TZ strings (CET-1CEST,M3.5.0,M10.5.0/3) ----------------------------------------------

_NAME = r"(?:<[^>]+>|[A-Za-z]{3,})"
_OFF = r"[+-]?\d{1,3}(?::\d\d){0,2}"
_TZ = re.compile(
    rf"(?P<std>{_NAME})(?P<off>{_OFF})(?:(?P<dst>{_NAME})(?P<doff>{_OFF})?"
    r"(?:,(?P<start>[^,]+),(?P<end>[^,]+))?)?"
)
_RULE = re.compile(r"M(\d{1,2})\.(\d)\.(\d)(?:/(" + _OFF + "))?")


def _seconds(text: str) -> int:
    sign = -1 if text.startswith("-") else 1
    parts = [int(p) for p in text.lstrip("+-").split(":")]
    parts += [0] * (3 - len(parts))
    return sign * (parts[0] * 3600 + parts[1] * 60 + parts[2])


def _transition(rule: str, year: int) -> int | None:
    """``Mm.w.d[/time]``: seconds from the start of ``year`` (local time) to the change."""
    m = _RULE.fullmatch(rule)
    if m is None:
        return None
    month, week, day = int(m.group(1)), int(m.group(2)), int(m.group(3))
    if not (1 <= month <= 12 and 1 <= week <= 5 and day <= 6):
        return None
    first = (calendar.weekday(year, month, 1) + 1) % 7  # 0 = Sunday, as POSIX counts
    mday = 1 + (day - first) % 7 + (week - 1) * 7
    while mday > calendar.monthrange(year, month)[1]:
        mday -= 7
    at = _seconds(m.group(4)) if m.group(4) else 7200
    start_of_year = datetime(year, 1, 1, tzinfo=UTC)
    return int((datetime(year, month, mday, tzinfo=UTC) - start_of_year).total_seconds()) + at


def posix_offset(tz: str, when: datetime) -> int | None:
    """Minutes east of UTC that the POSIX TZ string ``tz`` gives at the instant ``when``.

    Only the ``Mm.w.d`` rules (the ones OpenWrt's zone table uses); ``None`` for anything else.
    """
    if re.fullmatch(_NAME, tz.strip()):
        return 0  # a name alone (OpenWrt's default "UTC"): musl runs on UTC
    m = _TZ.fullmatch(tz.strip())
    if m is None:
        return None
    std = -_seconds(m.group("off"))  # POSIX counts west: CET-1 is UTC+1
    if not m.group("dst"):
        return std // 60
    dst = -_seconds(m.group("doff")) if m.group("doff") else std + 3600
    if not m.group("start"):
        return None
    year = when.astimezone(UTC).year
    start, end = _transition(m.group("start"), year), _transition(m.group("end"), year)
    if start is None or end is None:
        return None
    since = (when - datetime(year, 1, 1, tzinfo=UTC)).total_seconds()
    begins, ends = start - std, end - dst  # the rules are in local time
    summer = begins <= since < ends if begins < ends else not ends <= since < begins
    return (dst if summer else std) // 60


def _zone_section(uci: dict[str, Any], kind: str, name: str | None = None) -> dict[str, Any]:
    values = uci.get("values")
    for key, s in values.items() if isinstance(values, dict) else []:
        if isinstance(s, dict) and s.get(".type") == kind and name in (None, key):
            return s
    return {}


def _words(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(v).strip() for v in value if str(v).strip()]
    return str(value).split() if isinstance(value, str) else []


def _on(value: Any, default: bool) -> bool:
    return default if value is None else str(value).lower() in ("1", "true", "yes", "on")


def time_of(
    info: dict[str, Any],
    uci: dict[str, Any],
    start: datetime,
    end: datetime,
    segments: dict[str, str],
) -> DeviceTime:
    """``system info`` ``localtime`` (read between ``start`` and ``end``) and ``uci get
    system``. ``segments`` maps a network interface (``lan``) to its segment id, for the
    interface the NTP server is bound to (``system.ntp.interface``).

    The UTC offset is the one the POSIX ``timezone`` gives at the read (OpenWrt's default is
    ``UTC``). ``localtime`` has whole seconds: ``clock`` is the middle of that second and the
    uncertainty half the round trip plus half a second. OpenWrt does not tell whether sysntpd
    is in sync, so ``synchronised`` stays empty.
    """
    system = _zone_section(uci, "system")
    posix = str(system.get("timezone") or "UTC").strip()
    zonename = str(system.get("zonename") or "").strip()
    half = (end - start) / 2
    read_at = start + half
    offset = posix_offset(posix, read_at)
    if offset is not None and abs(offset) > 1080:
        offset = None
    local = _int(info.get("localtime"))
    clock = None
    if local is not None and offset is not None:
        try:
            zone = timezone(timedelta(minutes=offset))
            clock = datetime.fromtimestamp(local - offset * 60, tz=zone)
        except (OverflowError, OSError, ValueError):
            clock = None
    ntp = _zone_section(uci, "timeserver", "ntp")
    client = server = None
    if ntp:
        client = NtpClient(enabled=_on(ntp.get("enabled"), True), servers=_words(ntp.get("server")))
        bound = [segments[i] for i in _words(ntp.get("interface")) if i in segments]
        server = NtpServer(
            enabled=_on(ntp.get("enable_server"), False), segments=sorted(set(bound))
        )
    return DeviceTime(
        clock=clock + timedelta(seconds=0.5) if clock else None,
        read_at=read_at if clock else None,
        uncertainty_seconds=half.total_seconds() + 0.5 if clock else None,
        timezone=zonename or posix or None,
        utc_offset_minutes=offset,
        ntp_client=client,
        ntp_server=server,
    )
