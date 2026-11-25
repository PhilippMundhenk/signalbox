"""OPNsense health and time: the dashboard's ``/api/diagnostics/system/*`` widgets, the CPU type
and the NTP status (``/api/ntpd/service/status``).

The shapes are those of OPNsense 26.7 (``SystemController`` of the Diagnostics module, as the
integration tests record them, see ``docs/adapters/opnsense.md``): ``system_time`` answers the
uptime as text (``3 days, 04:05:06``), the load averages as ``"0.13, 0.07, 0.04"`` and the local
time as ``date("D M j G:i:s T Y")``; ``system_resources`` the physical memory and what is in use
(wired and active pages, so the ZFS ARC counts as used: it is subtracted again here);
``system_disk`` the mounted file systems in bytes; ``system_temperature`` one row per sensor.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from typing import Any

from signalbox.model import (
    DeviceHealth,
    DeviceTime,
    NtpClient,
    StorageKind,
    StorageUsage,
    TemperatureSensor,
)

# the word for "days" is translated with the web interface's language ("3 Tage, 04:05:06")
_UPTIME = re.compile(r"(?:(\d+)\s+[^\d\s,:]+,\s*)?(\d+):(\d\d):(\d\d)")
_SIZE = re.compile(r"(\d+(?:\.\d+)?)\s*([BKMGTP]?)i?B?", re.IGNORECASE)
_THREADS = re.compile(r"\((\d+) cores?, (\d+) threads?\)")
_LOCAL = "%a %b %d %H:%M:%S %Y"


def _number(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int | float):
        return float(value)
    try:
        return float(str(value).strip())
    except (TypeError, ValueError):
        return None


def _count(value: Any) -> int | None:
    number = _number(value)
    return int(number) if number is not None and number >= 0 else None


def uptime(text: Any) -> int | None:
    """``3 days, 04:05:06``, ``1 day, 00:00:01`` or ``04:05:06`` -> seconds."""
    m = _UPTIME.fullmatch(str(text).strip()) if isinstance(text, str) else None
    if m is None:
        return None
    days, hours, minutes, seconds = (int(g) if g else 0 for g in m.groups())
    return ((days * 24 + hours) * 60 + minutes) * 60 + seconds


def load_average(text: Any) -> tuple[float, float, float] | None:
    parts = [_number(p) for p in str(text).split(",")] if isinstance(text, str) else []
    if len(parts) != 3 or any(p is None or p < 0 for p in parts):
        return None
    one, five, fifteen = (p or 0.0 for p in parts)
    return one, five, fifteen


def cpu_count(answer: Any) -> int | None:
    """``["AMD GX-412TC SOC (4 cores, 4 threads)"]``: the threads."""
    text = answer[0] if isinstance(answer, list) and answer else answer
    m = _THREADS.search(text) if isinstance(text, str) else None
    return int(m.group(2)) or None if m else None


def size_bytes(value: Any) -> int | None:
    """``28G``, ``1.2M``, ``0B`` or a plain number of bytes -> bytes (1024-based, as ``df -h``).

    OPNsense before 26.7 answers the disk table of ``df -h``: the sizes are rounded for people."""
    if isinstance(value, int | float) and not isinstance(value, bool):
        return int(value) if value >= 0 else None
    m = _SIZE.fullmatch(value.strip()) if isinstance(value, str) else None
    if m is None:
        return None
    unit = "BKMGTP".index(m.group(2).upper() or "B")
    return int(float(m.group(1)) * 1024**unit)


def _storage(row: dict[str, Any]) -> StorageUsage | None:
    mount = str(row.get("mountpoint") or "").strip()
    # 26.7: total_bytes and used_bytes; 24.7 to 26.1: blocks and used as ``df -h`` prints them
    total = _count(row.get("total_bytes"))
    used = _count(row.get("used_bytes"))
    if total is None and "blocks" in row:
        total, used = size_bytes(row.get("blocks")), size_bytes(row.get("used"))
    if not mount or not total:
        return None
    kind = str(row.get("type") or "")
    if mount == "/":
        what = StorageKind.SYSTEM
    elif kind == "tmpfs":
        what = StorageKind.TEMPORARY
    elif kind in ("ufs", "zfs"):
        what = StorageKind.DATA
    else:
        what = StorageKind.OTHER
    return StorageUsage(
        name=mount,
        kind=what,
        total_bytes=total,
        used_bytes=min(used, total) if used is not None else None,
    )


def health_of(
    time: dict[str, Any],
    resources: dict[str, Any],
    disks: dict[str, Any] | list[Any],
    temperatures: list[Any],
    cpu: Any,
) -> DeviceHealth:
    found = resources.get("memory")
    memory: dict[str, Any] = found if isinstance(found, dict) else {}
    total = _count(memory.get("total"))
    used = _count(memory.get("used"))  # "N/A" when the sysctls are missing
    arc = _count(memory.get("arc")) or 0
    if used is not None:
        used = max(used - arc, 0)
        if total:
            used = min(used, total)
    rows = disks.get("devices") if isinstance(disks, dict) else None
    storage: dict[str, StorageUsage] = {}
    for row in rows if isinstance(rows, list) else []:
        if isinstance(row, dict) and (s := _storage(row)) is not None:
            storage.setdefault(s.name, s)
    sensors = []
    for row in temperatures:
        if not isinstance(row, dict):
            continue
        value, name = _number(row.get("temperature")), str(row.get("device") or "").strip()
        if value is not None and name:
            sensors.append(TemperatureSensor(name=name, value_c=value))
    return DeviceHealth(
        uptime_seconds=uptime(time.get("uptime")),
        load_average=load_average(time.get("loadavg")),
        cpu_count=cpu_count(cpu),
        memory_total_bytes=total or None,
        memory_used_bytes=used if total else None,
        storage=list(storage.values()),
        temperatures=sensors,
    )


def local_time(text: Any) -> datetime | None:
    """``Sun Nov 22 17:12:00 CET 2026`` (PHP ``D M j G:i:s T Y``) without its zone."""
    parts = str(text).split() if isinstance(text, str) else []
    if len(parts) != 6:
        return None
    try:
        return datetime.strptime(" ".join(parts[:4] + parts[5:]), _LOCAL)
    except ValueError:
        return None


def http_date(value: str | None) -> datetime | None:
    """The ``Date`` header of an answer: the device's own clock (UTC, whole seconds)."""
    if not value:
        return None
    try:
        when = parsedate_to_datetime(value)
    except (TypeError, ValueError, IndexError):
        return None
    return when.astimezone(UTC) if when.tzinfo is not None else None


def time_of(
    time: dict[str, Any],
    date_header: str | None,
    ntp_rows: list[Any] | None,
    start: datetime,
    end: datetime,
) -> DeviceTime:
    """The clock from the ``Date`` header of ``system_time`` (read between ``start`` and
    ``end``), the UTC offset from its local ``datetime`` against that header (rounded to 15
    minutes), and the NTP client from the ntpq rows (``*`` marks the peer in use).

    OPNsense's API has no time zone setting and no NTP configuration (both are legacy pages),
    so the zone name stays empty and the configured servers are the peers ntpq lists.
    """
    clock = http_date(date_header)
    local = local_time(time.get("datetime"))
    offset = None
    if clock is not None and local is not None:
        minutes = (local - clock.replace(tzinfo=None)).total_seconds() / 60
        quarter = round(minutes / 15) * 15
        offset = quarter if abs(quarter) <= 1080 and abs(minutes - quarter) < 5 else None
    if clock is not None and offset is not None:
        clock = clock.astimezone(timezone(timedelta(minutes=offset)))
    half = (end - start) / 2
    client = None
    if ntp_rows is not None:
        rows = [r for r in ntp_rows if isinstance(r, dict) and str(r.get("server") or "").strip()]
        peer = next((r for r in rows if str(r.get("status")).strip() == "*"), None)
        stratum = _count(peer.get("stratum")) if peer else None
        servers: list[str] = []
        for r in rows:
            if (name := str(r["server"]).strip()) not in servers:
                servers.append(name)
        client = NtpClient(
            enabled=bool(rows),
            servers=servers,
            synchronised=peer is not None if rows else None,
            stratum=stratum if stratum is not None and stratum <= 16 else None,
            current_server=str(peer["server"]).strip() if peer else None,
        )
    return DeviceTime(
        clock=clock + timedelta(seconds=0.5) if clock else None,
        read_at=start + half if clock else None,
        uncertainty_seconds=half.total_seconds() + 0.5 if clock else None,
        utc_offset_minutes=offset,
        ntp_client=client,
    )
