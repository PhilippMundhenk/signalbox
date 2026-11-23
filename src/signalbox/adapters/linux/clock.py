"""Clock, time zone and NTP of a Linux device (#240): ``date``, ``timedatectl show`` and
``show-timesync`` (systemd-timesyncd), ``chronyc -c tracking``/``sources`` and the chrony and
timesyncd configuration files."""

from __future__ import annotations

import contextlib
from datetime import UTC, datetime

from signalbox.adapters.linux.collect import Answer
from signalbox.model import DeviceTime, NtpClient, NtpServer


def _props(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in text.splitlines():
        key, sep, value = line.partition("=")
        if sep:
            out[key.strip()] = value.strip()
    return out


def clock(answer: Answer) -> datetime | None:
    text = answer.text("clock").strip()
    try:
        return datetime.fromtimestamp(float(text), UTC)
    except ValueError:
        return None


def timezone(answer: Answer) -> str | None:
    zone = _props(answer.text("timedatectl")).get("Timezone")
    if zone:
        return zone
    files = answer.files("timezone")
    if files.get("/etc/timezone", "").strip():
        return files["/etc/timezone"].strip()
    for line in answer.lines("timezone"):
        if "zoneinfo/" in line and not line.startswith("@@"):
            return line.split("zoneinfo/", 1)[1].strip() or None
    return None


def chrony_servers(answer: Answer) -> tuple[list[str], bool]:
    """``server``/``pool``/``peer`` lines; and whether an ``allow`` makes it serve time."""
    servers: list[str] = []
    serving = False
    for text in answer.files("chrony").values():
        for raw in text.splitlines():
            parts = raw.split("#", 1)[0].split()
            if not parts:
                continue
            if parts[0] in ("server", "pool", "peer") and len(parts) > 1:
                if parts[1] not in servers:
                    servers.append(parts[1])
            elif parts[0] == "allow":
                serving = True
    return servers, serving


def timesyncd_servers(answer: Answer) -> list[str]:
    values: list[str] = []
    for text in answer.files("timesyncd").values():
        for raw in text.splitlines():
            line = raw.strip()
            if line.startswith("NTP="):
                values = line[4:].split() or values
    return values


def ntp_client(answer: Answer, active: set[str]) -> NtpClient | None:
    tracking = answer.text("tracking").strip()
    if "chrony" in active or tracking:
        servers, _ = chrony_servers(answer)
        fields = tracking.split(",") if tracking else []
        synced: bool | None = None
        stratum: int | None = None
        current: str | None = None
        if len(fields) >= 14:
            synced = fields[13].strip() == "Normal" and fields[0] not in ("00000000", "7F7F0101")
            with contextlib.suppress(ValueError):
                stratum = int(fields[2])
            current = fields[1].strip() or None if synced else None
        for row in answer.lines("sources"):
            cols = row.split(",")
            if len(cols) > 2 and cols[1] == "*":
                current = cols[2]
        return NtpClient(
            enabled=bool(tracking) or "chrony" in active,
            servers=servers,
            synchronised=synced,
            stratum=stratum if stratum is not None and 0 <= stratum <= 16 else None,
            current_server=current,
        )
    show = _props(answer.text("timedatectl"))
    sync = _props(answer.text("timesync"))
    if "systemd-timesyncd" in active or show.get("NTP") == "yes":
        servers = timesyncd_servers(answer) or (
            sync.get("SystemNTPServers", "").split() or sync.get("FallbackNTPServers", "").split()
        )
        current = sync.get("ServerAddress") or sync.get("ServerName") or None
        state = show.get("NTPSynchronized")
        return NtpClient(
            enabled=show.get("NTP", "yes") == "yes",
            servers=servers,
            synchronised=state == "yes" if state else None,
            current_server=current,
        )
    if show:
        return NtpClient(enabled=False)
    return None


def ntp_server(answer: Answer, active: set[str]) -> NtpServer | None:
    if "chrony" not in active and not answer.text("tracking").strip():
        return None
    _, serving = chrony_servers(answer)
    return NtpServer(enabled=serving)


def device_time(answer: Answer, active: set[str]) -> DeviceTime:
    return DeviceTime(
        clock=clock(answer),
        timezone=timezone(answer),
        ntp_client=ntp_client(answer, active),
        ntp_server=ntp_server(answer, active),
    )
