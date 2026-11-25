"""Device health rules (checks #130, #131 and the health checks of #178).

They read :class:`~signalbox.model.DeviceHealth` and stay silent for devices that do not report
a value. Thresholds are fixed for now (rule parameters are issue #187); they are all here.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import datetime, timedelta

from signalbox.model import Device, DeviceHealth, Network, RebootReason, StorageKind
from signalbox.rules import Result, Rule, Severity, found, history_rule, rule
from signalbox.sightings import CPU_HIGH_PCT, History, parse_boot

#: Memory in use (programs, not page cache) from which a device is reported, in percent.
MEMORY_PCT = 90.0
#: Sustained CPU load: ``CPU_HIGH_PCT`` (90 %) in two consecutive observations.
CPU_PCT = CPU_HIGH_PCT
#: Temperature for sensors without a limit of their own, in °C.
TEMPERATURE_C = 85.0
#: Storage (system or data) fill level from which it is reported; an error from the second.
STORAGE_PCT = 90.0
STORAGE_ERROR_PCT = 98.0
#: A UPS whose remaining runtime is below this cannot carry the network through a clean
#: shutdown or a short outage.
UPS_RUNTIME = timedelta(minutes=10)
#: A UPS without a self-test for longer than this may have a dead battery nobody noticed.
UPS_TEST_AGE = timedelta(days=180)
#: Uptime from which a device is reported: it has not been updated for that long either.
UPTIME_LONG = timedelta(days=365)
#: Reboots in this period are reported; more than ``REBOOT_COUNT - 1`` of them is a warning.
REBOOT_PERIOD = timedelta(hours=24)
REBOOT_COUNT = 3
#: A boot time that moved by less than this is the same boot (rounding of a derived value).
REBOOT_MIN_SHIFT = timedelta(minutes=3)
#: Reasons of planned restarts: not reported.
PLANNED_REBOOTS = frozenset({RebootReason.UPGRADE.value, RebootReason.USER.value})


def _healthy(net: Network) -> Iterator[tuple[Device, DeviceHealth]]:
    for dev in net.devices:
        if dev.health is not None:
            yield dev, dev.health


def _pct(value: float) -> str:
    return f"{value:.0f} %"


def _span(delta: timedelta) -> str:
    minutes = int(delta.total_seconds() // 60)
    if minutes < 120:
        return f"{minutes} min"
    if minutes < 48 * 60:
        return f"{minutes // 60} h"
    return f"{minutes // (24 * 60)} d"


def _when(at: datetime) -> str:
    return f"{at:%Y-%m-%d %H:%M} UTC"


@history_rule(
    "device.resources",
    "Device memory, CPU or temperature above its limit",
    Severity.WARNING,
    "Low memory on small access points and routers causes random reboots and dropped clients; "
    "a CPU that is busy all the time makes the device slow to forward, answer DNS or roam "
    "clients; an overheating switch in a cupboard fails in summer. Memory counts what programs "
    "use (not the page cache); CPU load is reported only when it was high in two consecutive "
    "observations; temperatures are compared with the sensor's own limit, or a generic one.",
)
def resources(net: Network, history: History) -> Iterator[Result]:
    for dev, h in _healthy(net):
        mem = h.memory_used_pct()
        if mem is not None and mem >= MEMORY_PCT:
            yield found(
                f"{dev.name} has {_pct(mem)} of its memory in use",
                [dev.id],
                fix="Restart it, remove unused packages or features, or check for a memory leak "
                "in its firmware (an update may fix it).",
                key="memory",
                mid="health.memory",
                fix_id="health.memory.fix",
                params={"name": dev.name, "percent": _pct(mem)},
            )
        cpu = history.cpu.get(dev.id)
        if (
            h.cpu_load_pct is not None
            and h.cpu_load_pct >= CPU_PCT
            and cpu is not None
            and cpu.value == "high"
            and cpu.since < cpu.last_seen
        ):
            yield found(
                f"{dev.name} has a CPU load of {_pct(h.cpu_load_pct)}, high since "
                f"{_when(cpu.since)}",
                [dev.id],
                fix="Look for what keeps it busy (traffic inspection, a VPN, logging, a "
                "process that hangs); a device that is too small for the connection may need "
                "hardware offloading or a replacement.",
                key="cpu",
                mid="health.cpu",
                fix_id="health.cpu.fix",
                params={
                    "name": dev.name,
                    "percent": _pct(h.cpu_load_pct),
                    "since": _when(cpu.since),
                },
            )
        for sensor in h.temperatures:
            limit = sensor.limit_c if sensor.limit_c is not None else TEMPERATURE_C
            if sensor.value_c >= limit:
                own = "its limit" if sensor.limit_c is not None else "the generic limit"
                yield found(
                    f"{dev.name} sensor {sensor.name} is at {sensor.value_c:.0f} °C, above "
                    f"{own} of {limit:.0f} °C",
                    [dev.id],
                    fix="Give it more air (not in a closed cupboard, not stacked on other "
                    "devices), clean its vents and check its fans.",
                    key=f"temperature:{sensor.name}",
                    mid="health.temperatureOwn"
                    if sensor.limit_c is not None
                    else "health.temperature",
                    fix_id="health.temperature.fix",
                    params={
                        "name": dev.name,
                        "sensor": sensor.name,
                        "value": f"{sensor.value_c:.0f}",
                        "limit": f"{limit:.0f}",
                    },
                )


@rule(
    "health.storage-full",
    "Device storage nearly full",
    Severity.WARNING,
    "A full system storage (OpenWrt overlay, flash, root file system) means settings can no "
    "longer be saved and firmware or package updates fail; a full data disk stops logging. "
    "RAM-backed storage (tmpfs) is not counted: it is memory.",
)
def storage_full(net: Network) -> Iterator[Result]:
    for dev, h in _healthy(net):
        for st in h.storage:
            if st.kind not in (StorageKind.SYSTEM, StorageKind.DATA):
                continue
            used = st.used_pct()
            if used is None or used < STORAGE_PCT:
                continue
            what = "system storage" if st.kind is StorageKind.SYSTEM else "storage"
            yield found(
                f"{dev.name} {what} {st.name} is {_pct(used)} full",
                [dev.id],
                fix="Remove unused packages, old logs or firmware images, or move logs to "
                "another disk. Settings and updates fail when it is full.",
                severity=Severity.ERROR if used >= STORAGE_ERROR_PCT else None,
                key=st.name,
                mid="health.systemStorage" if st.kind is StorageKind.SYSTEM else "health.storage",
                fix_id="health.storage.fix",
                params={"name": dev.name, "storage": st.name, "percent": _pct(used)},
            )


@rule(
    "health.fan-failed",
    "Fan failed",
    Severity.WARNING,
    "A device with a failed fan overheats and restarts or slows down, usually on the first hot "
    "day. Reported where the device itself says the fan is not working; a fan standing still "
    "without such a verdict may be off on purpose (quiet mode).",
)
def fan_failed(net: Network) -> Iterator[Result]:
    for dev, h in _healthy(net):
        for fan in h.fans:
            if fan.ok is False:
                rpm = f" ({fan.rpm} rpm)" if fan.rpm is not None else ""
                yield found(
                    f"{dev.name} reports fan {fan.name} as failed{rpm}",
                    [dev.id],
                    fix="Clean or replace the fan; until then, keep the device cool.",
                    key=fan.name,
                    mid="health.fanRpm" if fan.rpm is not None else "health.fan",
                    fix_id="health.fan.fix",
                    params={"name": dev.name, "fan": fan.name, "rpm": fan.rpm},
                )


@rule(
    "health.psu-failed",
    "Power supply failed",
    Severity.WARNING,
    "A device with redundant power supplies keeps running when one fails, so nobody notices "
    "until the second one fails too. Reported where the device says a power supply is not ok "
    "(no input power or broken).",
)
def psu_failed(net: Network) -> Iterator[Result]:
    for dev, h in _healthy(net):
        for psu in h.power_supplies:
            if psu.ok is False:
                yield found(
                    f"{dev.name} reports power supply {psu.name} as failed",
                    [dev.id],
                    fix="Check its power cable and the outlet or UPS it is plugged into; replace "
                    "the power supply if it has power.",
                    key=psu.name,
                    mid="health.psu",
                    fix_id="health.psu.fix",
                    params={"name": dev.name, "psu": psu.name},
                )


@rule(
    "health.ups-on-battery",
    "UPS running on battery",
    Severity.WARNING,
    "A UPS on battery means the mains power is gone (or its input is not connected): the "
    "network stops when the battery is empty.",
)
def ups_on_battery(net: Network) -> Iterator[Result]:
    for dev, h in _healthy(net):
        for ups in h.ups:
            if ups.on_battery:
                charge = f", {_pct(ups.charge_pct)} charged" if ups.charge_pct is not None else ""
                yield found(
                    f"UPS {ups.name} (on {dev.name}) runs on battery{charge}",
                    [dev.id],
                    fix="Check the mains power and the UPS input cable; shut down devices that "
                    "are not needed to make the battery last.",
                    key=ups.name,
                    mid="health.upsBatteryCharge" if charge else "health.upsBattery",
                    fix_id="health.upsBattery.fix",
                    params={
                        "ups": ups.name,
                        "name": dev.name,
                        "charge": _pct(ups.charge_pct) if ups.charge_pct is not None else "",
                    },
                )


@rule(
    "health.ups-runtime-low",
    "UPS runtime too short",
    Severity.WARNING,
    "A UPS whose battery lasts only a few minutes at the present load cannot carry the network "
    "through a short power cut or give servers time for a clean shutdown. Usually the battery "
    "is old, or the UPS carries more load than it was meant for.",
)
def ups_runtime_low(net: Network) -> Iterator[Result]:
    limit = int(UPS_RUNTIME.total_seconds())
    for dev, h in _healthy(net):
        for ups in h.ups:
            if ups.runtime_seconds is None or ups.runtime_seconds >= limit:
                continue
            load = f" at {_pct(ups.load_pct)} load" if ups.load_pct is not None else ""
            yield found(
                f"UPS {ups.name} (on {dev.name}) has a runtime of {ups.runtime_seconds // 60} "
                f"minutes{load}, less than {limit // 60} minutes",
                [dev.id],
                fix="Replace the battery (they last 3 to 5 years) or move devices that do not "
                "need it to another outlet.",
                key=ups.name,
                mid="health.upsRuntimeLoad" if load else "health.upsRuntime",
                fix_id="health.upsRuntime.fix",
                params={
                    "ups": ups.name,
                    "name": dev.name,
                    "minutes": ups.runtime_seconds // 60,
                    "limit": limit // 60,
                    "load": _pct(ups.load_pct) if ups.load_pct is not None else "",
                },
            )


@history_rule(
    "health.ups-not-tested",
    "UPS not tested for a long time",
    Severity.INFO,
    "A UPS battery ages without anyone noticing; a self-test finds a dead battery before the "
    "next power cut does. Reported when the last self-test the UPS reports is more than 180 "
    "days ago; silent when it reports none.",
)
def ups_not_tested(net: Network, history: History) -> Iterator[Result]:
    if history.now is None:
        return
    for dev, h in _healthy(net):
        for ups in h.ups:
            if ups.last_test is None or history.now - ups.last_test < UPS_TEST_AGE:
                continue
            age = _span(history.now - ups.last_test)
            yield found(
                f"UPS {ups.name} (on {dev.name}) was last tested {age} ago",
                [dev.id],
                fix="Run a self-test (and schedule one, for example every three months).",
                key=ups.name,
                mid="health.upsNotTested",
                fix_id="health.upsNotTested.fix",
                params={"ups": ups.name, "name": dev.name, "age": age},
            )


@rule(
    "health.uptime-very-long",
    "Device not restarted for over a year",
    Severity.INFO,
    "A device that has not restarted for more than a year has not had a firmware update in that "
    "time either (updates restart it), and some problems only show at the next restart, for "
    "example settings that were never saved.",
)
def uptime_very_long(net: Network) -> Iterator[Result]:
    limit = UPTIME_LONG.total_seconds()
    for dev, h in _healthy(net):
        if h.uptime_seconds is not None and h.uptime_seconds >= limit:
            yield found(
                f"{dev.name} has been running for {h.uptime_seconds // 86400} days without a "
                "restart",
                [dev.id],
                fix="Check for a firmware update and install it in a quiet hour (it restarts "
                "the device); this also shows whether the device comes back up by itself.",
                mid="health.uptime",
                fix_id="health.uptime.fix",
                params={"name": dev.name, "days": int(h.uptime_seconds // 86400)},
            )


def _reboots(history: History, device_id: str, since: datetime) -> list[tuple[datetime, str]]:
    """Reboots (boot time, reason) seen since ``since``; boot time shifts by rounding ignored."""
    past = history.boots.get(device_id)
    out: list[tuple[datetime, str]] = []
    for change in past.changes if past else []:
        if change.at < since:
            continue
        old, _ = parse_boot(change.old)
        new, reason = parse_boot(change.new)
        if new - old < REBOOT_MIN_SHIFT:
            continue
        out.append((new, reason or ""))
    return out


@history_rule(
    "device.reboot",
    "Device restarted unexpectedly",
    Severity.INFO,
    "Unplanned restarts are a symptom of power problems (PoE budget, failing power supply), "
    "overheating, memory exhaustion or firmware crashes. A restart is seen when the device's "
    "boot time (from its uptime) moves between two observations. Restarts the device reports "
    "as a firmware update or as started by a user are not counted. Info for a restart in the "
    "last 24 hours, warning for three or more.",
)
def reboot(net: Network, history: History) -> Iterator[Result]:
    if history.now is None:
        return
    since = history.now - REBOOT_PERIOD
    for dev in net.devices:
        unplanned = [
            (at, reason)
            for at, reason in _reboots(history, dev.id, since)
            if reason not in PLANNED_REBOOTS
        ]
        if not unplanned:
            continue
        at, reason = unplanned[-1]
        why = f" (reason: {reason})" if reason else ""
        if len(unplanned) >= REBOOT_COUNT:
            yield found(
                f"{dev.name} restarted {len(unplanned)} times in the last 24 hours, last at "
                f"{_when(at)}{why}",
                [dev.id],
                fix="Check its power supply or PoE budget, its temperature and its memory use; "
                "look for a firmware update if it crashes.",
                severity=Severity.WARNING,
                mid="health.rebootsReason" if reason else "health.reboots",
                fix_id="health.reboots.fix",
                params={
                    "name": dev.name,
                    "count": len(unplanned),
                    "when": _when(at),
                    "reason": reason,
                },
            )
        else:
            yield found(
                f"{dev.name} restarted at {_when(at)}{why}",
                [dev.id],
                fix="If nobody restarted it, check its power supply or PoE budget and its "
                "temperature.",
                mid="health.rebootReason" if reason else "health.reboot",
                fix_id="health.reboot.fix",
                params={"name": dev.name, "when": _when(at), "reason": reason},
            )


#: A replacement is reported for this long after it was seen.
REPLACED_PERIOD = timedelta(days=7)


def _tail(value: str) -> str:
    """The last four characters: enough to tell two values apart, without the identifier
    itself (findings reach notifications and exporters, the serial number does not, #427)."""
    return "\u2026" + value[-4:]


@history_rule(
    "device.replaced",
    "Device was replaced",
    Severity.INFO,
    "A device that reports another serial number or base MAC address than at the read before "
    "is other hardware behind the same entry: it was replaced (or swapped with a spare). "
    "Everything Signalbox knows from the old device, its history, firmware and expectations, "
    "no longer applies. Reported for a week after the change; only the end of each value is "
    "shown, as serial numbers identify the hardware.",
)
def replaced(net: Network, history: History) -> Iterator[Result]:
    if history.now is None:
        return
    since = history.now - REPLACED_PERIOD
    for dev in net.devices:
        for source, what_id, label in (
            (history.serials, "history.replacedSerial", "serial number"),
            (history.base_macs, "history.replacedMac", "base MAC address"),
        ):
            past = source.get(dev.id)
            changes = [c for c in past.changes if c.at >= since] if past else []
            if not changes:
                continue
            first, last = changes[0], changes[-1]
            yield found(
                f"{dev.name} reports another {label} than before ({_tail(first.old)} -> "
                f"{_tail(last.new)}): it was replaced",
                [dev.id],
                fix="If you replaced the device, nothing to do; otherwise check who swapped it. "
                "Acknowledge this finding once you have seen it.",
                key=what_id,
                mid=what_id,
                fix_id="history.replaced.fix",
                params={"name": dev.name, "old": _tail(first.old), "new": _tail(last.new)},
            )


RULES: list[Rule] = [
    resources,
    storage_full,
    fan_failed,
    psu_failed,
    ups_on_battery,
    ups_runtime_low,
    ups_not_tested,
    uptime_very_long,
    reboot,
    replaced,
]
