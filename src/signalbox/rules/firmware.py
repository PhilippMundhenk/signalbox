"""Firmware hygiene: identical devices on different firmware, updates available, end of life."""

from __future__ import annotations

from collections.abc import Iterator

from signalbox.model import Network
from signalbox.rules import Result, Severity, found, rule


@rule(
    "firmware.drift",
    "Identical devices run different firmware",
    Severity.WARNING,
    "Devices of the same model behave the same only on the same firmware. Different versions "
    "make problems hard to reproduce and often mean one device missed an update.",
)
def drift(net: Network) -> Iterator[Result]:
    groups: dict[tuple[str, str, str], list[tuple[str, str]]] = {}
    for d in net.devices:
        if d.model and d.firmware and d.firmware.current:
            key = (d.site_id, (d.vendor or "").lower(), d.model.lower())
            groups.setdefault(key, []).append((d.id, d.firmware.current))
    for (_, _, model), devices in sorted(groups.items()):
        versions = sorted({v for _, v in devices})
        if len(versions) < 2:
            continue
        names = {d.id: d.name for d in net.devices}
        detail = "; ".join(f"{names[i]}: {v}" for i, v in sorted(devices))
        yield found(
            f"{len(devices)} devices of model {model} run {len(versions)} firmware versions "
            f"({detail})",
            [i for i, _ in devices],
            fix="Update all of them to the same (newest) version.",
            mid="firmware.drift",
            fix_id="firmware.drift.fix",
            params={
                "count": len(devices),
                "model": model,
                "versions": len(versions),
                "detail": detail,
            },
        )


@rule(
    "firmware.update-available",
    "Firmware update available",
    Severity.INFO,
    "The device reports a newer firmware than the one it runs. Updates often fix security "
    "problems; read the release notes and update in a maintenance window.",
)
def update_available(net: Network) -> Iterator[Result]:
    for d in net.devices:
        fw = d.firmware
        if fw and fw.available and fw.current and fw.available != fw.current:
            yield found(
                f"{d.name} runs {fw.current}, {fw.available} is available",
                [d.id],
                fix=f"Update {d.name} to {fw.available}.",
                mid="firmware.update",
                fix_id="firmware.update.fix",
                params={"name": d.name, "current": fw.current, "available": fw.available},
            )


@rule(
    "firmware.end-of-life",
    "Firmware no longer supported",
    Severity.WARNING,
    "The vendor no longer publishes updates for this firmware, so security problems stay open.",
)
def end_of_life(net: Network) -> Iterator[Result]:
    for d in net.devices:
        if d.firmware and d.firmware.end_of_life:
            yield found(
                f"{d.name} runs firmware {d.firmware.current or '?'}, which is end of life",
                [d.id],
                fix="Update to a supported release, or plan to replace the device.",
                mid="firmware.endOfLife",
                fix_id="firmware.endOfLife.fix",
                params={"name": d.name, "current": d.firmware.current or "?"},
            )


RULES = [drift, update_available, end_of_life]
