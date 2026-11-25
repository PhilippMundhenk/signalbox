"""Firmware hygiene: identical devices on different firmware, updates available, end of life."""

from __future__ import annotations

from collections.abc import Iterator

from signalbox.model import FirmwareChannel, Network
from signalbox.rules import Result, Severity, found, rule


@rule(
    "firmware.drift",
    "Identical devices run different firmware",
    Severity.WARNING,
    "Devices of the same model behave the same only on the same firmware. Different versions "
    "make problems hard to reproduce and often mean one device missed an update.",
)
def drift(net: Network) -> Iterator[Result]:
    groups: dict[tuple[str, str, str, str], list[tuple[str, str]]] = {}
    for d in net.devices:
        if d.model and d.firmware and d.firmware.current:
            # a device on a beta or development channel is not compared with stable ones (#181)
            channel = d.firmware.channel.value if d.firmware.channel else ""
            key = (d.site_id, (d.vendor or "").lower(), d.model.lower(), channel)
            groups.setdefault(key, []).append((d.id, d.firmware.current))
    for (_, _, model, _), devices in sorted(groups.items()):
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
        if fw and fw.security_update and (fw.available or fw.pending_security_updates):
            continue  # reported as firmware.security-update
        if fw and fw.pending_updates:
            yield found(
                f"{d.name} has {fw.pending_updates} package updates waiting",
                [d.id],
                fix=f"Install the pending updates of {d.name} in the next maintenance window.",
                mid="firmware.updatesPending",
                fix_id="firmware.updatesPending.fix",
                params={"name": d.name, "count": fw.pending_updates},
            )
        elif fw and fw.upgradable and not fw.available:
            yield found(
                f"{d.name} has a firmware update available",
                [d.id],
                fix=f"Update {d.name}.",
                mid="firmware.updateUnnamed",
                fix_id="firmware.updateUnnamed.fix",
                params={"name": d.name},
            )
        elif fw and fw.available and fw.current and fw.available != fw.current:
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


@rule(
    "firmware.security-update",
    "Security update available",
    Severity.WARNING,
    "The vendor marks the available firmware as a security update, so the running version has "
    "known problems that the update fixes. Read the release notes and update soon.",
)
def security_update(net: Network) -> Iterator[Result]:
    for d in net.devices:
        fw = d.firmware
        if fw and fw.security_update and not fw.available and fw.pending_security_updates:
            yield found(
                f"{d.name} has {fw.pending_security_updates} security updates waiting",
                [d.id],
                fix=f"Install the pending updates of {d.name} soon.",
                mid="firmware.securityUpdatesPending",
                fix_id="firmware.securityUpdatesPending.fix",
                params={"name": d.name, "count": fw.pending_security_updates},
            )
        elif fw and fw.security_update and fw.available:
            yield found(
                f"{d.name} has a security update available ({fw.available})",
                [d.id],
                fix=f"Update {d.name} to {fw.available} in the next maintenance window.",
                mid="firmware.securityUpdate",
                fix_id="firmware.securityUpdate.fix",
                params={"name": d.name, "available": fw.available},
            )


#: Channels that are not the vendor's stable or long-term release.
PRERELEASE = (
    FirmwareChannel.BETA,
    FirmwareChannel.RC,
    FirmwareChannel.TESTING,
    FirmwareChannel.DEVELOPMENT,
)


@rule(
    "firmware.beta-channel",
    "Device follows a test release channel",
    Severity.INFO,
    "The device runs, or is set to receive, a beta, release candidate, testing or development "
    "build. Those get new features first and fixes less tested; fine for a lab, not for the "
    "device the household depends on.",
)
def beta_channel(net: Network) -> Iterator[Result]:
    for d in net.devices:
        fw = d.firmware
        if fw and fw.channel in PRERELEASE:
            channel = fw.channel.value
            yield found(
                f"{d.name} follows the {channel} channel",
                [d.id],
                fix="Switch it to the stable or long-term channel unless you test on purpose.",
                mid="firmware.betaChannel",
                fix_id="firmware.betaChannel.fix",
                params={"name": d.name, "channel": channel},
            )


@rule(
    "firmware.auto-update-off",
    "Device does not install updates by itself",
    Severity.INFO,
    "The device says it does not install updates automatically (unattended-upgrades or "
    "dnf-automatic off, a FRITZ!Box or UniFi site set to update by hand). That is a choice, but "
    "then updates only happen when someone remembers; Signalbox lists them as they appear.",
)
def auto_update_off(net: Network) -> Iterator[Result]:
    for d in net.devices:
        if d.firmware and d.firmware.auto_update is False:
            yield found(
                f"{d.name} does not install updates by itself",
                [d.id],
                fix=f"Switch on automatic updates on {d.name} (at least the security updates), "
                "or update it by hand regularly.",
                mid="firmware.autoUpdateOff",
                fix_id="firmware.autoUpdateOff.fix",
                params={"name": d.name},
            )


@rule(
    "firmware.reboot-pending",
    "Restart needed to finish an update",
    Severity.INFO,
    "The device installed an update and runs the old code until it restarts (the file "
    "/var/run/reboot-required on Debian and Ubuntu, OPNsense's restart flag).",
)
def reboot_pending(net: Network) -> Iterator[Result]:
    for d in net.devices:
        if d.firmware and d.firmware.reboot_pending:
            yield found(
                f"{d.name} needs a restart to finish an update",
                [d.id],
                fix=f"Restart {d.name} in a maintenance window.",
                mid="firmware.rebootPending",
                fix_id="firmware.rebootPending.fix",
                params={"name": d.name},
            )


RULES = [
    drift,
    update_available,
    end_of_life,
    security_update,
    beta_channel,
    auto_update_off,
    reboot_pending,
]
