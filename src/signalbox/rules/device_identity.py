"""Device identity rules (#444, follow-up to #427): the device's own name and its boot loader.

They read ``Device.hostname``, ``Device.bootloader`` and ``Device.bootloader_available``
(#177) and stay silent where the device does not say. Neither rule reads or reports a serial
number or a MAC address: those stay on the device page unless ``exports.identity`` is on (#439).
Duplicate devices (#118) and unknown neighbours (#113) are separate rules that use the same
identity fields.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from ipaddress import ip_address

from signalbox.model import Device, Network
from signalbox.rules import Result, RuleParams, Severity, ctx, found, param, rule


class NameMismatchParams(RuleParams):
    strip_domain: float = param(
        1,
        unit="count",
        ge=0,
        le=1,
        description="1: compare only the part before the first dot (nas and nas.example.lan "
        "are the same name); 0: compare the full names.",
    )


def _is_address(text: str) -> bool:
    try:
        ip_address(text.strip("[]"))
    except ValueError:
        return False
    return True


def _normal(name: str, strip_domain: bool) -> str:
    text = name.strip().rstrip(".").lower()
    if strip_domain and not _is_address(text):
        text = text.split(".", 1)[0]
    return text


@rule(
    "device.name-mismatch",
    "Configured name differs from the name the device reports",
    Severity.INFO,
    "The name in Signalbox and the name the device calls itself (its hostname) differ. "
    "Logs, DHCP entries, DNS records and the vendor's own tools show the device's name, so a "
    "different name here makes findings hard to match to what you see elsewhere. Case and a "
    "domain suffix are ignored (parameter strip_domain). Devices that run on another device "
    "(they report the host's name) and devices named by their address are not compared.",
    params=NameMismatchParams,
)
def name_mismatch(net: Network) -> Iterator[Result]:
    for dev in net.devices:
        if not dev.hostname or not dev.hostname.strip() or dev.hosted_on:
            continue
        if _is_address(dev.name.strip()) or _is_address(dev.hostname.strip()):
            continue
        strip = bool(ctx.params(NameMismatchParams, dev).strip_domain)
        if _normal(dev.name, strip) == _normal(dev.hostname, strip):
            continue
        yield found(
            f"{dev.name} calls itself {dev.hostname.strip()}",
            [dev.id],
            fix="Rename it in Signalbox, or on the device, so that both use the same name. "
            "Ignore this if the difference is on purpose.",
            mid="device.nameMismatch",
            fix_id="device.nameMismatch.fix",
            params={"name": dev.name, "hostname": dev.hostname.strip()},
        )


def _numbers(version: str) -> tuple[int, ...] | None:
    parts = re.findall(r"\d+", version)
    return tuple(int(p) for p in parts) if parts else None


def _outdated(dev: Device) -> bool:
    """The boot loader is older than the one the installed firmware carries."""
    have, new = dev.bootloader, dev.bootloader_available
    if not have or not new or have.strip() == new.strip():
        return False
    a, b = _numbers(have), _numbers(new)
    if a is None or b is None:
        return True  # different and not comparable: report it, the text names both
    return a < b


@rule(
    "device.bootloader-outdated",
    "Boot loader older than the firmware carries",
    Severity.INFO,
    "Some devices update their boot loader separately from the firmware: after a firmware "
    "update the new boot loader sits in the firmware package but is only written when you "
    "ask for it. RouterOS (RouterBOOT) reports both versions; others are checked once they "
    "report the version their firmware carries. Boot loader updates fix hardware problems and "
    "are needed by some new features; read the release notes first.",
)
def bootloader_outdated(net: Network) -> Iterator[Result]:
    for dev in net.devices:
        if _outdated(dev):
            current = (dev.bootloader or "").strip()
            available = (dev.bootloader_available or "").strip()
            yield found(
                f"{dev.name} runs boot loader {current}, {available} is available",
                [dev.id],
                fix=f"Upgrade the boot loader of {dev.name} to {available} in a maintenance "
                "window (RouterOS: System > RouterBOARD > Upgrade, then restart).",
                mid="device.bootloaderOutdated",
                fix_id="device.bootloaderOutdated.fix",
                params={"name": dev.name, "current": current, "available": available},
            )


RULES = [name_mismatch, bootloader_outdated]
