"""CAPsMAN (#475): the access points a RouterOS controller manages, as devices.

Versions: RouterOS 7 (``wifi`` package, 7.13 and newer, and ``wifiwave2`` from 7.6) lists them in
``/interface/wifi/capsman/remote-cap``; RouterOS 6 and 7 with the ``wireless`` package use
``/caps-man/remote-cap``. Both are read with the policy ``read``. A controller of either kind
does not say how a CAP reaches it (cable or radio): the managed devices get no uplink.
*(Guess, #21: the column names below are from the RouterOS manual, not tried on a device.)*
"""

from __future__ import annotations

from ipaddress import ip_address
from typing import Any

from signalbox.model import (
    Device,
    DeviceRole,
    Firmware,
    MeshMembership,
    MeshRole,
    normalise_mac,
    object_id,
)

REMOTE_CAP_V7 = "/rest/interface/wifi/capsman/remote-cap"
REMOTE_CAP_LEGACY = "/rest/caps-man/remote-cap"

#: columns that hold the CAP's own MAC address, in the order they are tried
_MAC_KEYS = ("base-mac", "mac-address", "board-mac")


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _mac(row: dict[str, Any]) -> str | None:
    for key in _MAC_KEYS:
        try:
            return normalise_mac(_text(row.get(key)))
        except ValueError:
            continue
    return None


def _address(value: Any) -> str | None:
    """``192.0.2.9``, ``192.0.2.9/5246`` or ``192.0.2.9:5246`` -> the address."""
    text = _text(value)
    for candidate in (text, text.split("/")[0], text.rsplit(":", 1)[0]):
        try:
            return str(ip_address(candidate))
        except ValueError:
            continue
    return None


def _version(value: Any) -> str | None:
    """``7.15.1 (stable)`` -> ``7.15.1``."""
    parts = _text(value).split()
    return parts[0] if parts else None


def cap_devices(
    rows: list[dict[str, Any]], *, controller_id: str, site_id: str, adapter_id: str
) -> list[Device]:
    """One device per CAP the controller lists (``remote-cap``); a row with neither a MAC
    address nor an identity is skipped."""
    out: dict[str, Device] = {}
    for row in rows:
        mac = _mac(row)
        identity = _text(row.get("identity")) or _text(row.get("name"))
        key = mac or identity
        if not key:
            continue
        device_id = object_id(controller_id, "cap", key)
        model = _text(row.get("model")) or _text(row.get("board"))
        version = _version(row.get("version"))
        state = _text(row.get("state"))
        out.setdefault(
            device_id,
            Device(
                id=device_id,
                site_id=site_id,
                name=identity or key,
                role=DeviceRole.AP,
                vendor="MikroTik",
                model=model or None,
                firmware=Firmware(current=version) if version else None,
                management_address=_address(row.get("address")),
                mac=mac,
                serial=_text(row.get("serial")) or None,
                os="RouterOS",
                os_version=version,
                adapter=adapter_id,
                vendor_extra={"capsman_state": state} if state else {},
            ),
        )
    return list(out.values())


def controller_membership() -> MeshMembership:
    return MeshMembership(role=MeshRole.CONTROLLER, hop=0)


def cap_membership(controller_id: str) -> MeshMembership:
    return MeshMembership(role=MeshRole.AGENT, controller_id=controller_id)
