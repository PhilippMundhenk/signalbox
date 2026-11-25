"""CAPsMAN (#475): the access points a RouterOS controller manages, as devices.

Versions: RouterOS 7 (``wifi`` package, 7.13 and newer, and ``wifiwave2`` from 7.6) lists them in
``/interface/wifi/capsman/remote-cap``; RouterOS 6 and 7 with the ``wireless`` package use
``/caps-man/remote-cap``. Both are read with the policy ``read``. A controller of either kind
does not say how a CAP reaches it: the segment is the one its address lies in, the port and
the kind of uplink (cable or radio) come from where the controller's bridge table and ARP table
see the CAP (#481). The radios and SSIDs of the CAPs (interfaces of ``/caps-man/interface``, or
the CAP-managed rows of ``/interface/wifi``) and their clients (the controller's registration
table) belong to the CAP device.
*(Guess, #21: the column names below are from the RouterOS manual, not tried on a device.)*
"""

from __future__ import annotations

import re
from ipaddress import ip_address
from typing import Any

from signalbox.model import (
    Device,
    DeviceRole,
    Firmware,
    MeshMembership,
    MeshRole,
    MeshUplink,
    normalise_mac,
    object_id,
)

REMOTE_CAP_V7 = "/rest/interface/wifi/capsman/remote-cap"
REMOTE_CAP_LEGACY = "/rest/caps-man/remote-cap"
#: the interfaces CAPsMAN provisioned on the CAPs, the radios they run on and the clients
#: they carry (RouterOS 6 and 7 ``wireless`` package; ``wifi`` lists them in its own menus)
CAP_INTERFACE_LEGACY = "/rest/caps-man/interface"
CAP_RADIO_LEGACY = "/rest/caps-man/radio"
CAP_REGISTRATION_LEGACY = "/rest/caps-man/registration-table"
CAP_RADIO_V7 = "/rest/interface/wifi/radio"

#: columns of a radio or interface row that name the CAP it belongs to *(guess, #21)*
_OWNER_IDENTITY = ("remote-cap-identity", "remote-cap-name", "remote-cap")
_OWNER_MAC = ("remote-cap-mac", "remote-cap-base-mac")
_OWNER_ADDRESS = ("remote-cap-address",)

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


def cap_id(row: dict[str, Any], controller_id: str) -> str | None:
    """Device id of the CAP a ``remote-cap`` row describes; None: it names no CAP."""
    key = _mac(row) or _text(row.get("identity")) or _text(row.get("name"))
    return object_id(controller_id, "cap", key) if key else None


def current_channel(row: dict[str, Any]) -> tuple[int, int | None] | None:
    """``current-channel`` of a CAPsMAN interface (``5180/20-eeCe/ac``) -> (MHz, width)."""
    match = re.match(r"\s*(\d{4})(?:/(\d+))?", _text(row.get("current-channel")))
    if match is None:
        return None
    return int(match[1]), int(match[2]) if match[2] else None


def cap_devices(
    rows: list[dict[str, Any]], *, controller_id: str, site_id: str, adapter_id: str
) -> list[Device]:
    """One device per CAP the controller lists (``remote-cap``); a row with neither a MAC
    address nor an identity is skipped."""
    out: dict[str, Device] = {}
    for row in rows:
        mac = _mac(row)
        identity = _text(row.get("identity")) or _text(row.get("name"))
        device_id = cap_id(row, controller_id)
        if device_id is None:
            continue
        key = mac or identity
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


def _owner(row: dict[str, Any], caps: list[Device]) -> str | None:
    """The CAP a ``radio`` or ``interface`` row says it runs on (identity, MAC or address)."""
    by_name = {c.name.lower(): c.id for c in caps}
    by_mac = {c.mac: c.id for c in caps if c.mac}
    by_address = {c.management_address: c.id for c in caps if c.management_address}
    for key in _OWNER_IDENTITY:
        if (found := by_name.get(_text(row.get(key)).lower())) is not None:
            return found
    for key in _OWNER_MAC:
        try:
            if (found := by_mac.get(normalise_mac(_text(row.get(key))))) is not None:
                return found
        except ValueError:
            continue
    for key in _OWNER_ADDRESS:
        if (found := by_address.get(_address(row.get(key)) or "")) is not None:
            return found
    return None


def interface_owners(
    caps: list[Device],
    radios: list[dict[str, Any]],
    interfaces: list[dict[str, Any]],
) -> dict[str, str]:
    """Interface name -> id of the CAP it runs on. A ``radio`` row names its CAP and its
    ``interface`` and ``radio-mac``; an interface row is the CAP's when its own columns name
    the CAP or its ``radio-mac`` is that of a radio row of the CAP. Interfaces nobody claims
    stay with the controller."""
    out: dict[str, str] = {}
    by_radio_mac: dict[str, str] = {}
    for row in radios:
        cap = _owner(row, caps)
        if cap is None:
            continue
        if name := _text(row.get("interface")):
            out[name] = cap
        if radio_mac := _text(row.get("radio-mac")).lower():
            by_radio_mac[radio_mac] = cap
    for row in interfaces:
        name = _text(row.get("name"))
        cap = _owner(row, caps) or by_radio_mac.get(_text(row.get("radio-mac")).lower())
        if name and cap:
            out[name] = cap
    return out


def _cap_mac(value: Any) -> str | None:
    try:
        return normalise_mac(_text(value))
    except ValueError:
        return None


def uplink_of(
    cap: Device,
    *,
    arp: list[dict[str, Any]],
    hosts: list[dict[str, Any]],
    wireless_ports: set[str],
    segment_of_interface: dict[str, str],
    segment_of_address: Any,
    cap_address_text: str,
) -> tuple[dict[str, str], MeshMembership]:
    """How the controller sees a CAP (#481): ``vendor_extra`` (``capsman_segment``: the
    segment its address lies in or the interface it answers ARP on, ``capsman_port``: the
    interface of the controller's bridge table it sits behind, ``capsman_path``: ``layer2``
    when the controller answers ARP for the CAP or holds its address in an own network,
    ``layer3`` when it does not: a router lies between) and the mesh membership with the
    uplink kind (cable, or radio when the port is a Wi-Fi interface).
    Nothing is claimed that the tables do not show. ``cap_address_text`` is the raw
    ``address`` column: an L2 CAPsMAN lists the CAP's MAC address there."""
    macs: list[str] = []
    interface = ""
    if cap.management_address:
        for row in arp:
            if _text(row.get("address")) == cap.management_address:
                if mac := _cap_mac(row.get("mac-address")):
                    macs.append(mac)
                interface = _text(row.get("interface"))
                break
    macs.extend(m for m in (_cap_mac(cap_address_text), cap.mac) if m and m not in macs)
    extra: dict[str, str] = {}
    segment = (
        segment_of_address(cap.management_address) if cap.management_address else None
    ) or segment_of_interface.get(interface)
    if segment:
        extra["capsman_segment"] = segment
    port = ""
    for mac in macs:
        for row in hosts:
            if _cap_mac(row.get("mac-address")) == mac and _text(row.get("local")) != "true":
                port = _text(row.get("on-interface")) or _text(row.get("interface"))
                break
        if port:
            break
    if port:
        extra["capsman_port"] = port
    if cap.management_address is None and _cap_mac(cap_address_text):
        extra["capsman_path"] = "layer2"
    elif cap.management_address:
        local = bool(interface) or segment_of_address(cap.management_address) is not None
        extra["capsman_path"] = "layer2" if local else "layer3"
    uplink = None
    if port:
        uplink = MeshUplink.WIRELESS if port in wireless_ports else MeshUplink.WIRED
    return extra, MeshMembership(role=MeshRole.AGENT, hop=1, uplink=uplink)
