"""Switchyard's driver dictionaries → the Signalbox model. Pure functions, no I/O.

Both Switchyard drivers (NSDP and Easy Smart) return the same shapes:

- ``read_info``: ``mac``, ``model``, ``name``, ``ip``, ``firmware``, ... (see ``_INFO_EXTRA``)
- ``read_ports``: one row per port: ``port``, ``up``, ``speed_mbps``, ``duplex``, ``link``
- ``read_vlan``: ``mode`` (``disabled``, ``port_basic``, ``port_advanced``, ``dot1q_basic``,
  ``dot1q_advanced``), ``dot1q`` (``id``, ``members``, ``tagged``, ``name``), ``pvid``
  (port → VLAN) and ``port_vlans`` (``id``, ``members``); ``None`` when the switch has no
  VLAN settings
- ``read_lag``: ``lags`` (``id``, ``enabled``, ``members``) or ``None``

How VLANs are mapped (docs/adapters/plusswitch.md):

- 802.1Q mode: one segment per VLAN; tagged members are tagged, the other members untagged.
  VLAN 1 is the default VLAN and becomes the site's native segment. The PVID of a port is
  kept in its ``vendor_extra`` (the model has no ingress VLAN).
- No VLANs, or port-based VLANs: every port is an untagged member of the native segment.
  Port-based VLANs never tag a frame; they only restrict forwarding inside the switch, so
  the groups are listed per port in ``vendor_extra["port_groups"]`` instead of being made
  into segments that would look like VLANs on the wire to the other devices.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from pydantic import JsonValue

from signalbox.adapters import AdapterError, Observation, SystemInfo
from signalbox.model import (
    Firmware,
    Membership,
    Port,
    PortKind,
    PortMembership,
    Segment,
    normalise_mac,
    port_id,
    segment_id,
)

#: identity fields that go to the device's advanced tab when the switch reports them
_INFO_EXTRA = (
    "name",
    "ip",
    "netmask",
    "gateway",
    "dhcp",
    "serial",
    "hardware",
    "firmware2",
    "ports",
    "password_mode",
    "protocol_generation",
)


def _json(value: Any) -> JsonValue | None:
    if isinstance(value, bool | int | float | str):
        return value
    return None


def _number(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _ports(values: Any, known: set[int]) -> list[int]:
    """Port numbers of a member list, only those the switch has."""
    if not isinstance(values, Iterable) or isinstance(values, str | bytes):
        return []
    return sorted({p for p in values if _number(p) in known})


def system_info(info: Mapping[str, Any], vendor: str, address: str) -> SystemInfo:
    if not isinstance(info, Mapping):
        raise AdapterError("unexpected answer to the identity read")
    extra: dict[str, JsonValue] = {}
    try:
        extra["mac"] = normalise_mac(str(info.get("mac")))
    except ValueError:
        raise AdapterError("the switch reported no valid MAC address") from None
    for key in _INFO_EXTRA:
        value = _json(info.get(key))
        if value is not None and value != "":
            extra[key] = value
    firmware = info.get("firmware")
    return SystemInfo(
        vendor=vendor,
        model=str(info["model"]) if info.get("model") else None,
        firmware=Firmware(current=str(firmware)) if firmware else None,
        management_address=address,
        vendor_extra=extra,
    )


def interfaces(
    device_id: str,
    site_id: str,
    ports: list[dict[str, Any]],
    vlan: Mapping[str, Any] | None,
    lag: Mapping[str, Any] | None,
) -> Observation:
    """Ports and segments of one switch."""
    rows = {
        n: row
        for row in ports
        if isinstance(row, Mapping) and (n := _number(row.get("port"))) is not None and n > 0
    }
    known = set(rows)
    lag_of: dict[int, str] = {}
    for group in (lag or {}).get("lags") or []:
        if isinstance(group, Mapping) and group.get("enabled"):
            for p in _ports(group.get("members"), known):
                lag_of.setdefault(p, f"lag{group.get('id')}")

    mode = str(vlan.get("mode", "disabled")) if vlan else None
    extra: dict[int, dict[str, JsonValue]] = {n: {} for n in rows}
    segments: list[Segment] = []
    native = segment_id(site_id, None)

    def pid(n: int) -> str:
        return port_id(device_id, str(n))

    if vlan is not None and mode is not None and mode.startswith("dot1q"):
        pvids = vlan.get("pvid") or {}
        for n in rows:
            pvid = _number(pvids.get(n)) if isinstance(pvids, Mapping) else None
            if pvid is not None:
                extra[n]["pvid"] = pvid
        seen: set[int] = set()
        for entry in vlan.get("dot1q") or []:
            vid = _number(entry.get("id")) if isinstance(entry, Mapping) else None
            if vid is None or not 1 <= vid <= 4094 or vid in seen:
                continue
            seen.add(vid)
            tagged = set(_ports(entry.get("tagged"), known))
            members = sorted(set(_ports(entry.get("members"), known)) | tagged)
            name = entry.get("name")
            segments.append(
                Segment(
                    id=segment_id(site_id, vid),
                    site_id=site_id,
                    vlan=vid,
                    name=str(name) if name else None,
                    members=[
                        PortMembership(
                            port_id=pid(p),
                            mode=Membership.TAGGED if p in tagged else Membership.UNTAGGED,
                        )
                        for p in members
                    ],
                )
            )
    elif vlan is not None:
        groups: dict[int, list[int]] = {}
        if mode is not None and mode.startswith("port"):
            for group in vlan.get("port_vlans") or []:
                gid = _number(group.get("id")) if isinstance(group, Mapping) else None
                if gid is None:
                    continue
                for p in _ports(group.get("members"), known):
                    groups.setdefault(p, []).append(gid)
            for n, ids in groups.items():
                extra[n]["port_groups"] = [*map(int, sorted(ids))]
        segments.append(
            Segment(
                id=native,
                site_id=site_id,
                members=[
                    PortMembership(port_id=pid(n), mode=Membership.UNTAGGED) for n in sorted(rows)
                ],
            )
        )

    out_ports = []
    for n, row in sorted(rows.items()):
        up = row.get("up")
        up = up if isinstance(up, bool) else None
        speed = _number(row.get("speed_mbps"))
        duplex = row.get("duplex")
        port_extra = dict(extra[n])
        if mode is not None:
            port_extra["vlan_mode"] = mode
        for key in ("link", "enabled"):
            value = _json(row.get(key))
            if value is not None:
                port_extra[key] = value
        out_ports.append(
            Port(
                id=pid(n),
                device_id=device_id,
                name=str(n),
                kind=PortKind.ETHERNET,
                up=up,
                speed_mbps=speed if up and speed else None,
                full_duplex=(duplex == "full") if up and duplex in ("full", "half") else None,
                lag=lag_of.get(n),
                vendor_extra=port_extra,
            )
        )
    return Observation(ports=out_ports, segments=segments)
