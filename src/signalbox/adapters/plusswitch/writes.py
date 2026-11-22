"""PORT changes → an 802.1Q table for Switchyard's ``apply_dot1q``. Pure functions, no I/O.

A port change says which VLAN a port sends untagged (``"native"`` is VLAN 1) and which ones it
sends tagged. On these switches that is:

- the port is a member of exactly those VLANs, tagged where it is tagged;
- its PVID (the VLAN of untagged frames that arrive) is the untagged VLAN; without an untagged
  VLAN the PVID stays where it is if the port is still a member there, else it moves to the
  first tagged VLAN (the switch needs a PVID the port is a member of);
- VLANs that are missing are created; VLANs (other than 1) that this change leaves without any
  member are deleted. VLANs that were empty before are left alone.

``apply_dot1q`` then brings the switch to that table in a safe order (widen, move PVIDs, narrow,
delete), see Switchyard's drivers.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from signalbox.adapters import AdapterError, VendorCall
from signalbox.changes import Change, ChangeKind, PortValue
from signalbox.model import port_id

#: the format of a switch backup (``Backup.format``)
BACKUP_FORMAT = "switchyard-dot1q-json"


@dataclass
class Table:
    """An 802.1Q table: VLAN id → members, tagged members, name; port → PVID."""

    vlans: dict[int, dict[str, Any]] = field(default_factory=dict)
    pvid: dict[int, int] = field(default_factory=dict)

    @classmethod
    def read(cls, vlan: Mapping[str, Any] | None, host: str) -> Table:
        """The table of a ``read_vlan`` answer; refused unless the switch is in 802.1Q mode."""
        mode = str(vlan.get("mode", "disabled")) if isinstance(vlan, Mapping) else None
        if vlan is None or mode is None:
            raise AdapterError(f"{host}: the switch reports no VLAN settings; nothing is changed")
        if not mode.startswith("dot1q"):
            kind = "port-based VLANs" if mode.startswith("port") else "VLANs switched off"
            raise AdapterError(
                f"{host}: the switch is in {mode} mode ({kind}); Signalbox changes VLANs only "
                "in 802.1Q mode. Switch to 802.1Q in the vendor utility or Switchyard first; "
                "nothing is changed"
            )
        table = cls()
        for entry in vlan.get("dot1q") or []:
            if not isinstance(entry, Mapping) or not isinstance(entry.get("id"), int):
                continue
            tagged = {int(p) for p in entry.get("tagged") or []}
            table.vlans.setdefault(
                int(entry["id"]),
                {
                    "members": {int(p) for p in entry.get("members") or []} | tagged,
                    "tagged": tagged,
                    "name": str(entry.get("name") or ""),
                },
            )
        pvid = vlan.get("pvid") or {}
        table.pvid = {int(p): int(v) for p, v in pvid.items()} if isinstance(pvid, Mapping) else {}
        return table

    def rows(self) -> list[dict[str, Any]]:
        """``apply_dot1q``'s ``vlans`` argument."""
        return [
            {
                "id": vid,
                "members": sorted(v["members"]),
                "tagged": sorted(v["tagged"]),
                "name": v["name"],
            }
            for vid, v in sorted(self.vlans.items())
        ]

    def to_json(self) -> str:
        return json.dumps(
            {
                "mode": "dot1q",
                "vlans": self.rows(),
                "pvid": {str(p): v for p, v in sorted(self.pvid.items())},
            },
            sort_keys=True,
        )

    @classmethod
    def from_json(cls, text: str) -> Table:
        try:
            data = json.loads(text)
            table = cls()
            for row in data["vlans"]:
                tagged = {int(p) for p in row["tagged"]}
                table.vlans[int(row["id"])] = {
                    "members": {int(p) for p in row["members"]} | tagged,
                    "tagged": tagged,
                    "name": str(row.get("name") or ""),
                }
            table.pvid = {int(p): int(v) for p, v in data["pvid"].items()}
        except (ValueError, KeyError, TypeError, AttributeError) as exc:
            raise AdapterError(f"the backup is not a switch VLAN table: {exc}") from exc
        if 1 not in table.vlans:
            raise AdapterError("the backup is not a switch VLAN table: VLAN 1 is missing")
        return table


def port_number(device_id: str, change: Change) -> int:
    """The switch port a change is for (``<device>/port/<n>``)."""
    if change.kind is not ChangeKind.PORT:
        raise AdapterError(f"{change.id}: these switches only change ports (VLAN membership)")
    if change.device_id != device_id:
        raise AdapterError(f"{change.id}: not a change of this switch ({device_id})")
    name = change.key.removeprefix(port_id(device_id, ""))
    if change.key == name or not name.isdigit() or int(name) < 1:
        raise AdapterError(f"{change.id}: {change.key} is not a port of this switch")
    return int(name)


def wanted(change: Change) -> tuple[int | None, list[int]]:
    """Untagged VLAN (or None) and tagged VLANs of a change's new value; checked."""
    new = change.new if isinstance(change.new, PortValue) else PortValue()
    untagged = None if new.untagged is None else 1 if new.untagged == "native" else new.untagged
    tagged = sorted(set(new.tagged))
    if untagged in tagged:
        raise AdapterError(f"{change.id}: VLAN {untagged} cannot be both untagged and tagged")
    for vid in [*([untagged] if untagged else []), *tagged]:
        if not 1 <= vid <= 4093:
            raise AdapterError(f"{change.id}: VLAN {vid} is outside 1-4093")
    if 1 in tagged:
        raise AdapterError(
            f"{change.id}: VLAN 1 is the native network here and cannot be sent tagged"
        )
    if untagged is None and not tagged:
        raise AdapterError(
            f"{change.id}: a port in no VLAN at all is not possible on these switches "
            "(every port needs a PVID it is a member of)"
        )
    return untagged, tagged


def plan(device_id: str, host: str, changes: list[Change]) -> list[VendorCall]:
    """The calls ``apply`` makes, for the review (no secrets involved)."""
    calls = []
    for c in changes:
        port = port_number(device_id, c)
        untagged, tagged = wanted(c)
        calls.append(
            VendorCall(
                description=f"port {port}: "
                + (f"untagged VLAN {untagged} (PVID {untagged})" if untagged else "no untagged")
                + (", tagged " + ", ".join(map(str, tagged)) if tagged else ", nothing tagged")
                + "; VLANs created as needed, VLANs left empty deleted",
                method="apply_dot1q",
                target=f"{host} port {port}",
                payload={"port": port, "untagged": untagged, "tagged": list(tagged)},
            )
        )
    return calls


def apply(table: Table, device_id: str, changes: list[Change], ports: int) -> Table:
    """The table after the changes (``table`` is not modified)."""
    out = Table(
        vlans={
            vid: {"members": set(v["members"]), "tagged": set(v["tagged"]), "name": v["name"]}
            for vid, v in table.vlans.items()
        },
        pvid=dict(table.pvid),
    )
    touched: set[int] = set()
    for c in changes:
        port = port_number(device_id, c)
        if port > ports:
            raise AdapterError(f"{c.id}: the switch has {ports} ports, not port {port}")
        untagged, tagged = wanted(c)
        for vid, v in out.vlans.items():
            if port in v["members"]:
                touched.add(vid)
            v["members"].discard(port)
            v["tagged"].discard(port)
        for vid in [*([untagged] if untagged else []), *tagged]:
            v = out.vlans.setdefault(vid, {"members": set(), "tagged": set(), "name": ""})
            v["members"].add(port)
            if vid != untagged:
                v["tagged"].add(port)
        if untagged is not None:
            out.pvid[port] = untagged
        elif port not in out.vlans.get(out.pvid.get(port, 0), {"members": set()})["members"]:
            out.pvid[port] = tagged[0]
    for vid in touched:
        if vid != 1 and not out.vlans[vid]["members"]:
            del out.vlans[vid]
    return out
