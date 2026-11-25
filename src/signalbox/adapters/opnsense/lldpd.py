"""OPNsense LLDP neighbours (#470): the ``os-lldpd`` plugin.

``GET /api/lldpd/service/neighbor`` answers ``{"response": "<text>"}``: the output of
``lldpcli show neighbors`` in lldpd's plain text format (the plugin runs it through configd and
passes it on unchanged; there is no JSON variant). Per neighbour a block::

    Interface:    igb1, via: LLDP, RID: 1, Time: 0 day, 03:12:44
      Chassis:
        ChassisID:    mac 02:00:00:00:10:01
        SysName:      switch1
        MgmtIP:       192.0.2.2
        Capability:   Bridge, on
      Port:
        PortID:       ifname gi1
        PortDescr:    uplink
        TTL:          120
        VLAN:         20, pvid: yes
        MFS:          1522

The age counts from the first sighting, so only ``age_seconds`` is set (no ``last_seen``). The
privilege is *Services: Lldpd* (``page-services-lldpd``, ACL pattern ``api/lldpd/*`` in the
plugin's ACL.xml), granted only where the firewall offers it. The plugin is optional: a 404 means
it is not installed. The endpoint has been in the plugin since its first release, so every
OPNsense release covered has it (*guess*, #21: the text layout is the one of lldpd 1.0.x, the
version FreeBSD ships).
"""

from __future__ import annotations

import re
from typing import Any

from signalbox.lldp import age_seconds, int_of, med_class, protocol_of
from signalbox.model import (
    Neighbour,
    normalise_capabilities,
    normalise_id_kind,
    object_id,
    port_id,
)

NEIGHBORS = "/api/lldpd/service/neighbor"
PRIVILEGE = "Services: Lldpd (page-services-lldpd)"

_INTERFACE = re.compile(r"^Interface:\s*(?P<name>[^,\s]+)\s*(?P<rest>.*)$")
_FIELD = re.compile(r"^(?P<key>[A-Za-z][A-Za-z0-9 -]*?):\s*(?P<value>.*)$")


def _blocks(text: str) -> list[tuple[str, dict[str, list[str]]]]:
    """``(interface line, {field: [values]})`` per neighbour; separator lines are skipped."""
    out: list[tuple[str, dict[str, list[str]]]] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or set(line) == {"-"}:
            continue
        if _INTERFACE.match(line):
            out.append((line, {}))
            continue
        f = _FIELD.match(line)
        if f and out:
            out[-1][1].setdefault(f.group("key").strip().lower(), []).append(f.group("value"))
    return out


def _first(fields: dict[str, list[str]], key: str) -> str | None:
    values = fields.get(key)
    return values[0].strip() or None if values else None


def _id(value: str | None) -> tuple[str | None, str | None]:
    """``mac 02:00:...`` to (kind, id); an id without a kind word is kept as it is."""
    parts = (value or "").strip().split(None, 1)
    if len(parts) == 2 and normalise_id_kind(parts[0]) is not None:
        return normalise_id_kind(parts[0]), parts[1].strip()
    return None, (value or "").strip() or None


def neighbours(device_id: str, answer: Any, known_ports: set[str]) -> list[Neighbour]:
    """The neighbours of the answer; one on an interface the observed ports do not know is
    left out (the plugin may listen on a bridge or tunnel)."""
    text = answer.get("response") if isinstance(answer, dict) else None
    if not isinstance(text, str):
        return []
    out: dict[str, Neighbour] = {}
    for head, fields in _blocks(text):
        m = _INTERFACE.match(head)
        if m is None:  # pragma: no cover - _blocks only keeps interface lines
            continue
        local = port_id(device_id, m.group("name"))
        kind, chassis = _id(_first(fields, "chassisid"))
        if chassis is None or local not in known_ports:
            continue
        _, remote = _id(_first(fields, "portid"))
        vlans: list[int] = []
        pvid: int | None = None
        for value in fields.get("vlan", []):
            vid = int_of(value)
            if vid is not None and 1 <= vid <= 4094:
                vlans.append(vid)
                if re.search(r"pvid:\s*yes", value, re.IGNORECASE):
                    pvid = vid
        caps = [
            c.rsplit(",", 1)[0]
            for c in fields.get("capability", [])
            if c.rsplit(",", 1)[-1].strip().lower() == "on"
        ]
        mfs = int_of(_first(fields, "mfs"))
        via = re.search(r"via:\s*([^,\s]+)", m.group("rest"))
        time = re.search(r"Time:\s*(.+)$", m.group("rest"))
        nid = object_id(device_id, "neighbour", f"{m.group('name')}-{chassis}")
        out.setdefault(
            nid,
            Neighbour(
                id=nid,
                local_port_id=local,
                chassis_id=chassis,
                chassis_id_kind=kind,
                remote_port=remote,
                port_description=_first(fields, "portdescr"),
                system_name=_first(fields, "sysname"),
                description=_first(fields, "sysdescr"),
                management_address=_first(fields, "mgmtip"),
                capabilities=normalise_capabilities(caps),
                protocol=protocol_of(via.group(1) if via else None),
                port_vlan=pvid,
                vlans=vlans,
                max_frame_size=mfs if mfs is not None and 64 <= mfs <= 65535 else None,
                med_device_class=med_class(_first(fields, "device type")),
                ttl_seconds=int_of(_first(fields, "ttl")),
                age_seconds=age_seconds(time.group(1) if time else None),
            ),
        )
    return list(out.values())
