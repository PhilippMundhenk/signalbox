"""The bridge MAC address table (forwarding database, #160, #378) of an OpenWrt device.

Read through rpcd's ``file read`` with ``base64``: ``/sys/class/net/<bridge>/brforward`` is
the kernel's table as binary records (``struct __fdb_entry`` of ``linux/if_bridge.h``, 16
bytes each), ``/sys/class/net/<member>/brport/port_no`` names the bridge port of each member.
No extra package and no ``exec`` permission: only the ACL path ``/sys/class/net/*/brforward``.

The file has no VLAN: an address learned in several VLANs of a VLAN-aware bridge is one entry
per VLAN with the same port, kept once here. A DSA switch reports the addresses its software
bridge has seen (broadcasts and what reaches the CPU), not every address the switch chip keeps
in hardware: enough to tell which port leads to which device.
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass

#: Size of one ``struct __fdb_entry``.
RECORD = 16
#: ``ageing_timer_value`` counts in ``USER_HZ`` (clock ticks, 100 per second).
USER_HZ = 100


@dataclass(frozen=True)
class Row:
    mac: str
    port_no: int
    local: bool
    #: seconds since the entry was refreshed
    age_seconds: int


def decode(data: str) -> bytes | None:
    """The bytes of a base64 ``file read`` answer; None for anything else (an rpcd without
    ``base64`` sends the raw bytes as text, which is no valid table)."""
    try:
        raw = base64.b64decode(data.strip(), validate=True)
    except (binascii.Error, ValueError):
        return None
    return raw if len(raw) % RECORD == 0 else None


def parse(raw: bytes) -> list[Row]:
    """The records of ``brforward``. The age is a host-order ``u32`` (big-endian MIPS boards
    exist): the smaller of both readings is the right one, ages are far below 2^16 ticks."""
    out: dict[tuple[str, int], Row] = {}
    for off in range(0, len(raw) - RECORD + 1, RECORD):
        rec = raw[off : off + RECORD]
        mac = ":".join(f"{b:02x}" for b in rec[:6])
        port_no = rec[6] | (rec[12] << 8)
        ticks = min(int.from_bytes(rec[8:12], "little"), int.from_bytes(rec[8:12], "big"))
        row = Row(mac, port_no, bool(rec[7]), ticks // USER_HZ)
        key = (mac, port_no)
        if key not in out or row.age_seconds < out[key].age_seconds:
            out[key] = row
    return list(out.values())


def encode(rows: list[Row]) -> str:
    """The base64 answer for *rows* (little-endian, as on x86 and ARM): for the simulator."""
    out = bytearray()
    for r in rows:
        rec = bytearray(RECORD)
        rec[:6] = bytes(int(x, 16) for x in r.mac.split(":"))
        rec[6] = r.port_no & 0xFF
        rec[7] = 1 if r.local else 0
        rec[8:12] = (r.age_seconds * USER_HZ).to_bytes(4, "little")
        rec[12] = r.port_no >> 8
        out += rec
    return base64.b64encode(bytes(out)).decode()


def port_number(value: str | None) -> int | None:
    """``brport/port_no`` (``0x3``)."""
    if not value:
        return None
    try:
        return int(value.strip(), 0)
    except ValueError:
        return None
