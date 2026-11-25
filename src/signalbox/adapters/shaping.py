"""Helpers the readers of traffic shapers share (#166): rates, queueing disciplines and the
uplink a shaper sits on."""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any

from signalbox.model import ShaperKind, Uplink

_RATE = re.compile(r"^\s*([0-9]+(?:\.[0-9]+)?)\s*([a-zA-Z]*)\s*$")
#: Multiplier to bit/s of the unit spellings of RouterOS (``100M``, ``64k``) and OPNsense
#: (``Mbit``); plain numbers are bit/s.
_BITS = {
    "": 1,
    "b": 1,
    "bit": 1,
    "k": 1_000,
    "kbit": 1_000,
    "m": 1_000_000,
    "mbit": 1_000_000,
    "g": 1_000_000_000,
    "gbit": 1_000_000_000,
}


def kbps(value: Any, unit: str = "") -> int | None:
    """``100M`` -> 100000, ``"20000000"`` -> 20000, ``("50", "Mbit")`` -> 50000 (bit/s based
    units); ``None`` for nothing, ``0`` and what is not a rate."""
    text = str(value).strip() if value is not None else ""
    m = _RATE.match(text)
    if m is None:
        return None
    suffix = m.group(2).lower() or unit.strip().lower()
    factor = _BITS.get(suffix)
    if factor is None:
        return None
    rate = int(float(m.group(1)) * factor / 1000)
    return rate if rate > 0 else None


def kind_of(text: str | None) -> ShaperKind:
    """The queueing discipline named by ``text`` (``cake``, ``fq_codel``, ``FlowQueue-CoDel``,
    ``htb``, ``hfsc``, ``pfifo``, ...)."""
    low = (text or "").strip().lower().replace("_", "-")
    if "cake" in low:
        return ShaperKind.CAKE
    if "codel" in low:
        return ShaperKind.FQ_CODEL
    if low == "sqm":
        return ShaperKind.SQM
    if "hfsc" in low:
        return ShaperKind.HFSC
    if "htb" in low:
        return ShaperKind.HTB
    if low in ("prio", "priority"):
        return ShaperKind.PRIORITY
    if low in ("fifo", "pfifo", "bfifo", "pfifo-fast", "wfq", "rr", "qfq", "sfq", "pcq", "red"):
        return ShaperKind.SIMPLE_QUEUE
    return ShaperKind.OTHER


def uplink_for(uplinks: Iterable[Uplink], interface: str | None) -> Uplink | None:
    """The uplink an interface name belongs to: its name, or the port it uses."""
    if not interface:
        return None
    for u in sorted(uplinks, key=lambda u: u.id):
        if u.name == interface or (u.port_id or "").rsplit("/", 1)[-1] == interface:
            return u
    return None
