"""Small readers shared by the adapters that see LLDP, CDP or MNDP neighbours (#163): the
discovery protocol, the LLDP-MED device class and lldpd's age text. Pure functions, no I/O."""

from __future__ import annotations

import re

from signalbox.model import MedDeviceClass, NeighbourProtocol

_AGE = re.compile(r"(?:(\d+)\s*days?,?\s*)?(\d+):(\d{2}):(\d{2})", re.IGNORECASE)
_CLASS = re.compile(r"\bclass\s*(iii|ii|i|1|2|3)\b|\b(network\s+connectivity)\b", re.IGNORECASE)
_CLASSES = {
    "i": MedDeviceClass.ENDPOINT_1,
    "1": MedDeviceClass.ENDPOINT_1,
    "ii": MedDeviceClass.ENDPOINT_2,
    "2": MedDeviceClass.ENDPOINT_2,
    "iii": MedDeviceClass.ENDPOINT_3,
    "3": MedDeviceClass.ENDPOINT_3,
}
_PROTOCOLS = (
    ("lldp", NeighbourProtocol.LLDP),
    ("cdp", NeighbourProtocol.CDP),
    ("mndp", NeighbourProtocol.MNDP),
    ("edp", NeighbourProtocol.EDP),
    ("fdp", NeighbourProtocol.FDP),
)


def protocol_of(text: str | None) -> NeighbourProtocol | None:
    """The protocol from lldpd's ``via`` (``LLDP``, ``CDPv2``, ``EDP``, ``FDP``) or RouterOS'
    ``discovered-by`` (``lldp,mndp``: the first of lldp, cdp, mndp that is named)."""
    words = [w for w in re.split(r"[^a-z0-9]+", str(text or "").lower()) if w]
    for name, protocol in _PROTOCOLS:
        if any(re.fullmatch(name + r"(v?\d+)?", w) for w in words):
            return protocol
    return NeighbourProtocol.OTHER if words else None


def age_seconds(text: str | None) -> int | None:
    """lldpd's age ``0 day, 03:12:44`` in seconds; a plain number is taken as seconds."""
    value = str(text or "").strip()
    if value.isdigit():
        return int(value)
    m = _AGE.search(value)
    if m is None:
        return None
    days, hours, minutes, seconds = (int(g or 0) for g in m.groups())
    return ((days * 24 + hours) * 60 + minutes) * 60 + seconds


def med_class(text: str | None) -> MedDeviceClass | None:
    """The LLDP-MED device class from text such as ``Communication Device Endpoint (Class
    III)`` or ``Network Connectivity Device``; None for ``Generic`` or unknown text."""
    m = _CLASS.search(str(text or ""))
    if m is None:
        return None
    if m.group(2):
        return MedDeviceClass.NETWORK_CONNECTIVITY
    return _CLASSES.get(m.group(1).lower())


def int_of(value: object) -> int | None:
    """An integer from a number or a numeric text (``"1522"``, ``"1522 bytes"``); None else."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    m = re.match(r"\s*(\d+)", str(value if value is not None else ""))
    return int(m.group(1)) if m else None
