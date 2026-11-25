"""OpenWrt smart queue management (#166): ``uci get sqm`` (package ``sqm-scripts``, optional).

One ``queue`` section per shaped interface: ``enabled`` (``1``), ``interface`` (the device, for
example ``eth1`` or ``pppoe-wan``), ``download`` and ``upload`` (kbit/s, ``0``: not limited),
``qdisc`` (``cake`` or ``fq_codel``; ``cake`` is the default of the scripts), ``script``
(``piece_of_cake.qos``, ``layer_cake.qos``, ``simple.qos``, ...). ``diffserv`` modes are read from
``qdisc_opts`` / ``iqdisc_opts`` (``diffserv4``, ``diffserv8``, ``besteffort``).

A router without the package has no ``sqm`` config: nothing to report. Covered: sqm-scripts 1.5
(OpenWrt 21.02 to 25.12). Option names are the package's own, *guess* until seen on a device (#21).
"""

from __future__ import annotations

from typing import Any

from signalbox.adapters.shaping import kbps, kind_of, uplink_for
from signalbox.model import Shaper, ShaperKind, Uplink, object_id


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _flag(value: Any) -> bool:
    return _text(value).lower() in ("1", "true", "yes", "on", "enabled")


def shapers(
    device_id: str,
    sections: list[tuple[str, dict[str, Any]]],
    uplinks: list[Uplink],
    devices: dict[str, str],
) -> list[Shaper]:
    """One shaper per ``queue`` section. ``devices``: logical interface -> device name, to find
    the uplink of a section that names the logical interface."""
    out: list[Shaper] = []
    for name, s in sections:
        interface = _text(s.get("interface"))
        qdisc = _text(s.get("qdisc")) or "cake"
        kind = kind_of(qdisc)
        if kind is ShaperKind.OTHER:
            kind = ShaperKind.SQM
        up = uplink_for(uplinks, interface)
        if up is None:
            up = next(
                (
                    u
                    for u in sorted(uplinks, key=lambda u: u.id)
                    if devices.get(u.name or "") == interface
                ),
                None,
            )
        opts = f"{_text(s.get('qdisc_opts'))} {_text(s.get('iqdisc_opts'))}".lower()
        out.append(
            Shaper(
                id=object_id(device_id, "shaper", name),
                device_id=device_id,
                name=name,
                kind=kind,
                interface=interface or None,
                uplink_id=up.id if up else None,
                download_kbps=kbps(s.get("download"), "kbit"),
                upload_kbps=kbps(s.get("upload"), "kbit"),
                enabled=_flag(s.get("enabled")),
                dscp=("diffserv" in opts) or None,
                vendor_extra={"script": _text(s.get("script"))} if _text(s.get("script")) else {},
            )
        )
    return out
