"""Readable names of model objects for finding messages."""

from __future__ import annotations

from signalbox.model import Network


def device_name(net: Network, device_id: str) -> str:
    dev = net.device(device_id)
    return dev.name if dev else device_id


def segment_name(net: Network, segment_id: str) -> str:
    """``LAN (VLAN 10)``, ``VLAN 10``, ``untagged network`` or the bare id if unknown."""
    seg = net.segment(segment_id)
    if seg is None:
        return segment_id
    vlan = f"VLAN {seg.vlan}" if seg.vlan is not None else "untagged network"
    return f"{seg.name} ({vlan})" if seg.name else vlan


def site_of_device(net: Network, device_id: str) -> str | None:
    dev = net.device(device_id)
    return dev.site_id if dev else None
