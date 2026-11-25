"""Helpers shared by the rules: readable names of model objects, router subnets."""

from __future__ import annotations

from signalbox.model import DeviceRole, Network, Subnet


def device_name(net: Network, device_id: str) -> str:
    dev = net.device(device_id)
    return dev.name if dev else device_id


def segment_name(net: Network, segment_id: str) -> str:
    """``LAN (VLAN 10)``, ``VLAN 10``, ``untagged network`` or the bare id if unknown."""
    seg = net.segment(segment_id)
    if seg is None:
        return segment_id
    vlan = f"VLAN {seg.vlan}" if seg.vlan is not None else "untagged network"
    shown = seg.shown_name
    return f"{shown} ({vlan})" if shown else vlan


def site_of_device(net: Network, device_id: str) -> str | None:
    dev = net.device(device_id)
    return dev.site_id if dev else None


def router_subnets(net: Network) -> list[Subnet]:
    """Subnets of a router: marked as the gateway, or on a device with the gateway role."""
    gateways = {d.id for d in net.devices if d.role is DeviceRole.GATEWAY}
    return [s for s in net.subnets if s.gateway or s.device_id in gateways]
