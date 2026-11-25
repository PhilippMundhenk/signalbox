"""Who powers whom over Ethernet (issue #437).

``Port.poe`` says what a switch delivers on a port; the links between the managed devices say
what sits at the other end. Together they give the switch port that powers a device.
"""

from __future__ import annotations

from dataclasses import dataclass

from signalbox.model import LinkKind, LinkOrigin, Network, PoeStatus


@dataclass(frozen=True)
class PoweredBy:
    """The port of a switch that powers a managed device."""

    device_id: str
    port_id: str
    switch_id: str
    power_w: float | None


def powered_by(net: Network) -> dict[str, PoweredBy]:
    """Managed devices that get their power from a port of another managed device.

    That is the far end of a cable link whose PoE port delivers power (status ``delivering``,
    or a positive ``power_w``). Wireless, VPN and merely guessed (``inferred``) links count for
    nothing. A device with two powering links is listed once (the first by link id).
    """
    out: dict[str, PoweredBy] = {}
    for link in sorted(net.links, key=lambda x: x.id):
        if link.kind is not LinkKind.CABLE or link.inferred or link.origin is LinkOrigin.TUNNEL:
            continue
        for near_id, far_id in ((link.a, link.b), (link.b, link.a)):
            near, far = net.port(near_id), net.port(far_id)
            if near is None or far is None or near.device_id == far.device_id:
                continue
            poe = near.poe
            if poe is None:
                continue
            if poe.status is PoeStatus.DELIVERING or (poe.power_w or 0) > 0:
                out.setdefault(
                    far.device_id, PoweredBy(far.device_id, near.id, near.device_id, poe.power_w)
                )
    return out
