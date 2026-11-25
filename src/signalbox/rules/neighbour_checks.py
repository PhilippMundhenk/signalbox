"""Checks that compare what a neighbour announces about its own port (LLDP, #163) with what the
local port is set to: native VLAN, frame size and requested PoE power.

Both ends of a cable are compared where the neighbour announces the value; everything stays quiet
where the neighbour or the local port does not report it.
"""

from __future__ import annotations

from collections.abc import Iterator

from signalbox.model import MessageValue, Neighbour, Network, Port, PortKind
from signalbox.rules import Result, Rule, RuleParams, Severity, ctx, found, param, rule
from signalbox.rules._names import device_name

#: Ethernet header (14), FCS (4) and one VLAN tag (4): the bytes a frame carries on top of the MTU.
FRAME_OVERHEAD = 22


def _local(net: Network, nb: Neighbour, *, unlinked: bool = False) -> Port | None:
    """The local physical port of a wired neighbour, else None. With ``unlinked``, a port that
    is an end of a cable link is left out: the link rules compare both ends there."""
    if nb.wireless:
        return None
    if unlinked and any(nb.local_port_id in (link.a, link.b) for link in net.links):
        return None
    port = net.port(nb.local_port_id)
    if port is None or port.kind is not PortKind.ETHERNET:
        return None
    return port


def _where(net: Network, port: Port, nb: Neighbour) -> str:
    peer = nb.system_name or nb.chassis_id
    return f"{device_name(net, port.device_id)} port {port.name} (to {peer})"


@rule(
    "link.pvid-mismatch",
    "Native VLAN differs between the two ends of a link",
    Severity.WARNING,
    "The neighbour announces the VLAN it puts untagged frames into (port VLAN id, LLDP) and the "
    "local port uses another one. Untagged traffic then moves from one VLAN into the other "
    "(VLAN leaking) and spanning tree and DHCP replies end up in the wrong network. Both ends "
    "of a trunk should use the same native VLAN. Where both ends of the cable are read by "
    "Signalbox, vlan.native-mismatch compares them; this check covers a neighbour it only sees "
    "through LLDP.",
)
def pvid_mismatch(net: Network) -> Iterator[Result]:
    for nb in net.neighbours:
        port = _local(net, nb, unlinked=True)
        if port is None or port.pvid is None or nb.port_vlan is None:
            continue
        if port.pvid == nb.port_vlan:
            continue
        where = _where(net, port, nb)
        yield found(
            f"{where}: the native VLAN is {port.pvid} here but {nb.port_vlan} on the other end.",
            [port.id, nb.id],
            fix="Set the same native (untagged) VLAN on both ends of the cable.",
            key=nb.id,
            mid="link.pvidMismatch",
            fix_id="link.pvidMismatch.fix",
            params={"where": where, "local": port.pvid, "remote": nb.port_vlan},
        )


class MtuParams(RuleParams):
    tolerance_bytes: int = param(
        FRAME_OVERHEAD,
        unit="bytes",
        ge=0,
        le=1000,
        description="Frame size the neighbour may be smaller than the local MTU needs before "
        "it is reported (devices count header, tag and FCS differently).",
    )


@rule(
    "link.mtu-mismatch",
    "The other end of a link accepts smaller frames than this port sends",
    Severity.WARNING,
    "The neighbour announces the largest frame its port accepts (LLDP maximum frame size) and "
    "the local port is set to an MTU that needs bigger frames. Large packets (jumbo frames, "
    "tunnels) are dropped by the other end while small ones work, which looks like connections "
    "that hang after the handshake. The check allows the Ethernet header, one VLAN tag and the "
    "checksum on top of the MTU and the parameter tolerance_bytes extra. Where both ends of the "
    "cable are read by Signalbox, link.mtu compares them; this check covers a neighbour it only "
    "sees through LLDP.",
    params=MtuParams,
)
def mtu_mismatch(net: Network) -> Iterator[Result]:
    for nb in net.neighbours:
        port = _local(net, nb, unlinked=True)
        if port is None or port.mtu is None or nb.max_frame_size is None:
            continue
        needed = port.mtu + FRAME_OVERHEAD
        if needed <= nb.max_frame_size + ctx.params(MtuParams, port).tolerance_bytes:
            continue
        where = _where(net, port, nb)
        yield found(
            f"{where}: the MTU is {port.mtu} here but the other end accepts frames of only "
            f"{nb.max_frame_size} bytes.",
            [port.id, nb.id],
            fix="Lower the MTU of this port, or raise the frame size (jumbo frames) on the "
            "other end and everything between.",
            key=nb.id,
            mid="link.mtuMismatch",
            fix_id="link.mtuMismatch.fix",
            params={"where": where, "mtu": port.mtu, "frame": nb.max_frame_size},
        )


class PoeRequestParams(RuleParams):
    margin_w: float = param(
        0.5,
        unit="W",
        ge=0,
        le=100,
        description="Watts the request may exceed the port's limit by before it is reported.",
    )


def _watts(value: float) -> str:
    return f"{value:.1f}".removesuffix(".0")


@rule(
    "poe.request-unmet",
    "A powered device asks for more PoE power than its port gives",
    Severity.WARNING,
    "A neighbour announces how much power it requests (LLDP power TLV) and the switch port it "
    "is plugged into has PoE switched off or a lower limit. The device then runs with reduced "
    "functions (a camera without infrared, an access point with fewer radios) or does not start. "
    "Needs a switch that reports the PoE limit of its ports; the parameter margin_w is the "
    "tolerance.",
    params=PoeRequestParams,
)
def poe_request_unmet(net: Network) -> Iterator[Result]:
    for nb in net.neighbours:
        port = _local(net, nb)
        if port is None or port.poe is None or not nb.poe_requested_w:
            continue
        requested = nb.poe_requested_w
        where = _where(net, port, nb)
        values: dict[str, MessageValue] = {"where": where, "requested": _watts(requested)}
        if port.poe.enabled is False:
            yield found(
                f"{where}: the device asks for {values['requested']} W but PoE is off on the port.",
                [port.id, nb.id],
                fix="Turn PoE on for the port, or power the device another way.",
                key=f"{nb.id}\x00off",
                mid="poe.requestOff",
                fix_id="poe.requestOff.fix",
                params=values,
            )
            continue
        margin = ctx.params(PoeRequestParams, port).margin_w
        if port.poe.max_w is not None and requested > port.poe.max_w + margin:
            values["limit"] = _watts(port.poe.max_w)
            yield found(
                f"{where}: the device asks for {values['requested']} W but the port gives at "
                f"most {values['limit']} W.",
                [port.id, nb.id],
                fix="Raise the PoE limit of the port or move the device to a port or switch "
                "with a higher PoE class.",
                key=f"{nb.id}\x00limit",
                mid="poe.requestLimit",
                fix_id="poe.requestLimit.fix",
                params=values,
            )


RULES: list[Rule] = [pvid_mismatch, mtu_mismatch, poe_request_unmet]
