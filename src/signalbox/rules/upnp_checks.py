"""Dynamic port mappings of UPnP, NAT-PMP and PCP (issue #176, ADR 0029).

The checks use what gateways report about themselves (``Device.upnp``): the protocols, secure
mode and the mappings clients opened. Whether UPnP is on at all, and on which networks, is
``security.upnp`` (roaming_upnp.py). Everything stays quiet where a gateway did not report its
mappings, and a mapping whose target is not a known client is judged by its address only when
a network contains it.
"""

from __future__ import annotations

from collections.abc import Iterator

from signalbox.model import (
    UNTRUSTED_PURPOSES,
    Device,
    DynamicPortMapping,
    IPAddress,
    Network,
    Segment,
    ServiceKind,
)
from signalbox.rules import Result, RuleParams, Severity, ctx, found, param, rule
from signalbox.rules._names import device_name, segment_name

#: Ports of management and file sharing services: a mapping to one of them (or from one of them)
#: hands the login or the share of a device to the internet.
MANAGEMENT_PORTS = {
    22: "SSH",
    23: "Telnet",
    139: "SMB",
    445: "SMB",
    3389: "remote desktop",
    5900: "VNC",
    8291: "Winbox",
    8728: "RouterOS API",
    8729: "RouterOS API",
}


class ManyMappingsParams(RuleParams):
    max_mappings: int = param(
        20,
        unit="count",
        ge=1,
        le=1000,
        description="Report a gateway that has more dynamic port mappings than this.",
    )


def _enabled(net: Network, d: Device) -> bool:
    """UPnP is on according to the gateway's service object (or no service object says off)."""
    services = [s for s in net.services_of(d.id) if s.kind is ServiceKind.UPNP]
    return not services or any(s.enabled for s in services)


def _mappings(net: Network) -> Iterator[tuple[Device, DynamicPortMapping]]:
    for d in sorted(net.devices, key=lambda d: d.id):
        if d.upnp is None or not _enabled(net, d):
            continue
        for m in d.upnp.mappings:
            if m.enabled:
                yield d, m


def _segment_of(net: Network, address: IPAddress) -> Segment | None:
    """The network the address belongs to: where a client has it, else the smallest subnet that
    contains it."""
    for c in net.clients:
        if address in c.addresses and c.segment_id is not None:
            return net.segment(c.segment_id)
    best: tuple[int, str] | None = None
    for s in net.subnets:
        n = s.interface.network
        if (
            address.version == n.version
            and address in n
            and (best is None or n.prefixlen > best[0])
        ):
            best = (n.prefixlen, s.segment_id)
    return net.segment(best[1]) if best else None


def _who(net: Network, m: DynamicPortMapping) -> tuple[str, list[str]]:
    """The client with the target address (its name, else the address) and its object id."""
    for c in net.clients:
        if m.internal_address in c.addresses:
            return c.hostname or str(m.internal_address), [c.id]
    return str(m.internal_address), []


def _label(m: DynamicPortMapping) -> str:
    return f"{m.protocol.upper()} {m.external_port}"


# --- upnp.mapping-untrusted ------------------------------------------------------------------


@rule(
    "upnp.mapping-untrusted",
    "A port is open to the internet for a device in an IoT, camera or guest network",
    Severity.WARNING,
    "A device opened a port to the internet on the gateway through UPnP, NAT-PMP or PCP, and "
    "the device is in a network that is not trusted (IoT, cameras, guests). A camera, a "
    "cheap smart device or a compromised guest laptop can expose itself this way without "
    "anybody noticing. Reported per mapping, for gateways that report their mappings. The "
    "device is found by its address; descriptions are not part of the finding.",
)
def mapping_untrusted(net: Network) -> Iterator[Result]:
    for d, m in _mappings(net):
        seg = _segment_of(net, m.internal_address)
        if seg is None or seg.purpose not in UNTRUSTED_PURPOSES:
            continue
        who, objects = _who(net, m)
        gw = device_name(net, d.id)
        yield found(
            f"{gw} forwards {_label(m)} from the internet to {who} in {segment_name(net, seg.id)}, "
            "which a device asked for itself (UPnP)",
            [d.id, seg.id, *objects],
            fix=f"Turn UPnP off on {gw} for this network, or remove the mapping, and add the "
            "port forward by hand if the device really has to be reachable.",
            key=f"{m.protocol}/{m.external_port}/{m.internal_address}",
            mid="upnp.mappingUntrusted",
            fix_id="upnp.mappingUntrusted.fix",
            params={
                "gateway": gw,
                "mapping": _label(m),
                "client": who,
                "segment": segment_name(net, seg.id),
            },
        )


# --- upnp.management-port --------------------------------------------------------------------


@rule(
    "upnp.management-port",
    "A port mapping exposes a management or file sharing port",
    Severity.WARNING,
    "A client asked the gateway to forward a port of a management or file sharing service "
    "(SSH, Telnet, SMB, remote desktop, VNC, Winbox, RouterOS API) to the internet, either as the "
    "port on the internet side or as the port it leads to. Programs that open these without "
    "being asked are a sign of malware or of a service that should not be reachable from "
    "outside. Reported for gateways that report their mappings.",
)
def management_port(net: Network) -> Iterator[Result]:
    for d, m in _mappings(net):
        port = next((p for p in (m.internal_port, m.external_port) if p in MANAGEMENT_PORTS), None)
        if port is None:
            continue
        who, objects = _who(net, m)
        gw = device_name(net, d.id)
        yield found(
            f"{gw} forwards {_label(m)} from the internet to {who}, port {m.internal_port} "
            f"({MANAGEMENT_PORTS[port]})",
            [d.id, *objects],
            fix=f"Remove the mapping on {gw} and find the program that asked for it; if the "
            "service has to be reachable from outside, use a VPN instead.",
            key=f"{m.protocol}/{m.external_port}/{m.internal_address}",
            mid="upnp.managementPort",
            fix_id="upnp.managementPort.fix",
            params={
                "gateway": gw,
                "mapping": _label(m),
                "client": who,
                "port": m.internal_port,
                "service": MANAGEMENT_PORTS[port],
            },
        )


# --- upnp.insecure-mode ----------------------------------------------------------------------


@rule(
    "upnp.insecure-mode",
    "UPnP lets one device map ports for another",
    Severity.WARNING,
    "With secure mode off, any device that talks UPnP can open a port to the internet that leads "
    "to a different device, for example the printer or the NAS. Secure mode limits each "
    "mapping to the device that asks for it. Reported for gateways with UPnP on that say secure "
    "mode is off; quiet where the gateway does not report it.",
)
def insecure_mode(net: Network) -> Iterator[Result]:
    for d in sorted(net.devices, key=lambda d: d.id):
        if d.upnp is None or d.upnp.secure_mode is not False or not _enabled(net, d):
            continue
        gw = device_name(net, d.id)
        yield found(
            f"UPnP on {gw} is not in secure mode: a device can open ports that lead to another one",
            [d.id],
            fix=f"Turn secure mode on for UPnP on {gw} (miniupnpd: secure_mode), or UPnP off.",
            mid="upnp.insecureMode",
            fix_id="upnp.insecureMode.fix",
            params={"gateway": gw},
        )


# --- upnp.many-mappings ----------------------------------------------------------------------


@rule(
    "upnp.many-mappings",
    "A gateway has many dynamic port mappings",
    Severity.INFO,
    "Every application that opens a port through UPnP, NAT-PMP or PCP adds a mapping, and old "
    "ones stay when programs do not remove them (a lease of 0 never ends). A long list is "
    "hard to review and means that something keeps asking, which is worth a look. Reported "
    "when a gateway that reports its mappings has more than the configured number.",
    params=ManyMappingsParams,
)
def many_mappings(net: Network) -> Iterator[Result]:
    for d in sorted(net.devices, key=lambda d: d.id):
        if d.upnp is None or not _enabled(net, d):
            continue
        p = ctx.params(ManyMappingsParams, d)
        count = sum(1 for m in d.upnp.mappings if m.enabled)
        if count <= p.max_mappings:
            continue
        gw = device_name(net, d.id)
        permanent = sum(1 for m in d.upnp.mappings if m.enabled and m.lease_seconds == 0)
        yield found(
            f"{gw} has {count} dynamic port mappings ({permanent} without an end)",
            [d.id],
            fix="Open the list on the device page, remove the ones you do not know, and turn "
            "UPnP off if no device needs it.",
            mid="upnp.manyMappings",
            fix_id="upnp.manyMappings.fix",
            params={"gateway": gw, "count": count, "permanent": permanent},
        )


RULES = [mapping_untrusted, management_port, insecure_mode, many_mappings]
