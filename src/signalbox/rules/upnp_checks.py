"""Dynamic port mappings of UPnP, NAT-PMP and PCP (issue #176, ADR 0029).

The checks use what gateways report about themselves (``Device.upnp``): the protocols, secure
mode and the mappings clients opened. Whether UPnP is on at all, and on which networks, is
``security.upnp`` (roaming_upnp.py). Everything stays quiet where a gateway did not report its
mappings, and a mapping whose target is not a known client is judged by its address only when
a network contains it.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import suppress
from datetime import timedelta
from ipaddress import ip_address

from signalbox.model import (
    UNTRUSTED_PURPOSES,
    Device,
    DynamicPortMapping,
    IPAddress,
    NatClass,
    Network,
    Segment,
    ServiceKind,
)
from signalbox.rules import Result, RuleParams, Severity, ctx, found, history_rule, param, rule
from signalbox.rules._names import device_name, segment_name
from signalbox.sightings import History

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


class StaleMappingParams(RuleParams):
    stale_days: int = param(
        14,
        unit="d",
        ge=1,
        le=365,
        description="Report a mapping whose device was not seen for more than this many days.",
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


# --- upnp.mapping-to-unknown -----------------------------------------------------------------


def _known_addresses(net: Network) -> set[IPAddress]:
    """Addresses of clients and of the devices themselves (their networks, uplinks, management)."""
    known: set[IPAddress] = {a for c in net.clients for a in c.addresses}
    known.update(s.interface.ip for s in net.subnets)
    for u in net.uplinks:
        known.update(a.ip for a in u.addresses)
    for d in net.devices:
        if d.management_address:
            with suppress(ValueError):  # a host name is not an address
                known.add(ip_address(d.management_address))
    return known


@rule(
    "upnp.mapping-to-unknown",
    "A port mapping leads to an address that no known device has",
    Severity.INFO,
    "A mapping on the gateway forwards a port from the internet to an address that no client "
    "and no device of the network has. The device that asked for it may be switched off or "
    "gone, or the request came from somewhere that should not be there; either way a port "
    "stays open to nothing, or to whatever gets this address next. Reported per mapping, for "
    "gateways that report their mappings and only where clients are read.",
)
def mapping_to_unknown(net: Network) -> Iterator[Result]:
    if not net.clients:
        return  # no client list: every address would look unknown
    known = _known_addresses(net)
    for d, m in _mappings(net):
        if m.internal_address in known:
            continue
        gw = device_name(net, d.id)
        yield found(
            f"{gw} forwards {_label(m)} from the internet to {m.internal_address}, which no "
            "known device has",
            [d.id],
            fix=f"Remove the mapping on {gw} if you do not know the device it was for; it opens "
            "again by itself when the program asks for it.",
            key=f"{m.protocol}/{m.external_port}/{m.internal_address}",
            mid="upnp.mappingToUnknown",
            fix_id="upnp.mappingToUnknown.fix",
            params={"gateway": gw, "mapping": _label(m), "address": str(m.internal_address)},
        )


# --- upnp.cgnat-useless ----------------------------------------------------------------------


@rule(
    "upnp.cgnat-useless",
    "UPnP is on, but the internet connection cannot be reached from outside",
    Severity.INFO,
    "UPnP, NAT-PMP and PCP open ports on the gateway's own internet address. When that address is "
    "a carrier-grade NAT address (100.64.0.0/10) or a private one because another router is "
    "in front, the opened ports lead nowhere: nothing from the internet reaches them. UPnP "
    "still lets devices open ports on the gateway for nothing, and programs believe they "
    "are reachable. Reported for a gateway with UPnP on whose connected internet connections "
    "all have such an address.",
)
def cgnat_useless(net: Network) -> Iterator[Result]:
    for d in sorted(net.devices, key=lambda d: d.id):
        if not _enabled(net, d) or (
            d.upnp is None and not any(s.kind is ServiceKind.UPNP for s in net.services_of(d.id))
        ):
            continue
        classes = [u.nat_class() for u in net.uplinks_of(d.id) if u.up is not False]
        if not classes or any(c not in (NatClass.CGNAT, NatClass.PRIVATE) for c in classes):
            continue  # nothing known, or an address that works, or no IPv4 at all
        gw = device_name(net, d.id)
        cgnat = NatClass.CGNAT in classes
        yield found(
            f"UPnP is on at {gw}, but its internet connection is behind "
            + ("carrier-grade NAT" if cgnat else "another router")
            + ": opened ports cannot be reached from the internet",
            [d.id],
            fix=f"Turn UPnP off on {gw}; ports can only be reached from outside with a public "
            "IPv4 address, over IPv6, or through a VPN.",
            key="cgnat" if cgnat else "double-nat",
            mid="upnp.cgnatUseless" if cgnat else "upnp.behindRouterUseless",
            fix_id="upnp.cgnatUseless.fix",
            params={"gateway": gw},
        )


# --- upnp.stale-mapping ----------------------------------------------------------------------


@history_rule(
    "upnp.stale-mapping",
    "A port mapping is for a device that has not been seen for a long time",
    Severity.INFO,
    "A client opened a port on the gateway and has not been seen for the configured number of "
    "days (14 by default), but the mapping is still there. Programs that do not close their "
    "ports leave them open for good, and the address can go to another device later. The time "
    "the device was last seen comes from the client list and the history. Quiet where the "
    "device is unknown (see upnp.mapping-to-unknown) or the gateway does not report mappings.",
    params=StaleMappingParams,
)
def stale_mapping(net: Network, history: History) -> Iterator[Result]:
    now = history.now
    if now is None:
        return
    for d, m in _mappings(net):
        client = next((c for c in net.clients if m.internal_address in c.addresses), None)
        if client is None:
            continue
        past = history.clients.get(client.mac)
        seen = [t for t in (client.last_seen, past.last_seen if past else None) if t]
        p = ctx.params(StaleMappingParams, d)
        if not seen or now - max(seen) <= timedelta(days=p.stale_days):
            continue
        who = client.hostname or str(m.internal_address)
        gw = device_name(net, d.id)
        days = (now - max(seen)).days
        yield found(
            f"{gw} still forwards {_label(m)} from the internet to {who}, which was not seen "
            f"for {days} days",
            [d.id, client.id],
            fix=f"Remove the mapping on {gw}, or turn UPnP off if no device needs it.",
            key=f"{m.protocol}/{m.external_port}/{m.internal_address}",
            mid="upnp.staleMapping",
            fix_id="upnp.staleMapping.fix",
            params={"gateway": gw, "mapping": _label(m), "client": who, "days": days},
        )


RULES = [
    mapping_untrusted,
    management_port,
    insecure_mode,
    many_mappings,
    mapping_to_unknown,
    cgnat_useless,
    stale_mapping,
]
