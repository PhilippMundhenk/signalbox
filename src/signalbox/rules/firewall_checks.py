"""Rules that read the firewall model (#135, ADR 0013): port forwards, what guest and IoT
networks reach, and zones.

They stay quiet where the firewall was not read or does not decide exactly: a rule here only
reports what the rules and policies surely say.
"""

from __future__ import annotations

from collections.abc import Iterator
from ipaddress import IPv4Address

from signalbox.firewall import (
    address_owner,
    address_segment,
    forward_target_ports,
    own_addresses,
    port_ranges_overlap,
    reach,
)
from signalbox.model import (
    AddressSource,
    Firewall,
    IPAddress,
    Network,
    PortForward,
    SegmentPurpose,
    Verdict,
)
from signalbox.purpose import untrusted
from signalbox.rules import Result, Rule, Severity, found, rule
from signalbox.rules._names import device_name, segment_name


def _forwards(net: Network) -> Iterator[tuple[Firewall, int, PortForward]]:
    for fw in sorted(net.firewalls, key=lambda f: f.id):
        for i, pf in enumerate(fw.port_forwards):
            if pf.enabled:
                yield fw, i, pf


def _what(pf: PortForward) -> str:
    proto = "/".join(p.value.upper() for p in pf.protocols) or "all protocols"
    ports = ", ".join(str(r) for r in pf.external_ports)
    return f"{proto} {ports}" if ports else f"{proto} (exposed host)"


def _label(pf: PortForward, index: int) -> str:
    return f"{pf.name!r} ({_what(pf)})" if pf.name else f"forward {index + 1} ({_what(pf)})"


def _purpose(net: Network, segment_id: str) -> SegmentPurpose | None:
    seg = net.segment(segment_id)
    return seg.purpose if seg else None


def _is_reserved(net: Network, segment_id: str, address: IPAddress) -> bool:
    for server in net.dhcp_servers_on(segment_id):
        if any(r.address == address for r in server.reservations):
            return True
        if any(x.address == address and x.reserved for x in server.leases or []):
            return True
    return any(
        c.address_sources.get(address) in (AddressSource.DHCP_RESERVED, AddressSource.STATIC)
        for c in net.clients
        if address in c.addresses
    )


# --- security.port-forward-target (#125) ---------------------------------------------------


@rule(
    "security.port-forward-target",
    "Port forward to an unsuitable target",
    Severity.WARNING,
    "A port forward (destination NAT) on a router leads to an address that will not stay the "
    "right device or that should not be exposed: a dynamic DHCP address (the forward ends up "
    "on whatever device gets the address next), an address in no known network (a dead "
    "service), an address no known device uses, a client in an IoT or camera network "
    "(information), or a management service of a network device (an error). Disabled forwards "
    "are not checked; guest networks are firewall.forward-into-guest.",
)
def port_forward_target(net: Network) -> Iterator[Result]:
    for fw, i, pf in _forwards(net):
        target = pf.target_address
        dev = device_name(net, fw.device_id)
        label = _label(pf, i)
        head = f"{dev} forwards {label} to {target}"
        base = {"device": dev, "label": label, "target": str(target)}
        objects = [fw.device_id, fw.id]
        seg = address_segment(net, target)
        owner = address_owner(net, target)
        if owner is not None:
            exposed = [
                s
                for s in net.services_of(owner)
                if s.enabled
                and s.port is not None
                and any(s.port in r for r in forward_target_ports(pf))
            ]
            if exposed:
                yield found(
                    f"{head}, where {device_name(net, owner)} offers "
                    f"{', '.join(s.label() for s in exposed)}: its management reaches the "
                    "internet",
                    [*objects, owner, *(s.id for s in exposed)],
                    severity=Severity.ERROR,
                    fix="Forward to a different device or port, or remove the forward and use "
                    "a VPN for administration from outside.",
                    key=f"{i}/management",
                    mid="fw.forwardMgmt",
                    fix_id="fw.forwardMgmt.fix",
                    params={
                        **base,
                        "owner": device_name(net, owner),
                        "services": ", ".join(s.label() for s in exposed),
                    },
                )
        if seg is None:
            if target.is_private and net.subnets:
                yield found(
                    f"{head}, which is in none of the networks Signalbox knows",
                    objects,
                    fix="Check the target address: the device may have moved or the forward is "
                    "a leftover. Remove it if it is not needed.",
                    key=f"{i}/unknown-network",
                    mid="fw.forwardUnknownNet",
                    fix_id="fw.forwardUnknownNet.fix",
                    params=base,
                )
            continue
        purpose = _purpose(net, seg)
        if purpose in (SegmentPurpose.IOT, SegmentPurpose.CAMERAS):
            yield found(
                f"{head}, in the {purpose.value} network {segment_name(net, seg)}",
                [*objects, seg],
                severity=Severity.INFO,
                fix="Make sure that is intended: devices in this network are exposed to the "
                "internet. Prefer a VPN to reach them.",
                key=f"{i}/untrusted",
                mid="fw.forwardUntrusted",
                fix_id="fw.forwardUntrusted.fix",
                params={**base, "purpose": purpose.value, "segment": segment_name(net, seg)},
            )
        servers = [s for s in net.dhcp_servers_on(seg) if s.enabled]
        if (
            owner is None
            and any(s.in_pool(target) for s in servers)
            and not _is_reserved(net, seg, target)
        ):
            yield found(
                f"{head}, a dynamic DHCP address in {segment_name(net, seg)}",
                [*objects, seg],
                fix=f"Reserve {target} for the intended device's MAC address (or give it a "
                "fixed address outside the pool) so the forward cannot end up on another "
                "device.",
                key=f"{i}/dynamic",
                mid="fw.forwardDynamic",
                fix_id="fw.forwardDynamic.fix",
                params={**base, "segment": segment_name(net, seg)},
            )
        elif (
            owner is None
            and any(c.segment_id == seg for c in net.clients)
            and not any(target in c.addresses for c in net.clients)
            and not any(x.address == target for s in servers for x in s.leases or [])
        ):
            yield found(
                f"{head}, but no known device uses that address",
                [*objects, seg],
                severity=Severity.INFO,
                fix="Check whether the device is off or has a different address now; remove "
                "the forward if the service is gone.",
                key=f"{i}/no-client",
                mid="fw.forwardNoClient",
                fix_id="fw.forwardNoClient.fix",
                params=base,
            )


# --- firewall.forward-into-guest -------------------------------------------------------------


@rule(
    "firewall.forward-into-guest",
    "Port forward into a guest network",
    Severity.WARNING,
    "A port forward leads to an address in a guest network. Guest networks are meant for "
    "visitors' devices that nobody depends on: a service there is exposed to the internet and "
    "to every guest, and it stops working when the guest network is reset or isolated.",
)
def forward_into_guest(net: Network) -> Iterator[Result]:
    for fw, i, pf in _forwards(net):
        seg = address_segment(net, pf.target_address)
        if seg is None or _purpose(net, seg) is not SegmentPurpose.GUEST:
            continue
        yield found(
            f"{device_name(net, fw.device_id)} forwards {_label(pf, i)} to "
            f"{pf.target_address} in the guest network {segment_name(net, seg)}",
            [fw.device_id, fw.id, seg],
            fix="Move the service to a server or main network and forward there; keep guests "
            "away from anything that is exposed to the internet.",
            key=str(i),
            mid="fw.forwardGuest",
            fix_id="fw.forwardGuest.fix",
            params={
                "device": device_name(net, fw.device_id),
                "label": _label(pf, i),
                "target": str(pf.target_address),
                "segment": segment_name(net, seg),
            },
        )


# --- firewall.duplicate-port-forward -----------------------------------------------------------


def _overlap(a: PortForward, b: PortForward) -> list[tuple[int, int]]:
    if not a.external_ports or not b.external_ports:
        return []
    if a.protocols and b.protocols and not set(a.protocols) & set(b.protocols):
        return []
    if a.zones and b.zones and not set(a.zones) & set(b.zones):
        return []
    if a.external_address and b.external_address and a.external_address != b.external_address:
        return []
    if a.sources and b.sources and set(a.sources) != set(b.sources):
        return []  # may be for different clients
    return port_ranges_overlap(a.external_ports, b.external_ports)


@rule(
    "firewall.duplicate-port-forward",
    "The same external port is forwarded twice",
    Severity.WARNING,
    "Two enabled port forwards of one router listen on the same external port, protocol and "
    "uplink. Only one of them gets the connections (which one depends on the order); the other "
    "is dead. Forwards limited to different source networks are not compared.",
)
def duplicate_port_forward(net: Network) -> Iterator[Result]:
    for fw in sorted(net.firewalls, key=lambda f: f.id):
        items = [(i, pf) for i, pf in enumerate(fw.port_forwards) if pf.enabled]
        for n, (i, a) in enumerate(items):
            for j, b in items[n + 1 :]:
                hit = _overlap(a, b)
                if not hit:
                    continue
                ports = ", ".join(str(lo) if lo == hi else f"{lo}-{hi}" for lo, hi in hit)
                yield found(
                    f"{device_name(net, fw.device_id)} forwards external port {ports} twice: "
                    f"{_label(a, i)} to {a.target_address} and {_label(b, j)} to "
                    f"{b.target_address}",
                    [fw.device_id, fw.id],
                    fix="Remove one of the forwards, or give them different external ports.",
                    key=f"{i}/{j}",
                    mid="fw.duplicateForward",
                    fix_id="fw.duplicateForward.fix",
                    params={
                        "device": device_name(net, fw.device_id),
                        "ports": ports,
                        "first": _label(a, i),
                        "first_target": str(a.target_address),
                        "second": _label(b, j),
                        "second_target": str(b.target_address),
                    },
                )


# --- firewall.segment-without-zone -----------------------------------------------------------


@rule(
    "firewall.segment-without-zone",
    "Routed network that no firewall zone covers",
    Severity.WARNING,
    "A router has an address in a network, but none of its firewall zones contains that "
    "network. Its traffic then follows no zone policy: depending on the vendor it is blocked, "
    "or it bypasses the rules you wrote for the other networks. Typical after adding a VLAN. "
    "Only checked when the firewall was read completely.",
)
def segment_without_zone(net: Network) -> Iterator[Result]:
    for fw in sorted(net.firewalls, key=lambda f: f.id):
        if not fw.enabled or not fw.rules_complete or not fw.zones:
            continue
        if any(not z.complete or z.ports for z in fw.zones):
            continue  # an interface may be the network
        for seg in sorted({s.segment_id for s in net.subnets if s.device_id == fw.device_id}):
            if fw.zones_of(seg):
                continue
            yield found(
                f"{device_name(net, fw.device_id)} routes {segment_name(net, seg)}, but no "
                "firewall zone covers it",
                [fw.device_id, fw.id, seg],
                fix="Add the network's interface to a firewall zone (or create one for it) so "
                "that the rules and policies apply.",
                key=seg,
                mid="fw.noZone",
                fix_id="fw.noZone.fix",
                params={
                    "device": device_name(net, fw.device_id),
                    "segment": segment_name(net, seg),
                },
            )


# --- firewall.untrusted-reaches-lan ------------------------------------------------------------

_TRUSTED = (SegmentPurpose.MAIN, SegmentPurpose.MANAGEMENT)


def _probe(net: Network, segment_id: str) -> IPv4Address | None:
    """An IPv4 address in the segment that no known device, router or client uses."""
    used = {a for d in net.devices for a in own_addresses(net, d.id)}
    used |= {a for c in net.clients for a in c.addresses}
    for sub in sorted(net.subnets, key=lambda s: str(s.interface)):
        if sub.segment_id == segment_id and isinstance(sub.interface.ip, IPv4Address):
            for host in sub.interface.network.hosts():
                if host not in used:
                    return host
    return None


@rule(
    "firewall.untrusted-reaches-lan",
    "Guest or IoT network can reach the main or management network",
    Severity.WARNING,
    "The firewall of the router between them accepts new connections from a guest, IoT or "
    "camera network to any address and port of a main or management network. A compromised "
    "smart plug or a guest's laptop can then scan and attack your computers and network "
    "devices. Reported only when the rules and policies surely allow it: a firewall that was "
    "not read or does not decide exactly, and rules that allow only some ports, stay quiet.",
)
def untrusted_reaches_lan(net: Network) -> Iterator[Result]:
    for src in sorted(net.segments, key=lambda s: s.id):
        if src.purpose is None or not untrusted(src.purpose) or src.isolated:
            continue
        for dst in sorted(net.segments, key=lambda s: s.id):
            if dst.id == src.id or dst.purpose not in _TRUSTED:
                continue
            probe = _probe(net, dst.id)
            if probe is None:
                continue
            v = reach(net, src.id, probe)
            if v.verdict is not Verdict.ALLOWED or v.device_id is None:
                continue
            router = device_name(net, v.device_id)
            yield found(
                f"{segment_name(net, src.id)} ({src.purpose.value}) can reach "
                f"{segment_name(net, dst.id)} (main or management) through {router}: "
                f"{v.reason}",
                [v.device_id, src.id, dst.id],
                fix=f"Block {segment_name(net, src.id)} from {segment_name(net, dst.id)} in the "
                f"firewall of {router}; allow only what is needed (DNS, a printer, a media "
                "server).",
                key=f"{src.id}/{dst.id}",
                mid="fw.untrustedReachesLan",
                fix_id="fw.untrustedReachesLan.fix",
                params={
                    "source": segment_name(net, src.id),
                    "purpose": src.purpose.value,
                    "target": segment_name(net, dst.id),
                    "router": router,
                    "reason": v.reason,
                },
            )


RULES: list[Rule] = [
    port_forward_target,
    forward_into_guest,
    duplicate_port_forward,
    segment_without_zone,
    untrusted_reaches_lan,
]
