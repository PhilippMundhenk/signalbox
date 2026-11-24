"""Port rules: VLAN membership and PVID of a port, both ends of a link agree on its settings.

These rules use the port configuration details of the ``interfaces`` capability (PVID, admin
state, MTU, auto-negotiation, EEE, description; issue #156). Every detail is optional: a port
that does not report one is skipped, never reported as wrong.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from ipaddress import IPv4Address, IPv6Address

from signalbox.model import (
    STANDARD_MTU,
    FdbKind,
    FrameTypes,
    Link,
    LinkKind,
    Membership,
    Network,
    Port,
    PortKind,
)
from signalbox.rules import Result, Severity, found, rule
from signalbox.rules._names import device_name, segment_name
from signalbox.rules.vlan import INFRASTRUCTURE

#: Port kinds that are cables (or bundles of cables); wireless, bridge and virtual ports are not.
_WIRED = (PortKind.ETHERNET, PortKind.LAG)


def _port_name(net: Network, port_id: str) -> str:
    p = net.port(port_id)
    if p is None:
        dev, _, name = port_id.partition("/port/")
        return f"{device_name(net, dev)} port {name or port_id}"
    return f"{device_name(net, p.device_id)} port {p.label()}"


def _and(items: list[str]) -> str:
    return ", ".join(items[:-1]) + " and " + items[-1] if len(items) > 1 else "".join(items)


def _cable_ends(net: Network) -> Iterator[tuple[Link, Port, Port]]:
    """Cable links whose two ends are known wired ports, not internal ones (#252)."""
    for link in net.links:
        if link.kind is LinkKind.WIRELESS:
            continue
        a, b = net.port(link.a), net.port(link.b)
        if a is None or b is None or a.kind not in _WIRED or b.kind not in _WIRED:
            continue
        if a.external is False or b.external is False:
            continue
        yield link, a, b


def _site(net: Network, device_id: str) -> str | None:
    dev = net.device(device_id)
    return dev.site_id if dev else None


def _segment_site(net: Network, segment_id: str) -> str:
    seg = net.segment(segment_id)
    return seg.site_id if seg else segment_id.split("/segment/", 1)[0]


# --- vlan.single-untagged ------------------------------------------------------------------


@rule(
    "vlan.single-untagged",
    "Port is untagged in more than one VLAN, or its PVID is another VLAN",
    Severity.ERROR,
    "A port sends at most one network untagged. With two untagged VLANs the device behind it "
    "sees both networks mixed (a VLAN leak). A PVID (the VLAN for incoming untagged frames) "
    "that is not the port's untagged VLAN puts incoming traffic into another network than the "
    "outgoing one: DHCP may work, nothing else does.",
)
def single_untagged(net: Network) -> Iterator[Result]:
    for p in sorted(net.ports, key=lambda p: p.id):
        if p.kind not in _WIRED or p.external is False:
            continue  # bridges, Wi-Fi, CPU ports (#252): no device behind them
        untagged = net.untagged_segments(p.id)
        name = _port_name(net, p.id)
        if len(untagged) > 1:
            names = _and([segment_name(net, s) for s in untagged])
            yield found(
                f"{name} is untagged in {names}.",
                [p.id, *untagged],
                fix="Keep one untagged VLAN on the port (set the PVID to the same one) and make "
                "the others tagged.",
                key="several",
            )
            continue
        pvid = net.pvid_segment(p.id)
        if not untagged or pvid is None or pvid in untagged:
            continue  # tagged only, PVID unknown, or both agree
        yield found(
            f"{name} sends {segment_name(net, untagged[0])} untagged, but its PVID puts incoming "
            f"untagged frames into {segment_name(net, pvid)}.",
            [p.id, untagged[0]],
            fix=f"Set the PVID of {name} to the VLAN of {segment_name(net, untagged[0])}, or make "
            "that VLAN tagged on the port.",
            key="pvid",
        )


# --- vlan.client-port-mismatch -------------------------------------------------------------


def _usable(address: IPv4Address | IPv6Address) -> bool:
    return not (address.is_link_local or address.is_loopback or address.is_unspecified)


def _client_segment(net: Network, addresses: list[IPv4Address | IPv6Address], site: str) -> str:
    """The one network of the site whose subnets hold the addresses, or '' if none or several."""
    segments = {
        sn.segment_id
        for a in addresses
        if _usable(a)
        for sn in net.subnets
        if a.version == sn.interface.version
        and a in sn.interface.network
        and _segment_site(net, sn.segment_id) == site
    }
    return next(iter(segments)) if len(segments) == 1 else ""


def _port_segment(net: Network, p: Port, tagged: set[str]) -> str | None:
    """The network an access port puts its client into, or None for trunks and unknown ports."""
    if p.id in tagged or p.frame_types is FrameTypes.TAGGED_ONLY:
        return None
    pvid = net.pvid_segment(p.id)
    if pvid is not None:
        return pvid
    untagged = net.untagged_segments(p.id)
    return untagged[0] if len(untagged) == 1 else None


def _learned_segment(net: Network, mac: str, port_id: str) -> str | None:
    """The network the switch learned ``mac`` in on this port (MAC address table, #160)."""
    segments = {
        e.segment_id
        for e in net.fdb_on(port_id)
        if e.mac == mac and e.kind is not FdbKind.SELF and e.segment_id is not None
    }
    return next(iter(segments)) if len(segments) == 1 else None


def _others_behind(net: Network, port_id: str, mac: str) -> bool:
    return any(e.mac != mac and e.kind is not FdbKind.SELF for e in net.fdb_on(port_id))


@rule(
    "vlan.client-port-mismatch",
    "Wired client is in another network than its switch port",
    Severity.WARNING,
    "A device on an access port belongs to the port's VLAN. If its address is in another "
    "network, the port's VLAN setting is wrong, the device tags its own frames (a hypervisor, "
    "a misconfigured NAS) or a hidden switch with other VLAN settings sits in between. Where "
    "the switch reports a MAC address table, the VLAN it learned the device in counts as the "
    "port's network, and a port that learns other addresses too (a hidden switch) is skipped.",
)
def client_port_mismatch(net: Network) -> Iterator[Result]:
    by_port: dict[str, list[int]] = {}
    for i, c in enumerate(net.clients):
        if c.seen_on:
            by_port.setdefault(c.seen_on, []).append(i)
    ends = {e for link in net.links for e in (link.a, link.b)}
    tagged = {m.port_id for s in net.segments for m in s.members if m.mode is Membership.TAGGED}
    with_subnet = {sn.segment_id for sn in net.subnets}
    for port_id, indexes in sorted(by_port.items()):
        p = net.port(port_id)
        if p is None or p.kind is not PortKind.ETHERNET or port_id in ends or len(indexes) > 1:
            continue  # not a wired access port, an uplink, or several devices behind it
        if p.external is False:
            continue  # a CPU port (#252) carries every VLAN of the switch
        site = _site(net, p.device_id)
        c = net.clients[indexes[0]]
        learned = _learned_segment(net, c.mac, port_id)
        if _others_behind(net, port_id, c.mac):
            continue  # the device's table shows other devices behind the port
        port_seg = learned or _port_segment(net, p, tagged)
        if site is None or port_seg is None or port_seg not in with_subnet:
            continue
        client_seg = _client_segment(net, list(c.addresses), site)
        if not client_seg or client_seg == port_seg:
            continue
        who = c.hostname or c.mac
        shown = next(
            str(a)
            for a in c.addresses
            if _usable(a)
            and any(
                a in sn.interface.network
                for sn in net.subnets
                if sn.segment_id == client_seg and a.version == sn.interface.version
            )
        )
        source = "PVID" if net.pvid_segment(p.id) is not None else "access port"
        yield found(
            f"{who} is on {_port_name(net, port_id)} ({segment_name(net, port_seg)}, {source}) "
            f"but uses {shown} in {segment_name(net, client_seg)}.",
            [c.id, port_id],
            fix="Check the VLAN of the port and the network settings of the device (a fixed "
            "address, VLAN tagging on the device, or a switch in between).",
        )


# --- link.mtu ------------------------------------------------------------------------------


def _mtu_text(p: Port) -> str:
    if p.mtu is not None:
        return f"MTU {p.mtu}"
    return "jumbo frames on" if p.jumbo_frames() else "jumbo frames off"


@rule(
    "link.mtu",
    "MTU differs between the ends of a link",
    Severity.WARNING,
    "Both ends of a cable should use the same MTU. Jumbo frames (MTU 9000) on one end and 1500 "
    "on the other drop only large packets: ping works, but file copies and backups hang.",
)
def link_mtu(net: Network) -> Iterator[Result]:
    for link, a, b in _cable_ends(net):
        if a.mtu is not None and b.mtu is not None:
            differ = a.mtu != b.mtu
        else:
            ja, jb = a.jumbo_frames(), b.jumbo_frames()
            differ = ja is not None and jb is not None and ja != jb
        if not differ:
            continue
        yield found(
            f"{_port_name(net, a.id)} has {_mtu_text(a)}, the connected port "
            f"{_port_name(net, b.id)} {_mtu_text(b)}.",
            [link.id, a.id, b.id],
            fix=f"Use the same MTU on both ends ({STANDARD_MTU} unless every device on the path "
            "supports jumbo frames).",
        )


# --- port.admin-down-with-neighbour --------------------------------------------------------


@rule(
    "port.admin-down-with-neighbour",
    "Disabled port with a connected device",
    Severity.WARNING,
    "The port is switched off in its configuration, but a cable link or an LLDP neighbour says "
    "a device is connected to it. Often a port that was disabled for a test and forgotten, or "
    "the cable is in the wrong port.",
)
def admin_down_with_neighbour(net: Network) -> Iterator[Result]:
    far: dict[str, set[str]] = {}
    for link in net.links:
        if link.kind is LinkKind.WIRELESS:
            continue
        for here, there in ((link.a, link.b), (link.b, link.a)):
            far.setdefault(here, set()).add(_port_name(net, there))
    for nb in net.neighbours:
        far.setdefault(nb.local_port_id, set()).add(nb.system_name or nb.chassis_id)
    for p in sorted(net.ports, key=lambda p: p.id):
        if p.admin_up is not False or p.id not in far:
            continue
        yield found(
            f"{_port_name(net, p.id)} is disabled, but {_and(sorted(far[p.id]))} is connected "
            "to it.",
            [p.id],
            fix="Enable the port, or move the cable to an enabled port (and remove a link you "
            "entered by hand if the cable is gone).",
        )


# --- port.eee-on-uplink --------------------------------------------------------------------


@rule(
    "port.eee-on-uplink",
    "Energy-efficient Ethernet on a link between network devices",
    Severity.INFO,
    "Energy-efficient Ethernet (EEE, 802.3az) lets a port sleep between packets. On links "
    "between switches, routers and access points it saves little and is a known cause of link "
    "drops, added latency and interoperability problems, especially on cheap switches.",
)
def eee_on_uplink(net: Network) -> Iterator[Result]:
    roles = {d.id: d.role for d in net.devices}
    for link, a, b in _cable_ends(net):
        if roles.get(a.device_id) not in INFRASTRUCTURE:
            continue
        if roles.get(b.device_id) not in INFRASTRUCTURE:
            continue
        on = [p for p in (a, b) if p.eee is True]
        if not on:
            continue
        names = _and([_port_name(net, p.id) for p in on])
        yield found(
            f"Energy-efficient Ethernet is on for {names} (link {_port_name(net, a.id)} to "
            f"{_port_name(net, b.id)}).",
            [link.id, *(p.id for p in on)],
            fix=f"Turn off energy-efficient Ethernet (EEE, green Ethernet) on {names}.",
        )


# --- port.autoneg-mismatch -----------------------------------------------------------------


def _forced(p: Port) -> str:
    if p.speed_mbps is None:
        return "a fixed speed"
    duplex = {True: " full duplex", False: " half duplex", None: ""}[p.full_duplex]
    return f"a fixed {p.speed_mbps} Mbit/s{duplex}"


@rule(
    "port.autoneg-mismatch",
    "Auto-negotiation on only one end of a link",
    Severity.WARNING,
    "When one end of a cable has a fixed speed and the other uses auto-negotiation, the "
    "auto-negotiating end cannot learn the duplex mode and falls back to half duplex. The link "
    "works, but slowly and with collisions and errors.",
)
def autoneg_mismatch(net: Network) -> Iterator[Result]:
    for link, a, b in _cable_ends(net):
        if a.autoneg is None or b.autoneg is None or a.autoneg == b.autoneg:
            continue
        fixed, auto = (a, b) if a.autoneg is False else (b, a)
        yield found(
            f"{_port_name(net, fixed.id)} is set to {_forced(fixed)}, the connected port "
            f"{_port_name(net, auto.id)} uses auto-negotiation.",
            [link.id, a.id, b.id],
            fix="Set both ports to auto-negotiation (or, only if a device requires it, the same "
            "fixed speed and duplex on both).",
        )


# --- port.description-mismatch -------------------------------------------------------------

#: Device names shorter than this are too generic to look for in a port description.
_MIN_NAME = 4


def _words(text: str) -> tuple[str, ...]:
    return tuple(w for w in re.split(r"[^0-9a-z]+", text.lower()) if w)


def _mentions(description: tuple[str, ...], name: str) -> bool:
    """True when the device name appears in the description as a run of whole words."""
    words = _words(name)
    if not words or len("".join(words)) < _MIN_NAME:
        return False
    n = len(words)
    return any(description[i : i + n] == words for i in range(len(description) - n + 1))


@rule(
    "port.description-mismatch",
    "Port description names another device than the connected one",
    Severity.INFO,
    "The description of the port names a device that Signalbox knows, but the cable link or "
    "LLDP shows another device on that port. Either the cable was moved or the description is "
    "out of date; both mislead whoever works on the network next.",
)
def description_mismatch(net: Network) -> Iterator[Result]:
    far_devices: dict[str, set[str]] = {}
    for link in net.links:
        if link.kind is LinkKind.WIRELESS:
            continue
        for here, there in ((link.a, link.b), (link.b, link.a)):
            dev = net.port(there)
            dev_id = dev.device_id if dev else there.split("/port/", 1)[0]
            if net.device(dev_id) is not None:
                far_devices.setdefault(here, set()).add(dev_id)
    lldp_names: dict[str, set[str]] = {}
    for nb in net.neighbours:
        if nb.system_name:
            lldp_names.setdefault(nb.local_port_id, set()).add(nb.system_name)
    for p in sorted(net.ports, key=lambda p: p.id):
        if not p.description or p.kind not in _WIRED or p.id not in far_devices:
            continue
        words = _words(p.description)
        actual = far_devices[p.id]
        names = {device_name(net, d) for d in actual} | lldp_names.get(p.id, set())
        if any(_mentions(words, n) for n in names):
            continue
        named = sorted(
            d.name
            for d in net.devices
            if d.id != p.device_id and d.id not in actual and _mentions(words, d.name)
        )
        if not named:
            continue
        connected = _and(sorted(device_name(net, d) for d in actual))
        yield found(
            f"The description of {_port_name(net, p.id)} names {_and(named)}, but {connected} "
            "is connected to it.",
            [p.id],
            fix="Update the port description, or check whether the cable is in the right port.",
        )


RULES = [
    single_untagged,
    client_port_mismatch,
    link_mtu,
    admin_down_with_neighbour,
    eee_on_uplink,
    autoneg_mismatch,
    description_mismatch,
]
