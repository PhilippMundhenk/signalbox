"""Rules about what networks are for (issue #164): guest Wi-Fi, IoT and management exposure.

They read the purpose of segments and SSIDs (:mod:`signalbox.purpose`): declared in the desired
state, reported by the device, or guessed from the name. A guess makes a finding milder and says
so; declaring the purpose removes the doubt.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Iterator
from ipaddress import ip_address

from signalbox.firewall import reach
from signalbox.model import (
    Band,
    DeviceRole,
    FirewallProtocol,
    ManagementService,
    Network,
    PurposeSource,
    SegmentPurpose,
    ServiceTransport,
    Verdict,
    Wlan,
)
from signalbox.purpose import untrusted, wlan_purpose, wlan_source
from signalbox.rules import Result, Rule, Severity, found, incomplete, rule
from signalbox.rules._names import device_name, segment_name, site_of_device
from signalbox.rules.vlan import INFRASTRUCTURE, address_segment

_GUESSED = " (guessed from its name)"
_DECLARE = (
    "If the guess is wrong, declare the purpose in the desired state "
    "(purpose: main on the SSID or segment)."
)


def _names(items: Iterable[str]) -> str:
    items = list(items)
    return ", ".join(items[:-1]) + " and " + items[-1] if len(items) > 1 else "".join(items)


def _enabled(net: Network) -> list[Wlan]:
    return sorted((w for w in net.wlans if w.enabled), key=lambda w: w.id)


def _network_text(net: Network, segment_id: str) -> str:
    """``the IoT network IoT (VLAN 20)``, with a note when the purpose is a guess."""
    seg = net.segment(segment_id)
    name = segment_name(net, segment_id)
    if seg is None or seg.purpose is None:
        return name
    guessed = _GUESSED if seg.purpose_source is PurposeSource.HEURISTIC else ""
    label = "IoT" if seg.purpose is SegmentPurpose.IOT else seg.purpose.value
    return f"the {label} network {name}{guessed}"


# --- wifi.guest-isolation (#99) ------------------------------------------------------------


@rule(
    "wifi.guest-isolation",
    "Guest Wi-Fi shares a network with the main LAN",
    Severity.ERROR,
    "A guest SSID puts its clients into the same network (VLAN) as the main LAN or as other, "
    "non-guest SSIDs. The guest password is shared freely; guests then reach the NAS, printers "
    "and admin pages. Guest SSIDs are those declared as guest in the desired state or named "
    "like one (guest, gast, visitor; then only a warning). A guest network the device reports "
    "itself (Fritz!Box guest access, Omada guest network) is kept apart by that device and not "
    "checked.",
)
def guest_isolation(net: Network) -> Iterator[Result]:
    wlans = _enabled(net)
    groups: dict[tuple[str, str], list[Wlan]] = defaultdict(list)
    for w in wlans:
        if w.purpose is not SegmentPurpose.GUEST or w.purpose_source is PurposeSource.REPORTED:
            continue
        if w.segment_id is not None:
            groups[(w.ssid, w.segment_id)].append(w)
    for (ssid, seg_id), group in sorted(groups.items()):
        seg = net.segment(seg_id)
        if seg is not None and (seg.purpose is SegmentPurpose.GUEST or seg.isolated):
            continue
        site = site_of_device(net, group[0].device_id)
        others = sorted(
            {
                w.ssid
                for w in wlans
                if w.segment_id == seg_id
                and w.ssid != ssid
                and site_of_device(net, w.device_id) == site
                and wlan_purpose(net, w) is not SegmentPurpose.GUEST
            }
        )
        if others:
            shared = f"the same network as {_names(repr(o) for o in others)}"
        elif seg is not None and seg.purpose is not None:
            shared = f"which is {_network_text(net, seg_id)}"
        elif seg is None or seg.vlan is None:
            shared = "the untagged main network"
        else:
            continue  # its own VLAN without a known purpose: segment.purpose-missing asks
        guessed = all(w.purpose_source is PurposeSource.HEURISTIC for w in group)
        aps = _names(sorted({device_name(net, w.device_id) for w in group}))
        yield found(
            f"The guest Wi-Fi {ssid!r}{_GUESSED if guessed else ''} on {aps} is in "
            f"{segment_name(net, seg_id)}, {shared}",
            [*sorted(w.id for w in group), seg_id],
            fix="Bind it to a separate guest VLAN (or the router's guest network)."
            + (f" {_DECLARE}" if guessed else ""),
            severity=Severity.WARNING if guessed else None,
            key=ssid,
        )


# --- segment.guest-no-isolation (#164) -----------------------------------------------------


@rule(
    "segment.guest-no-isolation",
    "Guest Wi-Fi without client isolation",
    Severity.WARNING,
    "Stations of a guest SSID can reach each other: one infected phone of a visitor can attack "
    "the others, and anyone with the guest password can see the devices of the other guests. "
    "Access points can block this (client isolation, AP isolation). Checked where the access "
    "point reports the setting (OpenWrt) and the network is not isolated by the device anyway.",
)
def guest_no_isolation(net: Network) -> Iterator[Result]:
    groups: dict[str, list[Wlan]] = defaultdict(list)
    for w in _enabled(net):
        if wlan_purpose(net, w) is not SegmentPurpose.GUEST or w.client_isolation is not False:
            continue
        seg = net.segment(w.segment_id) if w.segment_id else None
        if seg is not None and seg.isolated:
            continue
        groups[w.ssid].append(w)
    for ssid, group in sorted(groups.items()):
        guessed = all(wlan_source(net, w) is PurposeSource.HEURISTIC for w in group)
        aps = _names(sorted({device_name(net, w.device_id) for w in group}))
        yield found(
            f"The guest Wi-Fi {ssid!r}{_GUESSED if guessed else ''} on {aps} lets its "
            "clients reach each other",
            sorted(w.id for w in group),
            fix="Turn on client isolation for the SSID (desired state: client_isolation: true; "
            "OpenWrt: option isolate '1').",
            key=ssid,
        )


# --- security.management-exposure (#120, level 1) ------------------------------------------


@rule(
    "security.management-exposure",
    "Network device managed in a guest or IoT network",
    Severity.ERROR,
    "A switch or access point is managed at an address in a guest or IoT network (or has an "
    "address there). Guests, or a compromised smart plug, can then reach its login page: brute "
    "force and firmware exploits are one step away. A router has an address in every network "
    "it serves; whether its web interface is reachable from there depends on its firewall: "
    "where that is not read, the case is reported as not checked, otherwise "
    "security.service-exposure decides. Level 2: with the firewall rules read (#135), a "
    "management service of a device in another network that guest, IoT or camera networks "
    "reach through the router is reported too; where the firewall does not decide exactly, "
    "the rule stays quiet.",
)
def management_exposure(net: Network) -> Iterator[Result]:
    reported: set[tuple[str, str]] = set()
    for d in sorted(net.devices, key=lambda d: d.id):
        if d.role not in INFRASTRUCTURE:
            continue
        seg = address_segment(net, d)
        if seg is None or not untrusted(_purpose(net, seg)):
            continue
        reported.add((d.id, seg))
        if d.role is DeviceRole.GATEWAY:
            continue  # the router case below
        yield found(
            f"{d.name} is managed at {d.management_address} in {_network_text(net, seg)}",
            [d.id, seg],
            fix=f"Move its management address to the LAN or a management VLAN, or block access "
            f"from {segment_name(net, seg)} to it.",
        )
    routers: dict[tuple[str, str], list[str]] = defaultdict(list)
    for sn in sorted(net.subnets, key=lambda s: s.id):
        dev = net.device(sn.device_id)
        if dev is None or dev.role not in INFRASTRUCTURE:
            continue
        if not untrusted(_purpose(net, sn.segment_id)):
            continue
        if dev.role is DeviceRole.GATEWAY or sn.gateway:
            routers[(dev.id, sn.segment_id)].append(str(sn.interface.ip))
        elif (dev.id, sn.segment_id) not in reported:
            reported.add((dev.id, sn.segment_id))
            yield found(
                f"{dev.name} has the address {sn.interface.ip} in "
                f"{_network_text(net, sn.segment_id)}",
                [dev.id, sn.segment_id],
                fix="Remove the address (a switch or access point only needs to forward that "
                "VLAN), or block access from that network to it.",
            )
    for (dev_id, seg), addresses in sorted(routers.items()):
        if net.firewall_of(dev_id) is not None:
            continue  # security.service-exposure asks the firewall
        yield incomplete(
            f"{device_name(net, dev_id)} is reachable at {', '.join(addresses)} in "
            f"{_network_text(net, seg)}; without firewall rules it is not known whether its "
            "management interface is blocked from there",
            [dev_id, seg],
            key=seg,
        )
    yield from _through_firewall(net)


def _protocol(service: ManagementService) -> FirewallProtocol | None:
    if service.transport is ServiceTransport.TCP:
        return FirewallProtocol.TCP
    return FirewallProtocol.UDP if service.transport is ServiceTransport.UDP else None


def _through_firewall(net: Network) -> Iterator[Result]:
    """Level 2: the management services of a device in another network that an untrusted
    network reaches through the firewall (#120, #135). Only what the firewalls surely allow."""
    sources = [
        s.id
        for s in sorted(net.segments, key=lambda s: s.id)
        if untrusted(s.purpose) and not s.isolated
    ]
    for d in sorted(net.devices, key=lambda d: d.id):
        if d.role not in INFRASTRUCTURE or not d.management_address:
            continue
        try:
            address = ip_address(d.management_address.strip("[]"))
        except ValueError:
            continue
        home = address_segment(net, d)
        services = [
            s
            for s in net.services_of(d.id)
            if s.enabled and s.transport is not ServiceTransport.LAYER2 and s.unrestricted()
        ]
        own = {x.segment_id for x in net.subnets if x.device_id == d.id}
        for src in sources:
            if src == home or src in own:
                continue  # level 1 and security.service-exposure
            hits = [
                (s, v)
                for s in services
                if (v := reach(net, src, address, s.port, _protocol(s))).verdict is Verdict.ALLOWED
            ]
            if not hits:
                continue
            who = _names(
                device_name(net, i) for i in sorted({v.device_id for _, v in hits if v.device_id})
            )
            yield found(
                f"{_names(s.label() for s, _ in hits)} of {d.name} ({address}) can be reached "
                f"from {_network_text(net, src)}"
                + (f" through the firewall of {who}" if who else ""),
                [d.id, src, *(s.id for s, _ in hits)],
                fix=f"Block {segment_name(net, src)} from reaching {d.name} in the firewall "
                f"of its router, or move {d.name} to a management VLAN that "
                f"{segment_name(net, src)} cannot reach.",
                key=f"{src}/firewall",
            )


def _purpose(net: Network, segment_id: str) -> SegmentPurpose | None:
    seg = net.segment(segment_id)
    return seg.purpose if seg else None


# --- segment.purpose-missing (#164) --------------------------------------------------------


@rule(
    "segment.purpose-missing",
    "Network purposes not declared",
    Severity.INFO,
    "The site has several networks (VLANs), but for some it is not known what they are for "
    "(main, guest, IoT, management, ...). The guest and IoT checks then rely on names or stay "
    "silent. Declare the purposes in the desired state; devices that know their guest network "
    "report it themselves.",
)
def purpose_missing(net: Network) -> Iterator[Result]:
    by_site: dict[str, list[str]] = defaultdict(list)
    for s in sorted(net.segments, key=lambda s: s.id):
        by_site[s.site_id].append(s.id)
    for site, segs in sorted(by_site.items()):
        if len(segs) < 2:
            continue
        unknown = []
        for sid in segs:
            seg = net.segment(sid)
            assert seg is not None
            if seg.purpose is None:
                unknown.append(segment_name(net, sid))
            elif seg.purpose_source is PurposeSource.HEURISTIC:
                unknown.append(f"{segment_name(net, sid)}, guessed: {seg.purpose.value}")
        if not unknown:
            continue
        yield found(
            f"It is not declared what these networks at site {site} are for: {'; '.join(unknown)}",
            [site],
            fix="Declare them in the desired state, e.g. segments: [{vlan: 20, purpose: iot}] "
            "(main, guest, iot, management, servers, lab, voice, cameras, transit, other).",
            key=site,
        )


# --- segment.iot-on-5ghz-only (#164) -------------------------------------------------------


@rule(
    "segment.iot-on-5ghz-only",
    "IoT Wi-Fi only on 5 or 6 GHz",
    Severity.INFO,
    "An SSID of an IoT network is only broadcast on 5 or 6 GHz. Many smart plugs, sensors and "
    "cameras only have 2.4 GHz radios and will not see it.",
)
def iot_5ghz_only(net: Network) -> Iterator[Result]:
    groups: dict[tuple[str, str], list[Wlan]] = defaultdict(list)
    for w in _enabled(net):
        site = site_of_device(net, w.device_id)
        if site is not None and wlan_purpose(net, w) is SegmentPurpose.IOT:
            groups[(site, w.ssid)].append(w)
    radios = {r.id: r for r in net.radios}
    for (site, ssid), group in sorted(groups.items()):
        bands = {radios[w.radio_id].band for w in group if w.radio_id in radios}
        if not bands or Band.GHZ_2_4 in bands:
            continue
        yield found(
            f"The IoT SSID {ssid!r} at site {site} is only on "
            f"{' and '.join(sorted(b.value for b in bands))} GHz",
            sorted(w.id for w in group),
            fix="Also broadcast it on 2.4 GHz, unless all its devices support 5 GHz.",
            key=f"{site}:{ssid}",
        )


RULES: list[Rule] = [
    guest_isolation,
    guest_no_isolation,
    management_exposure,
    purpose_missing,
    iot_5ghz_only,
]
