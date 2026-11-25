"""Captive portals (#460, split off #164): where a guest network has a login page, and where it
should not.

They read :class:`~signalbox.model.CaptivePortal` (Omada portals, MikroTik hotspots, OPNsense
zones, openNDS and nodogsplash) together with the purpose of networks and SSIDs
(:mod:`signalbox.purpose`) and their isolation. Unknown settings are never judged.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterator

from signalbox.model import (
    CaptivePortal,
    Network,
    PortalAuth,
    PurposeSource,
    SegmentPurpose,
    Wlan,
)
from signalbox.purpose import wlan_purpose, wlan_source
from signalbox.rules import Result, Rule, Severity, found, rule
from signalbox.rules._names import device_name, segment_name

#: Purposes a portal is not expected on: ``guest`` is the one it is for, ``other`` says nothing.
_PORTAL_PURPOSES = frozenset({SegmentPurpose.GUEST, SegmentPurpose.OTHER})


def _wlans(net: Network) -> list[Wlan]:
    return sorted((w for w in net.wlans if w.enabled and not w.backhaul), key=lambda w: w.id)


def _covered_wlans(net: Network, portal: CaptivePortal) -> list[Wlan]:
    return [w for w in _wlans(net) if portal in net.portals_for(w)]


def _isolated(net: Network, wlan: Wlan) -> bool:
    seg = net.segment(wlan.segment_id) if wlan.segment_id else None
    return wlan.client_isolation is True or bool(seg and seg.isolated)


# --- portal.guest-unprotected (#460) -------------------------------------------------------


@rule(
    "portal.guest-unprotected",
    "Guest network without a captive portal or isolation",
    Severity.INFO,
    "A guest SSID or guest network has neither a captive portal nor client isolation. Anyone "
    "with the guest password then reaches the other guests' devices, and there is no page where "
    "visitors accept your terms. Guest networks the device reports itself (Fritz!Box, Omada "
    "guest network) are kept apart by that device and not checked. Only SSIDs that report "
    "client isolation as off, and networks the device does not isolate, are reported; where no "
    "device reports portals, the finding is a hint to look at the portal settings.",
)
def guest_unprotected(net: Network) -> Iterator[Result]:
    groups: dict[str, list[Wlan]] = defaultdict(list)
    for w in _wlans(net):
        if wlan_purpose(net, w) is not SegmentPurpose.GUEST:
            continue
        if wlan_source(net, w) is PurposeSource.REPORTED or w.client_isolation is not False:
            continue
        if _isolated(net, w) or net.portals_for(w):
            continue
        groups[w.ssid].append(w)
    for ssid, group in sorted(groups.items()):
        aps = ", ".join(sorted({device_name(net, w.device_id) for w in group}))
        yield found(
            f"The guest Wi-Fi {ssid!r} on {aps} has no captive portal and no client isolation",
            sorted(w.id for w in group),
            fix="Turn on client isolation for the SSID, or put a captive portal in front of it.",
            key=ssid,
            mid="portals.guestUnprotected",
            fix_id="portals.guestUnprotected.fix",
            params={"ssid": repr(ssid), "aps": aps},
        )
    with_ssid = {w.segment_id for w in _wlans(net)}
    for seg in sorted(net.segments, key=lambda s: s.id):
        if seg.purpose is not SegmentPurpose.GUEST or seg.id in with_ssid:
            continue
        if seg.purpose_source is PurposeSource.REPORTED or seg.isolated is True:
            continue
        if net.portals_on(seg.id):
            continue
        name = segment_name(net, seg.id)
        yield found(
            f"The guest network {name} has no captive portal and is not isolated",
            [seg.id],
            fix="Isolate the network from the rest of the LAN and between its clients, or put "
            "a captive portal in front of it.",
            key=seg.id,
            mid="portals.guestNetworkUnprotected",
            fix_id="portals.guestNetworkUnprotected.fix",
            params={"segment": name},
        )


# --- portal.non-guest-network (#460) -------------------------------------------------------


@rule(
    "portal.non-guest-network",
    "Captive portal on a network that is not a guest network",
    Severity.WARNING,
    "An enabled captive portal covers a network or SSID whose purpose is known and is not "
    "guest (main, IoT, servers, ...). Everyone on it has to log in at the portal first, which "
    "locks out devices that cannot (printers, smart plugs, servers) and makes the guest login "
    "page the front door of your own network. Portals are for guests; a network whose purpose "
    "is unknown or other is not judged.",
)
def non_guest_network(net: Network) -> Iterator[Result]:
    for portal in sorted(net.portals, key=lambda p: p.id):
        if not portal.enabled:
            continue
        names: list[str] = []
        ids: list[str] = []
        for sid in portal.segments:
            seg = net.segment(sid)
            if seg is not None and seg.purpose is not None and seg.purpose not in _PORTAL_PURPOSES:
                names.append(f"{segment_name(net, sid)} ({seg.purpose.value})")
                ids.append(sid)
        for w in _covered_wlans(net, portal):
            purpose = wlan_purpose(net, w)
            label = f"SSID {w.ssid!r} ({purpose.value})" if purpose else ""
            if purpose is not None and purpose not in _PORTAL_PURPOSES and label not in names:
                names.append(label)
                ids.append(w.id)
        if not names:
            continue
        where = ", ".join(names)
        yield found(
            f"The captive portal {portal.name!r} on {device_name(net, portal.device_id)} covers "
            f"{where}, which is not a guest network",
            [portal.id, *ids],
            fix="Move the portal to the guest network or SSID, or disable it.",
            key=portal.id,
            mid="portals.nonGuest",
            fix_id="portals.nonGuest.fix",
            params={
                "portal": repr(portal.name),
                "device": device_name(net, portal.device_id),
                "where": where,
            },
        )


# --- portal.click-through-open (#460) ------------------------------------------------------


@rule(
    "portal.click-through-open",
    "Click-through portal without client isolation",
    Severity.WARNING,
    "A captive portal that only asks guests to accept the terms (no password, voucher or "
    "account) is open to anyone who can join the Wi-Fi, and without client isolation they can "
    "all see each other's devices. Reported where a covered SSID reports client isolation as "
    "off, or a covered network is reported as not isolated; unknown settings are not judged.",
)
def click_through_open(net: Network) -> Iterator[Result]:
    for portal in sorted(net.portals, key=lambda p: p.id):
        if not portal.enabled or portal.auth is not PortalAuth.CLICK_THROUGH:
            continue
        open_wlans = [
            w
            for w in _covered_wlans(net, portal)
            if w.client_isolation is False and not _isolated(net, w)
        ]
        with_ssid = {w.segment_id for w in _covered_wlans(net, portal)}
        open_segments = [
            sid
            for sid in portal.segments
            if sid not in with_ssid
            and (seg := net.segment(sid)) is not None
            and seg.isolated is False
        ]
        if not open_wlans and not open_segments:
            continue
        names = sorted(
            {f"SSID {w.ssid!r}" for w in open_wlans} | {segment_name(net, s) for s in open_segments}
        )
        where = ", ".join(names)
        yield found(
            f"The click-through portal {portal.name!r} on {device_name(net, portal.device_id)} "
            f"does not isolate its clients ({where})",
            [portal.id, *(w.id for w in open_wlans), *open_segments],
            fix="Turn on client isolation for the SSID or network, or let the portal ask for a "
            "password or voucher.",
            key=portal.id,
            mid="portals.clickThroughOpen",
            fix_id="portals.clickThroughOpen.fix",
            params={
                "portal": repr(portal.name),
                "device": device_name(net, portal.device_id),
                "where": where,
            },
        )


RULES: list[Rule] = [guest_unprotected, non_guest_network, click_through_open]
