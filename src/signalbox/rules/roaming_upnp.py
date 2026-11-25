"""Fast roaming settings of SSIDs (#90) and UPnP on gateways (#124)."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterator

from signalbox.model import UNTRUSTED_PURPOSES, Network, ServiceKind, Wlan
from signalbox.rules import Result, Rule, Severity, found, rule
from signalbox.rules._names import device_name, segment_name, site_of_device

# wifi.roaming (#90, parts 1 and 2) ------------------------------------------------------------


@rule(
    "wifi.roaming",
    "Fast roaming (802.11r) is not useful or not complete",
    Severity.INFO,
    "802.11r only helps when several access points of a site share the SSID: on an SSID that one "
    "access point broadcasts it brings no benefit and is known to keep some older clients from "
    "joining. Without 802.11k (neighbour lists) and 802.11v (transition requests) on the same "
    "SSID, clients still find the next access point late. Settings an access point did not "
    "report are not judged; access points that differ among themselves are the business of "
    "wifi.ssid-consistent. Mismatching mobility domains need data Signalbox does not read yet.",
)
def roaming(net: Network) -> Iterator[Result]:
    groups: dict[tuple[str, str], list[Wlan]] = defaultdict(list)
    for w in sorted(net.wlans, key=lambda w: w.id):
        site = site_of_device(net, w.device_id)
        if w.enabled and not w.backhaul and site is not None:
            groups[(site, w.ssid)].append(w)
    for (_, ssid), wlans in sorted(groups.items()):
        with_r = [w for w in wlans if w.roaming_80211r is True]
        if not with_r:
            continue
        aps = sorted({w.device_id for w in wlans})
        if len(aps) == 1:
            ap = device_name(net, aps[0])
            yield found(
                f"SSID {ssid!r} uses 802.11r but only {ap} broadcasts it, so fast roaming has "
                "nothing to roam to",
                [w.id for w in with_r],
                fix=f"Turn 802.11r off for {ssid!r}, or add the SSID on the other access points "
                "together with 802.11k and v.",
                key="single",
                mid="wifi.roamingSingleAp",
                fix_id="wifi.roamingSingleAp.fix",
                params={"ssid": repr(ssid), "ap": ap},
            )
        missing = [
            name
            for name, attr in (("802.11k", "roaming_80211k"), ("802.11v", "roaming_80211v"))
            if any(getattr(w, attr) is False for w in with_r)
        ]
        if missing:
            off = " and ".join(missing)
            yield found(
                f"SSID {ssid!r} uses 802.11r, but these are off: {off}, so clients still find "
                "the next access point late",
                [w.id for w in with_r if w.roaming_80211k is False or w.roaming_80211v is False],
                fix=f"Turn on {off} for {ssid!r} on the access points, or turn 802.11r off.",
                key="kv",
                mid="wifi.roamingNoKv",
                fix_id="wifi.roamingNoKv.fix",
                params={"ssid": repr(ssid), "missing": off},
            )


# security.upnp (#124) -------------------------------------------------------------------------


@rule(
    "security.upnp",
    "UPnP or NAT-PMP is enabled",
    Severity.WARNING,
    "UPnP lets any device inside the network open ports to the internet without anybody "
    "noticing; malware and cheap cameras use it, and many provider routers ship with it on. It "
    "is worst on a gateway that serves a guest, IoT or camera network, which is a warning; "
    "enabled anywhere else it is reported as information. Networks come from where the device "
    "says UPnP listens, otherwise from the networks the gateway has addresses in. The active "
    "port mappings are not read yet.",
)
def upnp(net: Network) -> Iterator[Result]:
    for s in sorted(net.services, key=lambda s: s.id):
        if s.kind is not ServiceKind.UPNP or not s.enabled or net.device(s.device_id) is None:
            continue
        gw = device_name(net, s.device_id)
        bad = [
            sid
            for sid in net.service_segments(s)
            if (seg := net.segment(sid)) is not None and seg.purpose in UNTRUSTED_PURPOSES
        ]
        if bad:
            where = ", ".join(segment_name(net, sid) for sid in bad)
            yield found(
                f"UPnP is enabled on {gw} for {where}",
                [s.device_id, s.id, *bad],
                fix=f"Turn UPnP off on {gw} (at least for {where}) and add the port forwards "
                "you need by hand.",
                severity=Severity.WARNING,
                key="untrusted",
                mid="security.upnpUntrusted",
                fix_id="security.upnpUntrusted.fix",
                params={"gateway": gw, "networks": where},
            )
        else:
            yield found(
                f"UPnP is enabled on {gw}",
                [s.device_id, s.id],
                fix=f"Turn UPnP off on {gw} unless a device needs it, and add the port forwards "
                "you need by hand.",
                severity=Severity.INFO,
                key="enabled",
                mid="security.upnpEnabled",
                fix_id="security.upnpEnabled.fix",
                params={"gateway": gw},
            )


RULES: list[Rule] = [roaming, upnp]
