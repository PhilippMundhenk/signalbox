"""Wi-Fi hygiene rules: security, PMF, SSIDs, channels and power
(issues #87, #88, #91, #92, #93, #94, #95, #97, #98, #100, #103)."""

from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Iterable, Iterator

from signalbox.model import Band, LinkKind, Network, Pmf, Radio, Security, Wlan
from signalbox.rules import Result, Rule, Severity, found, incomplete, rule
from signalbox.rules._names import device_name, segment_name, site_of_device
from signalbox.rules.wireless import DFS, _occupied, channel_ranges, quiet_channels

SECURITY_TEXT = {
    Security.OPEN: "no password (open)",
    Security.OWE: "Enhanced Open (OWE)",
    Security.WEP: "WEP",
    Security.WPA: "WPA (version 1)",
    Security.WPA_WPA2: "WPA/WPA2 mixed",
    Security.WPA2: "WPA2",
    Security.WPA3: "WPA3",
    Security.WPA2_WPA3: "WPA2/WPA3",
    Security.WPA2_ENTERPRISE: "WPA2-Enterprise",
    Security.WPA_ENTERPRISE: "WPA-Enterprise (version 1)",
    Security.WPA3_ENTERPRISE: "WPA3-Enterprise",
    Security.WPA3_ENTERPRISE_192: "WPA3-Enterprise 192-bit",
    Security.OTHER: "another security mode",
}
#: Modes without a password a stranger would need.
UNPROTECTED = {Security.OPEN, Security.OWE}
PSK = {Security.WPA, Security.WPA_WPA2, Security.WPA2, Security.WPA3, Security.WPA2_WPA3}
ENTERPRISE = {
    Security.WPA_ENTERPRISE,
    Security.WPA2_ENTERPRISE,
    Security.WPA3_ENTERPRISE,
    Security.WPA3_ENTERPRISE_192,
}


def _radios(net: Network) -> dict[str, Radio]:
    return {r.id: r for r in net.radios}


def _enabled_wlans(net: Network) -> list[Wlan]:
    return sorted((w for w in net.wlans if w.enabled and not w.backhaul), key=lambda w: w.id)


def _radio_of(net: Network, radio: Radio, *, start: bool = False) -> str:
    """``the 5 GHz radio of Access point 1`` (``The ...`` at the start of a sentence)."""
    return f"{device_name(net, radio.device_id)} ({radio.band.value} GHz)"


def _per_ap(wlans: Iterable[Wlan], *extra: str) -> dict[tuple[str, ...], list[Wlan]]:
    """WLANs grouped by device, SSID and the given attributes: one finding per AP and SSID."""
    groups: dict[tuple[str, ...], list[Wlan]] = defaultdict(list)
    for w in wlans:
        groups[(w.device_id, w.ssid, *(str(getattr(w, a)) for a in extra))].append(w)
    return groups


def _ids(wlans: Iterable[Wlan]) -> list[str]:
    return sorted(w.id for w in wlans)


# 6 GHz security (#87) -------------------------------------------------------------------------

SIX_GHZ_ALLOWED = {
    Security.WPA3,
    Security.WPA3_ENTERPRISE,
    Security.WPA3_ENTERPRISE_192,
    Security.OWE,
}


@rule(
    "wifi.6ghz-security",
    "Wi-Fi on 6 GHz without WPA3 or OWE",
    Severity.ERROR,
    "The Wi-Fi 6E and Wi-Fi 7 specifications allow only WPA3 and Enhanced Open (OWE) on 6 GHz. "
    "With WPA2, WPA2/WPA3 transition mode or an open network, clients do not show or cannot "
    "join the network on that band, so nothing uses the 6 GHz radio. A common result of copying "
    "the 2.4/5 GHz settings to the new radio. Protected management frames, which 6 GHz also "
    "requires, are checked by wifi.pmf.",
)
def six_ghz_security(net: Network) -> Iterator[Result]:
    radios = _radios(net)
    six = [
        w
        for w in _enabled_wlans(net)
        if (r := radios.get(w.radio_id)) is not None and r.band is Band.GHZ_6
    ]
    for (_, ssid, _sec), wlans in sorted(_per_ap(six, "security").items()):
        if wlans[0].security in SIX_GHZ_ALLOWED:
            continue
        radio = radios[wlans[0].radio_id]
        yield found(
            f"SSID {ssid!r} on radio {_radio_of(net, radio)} uses "
            f"{SECURITY_TEXT[wlans[0].security]}, which 6 GHz does not allow",
            _ids(wlans),
            fix="On 6 GHz use WPA3 only (or OWE for an open network) with protected management "
            "frames required. Keep WPA2/WPA3 transition mode on 2.4 and 5 GHz if old devices "
            "need it.",
            mid="wifi.sixGhzSecurity",
            fix_id="wifi.sixGhzSecurity.fix",
            params={
                "ssid": repr(ssid),
                "radio": _radio_of(net, radio),
                "mode": SECURITY_TEXT[wlans[0].security],
            },
        )


# PMF (#88) ------------------------------------------------------------------------------------

#: PMF a mode needs: WPA3 and OWE require it, transition mode needs it at least optional.
PMF_REQUIRED = {
    Security.WPA3,
    Security.WPA3_ENTERPRISE,
    Security.WPA3_ENTERPRISE_192,
    Security.OWE,
}


@rule(
    "wifi.pmf",
    "Protected management frames do not match the security mode",
    Severity.ERROR,
    "WPA3 and Enhanced Open (OWE) require protected management frames (PMF, 802.11w): without "
    "them it is not WPA3, and many phones and laptops refuse to connect or connect unreliably. "
    "In WPA2/WPA3 transition mode, PMF turned off keeps every client on WPA2. Vendors show PMF "
    "as a separate setting, so this mismatch happens easily.",
)
def pmf(net: Network) -> Iterator[Result]:
    wlans = [w for w in _enabled_wlans(net) if w.security in PMF_REQUIRED | {Security.WPA2_WPA3}]
    for (dev, ssid, _sec, _pmf), group in sorted(_per_ap(wlans, "security", "pmf").items()):
        w = group[0]
        mode = SECURITY_TEXT[w.security]
        ap = device_name(net, dev)
        if w.pmf is None:
            yield incomplete(
                f"{ap} did not report the protected management frames (PMF) setting of SSID "
                f"{ssid!r}, so it is not known whether it matches {mode}",
                _ids(group),
                mid="wifi.pmfUnknown",
                params={"ap": ap, "ssid": repr(ssid), "mode": mode},
            )
        elif w.security in PMF_REQUIRED and w.pmf is not Pmf.REQUIRED:
            yield found(
                f"SSID {ssid!r} on {ap} uses {mode} with protected management frames (PMF) "
                f"{w.pmf.value}",
                _ids(group),
                fix="Set protected management frames (PMF, 802.11w) to required.",
                mid="wifi.pmfNotRequired",
                fix_id="wifi.pmfNotRequired.fix",
                params={"ssid": repr(ssid), "ap": ap, "mode": mode, "pmf": w.pmf.value},
            )
        elif w.security is Security.WPA2_WPA3 and w.pmf is Pmf.DISABLED:
            yield found(
                f"SSID {ssid!r} on {ap} uses WPA2/WPA3 with protected management frames (PMF) "
                "disabled, so every client stays on WPA2",
                _ids(group),
                fix="Set protected management frames (PMF, 802.11w) to optional.",
                severity=Severity.WARNING,
                mid="wifi.pmfDisabled",
                fix_id="wifi.pmfDisabled.fix",
                params={"ssid": repr(ssid), "ap": ap},
            )


# hidden SSIDs (#91) ---------------------------------------------------------------------------


def _backhaul_ssids(net: Network) -> set[tuple[str, str]]:
    """(device, SSID) of hidden SSIDs that both ends of a wireless link broadcast (mesh)."""
    hidden: dict[str, set[str]] = defaultdict(set)
    for w in net.wlans:
        if w.enabled and (w.hidden or w.backhaul):
            hidden[w.device_id].add(w.ssid)
    out: set[tuple[str, str]] = set()
    for link in net.links:
        if link.kind is not LinkKind.WIRELESS:
            continue
        a, b = (link.a.split("/port/")[0], link.b.split("/port/")[0])
        for ssid in hidden[a] & hidden[b]:
            out |= {(a, ssid), (b, ssid)}
    return out


@rule(
    "wifi.hidden",
    "Hidden Wi-Fi network",
    Severity.INFO,
    "A hidden SSID is not secret: every phone that knows it calls out its name wherever it goes, "
    "which tells strangers which networks it knows, and some devices join or roam badly. Hiding "
    "adds no security; the password does. Hidden SSIDs that serve as a wireless uplink between "
    "two access points are skipped.",
)
def hidden(net: Network) -> Iterator[Result]:
    backhaul = _backhaul_ssids(net)
    groups: dict[tuple[str, str], list[Wlan]] = defaultdict(list)
    for w in _enabled_wlans(net):
        site = site_of_device(net, w.device_id)
        if w.hidden and site is not None and (w.device_id, w.ssid) not in backhaul:
            groups[(site, w.ssid)].append(w)
    for (_, ssid), wlans in sorted(groups.items()):
        aps = ", ".join(sorted({device_name(net, w.device_id) for w in wlans}))
        yield found(
            f"SSID {ssid!r} is hidden (on {aps})",
            _ids(wlans),
            fix="Hiding adds no security; consider broadcasting it and relying on WPA2/WPA3.",
            mid="wifi.hidden",
            fix_id="wifi.hidden.fix",
            params={"ssid": repr(ssid), "aps": aps},
        )


# SSIDs per radio (#92) ------------------------------------------------------------------------

#: Most SSIDs one radio should broadcast; every SSID costs beacon airtime.
MAX_SSIDS = {Band.GHZ_2_4: 3, Band.GHZ_5: 4, Band.GHZ_6: 4}


@rule(
    "wifi.ssid-count",
    "Radio broadcasts many SSIDs",
    Severity.WARNING,
    "Every SSID sends its own beacons at the lowest data rate, about ten times a second. With "
    "many SSIDs on one radio, beacons alone take a noticeable share of the airtime (10-20 % on "
    "2.4 GHz with five SSIDs) and every client gets slower. Hidden SSIDs beacon too. Often "
    "several SSIDs could be one, or a network nobody uses can be turned off.",
)
def ssid_count(net: Network) -> Iterator[Result]:
    per_radio: dict[str, list[Wlan]] = defaultdict(list)
    for w in _enabled_wlans(net):
        per_radio[w.radio_id].append(w)
    for radio in sorted(net.radios, key=lambda r: r.id):
        wlans = per_radio.get(radio.id, [])
        if not radio.enabled or len(wlans) <= MAX_SSIDS[radio.band]:
            continue
        names = ", ".join(sorted({repr(w.ssid) for w in wlans}))
        yield found(
            f"Radio {_radio_of(net, radio)} broadcasts {len(wlans)} SSIDs ({names}); "
            f"more than {MAX_SSIDS[radio.band]} cost noticeable airtime",
            [radio.id, *_ids(wlans)],
            fix="Merge SSIDs or turn off the ones you do not need (each one costs airtime).",
            mid="wifi.ssidCount",
            fix_id="wifi.ssidCount.fix",
            params={
                "radio": _radio_of(net, radio),
                "count": len(wlans),
                "names": names,
                "max": MAX_SSIDS[radio.band],
            },
        )


# channel width (#93) --------------------------------------------------------------------------


@rule(
    "wifi.channel-width",
    "Channel too wide for the band or the number of access points",
    Severity.WARNING,
    "On 2.4 GHz a 40 MHz channel covers two thirds of the band and collides with every "
    "neighbour; most clients fall back to 20 MHz anyway and throughput drops for everyone. On "
    "5 GHz (160 MHz) and 6 GHz (320 MHz), very wide channels leave no room for several access "
    "points to use channels that do not overlap.",
)
def channel_width(net: Network) -> Iterator[Result]:
    aps: dict[tuple[str | None, Band], set[str]] = defaultdict(set)
    for r in net.radios:
        if r.enabled:
            aps[(site_of_device(net, r.device_id), r.band)].add(r.device_id)
    wide = {Band.GHZ_5: 160, Band.GHZ_6: 320}
    for r in sorted(net.radios, key=lambda r: r.id):
        if not r.enabled or r.width_mhz is None:
            continue
        if r.band is Band.GHZ_2_4 and r.width_mhz > 20:
            yield found(
                f"Radio {_radio_of(net, r)} uses {r.width_mhz} MHz",
                [r.id],
                fix="Use 20 MHz on 2.4 GHz.",
                mid="wifi.width24",
                fix_id="wifi.width24.fix",
                params={"radio": _radio_of(net, r), "width": r.width_mhz},
            )
        elif r.band in wide and r.width_mhz >= wide[r.band]:
            n = len(aps[(site_of_device(net, r.device_id), r.band)])
            if n < 2:
                continue
            narrower = "80 MHz" if r.band is Band.GHZ_5 else "160 MHz or less"
            fix_id = "wifi.widthWide.fix5" if r.band is Band.GHZ_5 else "wifi.widthWide.fix6"
            extra: dict[str, int] = {}
            target = 80 if r.band is Band.GHZ_5 else 160
            supported = r.supported_widths_mhz or []
            if supported and target not in supported:  # what the radio can do (#172)
                fits = [w for w in supported if w < target]
                if not fits:
                    continue
                extra["narrower"] = max(fits)
                narrower, fix_id = f"{max(fits)} MHz", "wifi.widthWide.fixWidth"
            yield found(
                f"Radio {_radio_of(net, r)} uses {r.width_mhz} MHz at a site with {n} "
                f"{r.band.value} GHz access points",
                [r.id],
                fix=f"Use {narrower} so that the access points can use channels that do not "
                "overlap.",
                severity=Severity.INFO,
                mid="wifi.widthWide",
                fix_id=fix_id,
                params={
                    "radio": _radio_of(net, r),
                    "width": r.width_mhz,
                    "count": n,
                    "band": r.band.value,
                    **extra,
                },
            )


# 2.4 GHz channel plan (#94) -------------------------------------------------------------------

STANDARD_24 = {1, 6, 11}
#: Where channels 12 and 13 are allowed, 1, 5, 9 and 13 is an alternative plan. Countries that
#: allow only channels 1-11 (North America) keep the 1, 6, 11 plan.
EUROPEAN_24 = {1, 5, 9, 13}
ELEVEN_CHANNEL_COUNTRIES = {"US", "CA"}


@rule(
    "wifi.24-channel-plan",
    "2.4 GHz radio between the standard channels",
    Severity.INFO,
    "On 2.4 GHz only channels 1, 6 and 11 do not overlap. A radio in between (for example 3 or "
    "8) overlaps two of them and suffers from every neighbour that uses the standard plan. "
    "wifi.channel-overlap only compares your own access points; this rule is about the "
    "neighbours. Where channel 13 is allowed (outside North America), 1, 5, 9 and 13 is also "
    "accepted. Radios on automatic channel selection are skipped.",
)
def channel_plan_24(net: Network) -> Iterator[Result]:
    for r in sorted(net.radios, key=lambda r: r.id):
        if not r.enabled or r.band is not Band.GHZ_2_4 or r.channel is None or r.channel_auto:
            continue
        country = (r.country or "").upper()
        allowed = set(STANDARD_24)
        if country and country not in ELEVEN_CHANNEL_COUNTRIES:
            allowed |= EUROPEAN_24
        if r.channel in allowed:
            continue
        fix = "Use channel 1, 6 or 11" + (
            " (or 1, 5, 9 and 13 on all access points)." if allowed >= EUROPEAN_24 else "."
        )
        fix_id = "wifi.channelPlan.fixEu" if allowed >= EUROPEAN_24 else "wifi.channelPlan.fix"
        params: dict[str, str | int] = {"radio": _radio_of(net, r), "channel": r.channel}
        if r.supported_channels is not None and not set(r.supported_channels) >= STANDARD_24:
            # only channels the radio can use (#172)
            usable = sorted(STANDARD_24 & set(r.supported_channels))
            if not usable:
                continue
            listed = ", ".join(str(c) for c in usable)
            fix, fix_id = f"Use channel {listed}.", "wifi.channelPlan.fixSupported"
            params["channels"] = listed
        yield found(
            f"Radio {_radio_of(net, r)} uses channel {r.channel}",
            [r.id],
            fix=fix,
            mid="wifi.channelPlan",
            fix_id=fix_id,
            params=params,
        )


# DFS (#95) ------------------------------------------------------------------------------------


@rule(
    "wifi.dfs",
    "5 GHz radio on a radar (DFS) channel",
    Severity.INFO,
    "On 5 GHz channels 52-144 an access point must listen for radar for a minute after it "
    "starts (ten minutes on 120-128 in Europe) and leave the channel when it detects one; its "
    "clients then lose the network. Short unexplained Wi-Fi outages, or an access point that "
    "takes minutes to come back after a reboot, are often DFS. Some clients do not support "
    "these channels at all. DFS channels are allowed and often needed: this is for "
    "information, turn the rule off if you use them on purpose.",
)
def dfs(net: Network) -> Iterator[Result]:
    for r in sorted(net.radios, key=lambda r: r.id):
        if not r.enabled or r.band is not Band.GHZ_5 or r.channel is None:
            continue
        used = sorted(c for c in _occupied(r) if c in DFS)
        if not used:
            continue
        if r.channel in DFS:
            detail = f"channel {r.channel} (DFS)"
        else:
            detail = (
                f"channel {r.channel} at {r.width_mhz} MHz, which reaches the DFS channels "
                f"{used[0]}-{used[-1]}"
            )
        fix, fix_id, channels = dfs_fix(r)
        yield found(
            f"Radio {_radio_of(net, r)} uses {detail}",
            [r.id],
            fix=fix,
            mid="wifi.dfs" if r.channel in DFS else "wifi.dfsReach",
            fix_id=fix_id,
            params={
                "radio": _radio_of(net, r),
                "channel": r.channel,
                "width": r.width_mhz,
                "first": used[0],
                "last": used[-1],
                **({"channels": channels} if channels else {}),
            },
        )


def dfs_fix(radio: Radio) -> tuple[str, str, str | None]:
    """(fix, fix id, channels) to leave the radar channels, with only channels the radio
    supports where it reported them (#172)."""
    quiet = quiet_channels(radio)
    if quiet is None:
        return (
            "If clients lose Wi-Fi now and then, try channels 36-48 or 149-165.",
            "wifi.dfs.fix",
            None,
        )
    if not quiet:
        return (
            "This radio has no 5 GHz channel without radar detection: if clients lose Wi-Fi "
            "now and then, move them to another band or access point.",
            "wifi.dfs.fixNone",
            None,
        )
    listed = channel_ranges(quiet, Band.GHZ_5)
    return (
        f"If clients lose Wi-Fi now and then, try channels {listed}.",
        "wifi.dfs.fixSupported",
        listed,
    )


# transmit power (#97) -------------------------------------------------------------------------


@rule(
    "wifi.tx-power",
    "Transmit power unbalanced between bands or access points",
    Severity.INFO,
    "Clients pick the strongest signal. A 2.4 GHz radio louder than the 5 GHz radio of the same "
    "SSID keeps them on the slow band; one loud access point attracts clients from far away "
    "while closer ones stay idle, and roaming suffers. Radios with automatic or unreported "
    "power are skipped.",
)
def tx_power(net: Network) -> Iterator[Result]:
    ssids: dict[str, set[str]] = defaultdict(set)
    for w in _enabled_wlans(net):
        ssids[w.radio_id].add(w.ssid)
    radios = sorted(
        (r for r in net.radios if r.enabled and r.tx_power_dbm is not None), key=lambda r: r.id
    )
    by_device: dict[str, list[Radio]] = defaultdict(list)
    for r in radios:
        by_device[r.device_id].append(r)
    for dev, rs in sorted(by_device.items()):
        for low in (r for r in rs if r.band is Band.GHZ_2_4):
            for high in (r for r in rs if r.band is Band.GHZ_5):
                assert low.tx_power_dbm is not None and high.tx_power_dbm is not None
                if low.tx_power_dbm <= high.tx_power_dbm + 3 or not (
                    ssids[low.id] & ssids[high.id]
                ):
                    continue
                yield found(
                    f"The 2.4 GHz radio of {device_name(net, dev)} sends at "
                    f"{low.tx_power_dbm} dBm, its 5 GHz radio at {high.tx_power_dbm} dBm",
                    [low.id, high.id],
                    fix="Lower 2.4 GHz to about 3-6 dB below 5 GHz so that clients prefer 5 GHz.",
                    key="bands",
                    mid="wifi.txBands",
                    fix_id="wifi.txBands.fix",
                    params={
                        "device": device_name(net, dev),
                        "low": low.tx_power_dbm,
                        "high": high.tx_power_dbm,
                    },
                )
    by_band: dict[tuple[str, Band], list[Radio]] = defaultdict(list)
    for r in radios:
        site = site_of_device(net, r.device_id)
        if site is not None:
            by_band[(site, r.band)].append(r)
    for (site, band), rs in sorted(by_band.items()):
        if len({r.device_id for r in rs}) < 2:
            continue
        loud = max(rs, key=lambda r: (r.tx_power_dbm or 0, r.id))
        quiet = min(rs, key=lambda r: (r.tx_power_dbm or 0, r.id))
        assert loud.tx_power_dbm is not None and quiet.tx_power_dbm is not None
        if loud.tx_power_dbm - quiet.tx_power_dbm <= 6:
            continue
        yield found(
            f"On {band.value} GHz at site {site}, {device_name(net, loud.device_id)} sends at "
            f"{loud.tx_power_dbm} dBm and {device_name(net, quiet.device_id)} at "
            f"{quiet.tx_power_dbm} dBm",
            sorted(r.id for r in rs),
            fix="Bring the access points within about 6 dB of each other, usually by lowering "
            "the loud one.",
            key=f"aps:{site}:{band.value}",
            mid="wifi.txAps",
            fix_id="wifi.txAps.fix",
            params={
                "band": band.value,
                "site": site,
                "loud": device_name(net, loud.device_id),
                "loud_dbm": loud.tx_power_dbm,
                "quiet": device_name(net, quiet.device_id),
                "quiet_dbm": quiet.tx_power_dbm,
            },
        )


# SSID coverage (#98) --------------------------------------------------------------------------


@rule(
    "wifi.ssid-coverage",
    "Wi-Fi network missing on some access points or bands",
    Severity.INFO,
    "A Wi-Fi network (SSID) that only some access points of a site broadcast, or that is on "
    "5 GHz at some and only on 2.4 GHz at others, makes roaming clients lose the network or end "
    "up on the slow band near one access point. Usually it was added to one access point and "
    "forgotten on the others. wifi.ssid-consistent only compares the access points that have "
    "the SSID. Guest networks limited to one area are common: turn the rule off if that is "
    "intended.",
)
def ssid_coverage(net: Network) -> Iterator[Result]:
    radios = _radios(net)
    bands_of_ap: dict[str, set[Band]] = defaultdict(set)
    for r in net.radios:
        if r.enabled:
            bands_of_ap[r.device_id].add(r.band)
    sites: dict[str, dict[str, dict[str, list[Wlan]]]] = defaultdict(
        lambda: defaultdict(lambda: defaultdict(list))
    )
    for w in _enabled_wlans(net):
        site = site_of_device(net, w.device_id)
        if site is not None:
            sites[site][w.ssid][w.device_id].append(w)
    for site, by_ssid in sorted(sites.items()):
        aps = {dev for per_ap in by_ssid.values() for dev in per_ap}
        if len(aps) < 2:
            continue
        for ssid, per_ap in sorted(by_ssid.items()):
            objects = _ids(w for ws in per_ap.values() for w in ws)
            bands = {
                dev: {radios[w.radio_id].band for w in ws if w.radio_id in radios}
                for dev, ws in per_ap.items()
            }
            offered: set[Band] = set().union(*bands.values())
            # an access point without a radio for the SSID's bands cannot offer it
            missing = sorted(
                device_name(net, d) for d in aps - set(per_ap) if bands_of_ap[d] & offered
            )
            have = sorted(device_name(net, d) for d in per_ap)
            if missing:
                yield found(
                    f"SSID {ssid!r} is broadcast by {', '.join(have)} but not by "
                    f"{', '.join(missing)}",
                    objects,
                    fix=f"Add {ssid!r} to {', '.join(missing)}, or ignore this if it is meant "
                    "to cover only part of the site.",
                    key=f"{site}:{ssid}:aps",
                    mid="wifi.coverageAps",
                    fix_id="wifi.coverageAps.fix",
                    params={
                        "ssid": repr(ssid),
                        "have": ", ".join(have),
                        "missing": ", ".join(missing),
                    },
                )
            for band in sorted(offered, key=lambda b: float(b.value)):
                lacking = sorted(
                    device_name(net, d)
                    for d, bs in bands.items()
                    if band not in bs and band in bands_of_ap[d]
                )
                if not lacking:
                    continue
                with_band = sorted(device_name(net, d) for d, bs in bands.items() if band in bs)
                yield found(
                    f"SSID {ssid!r} is on {band.value} GHz at {', '.join(with_band)} but not at "
                    f"{', '.join(lacking)}, although they have a {band.value} GHz radio",
                    objects,
                    fix=f"Add {ssid!r} to the {band.value} GHz radio of {', '.join(lacking)}, "
                    "or ignore this if it is intended.",
                    key=f"{site}:{ssid}:{band.value}",
                    mid="wifi.coverageBand",
                    fix_id="wifi.coverageBand.fix",
                    params={
                        "ssid": repr(ssid),
                        "band": band.value,
                        "with": ", ".join(with_band),
                        "lacking": ", ".join(lacking),
                    },
                )


# security per network (#100) ------------------------------------------------------------------


@rule(
    "wifi.segment-weakest-link",
    "Weaker Wi-Fi network shares a network with a protected one",
    Severity.ERROR,
    "A network (VLAN) is only as protected as the weakest Wi-Fi network (SSID) that puts clients "
    "into it. An open SSID in the same VLAN as the private Wi-Fi gives everyone nearby the "
    "private network; it happens when an extra SSID is created without choosing a VLAN and "
    "joins the default bridge. Two password-protected SSIDs with different passwords on one "
    "network are often deliberate, but then only the password separates them.",
)
def segment_weakest_link(net: Network) -> Iterator[Result]:
    per_seg: dict[str, dict[str, list[Wlan]]] = defaultdict(lambda: defaultdict(list))
    unknown: dict[str, set[str]] = defaultdict(set)
    protected_sites: set[str] = set()
    for w in _enabled_wlans(net):
        site = site_of_device(net, w.device_id)
        if w.security not in UNPROTECTED and site is not None:
            protected_sites.add(site)
        if w.segment_id is not None:
            per_seg[w.segment_id][w.ssid].append(w)
        elif w.security in UNPROTECTED and site is not None:
            unknown[site].add(w.ssid)
    for seg, by_ssid in sorted(per_seg.items()):
        modes = {s: {w.security for w in ws} for s, ws in by_ssid.items()}
        protected = sorted(s for s, ms in modes.items() if ms - UNPROTECTED)
        objects = _ids(w for ws in by_ssid.values() for w in ws)
        for ssid in sorted(s for s, ms in modes.items() if ms & UNPROTECTED):
            others = [p for p in protected if p != ssid]
            if not others:
                continue
            weak = "/".join(SECURITY_TEXT[m] for m in sorted(modes[ssid] & UNPROTECTED))
            strong = ", ".join(
                f"{p!r} ({'/'.join(SECURITY_TEXT[m] for m in sorted(modes[p]))})" for p in others
            )
            yield found(
                f"{ssid!r} ({weak}) and {strong} both put clients into {segment_name(net, seg)}",
                objects,
                fix=f"Move {ssid!r} to its own network (VLAN), for example a guest network.",
                key=f"{seg}:{ssid}",
                mid="wifi.weakestLink",
                fix_id="wifi.weakestLink.fix",
                params={
                    "ssid": repr(ssid),
                    "weak": weak,
                    "strong": strong,
                    "segment": segment_name(net, seg),
                },
            )
        fingerprints: dict[str, str] = {}
        for s, ws in by_ssid.items():
            fps = {w.passphrase_fingerprint for w in ws if w.security in PSK}
            known = {f for f in fps if f is not None}
            # an SSID with several passwords is wifi.ssid-consistent's finding
            if len(known) == 1 and None not in fps:
                fingerprints[s] = next(iter(known))
        if len(set(fingerprints.values())) > 1:
            names = ", ".join(repr(s) for s in sorted(fingerprints))
            yield found(
                f"SSIDs {names} use different passwords but put clients into the same network "
                f"{segment_name(net, seg)}",
                objects,
                fix="If the SSIDs should be separated (IoT, guests), give each its own network "
                "(VLAN); otherwise ignore this or turn the rule off.",
                severity=Severity.INFO,
                key=f"{seg}:passwords",
                mid="wifi.passwordsDiffer",
                fix_id="wifi.passwordsDiffer.fix",
                params={"names": names, "segment": segment_name(net, seg)},
            )
    for site, ssids in sorted(unknown.items()):
        if site not in protected_sites:
            continue
        yield incomplete(
            f"It is not known which network (VLAN) the unprotected SSIDs "
            f"{', '.join(repr(s) for s in sorted(ssids))} at site {site} use, so it is not "
            "known whether they share one with a protected SSID",
            [site],
            key=site,
            mid="wifi.weakestUnknown",
            params={"ssids": ", ".join(repr(s) for s in sorted(ssids)), "site": site},
        )


# factory SSIDs (#103) -------------------------------------------------------------------------

#: Factory default SSIDs (whole name, case-insensitive). Keep the patterns specific: a user's own
#: SSID must not match by accident.
DEFAULT_SSIDS = [
    re.compile(p, re.IGNORECASE)
    for p in (
        r"OpenWrt(_[0-9a-f]{2,6})?",
        r"LEDE",
        r"MikroTik(-[0-9a-f]{6})?",
        r"FRITZ!Box( .*)?",
        r"FRITZ!Repeater( .*)?",
        r"TP-Link_[0-9a-f]{4,6}(_5G|_6G)?",
        r"NETGEAR\d{2}(-5G)?",
        r"Omada_[0-9a-f]{4,6}(_5G)?",
        r"dlink(-[0-9a-f]{4})?(-5GHz)?",
        r"ASUS(_[0-9a-f]{2,4})?(_2G|_5G)?",
        r"Linksys\d{5}(_5GHz)?",
        r"ubnt",
        r"Xiaomi_[0-9a-f]{4}(_5G)?",
        r"Tenda_[0-9a-f]{6}(_5G)?",
    )
]


@rule(
    "wifi.default-ssid",
    "Wi-Fi network with a factory SSID",
    Severity.WARNING,
    "An SSID such as OpenWrt, MikroTik-1A2B3C or FRITZ!Box 7590 XY means the access point was "
    "never set up: often open (OpenWrt) or with the password printed on the label, in the "
    "default network, and it tells everyone nearby which device it is. Turn the rule off if "
    "you kept a factory name on purpose.",
)
def default_ssid(net: Network) -> Iterator[Result]:
    for (dev, ssid, _sec), wlans in sorted(_per_ap(_enabled_wlans(net), "security").items()):
        if not any(p.fullmatch(ssid) for p in DEFAULT_SSIDS):
            continue
        open_ = wlans[0].security is Security.OPEN
        yield found(
            f"{device_name(net, dev)} broadcasts the factory SSID {ssid!r}"
            + (" without a password (open)" if open_ else ""),
            _ids(wlans),
            fix="Set up the access point (own SSID name and password) or turn the radio off.",
            severity=Severity.ERROR if open_ else None,
            key=wlans[0].security.value,
            mid="wifi.defaultSsidOpen" if open_ else "wifi.defaultSsid",
            fix_id="wifi.defaultSsid.fix",
            params={"device": device_name(net, dev), "ssid": repr(ssid)},
        )


RULES: list[Rule] = [
    six_ghz_security,
    pmf,
    hidden,
    ssid_count,
    channel_width,
    channel_plan_24,
    dfs,
    tx_power,
    ssid_coverage,
    segment_weakest_link,
    default_ssid,
]
