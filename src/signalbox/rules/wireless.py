"""Wi-Fi consistency rules (issue #7)."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterator
from itertools import combinations

from signalbox.model import Band, Network, Radio, Security, Wlan
from signalbox.purpose import device_internal
from signalbox.rules import Result, Rule, Severity, found, incomplete, rule
from signalbox.rules._names import device_name, router_subnets, segment_name, site_of_device

#: Attributes that must match for one SSID, with a readable name and the severity of a mismatch.
#: Security, passphrase and network decide whether a client can connect at all after roaming.
_SSID_ATTRIBUTES: list[tuple[str, str, Severity]] = [  # (attribute, English label, severity)
    ("security", "security mode", Severity.ERROR),
    ("passphrase_fingerprint", "passphrase", Severity.ERROR),
    ("segment_id", "network (VLAN)", Severity.ERROR),
    ("pmf", "protected management frames (PMF)", Severity.WARNING),
    ("hidden", "hidden setting", Severity.WARNING),
    ("roaming_80211r", "fast roaming (802.11r)", Severity.WARNING),
    ("roaming_80211k", "neighbour reports (802.11k)", Severity.WARNING),
    ("roaming_80211v", "BSS transition (802.11v)", Severity.WARNING),
    ("client_isolation", "client isolation", Severity.WARNING),
]


def _show(net: Network, attr: str, value: object) -> str:
    if attr == "segment_id":
        return segment_name(net, str(value))
    if isinstance(value, bool):
        return "\u2713" if value else "\u2717"
    return str(value)


def _ssid_groups(net: Network) -> dict[tuple[str, str], list[Wlan]]:
    """Enabled WLANs by (site, SSID). Sites are compared separately: segments are per site."""
    groups: dict[tuple[str, str], list[Wlan]] = defaultdict(list)
    for wlan in net.wlans:
        site = site_of_device(net, wlan.device_id)
        if wlan.enabled and not wlan.backhaul and site is not None:
            groups[(site, wlan.ssid)].append(wlan)
    return groups


@rule(
    "wifi.ssid-consistent",
    "Wi-Fi network set up differently on access points",
    Severity.ERROR,
    "A Wi-Fi network (SSID) that is broadcast by several access points must be set up the same "
    "way on all of them. Phones and laptops remember one set of settings per name: when they "
    "move to an access point with a different security mode, password or VLAN, they fail to "
    "connect or end up on the wrong network. Different roaming or PMF settings make roaming "
    "slow or unreliable. Passwords are only compared by a fingerprint and never shown. Where "
    "a scan heard your own access points (#169), the security each BSSID announces is "
    "compared with its settings too.",
)
def ssid_consistent(net: Network) -> Iterator[Result]:
    on_air: dict[str, Security] = {}
    for r in sorted(net.wifi_scan, key=lambda r: r.id):
        if r.security is not None and r.security is not Security.OTHER:
            on_air.setdefault(r.bssid, r.security)
    for (site, ssid), wlans in sorted(_ssid_groups(net).items()):
        for wlan in sorted(wlans, key=lambda w: w.id):
            air = on_air.get(wlan.bssid or "")
            if air is None or air is wlan.security or wlan.security is Security.OTHER:
                continue
            name = device_name(net, wlan.device_id)
            yield found(
                f"SSID {ssid!r} at site {site}: {name} announces {air.value} on the air "
                f"although it is set to {wlan.security.value}",
                [wlan.id],
                fix=f"Check the security settings of {ssid!r} on {name}: the access point "
                "does not send what it is set to (a settings change not applied yet, or a "
                "firmware that falls back to another mode).",
                severity=Severity.WARNING,
                key=f"air-security/{wlan.id}",
                mid="wireless.airSecurity",
                fix_id="wireless.airSecurity.fix",
                params={
                    "ssid": repr(ssid),
                    "site": site,
                    "device": name,
                    "air": air.value,
                    "security": wlan.security.value,
                },
            )
        for attr, label, severity in _SSID_ATTRIBUTES:
            by_device: dict[str, set[str]] = defaultdict(set)
            for wlan in wlans:
                value = getattr(wlan, attr)
                if value is not None:  # unknown values are not compared
                    by_device[device_name(net, wlan.device_id)].add(str(value))
            values = {v for vs in by_device.values() for v in vs}
            if len(values) < 2:
                continue
            objects = sorted(w.id for w in wlans)
            if attr == "passphrase_fingerprint":
                groups: dict[str, list[str]] = defaultdict(list)
                for name, vs in sorted(by_device.items()):
                    groups["+".join(sorted(vs))].append(name)
                parts = sorted(", ".join(names) for names in groups.values())
                detail = f"passphrase differs ({' / '.join(parts)})"
                shown = " / ".join(parts)
            else:
                sample = {str(getattr(w, attr)): getattr(w, attr) for w in wlans}
                parts = [
                    f"{name}: {', '.join(_show(net, attr, sample[v]) for v in sorted(vs))}"
                    for name, vs in sorted(by_device.items())
                ]
                detail = f"{label} differs ({'; '.join(parts)})"
                shown = "; ".join(parts)
            yield found(
                f"SSID {ssid!r} at site {site}: {detail}",
                objects,
                fix=f"Set the same {label} for {ssid!r} on every access point.",
                severity=severity,
                key=attr,
                mid=f"wireless.differs.{attr}",
                fix_id=f"wireless.differs.{attr}.fix",
                params={"ssid": repr(ssid), "site": site, "parts": shown, "label": label},
            )


def _radio_label(net: Network, radio: Radio) -> str:
    return f"{device_name(net, radio.device_id)} {radio.name} ({radio.band.value} GHz)"


@rule(
    "wifi.country",
    "Wi-Fi country code missing or different",
    Severity.WARNING,
    "The country code tells a radio which channels and transmit power are allowed where it is "
    "used. Without it, radios fall back to a restrictive world setting (fewer channels, lower "
    "power); with different codes, access points of one site disagree about which channels "
    "exist and clients may not find them after roaming.",
)
def country(net: Network) -> Iterator[Result]:
    by_site: dict[str, list[Radio]] = defaultdict(list)
    for radio in net.radios:
        site = site_of_device(net, radio.device_id)
        if radio.enabled and site is not None:
            by_site[site].append(radio)
    for site, radios in sorted(by_site.items()):
        for radio in radios:
            if radio.country is None:
                yield found(
                    f"{_radio_label(net, radio)} has no country code set (or did not report it)",
                    [radio.id],
                    fix="Set the country code of this radio to the country it is used in.",
                    mid="wireless.noCountry",
                    fix_id="wireless.noCountry.fix",
                    params={"radio": _radio_label(net, radio)},
                )
        codes: dict[str, set[str]] = defaultdict(set)
        for radio in radios:
            if radio.country is not None:
                codes[radio.country.upper()].add(device_name(net, radio.device_id))
        if len(codes) > 1:
            parts = "; ".join(f"{c}: {', '.join(sorted(d))}" for c, d in sorted(codes.items()))
            yield found(
                f"Radios at site {site} use different country codes ({parts})",
                sorted(r.id for r in radios if r.country is not None),
                fix="Set the same country code, the one of the country the site is in, on every "
                "radio.",
                key=site,
                mid="wireless.countries",
                fix_id="wireless.countries.fix",
                params={"site": site, "parts": parts},
            )


#: First 20 MHz channel of each 5 and 6 GHz channel plan; wider channels are aligned blocks
#: starting there (5 GHz: 36-64 and 100-144 from 36, 149-177 from 149; 6 GHz from 1).
def _base(band: Band, channel: int) -> int:
    if band is Band.GHZ_6:
        return 1
    return 149 if channel >= 149 else 36


def _occupied(radio: Radio) -> set[int]:
    """The 20 MHz channels (by number) a 5 or 6 GHz radio occupies: around the reported centre
    channel (#172) where it fits the channel and width, else the aligned block of the width."""
    assert radio.channel is not None
    width = radio.width_mhz if radio.width_mhz and radio.width_mhz >= 20 else 20
    n = width // 20
    centre = radio.center_channel
    if centre is not None and n > 1:
        span = {centre - 2 * (n - 1) + 4 * k for k in range(n)}
        if radio.channel in span:
            return span
    base = _base(radio.band, radio.channel)
    block = (radio.channel - base) // (4 * n)
    return {base + 4 * (block * n + k) for k in range(n)}


#: 5 GHz channels with radar detection (DFS).
DFS = range(52, 145)


def channel_ranges(channels: list[int], band: Band) -> str:
    """``36-48, 149-165``: runs of neighbouring channels (4 apart on 5 and 6 GHz)."""
    step = 1 if band is Band.GHZ_2_4 else 4
    runs: list[list[int]] = []
    for c in sorted(set(channels)):
        if runs and c - runs[-1][-1] == step:
            runs[-1].append(c)
        else:
            runs.append([c])
    return ", ".join(str(r[0]) if len(r) == 1 else f"{r[0]}-{r[-1]}" for r in runs)


def quiet_channels(radio: Radio) -> list[int] | None:
    """The 5 GHz channels without radar detection this radio supports (#172); None when it did
    not report its channels."""
    if radio.supported_channels is None:
        return None
    return sorted(c for c in radio.supported_channels if c not in DFS)


def _overlap(a: Radio, b: Radio) -> bool:
    assert a.channel is not None and b.channel is not None
    if a.band is Band.GHZ_2_4:
        return abs(a.channel - b.channel) < 5
    return bool(_occupied(a) & _occupied(b))


@rule(
    "wifi.channel-overlap",
    "Access points on overlapping channels",
    Severity.WARNING,
    "Two access points of the same site send on channels that overlap in the same band, so they "
    "take turns instead of working in parallel and the Wi-Fi gets slower for everyone. Signalbox "
    "does not know which access points can hear each other, so every pair at one site counts as "
    "neighbours. 2.4 GHz channels overlap when they are less than 5 apart (use 1, 6 and 11); "
    "5 and 6 GHz channels overlap when their 20/40/80/160 MHz blocks share a 20 MHz channel.",
)
def channel_overlap(net: Network) -> Iterator[Result]:
    radios = sorted(
        (r for r in net.radios if r.enabled and r.channel is not None),
        key=lambda r: r.id,
    )
    for a, b in combinations(radios, 2):
        if a.device_id == b.device_id or a.band != b.band:
            continue
        site = site_of_device(net, a.device_id)
        if site is None or site != site_of_device(net, b.device_id):
            continue
        if _overlap(a, b):
            yield found(
                f"{_radio_label(net, a)} on channel {a.channel} overlaps "
                f"{_radio_label(net, b)} on channel {b.channel}",
                [a.id, b.id],
                fix="Move one of the access points to a channel that does not overlap"
                + (" (1, 6 or 11)." if a.band is Band.GHZ_2_4 else ", or use a narrower width."),
                mid="wireless.overlap",
                fix_id="wireless.overlap.fix24"
                if a.band is Band.GHZ_2_4
                else "wireless.overlap.fix",
                params={
                    "a": _radio_label(net, a),
                    "a_channel": a.channel,
                    "b": _radio_label(net, b),
                    "b_channel": b.channel,
                },
            )


@rule(
    "wifi.segment-at-gateway",
    "Wi-Fi network bound to a network the router does not serve",
    Severity.ERROR,
    "The Wi-Fi network puts its clients into a VLAN for which no router has an address. Clients "
    "connect but get no IP address and cannot reach anything. A network a router keeps to "
    "itself (an isolated guest network without a subnet in the model, such as the Fritz!Box "
    "guest Wi-Fi) is served by that router and not reported.",
)
def segment_at_gateway(net: Network) -> Iterator[Result]:
    at_router = router_subnets(net)
    routed = {s.segment_id for s in at_router}
    gateways = {site for s in at_router if (site := site_of_device(net, s.device_id))}
    unchecked: dict[str, set[str]] = defaultdict(set)
    for wlan in sorted(net.wlans, key=lambda w: w.id):
        if (
            not wlan.enabled
            or wlan.backhaul
            or wlan.segment_id is None
            or wlan.segment_id in routed
        ):
            continue
        if device_internal(net, wlan.segment_id):
            continue
        site = site_of_device(net, wlan.device_id)
        if site not in gateways:
            unchecked[str(site)].add(wlan.ssid)
            continue
        yield found(
            f"SSID {wlan.ssid!r} on {device_name(net, wlan.device_id)} uses "
            f"{segment_name(net, wlan.segment_id)}, which has no subnet on the router",
            [wlan.id, wlan.segment_id],
            fix="Create this VLAN with an address and DHCP on the router, or bind the SSID to a "
            "network that exists there.",
            mid="wireless.noSubnet",
            fix_id="wireless.noSubnet.fix",
            params={
                "ssid": repr(wlan.ssid),
                "device": device_name(net, wlan.device_id),
                "segment": segment_name(net, wlan.segment_id),
            },
        )
    for site, ssids in sorted(unchecked.items()):
        yield incomplete(
            f"No router at site {site} reported its subnets, so it is not known whether the "
            f"networks of {', '.join(repr(s) for s in sorted(ssids))} exist there",
            [site],
            key=site,
            mid="wireless.noSubnetUnknown",
            params={"site": site, "ssids": ", ".join(repr(s) for s in sorted(ssids))},
        )


RULES: list[Rule] = [ssid_consistent, country, channel_overlap, segment_at_gateway]
