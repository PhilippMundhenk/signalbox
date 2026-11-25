"""Wi-Fi settings and clients that need more than one reading (#447; follow-ups of #168, #170).

Fast-transition mode, DTIM period, client limit, radio load, clients that stay on 2.4 GHz and
sticky clients (the last one with the observation history). Settings or readings a device did
not report are never judged; backhaul SSIDs and mesh peers are skipped.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterator
from datetime import timedelta

from signalbox.model import Band, Client, Network, WifiStandard, Wlan
from signalbox.rules import (
    Result,
    Rule,
    RuleParams,
    Severity,
    ctx,
    found,
    history_rule,
    param,
    rule,
)
from signalbox.rules._names import device_name, site_of_device
from signalbox.rules.wifi_roaming import by_ssid, is_node, own_wlan, who
from signalbox.sightings import History, weak_run, wifi_spans

#: Standards no 2.4 GHz-only device uses: 802.11ac is 5 GHz only, newer ones are dual band.
FIVE_GHZ_STANDARDS = (WifiStandard.AC, WifiStandard.AX, WifiStandard.BE)


def _stations(net: Network) -> Iterator[tuple[Client, Wlan]]:
    """Wireless clients with the (non-backhaul) WLAN they are on, by MAC address."""
    for c in sorted(net.clients, key=lambda c: c.mac):
        wlan = own_wlan(net, c)
        if wlan is not None and not wlan.backhaul and not is_node(net, c.mac):
            yield c, wlan


# wifi.ft-over-ds (#447, #168) -----------------------------------------------------------------


@rule(
    "wifi.ft-over-ds",
    "Fast roaming (802.11r) uses the distribution system instead of the air",
    Severity.INFO,
    "With 802.11r over the distribution system the client sends its roaming requests through "
    "the old access point and the wired network. Many clients (some phones, laptops and IoT "
    "devices) handle this badly or not at all, while fast transition over the air works "
    "everywhere 802.11r does. Only access points that report the setting are judged.",
)
def ft_over_ds(net: Network) -> Iterator[Result]:
    for (_, ssid), wlans in sorted(by_ssid(net).items()):
        for w in wlans:
            if w.roaming_80211r is False or w.ft is None or not w.ft.over_ds:
                continue
            ap = device_name(net, w.device_id)
            yield found(
                f"SSID {ssid!r} on {ap} uses fast transition over the distribution system",
                [w.id, w.device_id],
                fix=f"Turn off 'FT over DS' for {ssid!r} on {ap} (fast transition over the air "
                "stays on).",
                key=w.id,
                mid="wifi.ftOverDs",
                fix_id="wifi.ftOverDs.fix",
                params={"ssid": repr(ssid), "ap": ap},
            )


# wifi.dtim-high (#447) ------------------------------------------------------------------------


class DtimParams(RuleParams):
    max_period: int = param(
        3,
        unit="count",
        ge=1,
        le=255,
        description="A DTIM period above this makes sleeping clients wait that many beacons "
        "for broadcast and multicast traffic (#447).",
    )


@rule(
    "wifi.dtim-high",
    "The DTIM period of an SSID is high",
    Severity.INFO,
    "The DTIM period says after how many beacons the access point sends the queued broadcast "
    "and multicast frames. A long period lets phones sleep longer but delays everything that "
    "depends on those frames (mDNS discovery, AirPlay, Chromecast, ARP and IPv6 neighbour "
    "discovery) and causes dropped connections on some clients. Above 3 (the parameter "
    "max_period) it is rarely what you want at home.",
    params=DtimParams,
)
def dtim_high(net: Network) -> Iterator[Result]:
    for w in sorted(net.wlans, key=lambda w: w.id):
        if not w.enabled or w.backhaul or w.dtim_period is None:
            continue
        if w.dtim_period <= ctx.params(DtimParams, w).max_period:
            continue
        ap = device_name(net, w.device_id)
        yield found(
            f"SSID {w.ssid!r} on {ap} has a DTIM period of {w.dtim_period}",
            [w.id, w.device_id],
            fix=f"Set the DTIM period of {w.ssid!r} on {ap} to 1 or 2 (3 at most).",
            mid="wifi.dtimHigh",
            fix_id="wifi.dtimHigh.fix",
            params={"ssid": repr(w.ssid), "ap": ap, "period": w.dtim_period},
        )


# wifi.max-clients-low (#447) ------------------------------------------------------------------


@rule(
    "wifi.max-clients-low",
    "The client limit of an SSID is reached",
    Severity.WARNING,
    "An access point refuses new clients once an SSID has as many as its limit allows, so "
    "devices fail to connect although the radio has capacity. Signalbox counts the clients it "
    "sees on the SSID of that access point; a limit of 0 is taken as no limit.",
)
def max_clients_low(net: Network) -> Iterator[Result]:
    seen = Counter(w.id for _, w in _stations(net))
    for w in sorted(net.wlans, key=lambda w: w.id):
        limit = w.max_clients
        if not w.enabled or w.backhaul or not limit or seen[w.id] < limit:
            continue
        ap = device_name(net, w.device_id)
        yield found(
            f"SSID {w.ssid!r} on {ap} allows {limit} clients and has {seen[w.id]}",
            [w.id, w.device_id],
            fix=f"Raise or remove the client limit of {w.ssid!r} on {ap}, or spread the "
            "clients over more access points.",
            mid="wifi.maxClientsLow",
            fix_id="wifi.maxClientsLow.fix",
            params={"ssid": repr(w.ssid), "ap": ap, "limit": limit, "clients": seen[w.id]},
        )


# wifi.client-2-4-only (#447, #170) ------------------------------------------------------------


@rule(
    "wifi.client-2-4-only",
    "A client that could use 5 GHz stays on 2.4 GHz",
    Severity.INFO,
    "A device that connects with 802.11ac or newer can use 5 GHz, which is faster and less "
    "crowded, but sits on 2.4 GHz of an access point that offers the same SSID on 5 or 6 GHz. "
    "It stays there because the signal on 5 GHz is weaker at its place, or because the access "
    "point does not steer it. Only clients whose standard the access point reports are judged.",
)
def client_2_4_only(net: Network) -> Iterator[Result]:
    radios = {r.id: r for r in net.radios}
    for c, wlan in _stations(net):
        radio = radios.get(wlan.radio_id)
        band = c.wireless.band if c.wireless and c.wireless.band else radio.band if radio else None
        standard = c.wireless.standard if c.wireless else None
        if band is not Band.GHZ_2_4 or standard not in FIVE_GHZ_STANDARDS:
            continue
        higher = [
            w
            for w in net.wlans
            if w.device_id == wlan.device_id
            and w.ssid == wlan.ssid
            and w.enabled
            and not w.backhaul
            and (r := radios.get(w.radio_id)) is not None
            and r.enabled
            and r.band in (Band.GHZ_5, Band.GHZ_6)
        ]
        if not higher:
            continue
        ap = device_name(net, wlan.device_id)
        yield found(
            f"{who(c)} uses 2.4 GHz on {ap} although it could use 5 GHz",
            [c.id, wlan.id],
            fix="Turn on band steering for the SSID, or move the device closer to the access "
            "point; a separate 5 GHz SSID for devices that support it also works.",
            key=c.mac,
            mid="wifi.client24Only",
            fix_id="wifi.client24Only.fix",
            params={"client": who(c), "ap": ap, "ssid": repr(wlan.ssid)},
        )


# wifi.radio-overloaded (#447, #170) -----------------------------------------------------------


class OverloadParams(RuleParams):
    max_clients: int = param(
        30,
        unit="count",
        ge=1,
        description="A radio with more clients than this is crowded (#447).",
    )
    idle_clients: int = param(
        10,
        unit="count",
        ge=0,
        description="Another radio with the same SSID and fewer clients than this counts as "
        "free (#447).",
    )


@rule(
    "wifi.radio-overloaded",
    "Many clients on one radio while another radio with the same SSID is idle",
    Severity.INFO,
    "Every client takes air time, so a radio with more than 30 clients (the parameter "
    "max_clients) gets slow for all of them. If another radio offering the same SSID has fewer "
    "than 10 (idle_clients), moving some clients there helps. Only clients whose access point "
    "reports the WLAN count.",
    params=OverloadParams,
)
def radio_overloaded(net: Network) -> Iterator[Result]:
    seen = Counter(w.radio_id for _, w in _stations(net))
    radios = {r.id: r for r in net.radios}
    groups = by_ssid(net)
    for radio_id, count in sorted(seen.items()):
        radio = radios.get(radio_id)
        if radio is None:
            continue
        p = ctx.params(OverloadParams, radio)
        if count <= p.max_clients:
            continue
        site = site_of_device(net, radio.device_id)
        ssids = {w.ssid for w in net.wlans if w.radio_id == radio_id and not w.backhaul}
        free = sorted(
            {
                w.radio_id
                for (s, ssid), wlans in groups.items()
                for w in wlans
                if s == site and ssid in ssids and w.radio_id != radio_id
                if seen[w.radio_id] < p.idle_clients
            }
        )
        other = radios.get(free[0]) if free else None
        if other is None:
            continue
        ap, other_ap = device_name(net, radio.device_id), device_name(net, other.device_id)
        yield found(
            f"{radio.name} on {ap} has {count} clients while {other.name} on {other_ap} has "
            f"{seen[other.id]}",
            [radio.id, other.id],
            fix="Turn on band steering or client load balancing (usteer, dawn, the "
            "controller's setting), or lower the transmit power of the busy radio so that "
            "clients prefer the other one.",
            key=radio.id,
            mid="wifi.radioOverloaded",
            fix_id="wifi.radioOverloaded.fix",
            params={
                "radio": radio.name,
                "ap": ap,
                "clients": count,
                "other": other.name,
                "other_ap": other_ap,
                "other_clients": seen[other.id],
            },
        )


# wifi.client-sticky (#447, #170) --------------------------------------------------------------


class StickyParams(RuleParams):
    min_dbm: int = param(
        -75,
        unit="dBm",
        ge=-120,
        le=0,
        description="A client below this signal is weak (#447). The history keeps the signal in "
        "steps of 5 dB.",
    )
    sustained_minutes: int = param(
        30,
        unit="min",
        ge=1,
        description="How long the client has been weak on the same access point (#447).",
    )
    margin_db: int = param(
        10,
        unit="dBm",
        ge=1,
        le=60,
        description="How much stronger the client's signal was on another access point of the "
        "SSID before (#447).",
    )


@history_rule(
    "wifi.client-sticky",
    "A Wi-Fi client stays on an access point with a weak signal",
    Severity.INFO,
    "A client that has been below -75 dBm (the parameter min_dbm) on one access point for at "
    "least 30 minutes (sustained_minutes), although it was connected to another access point "
    "of the same SSID with a signal at least 10 dB stronger (margin_db), is probably sticky: it "
    "does not roam because it does not know that a better access point exists. Based on the "
    "observation history (signal in steps of 5 dB); without it, or without a previous access "
    "point, nothing is reported.",
    params=StickyParams,
)
def client_sticky(net: Network, history: History) -> Iterator[Result]:
    for c, wlan in _stations(net):
        past = history.wifi.get(c.mac)
        signal = c.wireless.signal_dbm if c.wireless else None
        if past is None or signal is None:
            continue
        p = ctx.params(StickyParams, wlan)
        run = weak_run(past, p.min_dbm)
        if not run or run[0].device_id != wlan.device_id:
            continue
        weak_for = run[-1].end - run[0].start
        if weak_for < timedelta(minutes=p.sustained_minutes):
            continue
        site = site_of_device(net, wlan.device_id)
        peers = {
            w.device_id
            for w in net.wlans
            if w.ssid == wlan.ssid
            and w.enabled
            and not w.backhaul
            and w.device_id != wlan.device_id
            and site_of_device(net, w.device_id) == site
        }
        better = [
            s
            for s in wifi_spans(past)
            if s.end <= run[0].start
            and s.device_id in peers
            and s.bucket_dbm >= run[-1].bucket_dbm + p.margin_db
        ]
        if not better:
            continue
        before = better[-1]
        ap, other = device_name(net, wlan.device_id), device_name(net, before.device_id)
        minutes = int(weak_for.total_seconds() // 60)
        yield found(
            f"{who(c)} has been on {ap} for {minutes} min with {signal} dBm, but was on "
            f"{other} with about {before.bucket_dbm} dBm before",
            [c.id, wlan.id],
            fix="Turn on 802.11k and 802.11v (BSS transition) for the SSID and set a minimum "
            "signal, or run a steering daemon (usteer, dawn); the device may also need Wi-Fi "
            "roaming set to aggressive.",
            key=c.mac,
            mid="wifi.clientSticky",
            fix_id="wifi.clientSticky.fix",
            params={
                "client": who(c),
                "ap": ap,
                "dbm": signal,
                "minutes": minutes,
                "other": other,
                "other_dbm": before.bucket_dbm,
            },
        )


RULES: list[Rule] = [
    ft_over_ds,
    dtim_high,
    max_clients_low,
    client_2_4_only,
    radio_overloaded,
    client_sticky,
]
