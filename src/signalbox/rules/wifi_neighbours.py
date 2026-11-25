"""Neighbouring Wi-Fi networks: evil twins and crowded channels (issue #169, ADR 0025).

They use the access points the radios heard (``Network.wifi_scan``): a controller's rogue AP
list, or a scan the user turned on. Without scan results they stay quiet. Findings never name
a foreign BSSID or SSID (they reach MQTT and exporters): the device's neighbours list shows
them.
"""

from __future__ import annotations

import hashlib
from collections import defaultdict
from collections.abc import Iterator

from signalbox.model import Band, Network, Radio, ScanSource, WifiScanResult, Wlan
from signalbox.neighbours import foreign_on_channel, heard_by, own_macs, shares_channel
from signalbox.rules import Result, Rule, RuleParams, Severity, ctx, found, param, rule
from signalbox.rules._names import device_name, site_of_device

#: Signal (dBm) from which a foreign access point counts for a crowded channel: weaker ones
#: hardly take air time.
AUDIBLE_DBM = -80
#: Foreign access points on the channel from which it counts as crowded.
CROWDED = 3
#: 20 MHz channels a radio can move to when it does not report its supported channels.
_CANDIDATES: dict[Band, list[int]] = {
    Band.GHZ_2_4: [1, 6, 11],
    Band.GHZ_5: [36, 40, 44, 48, 149, 153, 157, 161],
    Band.GHZ_6: [1, 5, 21, 37, 53, 69, 85, 101],
}


def _label(net: Network, radio: Radio) -> str:
    return f"{device_name(net, radio.device_id)} ({radio.band.value} GHz)"


def _key(bssid: str) -> str:
    """A stable key for a foreign BSSID that does not show it (findings leave the server)."""
    return hashlib.sha256(bssid.encode()).hexdigest()[:12]


def _near(bssid: str, own: set[str]) -> bool:
    """The BSSID looks like one of our MACs: access points derive their BSSIDs from their base
    MAC (the locally administered bit set, the last byte counted up)."""
    a = bytes.fromhex(bssid.replace(":", ""))
    for mac in own:
        b = bytes.fromhex(mac.replace(":", ""))
        if a[0] | 2 == b[0] | 2 and a[1:5] == b[1:5] and abs(a[5] - b[5]) < 16:
            return True
    return False


@rule(
    "wifi.rogue-ssid",
    "Foreign access point with one of your Wi-Fi names",
    Severity.WARNING,
    "An access point that is not one of yours broadcasts one of your Wi-Fi names (SSIDs). "
    "Phones and laptops join any network with a remembered name, so this can be an evil "
    "twin that tries to catch your devices and their traffic, or simply a forgotten old "
    "router, a repeater or a neighbour who picked the same name. Based on the access points "
    "your radios heard: a controller's rogue AP list, or a scan you turned on. An access "
    "point is yours when its BSSID belongs to one of your WLANs or ports; scan results are "
    "only compared where every access point with that name reports its BSSID. The finding "
    "does not show the foreign BSSID: the device's neighbours list does.",
)
def rogue_ssid(net: Network) -> Iterator[Result]:
    own = own_macs(net)
    ours: dict[tuple[str, str], list[Wlan]] = defaultdict(list)
    for w in net.wlans:
        site = site_of_device(net, w.device_id)
        if w.enabled and site is not None:
            ours[(site, w.ssid)].append(w)
    radios = {r.id: r for r in net.radios}
    for r in sorted(net.wifi_scan, key=lambda r: r.id):
        site = site_of_device(net, r.device_id)
        if r.ssid is None or site is None or r.bssid in own:
            continue
        wlans = ours.get((site, r.ssid))
        if not wlans:
            continue
        # a scan cannot tell our access points from others while some do not report BSSIDs;
        # a controller's rogue list already leaves out the access points it manages
        if r.kind is ScanSource.SCAN and (
            any(w.bssid is None for w in wlans) or _near(r.bssid, own)
        ):
            continue
        radio = radios.get(r.radio_id or "")
        heard = _label(net, radio) if radio else device_name(net, r.device_id)
        open_twin = r.security is not None and r.security.value in ("open", "owe")
        params: dict[str, str | int | None] = {
            "ssid": repr(r.ssid),
            "heard": heard,
            "device": device_name(net, r.device_id),
            "channel": r.channel,
            "signal": r.signal_dbm,
        }
        if open_twin:
            text = (
                f"An access point that is not yours broadcasts your Wi-Fi name {r.ssid!r} as "
                f"an open network (heard by {heard})"
            )
            mid = "wifiNeighbours.rogueOpen"
        else:
            text = (
                f"An access point that is not yours broadcasts your Wi-Fi name {r.ssid!r} "
                f"(heard by {heard})"
            )
            mid = "wifiNeighbours.rogue"
        yield found(
            text,
            [r.radio_id or r.device_id, *sorted(w.id for w in wlans)],
            fix=f"Find it in the neighbours list of {device_name(net, r.device_id)} "
            "(signal and channel help to locate it). If it is an old router or repeater of "
            "yours, switch it off or add it to Signalbox; if it is not yours, rename your "
            "network or ask its owner to, and make sure your devices use WPA3, or WPA2 with "
            "protected management frames.",
            key=_key(r.bssid),
            mid=mid,
            fix_id="wifiNeighbours.rogue.fix",
            params=params,
        )


def _candidates(radio: Radio) -> list[int]:
    """20 MHz channels the radio could move to: its supported ones of the usual plan (on
    2.4 GHz 1, 6 and 11; on 5 GHz without radar detection)."""
    plan = _CANDIDATES[radio.band]
    if radio.supported_channels is None:
        return plan
    if radio.band is Band.GHZ_2_4:
        return [c for c in plan if c in radio.supported_channels]
    return sorted(c for c in radio.supported_channels if not 52 <= c <= 144)


def _audible(results: list[WifiScanResult], dbm: int = AUDIBLE_DBM) -> list[WifiScanResult]:
    return [r for r in results if r.signal_dbm is None or r.signal_dbm >= dbm]


class CrowdParams(RuleParams):
    dbm: int = param(
        AUDIBLE_DBM,
        unit="dBm",
        ge=-100,
        le=-30,
        description="Neighbours weaker than this are not counted.",
    )
    count: int = param(
        CROWDED, unit="count", ge=1, le=50, description="Neighbours from which it is reported."
    )


@rule(
    "wifi.channel-crowded",
    "Wi-Fi channel shared with many neighbours",
    Severity.INFO,
    f"The radio heard at least {CROWDED} foreign access points stronger than {AUDIBLE_DBM} "
    "dBm on a channel overlapping its own. They all share the air time, so your clients wait "
    "longer to send, more so when the channel is also busy (wifi.channel-busy). Where the "
    "radio heard a channel with fewer neighbours, the finding names it. Based on a scan "
    "(off by default) or a controller's rogue AP list; radios without one are skipped. "
    "The limits are the parameters count and dbm.",
    params=CrowdParams,
)
def channel_crowded(net: Network) -> Iterator[Result]:
    own = own_macs(net)
    for radio in sorted(net.radios, key=lambda r: r.id):
        if not radio.enabled or radio.channel is None:
            continue
        p = ctx.params(CrowdParams, radio)
        crowd = _audible(foreign_on_channel(net, radio, own), p.dbm)
        if len(crowd) < p.count:
            continue
        heard = [r for r in _audible(heard_by(net, radio), p.dbm) if r.bssid not in own]
        best: tuple[int, int] | None = None
        for c in _candidates(radio):
            if c == radio.channel:
                continue
            moved = radio.model_copy(update={"channel": c, "center_channel": None})
            n = sum(1 for r in heard if shares_channel(moved, r))
            if best is None or n < best[0]:
                best = (n, c)
        label = _label(net, radio)
        params: dict[str, str | int | None] = {
            "radio": label,
            "channel": radio.channel,
            "count": len(crowd),
        }
        busy = radio.channel_utilisation_pct
        if busy is not None:
            params["busy"] = round(busy)
            text = (
                f"{label} shares channel {radio.channel} with {len(crowd)} foreign access "
                f"points (busy {busy:.0f} % of the time)"
            )
            mid = "wifiNeighbours.crowdedBusy"
        else:
            text = f"{label} shares channel {radio.channel} with {len(crowd)} foreign access points"
            mid = "wifiNeighbours.crowded"
        if best is not None and best[0] < len(crowd):
            params |= {"better": best[1], "better_count": best[0]}
            fix = (
                f"Channel {best[1]} has {best[0]} of them: move the radio there, or turn on "
                "automatic channel selection."
            )
            fix_id = "wifiNeighbours.crowded.fixChannel"
        else:
            fix = (
                "No channel the radio heard is less crowded: use a narrower channel, or move "
                "clients to 5 or 6 GHz."
                if radio.band is Band.GHZ_2_4
                else "No channel the radio heard is less crowded: use a narrower channel."
            )
            fix_id = (
                "wifiNeighbours.crowded.fix24"
                if radio.band is Band.GHZ_2_4
                else "wifiNeighbours.crowded.fix"
            )
        yield found(text, [radio.id], fix=fix, mid=mid, fix_id=fix_id, params=params)


RULES: list[Rule] = [rogue_ssid, channel_crowded]
