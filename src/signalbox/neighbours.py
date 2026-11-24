"""Neighbouring Wi-Fi networks (#169, ADR 0025): which scan results are our own access points,
which share a radio's channel, and the rows of ``GET /api/wifi-scan``.

Scan results are other people's data; this module only derives counts and flags from them,
for the checks, the channel planner and the device page.
"""

from __future__ import annotations

from typing import Any

from signalbox.model import Band, Network, Radio, WifiScanResult


def own_macs(net: Network) -> set[str]:
    """MAC addresses that are ours: the BSSIDs of our WLANs and the MACs of our ports (a
    Wi-Fi interface's MAC is often its BSSID)."""
    return net.own_bssids() | {p.mac for p in net.ports if p.mac is not None}


def is_own(net: Network, result: WifiScanResult, own: set[str] | None = None) -> bool:
    return result.bssid in (own if own is not None else own_macs(net))


def _span(band: Band, channel: int, width: int | None) -> set[int]:
    """The 20 MHz channels a 5 or 6 GHz network on ``channel`` occupies: the aligned block of
    its width (20 MHz where the width is not known); on 2.4 GHz the channel and the four
    on each side it overlaps."""
    if band is Band.GHZ_2_4:
        return set(range(channel - 4, channel + 5))
    n = max(1, (width or 20) // 20)
    base = 1 if band is Band.GHZ_6 else (149 if channel >= 149 else 36)
    block = (channel - base) // (4 * n)
    return {base + 4 * (block * n + k) for k in range(n)}


def shares_channel(radio: Radio, result: WifiScanResult) -> bool:
    """The scan result sends on a channel that overlaps the radio's (same band)."""
    if radio.channel is None or result.channel is None or result.band is not radio.band:
        return False
    if radio.band is Band.GHZ_2_4:
        return abs(radio.channel - result.channel) < 5
    mine = _span(radio.band, radio.channel, radio.width_mhz)
    return bool(mine & _span(radio.band, result.channel, result.width_mhz))


def heard_by(net: Network, radio: Radio) -> list[WifiScanResult]:
    """Scan results of this radio; results without a radio count for the device's radio of
    their band (a controller that does not say which radio heard them)."""
    return [
        r
        for r in net.wifi_scan
        if r.radio_id == radio.id
        or (r.radio_id is None and r.device_id == radio.device_id and r.band is radio.band)
    ]


def foreign_on_channel(
    net: Network, radio: Radio, own: set[str] | None = None
) -> list[WifiScanResult]:
    """Foreign access points this radio heard on a channel overlapping its own."""
    mine = own if own is not None else own_macs(net)
    return [r for r in heard_by(net, radio) if r.bssid not in mine and shares_channel(radio, r)]


def radio_neighbours(net: Network, radio: Radio) -> dict[str, Any]:
    """``neighbour_count`` (foreign access points on the radio's channel) and
    ``strongest_foreign_dbm``; both None while the radio reported no scan."""
    if not heard_by(net, radio):
        return {"neighbour_count": None, "strongest_foreign_dbm": None}
    foreign = foreign_on_channel(net, radio)
    signals = [r.signal_dbm for r in foreign if r.signal_dbm is not None]
    return {
        "neighbour_count": len(foreign),
        "strongest_foreign_dbm": max(signals) if signals else None,
    }


def scan_rows(net: Network) -> list[dict[str, Any]]:
    """Every scan result as JSON with ``own`` and ``own_ssid`` (a foreign BSSID with one of
    our SSIDs at the same site), strongest first per device."""
    own = own_macs(net)
    ssids: dict[str, set[str]] = {}
    for w in net.wlans:
        dev = net.device(w.device_id)
        if dev is not None and w.enabled:
            ssids.setdefault(dev.site_id, set()).add(w.ssid)
    out = []
    for r in sorted(
        net.wifi_scan,
        key=lambda r: (r.device_id, -(r.signal_dbm if r.signal_dbm is not None else -999), r.id),
    ):
        raw = r.model_dump(mode="json")
        dev = net.device(r.device_id)
        mine = r.bssid in own
        raw["own"] = mine
        raw["own_ssid"] = (
            not mine
            and r.ssid is not None
            and dev is not None
            and r.ssid in ssids.get(dev.site_id, set())
        )
        out.append(raw)
    return out
