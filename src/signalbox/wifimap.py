"""The data of the Wi-Fi map (#366): own radios and the neighbouring access points they hear,
with the signal between them, for ``GET /api/wifi-map``.

Privacy (ADR 0025): the neighbours are anonymous here. A foreign SSID or BSSID never leaves
this module; a neighbour is a number, a band, a channel and a signal. The device page's
neighbours card stays the only place that names them.
"""

from __future__ import annotations

from typing import Any

from signalbox.model import Network, Radio, WifiScanResult
from signalbox.neighbours import own_macs

#: The strongest neighbours that get a bubble; more would only be noise on the map.
MAX_NEIGHBOURS = 40

_Group = tuple[str, int | None, str]


def _group_key(r: WifiScanResult) -> _Group:
    """BSSIDs that differ only in the last byte are the SSIDs of one access point (most
    access points derive them from one base address): they are one neighbour. An estimate."""
    return (r.band.value if r.band else "", r.channel, r.bssid.rsplit(":", 1)[0])


def _of_band(radios: dict[str, Radio], device_id: str, result: WifiScanResult) -> Radio | None:
    same = sorted(
        (r for r in radios.values() if r.device_id == device_id and r.band is result.band),
        key=lambda r: r.id,
    )
    return same[0] if same else None


def _hearer(radios: dict[str, Radio], result: WifiScanResult) -> Radio | None:
    """The own radio that reported the result: its radio, else the device's radio of its band
    (a controller that does not say which radio heard it)."""
    if result.radio_id is not None and result.radio_id in radios:
        return radios[result.radio_id]
    return _of_band(radios, result.device_id, result)


def _own_radio(net: Network, radios: dict[str, Radio], result: WifiScanResult) -> Radio | None:
    """The own radio that sends the BSSID of an own scan result."""
    for w in net.wlans:
        if w.bssid == result.bssid and w.radio_id in radios:
            return radios[w.radio_id]
    for p in net.ports:
        if p.mac == result.bssid:
            return _of_band(radios, p.device_id, result)
    return None


def _strength(members: list[tuple[Radio, WifiScanResult]]) -> int:
    return max((m.signal_dbm for _, m in members if m.signal_dbm is not None), default=-999)


def wifi_map(net: Network) -> dict[str, Any]:
    """Nodes (own radios and anonymous neighbours) and edges (the strongest signal heard
    between two of them, in dBm)."""
    radios = {r.id: r for r in net.radios if r.enabled and net.device(r.device_id) is not None}
    own = own_macs(net)
    edges: dict[tuple[str, str], int | None] = {}
    groups: dict[_Group, list[tuple[Radio, WifiScanResult]]] = {}

    def bump(a: str, b: str, signal: int | None) -> None:
        key = (a, b) if a < b else (b, a)
        old = edges.get(key)
        if key not in edges or (signal is not None and (old is None or signal > old)):
            edges[key] = signal

    for res in net.wifi_scan:
        heard = _hearer(radios, res)
        if heard is None:
            continue
        if res.bssid in own:
            other = _own_radio(net, radios, res)
            if other is not None and other.id != heard.id:
                bump(heard.id, other.id, res.signal_dbm)
            continue
        groups.setdefault(_group_key(res), []).append((heard, res))

    ranked = sorted(
        groups.items(), key=lambda kv: (-_strength(kv[1]), kv[0][0], kv[0][1] or 0, kv[0][2])
    )
    nodes: list[dict[str, Any]] = []
    for r in sorted(radios.values(), key=lambda r: r.id):
        dev = net.device(r.device_id)
        nodes.append(
            {
                "id": r.id,
                "kind": "own",
                "device_id": r.device_id,
                "site_id": dev.site_id if dev is not None else None,
                "radio": r.name,
                "band": r.band.value,
                "channel": r.channel,
                "width_mhz": r.width_mhz,
                "utilisation_pct": r.channel_utilisation_pct,
            }
        )
    for index, (_, members) in enumerate(ranked[:MAX_NEIGHBOURS], start=1):
        nid = f"neighbour/{index}"
        first = members[0][1]
        best = _strength(members)
        nodes.append(
            {
                "id": nid,
                "kind": "neighbour",
                "index": index,
                "band": first.band.value if first.band else None,
                "channel": first.channel,
                "width_mhz": first.width_mhz,
                "signal_dbm": None if best == -999 else best,
            }
        )
        for heard, res in members:
            bump(heard.id, nid, res.signal_dbm)
    return {
        "has_scan": bool(net.wifi_scan),
        "nodes": nodes,
        "edges": [{"a": a, "b": b, "signal_dbm": s} for (a, b), s in sorted(edges.items())],
    }
