"""Radio capabilities and current state from ``iwinfo`` and ``hostapd`` over ubus (#172).

``iwinfo info`` (``hwmodes``, ``htmodes``, ``noise``, ``center_chan1``), ``iwinfo freqlist``,
``iwinfo txpowerlist`` and ``iwinfo survey`` (rpcd-mod-iwinfo), called with the radio's
first running interface (``phy0-ap0``), and ``hostapd.<ifname> get_status`` (DFS state, air
time). Each answer is optional: a field the device does not answer stays None.

``iwinfo scan`` (#169) is an active probe: only where the user turned on ``scan_neighbours``.
"""

from __future__ import annotations

from typing import Any

from signalbox.model import Band, DfsState, Security, WifiStandard, normalise_mac

#: ``htmode`` prefix -> the newest standard it enables (``NOHT``: by band).
_HTMODE_STANDARD = {
    "EHT": WifiStandard.BE,
    "HE": WifiStandard.AX,
    "VHT": WifiStandard.AC,
    "HT": WifiStandard.N,
}
_HWMODES = {s.value: s for s in WifiStandard}


def standard_of(htmode: Any, band: Band) -> WifiStandard | None:
    """The configured standard from UCI ``htmode`` (``HE80`` -> ax, ``NOHT`` -> a or g)."""
    text = str(htmode or "").upper()
    if not text:
        return None
    if text.startswith("NOHT"):
        return WifiStandard.G if band is Band.GHZ_2_4 else WifiStandard.A
    for prefix, standard in _HTMODE_STANDARD.items():
        if text.startswith(prefix) and text[len(prefix) :].isdigit():
            return standard
    return None


def band_of_mhz(mhz: int) -> Band | None:
    if 2400 <= mhz < 2500:
        return Band.GHZ_2_4
    if 5150 <= mhz < 5900:
        return Band.GHZ_5
    if 5925 <= mhz <= 7125:
        return Band.GHZ_6
    return None


def _num(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    return float(value)


def _results(answer: dict[str, Any] | None) -> list[dict[str, Any]]:
    rows = (answer or {}).get("results")
    return [r for r in rows if isinstance(r, dict)] if isinstance(rows, list) else []


def capabilities(
    band: Band,
    info: dict[str, Any] | None,
    freqs: dict[str, Any] | None,
    powers: dict[str, Any] | None,
) -> dict[str, Any]:
    """Radio fields from ``iwinfo info``, ``freqlist`` and ``txpowerlist`` (each may be None)."""
    out: dict[str, Any] = {}
    if info:
        modes = info.get("hwmodes")
        if isinstance(modes, list):
            standards = [_HWMODES[m] for m in modes if m in _HWMODES]
            # a dual-band phy lists the modes of both bands: keep those of this band
            if band is Band.GHZ_2_4:
                standards = [s for s in standards if s not in (WifiStandard.A, WifiStandard.AC)]
            else:
                standards = [s for s in standards if s not in (WifiStandard.B, WifiStandard.G)]
            if band is Band.GHZ_6:
                standards = [s for s in standards if s in (WifiStandard.AX, WifiStandard.BE)]
            out["standards"] = sorted(set(standards), key=list(WifiStandard).index)
        htmodes = info.get("htmodes")
        if isinstance(htmodes, list):
            widths = {int(m.lstrip("EHTVN")) for m in htmodes if m.lstrip("EHTVN").isdigit()}
            if band is Band.GHZ_2_4:
                widths &= {20, 40}
            out["supported_widths_mhz"] = sorted(widths) or None
        noise = _num(info.get("noise"))
        if noise is not None and noise < 0:  # 0: the driver does not report noise
            out["noise_dbm"] = int(noise)
        centre = _num(info.get("center_chan1"))
        channel = _num(info.get("channel"))
        if centre and channel and centre != channel:
            out["center_channel"] = int(centre)
    rows = [r for r in _results(freqs) if band_of_mhz(int(_num(r.get("mhz")) or 0)) is band]
    if rows:
        channels = sorted({int(c) for r in rows if (c := _num(r.get("channel"))) is not None})
        out["supported_channels"] = channels
        if band is Band.GHZ_5:
            out["dfs_capable"] = any(52 <= c <= 144 for c in channels)
    dbm = [int(d) for r in _results(powers) if (d := _num(r.get("dbm"))) is not None]
    if dbm:
        out["max_tx_power_dbm"] = max(dbm)
    return out


def utilisation(survey: dict[str, Any] | None, mhz: int | None) -> dict[str, Any]:
    """Busy and interference share of the radio's frequency from ``iwinfo survey``: busy is
    ``busy_time`` of ``active_time``; interference is busy time neither received nor sent by
    this radio. The counters run since the driver started, so they are averages."""
    for row in _results(survey):
        if mhz is None or _num(row.get("mhz")) != mhz:
            continue
        active, busy = _num(row.get("active_time")), _num(row.get("busy_time"))
        if not active or busy is None:
            return {}
        out: dict[str, Any] = {"channel_utilisation_pct": round(min(100.0, 100 * busy / active), 1)}
        rx, tx = _num(row.get("rx_time")), _num(row.get("tx_time"))
        if rx is not None and tx is not None:
            other = max(0.0, busy - rx - tx)
            out["interference_pct"] = round(min(100.0, 100 * other / active), 1)
        noise = _num(row.get("noise"))
        if noise is not None and noise < 0:
            out["noise_dbm"] = int(noise)
        return out
    return {}


def status(answer: dict[str, Any] | None, dfs_channel: bool) -> dict[str, Any]:
    """``hostapd get_status``: the DFS state (channel availability check running or done) and,
    without a survey, hostapd's channel utilisation (0-255)."""
    if not answer:
        return {}
    out: dict[str, Any] = {}
    dfs = answer.get("dfs")
    if dfs_channel and isinstance(dfs, dict):
        out["dfs_state"] = DfsState.CAC if dfs.get("cac_active") is True else DfsState.AVAILABLE
    airtime = answer.get("airtime")
    load = _num(airtime.get("utilization")) if isinstance(airtime, dict) else None
    if load is not None:
        out["channel_utilisation_pct"] = round(min(100.0, 100 * load / 255), 1)
    return out


def bssid_of(info: dict[str, Any] | None) -> str | None:
    """The interface's BSSID from ``iwinfo info`` (#169)."""
    try:
        return normalise_mac(str((info or {})["bssid"]))
    except (KeyError, ValueError):
        return None


def scan_security(enc: Any) -> Security | None:
    """Security of a scanned network from rpcd-mod-iwinfo's ``encryption`` object."""
    if not isinstance(enc, dict):
        return None
    if enc.get("enabled") is False:
        return Security.OPEN
    if enc.get("enabled") is not True:
        return None
    auth = {str(a) for a in enc.get("authentication") or []}
    versions = {v for v in enc.get("wpa") or [] if isinstance(v, int)}
    if "owe" in auth:
        return Security.OWE
    if enc.get("wep") or (not versions and not auth):
        return Security.WEP
    if "802.1x" in auth:
        if versions == {3}:
            return Security.WPA3_ENTERPRISE
        if 1 in versions:
            return Security.WPA_ENTERPRISE
        return Security.WPA2_ENTERPRISE
    if "sae" in auth:
        return Security.WPA2_WPA3 if "psk" in auth else Security.WPA3
    if "psk" in auth:
        if versions == {1}:
            return Security.WPA
        if 1 in versions:
            return Security.WPA_WPA2
        return Security.WPA2
    return Security.OTHER


def _scan_width(row: dict[str, Any]) -> int | None:
    vht = row.get("vht_operation")
    if isinstance(vht, dict) and (w := _num(vht.get("channel_width"))) is not None:
        return 160 if w in (160, 8080) else int(w)
    ht = row.get("ht_operation")
    if isinstance(ht, dict) and (w := _num(ht.get("channel_width"))) is not None:
        return 40 if w == 2040 else 20
    return None


def scan(answer: dict[str, Any] | None) -> list[dict[str, Any]]:
    """Fields of :class:`~signalbox.model.WifiScanResult` from ``iwinfo scan``: access points
    only (mode ``Master``); a hidden network has no SSID. Nothing about their stations."""
    out = []
    for row in _results(answer):
        if str(row.get("mode", "Master")) != "Master":
            continue
        try:
            bssid = normalise_mac(str(row.get("bssid")))
        except ValueError:
            continue
        mhz = _num(row.get("mhz"))
        channel = _num(row.get("channel"))
        signal = _num(row.get("signal"))
        ssid = row.get("ssid")
        out.append(
            {
                "bssid": bssid,
                "ssid": ssid if isinstance(ssid, str) and ssid else None,
                "band": band_of_mhz(int(mhz)) if mhz else None,
                "channel": int(channel) if channel else None,
                "width_mhz": _scan_width(row),
                "signal_dbm": int(signal) if signal is not None and -120 <= signal < 0 else None,
                "security": scan_security(row.get("encryption")),
            }
        )
    return out
