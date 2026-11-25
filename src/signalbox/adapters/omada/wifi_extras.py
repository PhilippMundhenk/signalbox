"""Omada roaming and steering settings (#469) as Wlan fields.

All spellings are *guesses* from the Open API's wireless pages (not checked against a
controller, #21): the SSID detail has ``rateAndBeaconCtrl`` / ``dtimPeriod`` and ``rssiSetting``;
the site settings ``…/setting/roaming``, ``…/setting/band-steering`` and
``…/setting/airtime-fairness`` answer a flat object each. A setting that is absent is not
reported (never an invented default); controllers without these endpoints (5.x before the
wireless settings were added to the Open API) answer 404 and nothing is reported.
Not in the API at all: the 802.11r mobility domain and the key holder.
"""

from __future__ import annotations

from typing import Any

from signalbox.model import BandSteering


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    text = _text(value)
    return int(text) if text.lstrip("-").isdigit() else None


def _flag(value: Any) -> bool | None:
    if value is None:
        return None
    return value in (True, 1, "1", "true")


def _first(obj: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if obj.get(key) is not None:
            return obj[key]
    return None


def site_fields(
    roaming: dict[str, Any] | None,
    steering: dict[str, Any] | None,
    airtime: dict[str, Any] | None,
) -> dict[str, Any]:
    """Fields every SSID of the site shares: 802.11k and 802.11v (``dualBand11kReportEnable``,
    ``btmEnable`` / ``forceDisassociationEnable``), band steering and airtime fairness."""
    out: dict[str, Any] = {}
    if roaming:
        k = _flag(_first(roaming, "dualBand11kReportEnable", "enable11k"))
        v = _flag(_first(roaming, "btmEnable", "enable11v"))
        if k is not None:
            out["roaming_80211k"] = k
        if v is not None:
            out["roaming_80211v"] = v
    if steering:
        on = _flag(_first(steering, "enable", "bandSteeringEnable"))
        if on is not None:
            out["band_steering"] = BandSteering.PREFER_5GHZ if on else BandSteering.OFF
    if airtime:
        on = _flag(_first(airtime, "enable", "airtimeFairnessEnable"))
        if on is not None:
            out["airtime_fairness"] = on
    return out


def ssid_fields(ssid: dict[str, Any]) -> dict[str, Any]:
    """Fields of one SSID detail: DTIM period and the minimum RSSI (``rssiSetting``)."""
    out: dict[str, Any] = {}
    beacon = ssid.get("rateAndBeaconCtrl")
    dtim = _int(_first(beacon, "dtimPeriod", "dtim") if isinstance(beacon, dict) else None)
    if dtim is None:
        dtim = _int(ssid.get("dtimPeriod"))
    if dtim is not None and 1 <= dtim <= 255:
        out["dtim_period"] = dtim
    rssi = ssid.get("rssiSetting")
    if isinstance(rssi, dict) and _flag(rssi.get("rssiEnable")):
        low = _int(_first(rssi, "threshold", "rssi"))
        if low is not None and -120 <= low < 0:
            out["min_rssi_dbm"] = low
    return out
