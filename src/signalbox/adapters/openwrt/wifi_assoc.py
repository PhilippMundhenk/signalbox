"""Roaming settings of a Wi-Fi interface (#168) and the association details of its stations
(#170) as OpenWrt reports them.

Versions: ``hostapd.<if> get_clients`` has ``signal`` everywhere, ``rate`` (kbit/s) since 22.03
(hostapd 2.10); ``iwinfo assoclist`` (rpcd-mod-iwinfo) answers signal, noise, rates, inactive
time and connected time on 21.02 as well, and fills what hostapd does not say.
"""

from __future__ import annotations

import hashlib
from typing import Any

from signalbox.model import (
    Band,
    BandSteering,
    FastTransition,
    FtKeyHolder,
    WifiStandard,
    WirelessAssociation,
)


def _flag(value: Any) -> bool | None:
    if value is None:
        return None
    return str(value).lower() in ("1", "true", "yes", "on", "enabled")


def _int(value: Any) -> int | None:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return None


def default_mobility_domain(ssid: str) -> str:
    """What netifd's hostapd.sh uses without ``mobility_domain``: the first four hex digits of
    the MD5 sum of the SSID (``echo "$ssid" | md5sum``, so with the newline)."""
    return hashlib.md5(f"{ssid}\n".encode(), usedforsecurity=False).hexdigest()[:4]


def roaming_fields(iface: dict[str, Any], device: dict[str, Any], ssid: str) -> dict[str, Any]:
    """Wlan fields (#168) from a ``wifi-iface`` section and its ``wifi-device`` section."""
    fields: dict[str, Any] = {}
    if _flag(iface.get("ieee80211r")):
        domain = str(iface.get("mobility_domain") or "").lower()
        if len(domain) != 4 or any(c not in "0123456789abcdef" for c in domain):
            domain = default_mobility_domain(ssid)
        holder = None
        if "ft_psk_generate_local" in iface:
            holder = FtKeyHolder.LOCAL if _flag(iface["ft_psk_generate_local"]) else None
            if holder is None:
                holder = FtKeyHolder.PMK_R1_PUSH
        fields["ft"] = FastTransition(
            mobility_domain=domain,
            over_ds=_flag(iface.get("ft_over_ds")),
            key_holder=holder,
            reassociation_deadline_ms=_int(iface.get("reassociation_deadline")),
        )
    rssi = _int(iface.get("rssi_reject_assoc_rssi"))
    if rssi is not None and -120 <= rssi < 0:
        fields["assoc_rssi_dbm"] = rssi
    mode = _int(device.get("airtime_mode"))
    if mode is not None:
        fields["airtime_fairness"] = mode > 0
    if "multicast_to_unicast" in iface:
        fields["multicast_to_unicast"] = _flag(iface["multicast_to_unicast"])
    dtim = _int(iface.get("dtim_period"))
    if dtim is not None and 1 <= dtim <= 255:
        fields["dtim_period"] = dtim
    beacon = _int(device.get("beacon_int"))
    if beacon is not None and beacon > 0:
        fields["beacon_interval_ms"] = beacon
    idle = _int(iface.get("max_inactivity"))
    if idle is not None and idle >= 0:
        fields["bss_max_idle_seconds"] = idle
    limit = _int(iface.get("maxassoc"))
    if limit is not None and limit >= 0:
        fields["max_clients"] = limit
    return fields


#: usteer's defaults (``band_steering_interval`` in ms, ``load_balancing_threshold`` in clients).
USTEER_BAND_STEERING_MS = 120000
#: dawn's metric weights for a station on 5 GHz and on 2.4 GHz (``freq_5``, ``freq_2``).
DAWN_FREQ_5, DAWN_FREQ_2 = 100, 0


def band_steering(usteer: dict[str, Any], dawn: dict[str, Any]) -> BandSteering | None:
    """Band steering a steering daemon does for this access point's SSIDs (#447), from the
    ``usteer`` and ``dawn`` UCI configs (each ``{"values": {...}}`` as ``uci get`` answers; empty:
    package not installed or not readable). None: neither is installed, so nothing is known.

    usteer: ``band_steering_interval`` (ms, 0 off; default 120000) steers clients to a higher
    band, ``load_balancing_threshold`` (clients, 0 off) balances them. dawn: the ``metric``
    section's ``freq_5`` against ``freq_2`` ranks 5 GHz above 2.4 GHz. *(Guess: option names and
    defaults from the usteer and dawn READMEs, not tried on a device, #21.)* The daemons' own
    ``network`` filter and whether the service runs are not looked at.
    """
    steer = _usteer(usteer)
    return steer if steer is not None else _dawn(dawn)


def _sections_of(config: dict[str, Any], kind: str) -> list[dict[str, Any]]:
    values = config.get("values")
    if not isinstance(values, dict):
        return []
    return [v for v in values.values() if isinstance(v, dict) and v.get(".type") == kind]


def _usteer(config: dict[str, Any]) -> BandSteering | None:
    for sec in _sections_of(config, "usteer")[:1]:
        interval = _int(sec.get("band_steering_interval"))
        if (USTEER_BAND_STEERING_MS if interval is None else interval) > 0:
            return BandSteering.PREFER_5GHZ
        balance = _int(sec.get("load_balancing_threshold"))
        return BandSteering.BALANCE if balance and balance > 0 else BandSteering.OFF
    return None


def _dawn(config: dict[str, Any]) -> BandSteering | None:
    for sec in _sections_of(config, "metric")[:1]:
        f5, f2 = _int(sec.get("freq_5")), _int(sec.get("freq_2"))
        high = DAWN_FREQ_5 if f5 is None else f5
        low = DAWN_FREQ_2 if f2 is None else f2
        return BandSteering.PREFER_5GHZ if high > low else BandSteering.OFF
    return None


def _valid_dbm(value: Any) -> int | None:
    number = _int(value)
    return number if number is not None and -120 <= number < 0 else None


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _kbit(value: Any) -> float | None:
    number = _int(value)
    return round(number / 1000, 1) if number is not None and number >= 0 else None


def _standard(entry: dict[str, Any], band: Band | None) -> WifiStandard | None:
    if entry.get("eht"):
        return WifiStandard.BE
    if entry.get("he"):
        return WifiStandard.AX
    if entry.get("vht"):
        return WifiStandard.AC
    if entry.get("ht"):
        return WifiStandard.N
    if band is Band.GHZ_2_4:
        return WifiStandard.G
    return WifiStandard.A if band is not None else None


def _capabilities(entry: dict[str, Any]) -> list[str]:
    caps: list[str] = []
    rrm = entry.get("rrm")
    if isinstance(rrm, list) and any(_int(b) for b in rrm):
        caps.append("11k")
    ext = entry.get("extended_capabilities")
    # BSS transition management (802.11v) is bit 19 of the extended capabilities
    if isinstance(ext, list) and len(ext) > 2 and (_int(ext[2]) or 0) & 0x08:
        caps.append("11v")
    if entry.get("mfp"):
        caps.append("pmf")
    return caps


def association(
    entry: dict[str, Any],
    *,
    radio_id: str,
    wlan_id: str,
    band: Band | None,
    bssid: str | None,
    iwinfo: dict[str, Any] | None,
    noise_dbm: int | None,
) -> WirelessAssociation:
    """One station from ``hostapd get_clients`` plus its ``iwinfo assoclist`` entry (if any)."""
    info = iwinfo or {}
    rx_info = _dict(info.get("rx"))
    tx_info = _dict(info.get("tx"))
    rate = _dict(entry.get("rate"))
    signal = _valid_dbm(entry.get("signal"))
    if signal is None:
        signal = _valid_dbm(info.get("signal"))
    noise = _valid_dbm(info.get("noise"))
    if noise is None:
        noise = noise_dbm
    snr = signal - noise if signal is not None and noise is not None and signal > noise else None
    packets = _int(tx_info.get("packets"))
    retries = _int(tx_info.get("retries"))
    retries_pct = (
        round(100 * retries / packets, 1)
        if packets and retries is not None and 0 <= retries <= packets
        else None
    )
    inactive = _int(info.get("inactive"))  # milliseconds
    return WirelessAssociation(
        radio_id=radio_id,
        wlan_id=wlan_id,
        bssid=bssid,
        band=band,
        signal_dbm=signal,
        noise_dbm=noise,
        snr_db=snr,
        tx_rate_mbps=_kbit(rate.get("tx")) if rate else _kbit(tx_info.get("rate")),
        rx_rate_mbps=_kbit(rate.get("rx")) if rate else _kbit(rx_info.get("rate")),
        standard=_standard({**entry, **{k: v for k, v in rx_info.items() if v}}, band),
        width_mhz=_width(rx_info),
        connected_seconds=_int(info.get("connected_time")),
        inactive_seconds=inactive // 1000 if inactive is not None and inactive >= 0 else None,
        capabilities=_capabilities(entry),
        retries_pct=retries_pct,
        tx_failed=_int(tx_info.get("failed")),
    )


def _width(rx: dict[str, Any]) -> int | None:
    for key, mhz in (("160mhz", 160), ("80mhz", 80), ("40mhz", 40)):
        if rx.get(key):
            return mhz
    return 20 if any(k in rx for k in ("40mhz", "80mhz", "160mhz")) else None
