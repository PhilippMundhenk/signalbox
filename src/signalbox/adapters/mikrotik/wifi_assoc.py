"""RouterOS Wi-Fi roaming settings (#168) and registration-table rows (#170) as values.

Versions: ``/interface/wifi`` (RouterOS 7.13 and newer; the ``wifiwave2`` package of 7.6 to
7.12 has the same menu) and the older ``/interface/wireless`` registration table (RouterOS 6
and 7 with the ``wireless`` package). Spellings not checked against a device are marked
*(guess)*.
"""

from __future__ import annotations

import re
from typing import Any

from signalbox.model import Band, WifiStandard, WirelessAssociation

_RATE = re.compile(
    r"(?P<rate>\d+(?:\.\d+)?)\s*(?P<unit>[GMK]?)bps"
    r"(?:[-/ ]+(?P<width>\d+)\s*MHz)?(?:[-/ ]+(?P<streams>\d+)\s*S\b)?",
    re.IGNORECASE,
)
_SIGNAL = re.compile(r"-?\d+")
_TIME = re.compile(r"(?:(\d+)w)?(?:(\d+)d)?(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?")


def _text(value: Any) -> str:
    return "" if value is None else str(value).strip()


def rate(value: Any) -> tuple[float | None, int | None, int | None]:
    """``866.7Mbps-80MHz-2S-short-GI`` (``wifi``) or ``144.4Mbps-20MHz/2S/SGI`` (``wireless``)
    -> (Mbit/s, width in MHz, spatial streams); parts the text does not have are None."""
    match = _RATE.search(_text(value))
    if match is None:
        return None, None, None
    factor = {"G": 1000.0, "M": 1.0, "K": 0.001, "": 1e-6}[match["unit"].upper()]
    mbps = round(float(match["rate"]) * factor, 1)
    width = int(match["width"]) if match["width"] else None
    streams = int(match["streams"]) if match["streams"] else None
    return mbps, width, streams


def signal(value: Any) -> int | None:
    """``-61`` (``wifi``) or ``-55dBm`` / ``-55@6Mbps`` (``wireless``) -> dBm."""
    match = _SIGNAL.match(_text(value))
    if match is None:
        return None
    dbm = int(match.group())
    return dbm if -120 <= dbm < 0 else None


def uptime(value: Any) -> int | None:
    """``1h2m3s`` or ``00:10:00`` -> seconds."""
    text = _text(value).replace(" ", "")
    if not text:
        return None
    if ":" in text:
        try:
            parts = [int(float(p)) for p in text.split(":")]
        except ValueError:
            return None
        h, m, s = ([0] * (3 - len(parts)) + parts)[-3:]
        return h * 3600 + m * 60 + s
    match = _TIME.fullmatch(text)
    if match is None or not any(match.groups()):
        return None
    w, d, h, m, s = (int(g) if g else 0 for g in match.groups())
    return (((w * 7 + d) * 24 + h) * 60 + m) * 60 + s


def mobility_domain(value: Any) -> str | None:
    """``ft-mobility-domain`` as four hex digits: RouterOS shows an integer, 0 to 65535, or
    ``0xadc1`` *(guess: which of the two the REST API sends)*."""
    text = _text(value).lower()
    try:
        number = int(text, 16) if text.startswith("0x") else int(text)
    except ValueError:
        return None
    return f"{number:04x}" if 0 <= number <= 0xFFFF else None


def min_signal(rows: list[dict[str, Any]], interface: str) -> int | None:
    """Weakest signal ``/interface/wifi/access-list`` lets an interface's clients have: the
    lower end of ``signal-range`` (``-80..120``) of the entries that accept clients on this
    interface (or on all) without limiting them to a MAC address or an SSID. None: no limit
    *(guess: the REST spelling)*."""
    best: int | None = None
    for row in rows:
        if _text(row.get("disabled")).lower() in ("true", "yes"):
            continue
        if _text(row.get("action")) not in ("", "accept"):
            continue
        if _text(row.get("mac-address")) or _text(row.get("ssid-regexp")):
            continue
        if _text(row.get("interface")) not in ("", interface):
            continue
        match = re.match(r"(-\d+)\s*\.\.", _text(row.get("signal-range")))
        if match is not None:
            low = int(match.group(1))
            if -120 <= low < 0:
                best = low if best is None else max(best, low)
    return best


def association(
    row: dict[str, Any],
    *,
    radio_id: str | None,
    wlan_id: str,
    band: Band | None,
    standard: WifiStandard | None,
) -> WirelessAssociation:
    """One registration-table row of either package."""
    tx, tx_width, tx_streams = rate(row.get("tx-rate"))
    rx, rx_width, rx_streams = rate(row.get("rx-rate"))
    return WirelessAssociation(
        radio_id=radio_id,
        wlan_id=wlan_id,
        band=band,
        signal_dbm=signal(row.get("signal", row.get("signal-strength"))),
        tx_rate_mbps=tx,
        rx_rate_mbps=rx,
        standard=standard,
        width_mhz=tx_width or rx_width,
        spatial_streams=tx_streams or rx_streams,
        connected_seconds=uptime(row.get("uptime")),
        capabilities=["pmf"] if "pmf" in _text(row.get("auth-type")).lower() else [],
    )
