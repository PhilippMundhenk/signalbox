"""Roaming settings across access points (#168) and client association quality (#170)."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterator

from signalbox.model import Client, Network, WifiStandard, Wlan
from signalbox.rules import Result, Rule, RuleParams, Severity, ctx, found, param, rule
from signalbox.rules._names import device_name, site_of_device

#: Standards that slow a whole radio down: 802.11b and g clients (#170).
LEGACY_STANDARDS = (WifiStandard.B, WifiStandard.G)


def _by_ssid(net: Network) -> dict[tuple[str, str], list[Wlan]]:
    """Enabled WLANs by (site, SSID), in id order."""
    groups: dict[tuple[str, str], list[Wlan]] = defaultdict(list)
    for w in sorted(net.wlans, key=lambda w: w.id):
        site = site_of_device(net, w.device_id)
        if w.enabled and not w.backhaul and site is not None:
            groups[(site, w.ssid)].append(w)
    return groups


def _who(c: Client) -> str:
    return f"{c.hostname} ({c.mac})" if c.hostname else c.mac


def _ap_of(net: Network, c: Client) -> tuple[Wlan, str] | None:
    """The WLAN a client is associated with and the name of its access point."""
    if c.wireless is None or c.wireless.wlan_id is None:
        return None
    w = next((w for w in net.wlans if w.id == c.wireless.wlan_id), None)
    return (w, device_name(net, w.device_id)) if w is not None else None


# wifi.ft-mobility-domain-mismatch (#168, #90) -----------------------------------------------


@rule(
    "wifi.ft-mobility-domain-mismatch",
    "Access points use different 802.11r mobility domains for one SSID",
    Severity.WARNING,
    "Fast roaming (802.11r) only works between access points of the same mobility domain. "
    "With different domains on one SSID, clients fall back to a slow full reconnect or cannot "
    "roam at all. Only access points that report their domain are compared.",
)
def ft_mobility_domain_mismatch(net: Network) -> Iterator[Result]:
    for (_, ssid), wlans in sorted(_by_ssid(net).items()):
        domains = {
            w.device_id: w.ft.mobility_domain
            for w in wlans
            if w.roaming_80211r is not False and w.ft is not None and w.ft.mobility_domain
        }
        if len(set(domains.values())) < 2:
            continue
        listed = ", ".join(f"{device_name(net, d)}: {m}" for d, m in sorted(domains.items()))
        yield found(
            f"SSID {ssid!r} uses different 802.11r mobility domains ({listed}), so fast "
            "roaming between these access points does not work",
            [w.id for w in wlans if w.device_id in domains],
            fix=f"Set the same mobility domain for {ssid!r} on all access points.",
            mid="wifi.ftDomainMismatch",
            fix_id="wifi.ftDomainMismatch.fix",
            params={"ssid": repr(ssid), "domains": listed},
        )


# wifi.min-rssi-too-high (#168) ----------------------------------------------------------------


class MinRssiHighParams(RuleParams):
    max_dbm: int = param(
        -70,
        unit="dBm",
        ge=-120,
        le=0,
        description="A minimum signal above this kicks clients that are still usable (#168). "
        "The fix suggests 5 dBm below it.",
    )


@rule(
    "wifi.min-rssi-too-high",
    "Minimum signal strength of an SSID is set so high that it kicks usable clients",
    Severity.WARNING,
    "A minimum signal (minimum RSSI) helps sticky clients roam, but above -70 dBm (the "
    "parameter max_dbm) it also kicks clients that still have a usable connection, and they "
    "reconnect in a loop. Only access points that report the limit are judged.",
    params=MinRssiHighParams,
)
def min_rssi_too_high(net: Network) -> Iterator[Result]:
    for w in sorted(net.wlans, key=lambda w: w.id):
        limits = [v for v in (w.min_rssi_dbm, w.assoc_rssi_dbm) if v is not None]
        max_dbm = ctx.params(MinRssiHighParams, w).max_dbm
        if not w.enabled or w.backhaul or not limits or max(limits) <= max_dbm:
            continue
        ap = device_name(net, w.device_id)
        yield found(
            f"SSID {w.ssid!r} on {ap} refuses or kicks clients weaker than {max(limits)} dBm",
            [w.id, w.device_id],
            fix=f"Lower the minimum signal of {w.ssid!r} on {ap} to {max_dbm - 5} dBm "
            "or weaker, or turn it off.",
            mid="wifi.minRssiHigh",
            fix_id="wifi.minRssiHigh.fix",
            params={
                "ssid": repr(w.ssid),
                "ap": ap,
                "dbm": max(limits),
                "suggested": max_dbm - 5,
            },
        )


# wifi.min-rssi-inconsistent (#168) ------------------------------------------------------------


@rule(
    "wifi.min-rssi-inconsistent",
    "Minimum signal strength differs between the access points of an SSID",
    Severity.INFO,
    "With different minimum signal limits, one access point kicks a client that the next one "
    "accepts, so roaming depends on where the client is. Only access points that report a "
    "limit are compared.",
)
def min_rssi_inconsistent(net: Network) -> Iterator[Result]:
    for (_, ssid), wlans in sorted(_by_ssid(net).items()):
        limits = {w.device_id: w.min_rssi_dbm for w in wlans if w.min_rssi_dbm is not None}
        if len(set(limits.values())) < 2:
            continue
        listed = ", ".join(f"{device_name(net, d)}: {v} dBm" for d, v in sorted(limits.items()))
        yield found(
            f"SSID {ssid!r} has different minimum signal limits ({listed})",
            [w.id for w in wlans if w.device_id in limits],
            fix=f"Use the same minimum signal for {ssid!r} on all access points.",
            mid="wifi.minRssiInconsistent",
            fix_id="wifi.minRssiInconsistent.fix",
            params={"ssid": repr(ssid), "limits": listed},
        )


# wifi.client-weak-signal (#170) ---------------------------------------------------------------


class WeakSignalParams(RuleParams):
    min_dbm: int = param(
        -75,
        unit="dBm",
        ge=-120,
        le=0,
        description="A client below this signal is slow and drops packets (#170).",
    )


@rule(
    "wifi.client-weak-signal",
    "A Wi-Fi client has a weak signal",
    Severity.INFO,
    "A client below -75 dBm (the parameter min_dbm) gets slow rates and many retries. This is "
    "one reading, not a trend: a device carried past the access point shows up too. Clients "
    "without a reported signal are not judged.",
    params=WeakSignalParams,
)
def client_weak_signal(net: Network) -> Iterator[Result]:
    for c in sorted(net.clients, key=lambda c: c.mac):
        signal = c.wireless.signal_dbm if c.wireless else None
        where = _ap_of(net, c)
        if signal is None or where is None:
            continue
        wlan, ap = where
        if signal >= ctx.params(WeakSignalParams, wlan).min_dbm:
            continue
        yield found(
            f"{_who(c)} has a weak Wi-Fi signal ({signal} dBm) on {ap}",
            [wlan.id, c.id],
            fix="Move the device or an access point closer together, or add an access point "
            "where the device is used.",
            key=c.mac,
            mid="wifi.clientWeakSignal",
            fix_id="wifi.clientWeakSignal.fix",
            params={"client": _who(c), "dbm": signal, "ap": ap},
        )


# wifi.legacy-client (#170) --------------------------------------------------------------------


@rule(
    "wifi.legacy-client",
    "A Wi-Fi client only uses an old standard (802.11b or g)",
    Severity.INFO,
    "Frames of an 802.11b or g client take far more air time than those of a newer client, so "
    "one old device slows down everyone on the same radio. Clients without a reported "
    "standard are not judged.",
)
def legacy_client(net: Network) -> Iterator[Result]:
    for c in sorted(net.clients, key=lambda c: c.mac):
        standard = c.wireless.standard if c.wireless else None
        where = _ap_of(net, c)
        if standard not in LEGACY_STANDARDS or where is None:
            continue
        wlan, ap = where
        yield found(
            f"{_who(c)} connects to {ap} with 802.11{standard.value if standard else ''}, which "
            "slows down the other devices on the radio",
            [c.id, wlan.id],
            fix="Replace the device, or give it an SSID of its own on a separate radio.",
            key=c.mac,
            mid="wifi.legacyClient",
            fix_id="wifi.legacyClient.fix",
            params={"client": _who(c), "ap": ap, "standard": standard.value if standard else ""},
        )


RULES: list[Rule] = [
    ft_mobility_domain_mismatch,
    min_rssi_too_high,
    min_rssi_inconsistent,
    client_weak_signal,
    legacy_client,
]
