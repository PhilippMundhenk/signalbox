"""Wi-Fi security details rules: weak modes, WPA3, passphrase reuse, WPS, H2E (#86, #89, #101,
#104). They use the security details of the model (#167); where a device did not report one the
rules stay quiet."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterator

from signalbox.model import (
    Band,
    Cipher,
    Network,
    SaePwe,
    Security,
    SegmentPurpose,
    Wlan,
    WpsMethod,
)
from signalbox.rules import Result, Rule, Severity, found, rule
from signalbox.rules._names import device_name, site_of_device
from signalbox.rules.wifi_hygiene import (
    SECURITY_TEXT,
    _enabled_wlans,
    _ids,
    _per_ap,
    _radios,
)

WEAK_CIPHERS = {Cipher.TKIP, Cipher.WEP}
WPA3_MODES = {Security.WPA3, Security.WPA2_WPA3}


def _is_guest(net: Network, w: Wlan) -> bool:
    """A guest WLAN: its own purpose, else the purpose of its network."""
    if w.purpose is not None:
        return w.purpose is SegmentPurpose.GUEST
    seg = net.segment(w.segment_id) if w.segment_id else None
    return seg is not None and seg.purpose is SegmentPurpose.GUEST


# weak security (#86) --------------------------------------------------------------------------


@rule(
    "wifi.weak-security",
    "Wi-Fi network with open, WEP, WPA1 or TKIP security",
    Severity.ERROR,
    "An open network lets anyone nearby join and read unencrypted traffic, WEP and TKIP are "
    "broken, and WPA version 1 and WPA/WPA2 mixed mode keep the weak TKIP cipher available. "
    "Old ciphers also force slow legacy rates on the whole radio. An open guest network is "
    "only a warning (Enhanced Open, OWE, is better); the other findings are errors, except "
    "WPA/WPA2 mixed mode and TKIP offered next to AES, which are warnings.",
)
def weak_security(net: Network) -> Iterator[Result]:
    wlans = _enabled_wlans(net)
    groups = _per_ap(wlans, "security", "ciphers", "group_cipher")
    for (dev, ssid, *_), group in sorted(groups.items()):
        w = group[0]
        errors: list[str] = []
        warnings: list[str] = []
        if w.security is Security.OPEN:
            (warnings if _is_guest(net, w) else errors).append("open (no password)")
        elif w.security in (Security.WEP, Security.WPA):
            errors.append(SECURITY_TEXT[w.security])
        elif w.security in (Security.WPA_WPA2, Security.WPA_ENTERPRISE):
            warnings.append(SECURITY_TEXT[w.security])
        ciphers = set(w.ciphers or [])
        weak = sorted(c.value.upper() for c in ciphers & WEAK_CIPHERS)
        if weak and ciphers <= WEAK_CIPHERS:
            errors.append(f"only {', '.join(weak)}")
        elif weak:
            warnings.append(f"also {', '.join(weak)}")
        if w.group_cipher in WEAK_CIPHERS and not (ciphers and ciphers <= WEAK_CIPHERS):
            assert w.group_cipher is not None
            warnings.append(f"{w.group_cipher.value.upper()} (broadcast)")
        if not errors and not warnings:
            continue
        reasons = errors + warnings
        fix = (
            "Use WPA2/WPA3 with AES (CCMP) only"
            + (
                ", or OWE (Enhanced Open) for a guest network"
                if w.security is Security.OPEN
                else ""
            )
            + "."
        )
        yield found(
            f"SSID {ssid!r} on {device_name(net, dev)} has weak security: " + ", ".join(reasons),
            _ids(group),
            fix=fix,
            severity=Severity.ERROR if errors else Severity.WARNING,
            mid="wifi.weakSecurity",
            fix_id="wifi.weakSecurity.openFix"
            if w.security is Security.OPEN
            else "wifi.weakSecurity.fix",
            params={
                "ssid": repr(ssid),
                "device": device_name(net, dev),
                "reasons": ", ".join(reasons),
            },
        )


# WPA3 available (#89) -------------------------------------------------------------------------


@rule(
    "wifi.wpa3-available",
    "WPA2-only Wi-Fi although the radio supports WPA3",
    Severity.INFO,
    "WPA3 protects weak passphrases against offline guessing and gives forward secrecy. In "
    "WPA2/WPA3 transition mode old devices keep working, so there is rarely a reason to stay on "
    "WPA2 only when the radio supports WPA3. Quiet where the access point did not report what "
    "its radios support.",
)
def wpa3_available(net: Network) -> Iterator[Result]:
    radios = _radios(net)
    wlans = [
        w
        for w in _enabled_wlans(net)
        if w.security is Security.WPA2
        and (r := radios.get(w.radio_id)) is not None
        and WPA3_MODES & set(r.supported_security or [])
    ]
    for (dev, ssid, _sec), group in sorted(_per_ap(wlans, "security").items()):
        yield found(
            f"SSID {ssid!r} on {device_name(net, dev)} uses WPA2 only although the radio "
            "supports WPA3",
            _ids(group),
            fix="Switch to WPA2/WPA3 transition mode (protected management frames optional).",
            mid="wifi.wpa3Available",
            fix_id="wifi.wpa3Available.fix",
            params={"ssid": repr(ssid), "device": device_name(net, dev)},
        )


# passphrase reuse (#101) ----------------------------------------------------------------------


@rule(
    "wifi.passphrase-reuse",
    "Different Wi-Fi networks use the same passphrase",
    Severity.WARNING,
    "If a guest network has the passphrase of the main network, giving it to visitors gives "
    "them the main network as well, and separate networks (VLANs) are worth nothing. Compared "
    "across different SSIDs of a site by a keyed digest that is never shown. Not reported: the "
    "same SSID on several radios or access points, and SSIDs that put clients into the same "
    "network (for example one SSID per band), because they are one network anyway.",
)
def passphrase_reuse(net: Network) -> Iterator[Result]:
    # (site, digest) -> ssid -> WLANs
    clusters: dict[tuple[str, str], dict[str, list[Wlan]]] = defaultdict(lambda: defaultdict(list))
    for w in _enabled_wlans(net):
        if w.passphrase_digest is not None:
            site = site_of_device(net, w.device_id) or ""
            clusters[(site, w.passphrase_digest)][w.ssid].append(w)
    for (site, _digest), by_ssid in sorted(clusters.items()):
        if len(by_ssid) < 2:
            continue
        guest = {s: any(_is_guest(net, w) for w in ws) for s, ws in by_ssid.items()}
        segs = {s: {w.segment_id for w in ws} for s, ws in by_ssid.items()}
        names = sorted(by_ssid)
        separate = [
            (a, b)
            for i, a in enumerate(names)
            for b in names[i + 1 :]
            if guest[a] or guest[b] or (None not in segs[a] | segs[b] and not segs[a] & segs[b])
        ]
        if not separate:
            continue
        involved = sorted({s for pair in separate for s in pair})
        listed = ", ".join(repr(s) for s in involved)
        any_guest = any(guest[s] for s in involved)
        yield found(
            f"SSIDs {listed} use the same passphrase",
            _ids(w for s in involved for w in by_ssid[s]),
            fix="Give the guest network its own passphrase."
            if any_guest
            else "Give each network its own passphrase, or put the SSIDs into one network.",
            key=f"{site}:{'/'.join(involved)}",
            mid="wifi.passphraseReuse",
            fix_id="wifi.passphraseReuse.guestFix" if any_guest else "wifi.passphraseReuse.fix",
            params={"ssids": listed},
        )


# WPS (#104) -----------------------------------------------------------------------------------


@rule(
    "wifi.wps",
    "Wi-Fi Protected Setup (WPS) is turned on",
    Severity.WARNING,
    "The WPS PIN method can be guessed in hours on many devices and then reveals the "
    "passphrase; the push button lets anyone with brief physical access join. Most networks "
    "never use WPS after setup. A warning for the PIN method, info for the push button (and "
    "NFC or an unknown method).",
)
def wps(net: Network) -> Iterator[Result]:
    wlans = [w for w in _enabled_wlans(net) if w.wps is not None and w.wps.enabled]
    for (dev, ssid), group in sorted(_per_ap(wlans).items()):
        methods = {m for w in group for m in (w.wps.methods if w.wps else [])}
        pin = WpsMethod.PIN in methods
        how = "PIN" if pin else "push button" if methods == {WpsMethod.PUSH_BUTTON} else None
        yield found(
            f"WPS{f' ({how})' if how else ''} is turned on for SSID {ssid!r} on "
            f"{device_name(net, dev)}",
            _ids(group),
            fix="Turn WPS off; join devices with the passphrase or a QR code instead.",
            severity=Severity.WARNING if pin else Severity.INFO,
            mid="wifi.wps.pin" if pin else "wifi.wps.button" if how else "wifi.wps",
            fix_id="wifi.wps.fix",
            params={"ssid": repr(ssid), "device": device_name(net, dev)},
        )


# H2E on 6 GHz ---------------------------------------------------------------------------------


@rule(
    "wifi.6ghz-h2e",
    "WPA3 on 6 GHz without hash-to-element (H2E)",
    Severity.ERROR,
    "On 6 GHz, WPA3 must derive the SAE password with hash-to-element (H2E); with the older "
    "hunting-and-pecking method only, 6 GHz clients cannot join. Only WPA3-only networks are "
    "checked here (other modes are not allowed on 6 GHz, see wifi.6ghz-security).",
)
def six_ghz_h2e(net: Network) -> Iterator[Result]:
    radios = _radios(net)
    wlans = [
        w
        for w in _enabled_wlans(net)
        if w.security is Security.WPA3
        and w.sae is not None
        and w.sae.pwe is SaePwe.HUNTING_AND_PECKING
        and (r := radios.get(w.radio_id)) is not None
        and r.band is Band.GHZ_6
    ]
    for (dev, ssid), group in sorted(_per_ap(wlans).items()):
        yield found(
            f"SSID {ssid!r} on the 6 GHz radio of {device_name(net, dev)} derives the WPA3 "
            "password only with hunting-and-pecking, which 6 GHz clients do not accept",
            _ids(group),
            fix="Set the SAE password element (sae_pwe) to hash-to-element (H2E).",
            mid="wifi.sixGhzH2e",
            fix_id="wifi.sixGhzH2e.fix",
            params={"ssid": repr(ssid), "device": device_name(net, dev)},
        )


RULES: list[Rule] = [weak_security, wpa3_available, passphrase_reuse, wps, six_ghz_h2e]
