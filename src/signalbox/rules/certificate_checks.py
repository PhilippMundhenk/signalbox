"""Device HTTPS certificate rules (#121, #174).

They read :attr:`~signalbox.model.Device.certificate`, the certificate a device presents,
which core fills from the pinning handshake of every HTTPS integration. Signalbox trusts the
pinned certificate whatever its dates; browsers, apps and VPN clients do not. A device without
HTTPS (no certificate read) is left out, and so is a certificate that is not pinned yet.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import datetime

from signalbox.certificates import weak_signature
from signalbox.model import Device, KeyType, Network
from signalbox.rules import Result, Rule, Severity, ctx, found, history_rule, rule
from signalbox.rules._certificate_params import HttpsExpiryParams
from signalbox.sightings import History

#: RSA keys shorter than this are weak.
MIN_RSA_BITS = 2048
_RENEW_FIX = "Renew the certificate on the device, then confirm the new fingerprint in Signalbox."


def _day(value: datetime) -> str:
    return value.strftime("%Y-%m-%d")


def _certified(net: Network) -> Iterator[Device]:
    """Devices with a certificate Signalbox has pinned, in a stable order."""
    for dev in sorted(net.devices, key=lambda d: d.id):
        if dev.certificate is not None and dev.certificate.trusted:
            yield dev


@history_rule(
    "security.certificate-expiry",
    "HTTPS certificate expired or about to expire",
    Severity.WARNING,
    "Signalbox pins the certificate of a device and ignores its dates, but browsers, apps and "
    "controllers do not: when it expires the web interface and everything that talks to the "
    "device over HTTPS stops working. A warning is reported 30 days before the expiry date, an "
    "error 7 days before and after it (the parameters warn_days and urgent_days). Devices "
    "without HTTPS and certificates that are not trusted yet are left out.",
    params=HttpsExpiryParams,
)
def certificate_expiry(net: Network, history: History) -> Iterator[Result]:
    if history.now is None:
        return
    for dev in _certified(net):
        cert = dev.certificate
        assert cert is not None
        left = cert.not_after - history.now
        date = _day(cert.not_after)
        params = {"device": dev.name, "date": date}
        if left.total_seconds() <= 0:
            yield found(
                f"The HTTPS certificate of {dev.name} expired on {date}",
                [dev.id],
                fix=_RENEW_FIX,
                severity=Severity.ERROR,
                mid="certificate.expired",
                fix_id="certificate.renew.fix",
                params=params,
            )
            continue
        days = left.days
        limits = ctx.params(HttpsExpiryParams, dev)
        if days > limits.warn_days:
            continue
        yield found(
            f"The HTTPS certificate of {dev.name} expires on {date} (in {days} days)",
            [dev.id],
            fix=_RENEW_FIX,
            severity=Severity.ERROR if days <= limits.urgent_days else Severity.WARNING,
            mid="certificate.expiring",
            fix_id="certificate.renew.fix",
            params={**params, "days": days},
        )


@rule(
    "cert.weak-key",
    "HTTPS certificate with a weak key or signature",
    Severity.INFO,
    "A certificate with an RSA key shorter than 2048 bits or a SHA-1 (or MD5) signature can be "
    "forged with today's means, and current browsers refuse it. Reported for the certificate "
    "the device presents once it is trusted. Elliptic-curve and Ed25519 keys are not checked.",
)
def weak_key(net: Network) -> Iterator[Result]:
    for dev in _certified(net):
        cert = dev.certificate
        assert cert is not None
        if cert.key_type is KeyType.RSA and cert.key_bits < MIN_RSA_BITS:
            yield found(
                f"The HTTPS certificate of {dev.name} uses a {cert.key_bits}-bit RSA key",
                [dev.id],
                fix="Create a new certificate with an RSA key of at least 2048 bits (or an "
                "elliptic-curve key) on the device, then confirm its fingerprint in Signalbox.",
                key="key",
                mid="certificate.weakKey",
                fix_id="certificate.weakKey.fix",
                params={"device": dev.name, "bits": cert.key_bits},
            )
        if weak_signature(cert.signature_algorithm):
            yield found(
                f"The HTTPS certificate of {dev.name} is signed with a weak algorithm "
                f"({cert.signature_algorithm})",
                [dev.id],
                fix="Create a new certificate signed with SHA-256 or better on the device, then "
                "confirm its fingerprint in Signalbox.",
                key="signature",
                mid="certificate.weakSignature",
                fix_id="certificate.weakSignature.fix",
                params={"device": dev.name, "algorithm": cert.signature_algorithm},
            )


@rule(
    "cert.renewed",
    "Device presented a new HTTPS certificate",
    Severity.INFO,
    "A device that regenerates its certificate (after a firmware update, a reset or when the old "
    "one expired) no longer matches the fingerprint Signalbox pinned, so it is not read until "
    "the new one is trusted. This explains that status, with the expiry dates of the old and the "
    "new certificate, so a renewal is not mistaken for an attack. Compare the fingerprint with "
    "the device before trusting it.",
)
def renewed(net: Network) -> Iterator[Result]:
    for dev in sorted(net.devices, key=lambda d: d.id):
        cert = dev.certificate
        if cert is None or cert.trusted or cert.previous_fingerprint_sha256 is None:
            continue
        old = _day(cert.previous_not_after) if cert.previous_not_after else "?"
        new = _day(cert.not_after)
        yield found(
            f"{dev.name} presented a new HTTPS certificate (valid until {new}, the trusted one "
            f"until {old})",
            [dev.id],
            fix="Compare the fingerprint with the one the device shows and trust it if the "
            "certificate was renewed on purpose.",
            mid="certificate.renewed",
            fix_id="certificate.renewed.fix",
            params={"device": dev.name, "old": old, "new": new},
        )


RULES: list[Rule] = [certificate_expiry, weak_key, renewed]
