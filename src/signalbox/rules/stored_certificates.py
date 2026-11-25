"""Rules about the certificates stored on devices (VPN, RADIUS, authorities; #330).

They read :attr:`~signalbox.model.Network.certificates`, which devices that list their
certificates report (MikroTik, OPNsense). The thresholds are the parameters ``warn_days``
and ``urgent_days`` of each rule (#174, #441). A device that does not list certificates is left
out: an empty list means "not read".
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import datetime

from signalbox.model import Certificate, CertificateUse, Network
from signalbox.rules import Result, Rule, Severity, ctx, found, history_rule
from signalbox.rules._certificate_params import (
    CaExpiringParams,
    CertificateExpiryParams,
    VpnExpiringParams,
)
from signalbox.rules._names import device_name
from signalbox.sightings import History

_VPN_FIX = (
    "Renew the certificate on the device and select it again where the VPN uses it, before the "
    "peers refuse the connection."
)
_CA_FIX = (
    "Create a new authority, sign the certificates again and distribute the new authority to "
    "everything that trusts the old one, before the old one expires."
)


def _day(value: datetime) -> str:
    return value.strftime("%Y-%m-%d")


def _cn(dn: str) -> str:
    for part in dn.split(","):
        key, _, value = part.strip().partition("=")
        if key.upper() == "CN":
            return value
    return ""


def issued_by(ca: Certificate, net: Network) -> list[Certificate]:
    """The other certificates of the device that name ``ca`` as their issuer (same subject, or
    the same common name where the device writes the issuer shorter)."""
    out = []
    for c in net.certificates_of(ca.device_id):
        if c.id == ca.id or c.self_signed:
            continue
        if c.issuer == ca.subject or (_cn(c.issuer) and _cn(c.issuer) == _cn(ca.subject)):
            out.append(c)
    return out


def _state(
    model: type[CertificateExpiryParams], cert: Certificate, now: datetime
) -> tuple[Severity, int] | None:
    """``(severity, days)`` when the certificate is expired (days < 0) or expires within the
    warning period of its device; ``None`` otherwise."""
    left = cert.not_after - now
    if left.total_seconds() <= 0:
        return Severity.ERROR, -1
    days = left.days
    limits = ctx.params(model, cert)
    if days > limits.warn_days:
        return None
    return (Severity.ERROR if days <= limits.urgent_days else Severity.WARNING), days


@history_rule(
    "cert.vpn-expiring",
    "Certificate used by a VPN is expired or about to expire",
    Severity.WARNING,
    "A VPN server or peer whose certificate expires stops accepting connections, often without "
    "any sign on the device until the first user is turned away. Reported for stored "
    "certificates a device names in its VPN configuration (MikroTik IPsec, OpenVPN and SSTP): "
    "a warning 30 days before the expiry date, an error 7 days before and after it "
    "(the parameters warn_days and urgent_days). "
    "Authorities are reported by `cert.ca-expiring`. Devices that do not list their "
    "certificates, and certificates whose use the device does not say, are left out.",
    params=VpnExpiringParams,
)
def vpn_expiring(net: Network, history: History) -> Iterator[Result]:
    if history.now is None:
        return
    for cert in sorted(net.certificates, key=lambda c: c.id):
        if CertificateUse.VPN not in cert.uses or cert.ca:
            continue
        state = _state(VpnExpiringParams, cert, history.now)
        if state is None:
            continue
        severity, days = state
        device = device_name(net, cert.device_id)
        date = _day(cert.not_after)
        params: dict[str, str | int] = {"device": device, "name": cert.name, "date": date}
        if days < 0:
            yield found(
                f"The VPN certificate {cert.name} of {device} expired on {date}",
                [cert.id, cert.device_id],
                fix=_VPN_FIX,
                severity=severity,
                mid="certificate.vpnExpired",
                fix_id="certificate.vpn.renew.fix",
                params=params,
            )
        else:
            yield found(
                f"The VPN certificate {cert.name} of {device} expires on {date} (in {days} days)",
                [cert.id, cert.device_id],
                fix=_VPN_FIX,
                severity=severity,
                mid="certificate.vpnExpiring",
                fix_id="certificate.vpn.renew.fix",
                params={**params, "days": days},
            )


@history_rule(
    "cert.ca-expiring",
    "Certificate authority on a device is expired or about to expire",
    Severity.WARNING,
    "A local certificate authority that expires breaks every certificate it issued: VPN "
    "clients, RADIUS servers and web interfaces signed by it are refused at once. Reported for "
    "authorities stored on a device, with the number of certificates on the same device that "
    "it issued: a warning 30 days before the expiry date, an error 7 days before and after it "
    "(the parameters warn_days and urgent_days). Devices that do not list their "
    "certificates are left out.",
    params=CaExpiringParams,
)
def ca_expiring(net: Network, history: History) -> Iterator[Result]:
    if history.now is None:
        return
    for cert in sorted(net.certificates, key=lambda c: c.id):
        if not cert.ca:
            continue
        state = _state(CaExpiringParams, cert, history.now)
        if state is None:
            continue
        severity, days = state
        device = device_name(net, cert.device_id)
        date = _day(cert.not_after)
        issued = len(issued_by(cert, net))
        params: dict[str, str | int] = {
            "device": device,
            "name": cert.name,
            "date": date,
            "issued": issued,
        }
        if days < 0:
            yield found(
                f"The certificate authority {cert.name} of {device} expired on {date} "
                f"(certificates of the device issued by it: {issued})",
                [cert.id, cert.device_id],
                fix=_CA_FIX,
                severity=severity,
                mid="certificate.caExpired",
                fix_id="certificate.ca.renew.fix",
                params=params,
            )
        else:
            yield found(
                f"The certificate authority {cert.name} of {device} expires on {date} "
                f"(in {days} days; certificates of the device issued by it: {issued})",
                [cert.id, cert.device_id],
                fix=_CA_FIX,
                severity=severity,
                mid="certificate.caExpiring",
                fix_id="certificate.ca.renew.fix",
                params={**params, "days": days},
            )


RULES: list[Rule] = [vpn_expiring, ca_expiring]
