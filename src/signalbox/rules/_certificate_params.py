"""Thresholds shared by the certificate expiry rules (#441, ADR 0027).

Each rule has its own subclass (one parameter model per rule), so they can be set apart; the
old ``certificates.warn_days`` / ``urgent_days`` settings still set all three (deprecated).
"""

from __future__ import annotations

from signalbox.rules._params import RuleParams, param


class CertificateExpiryParams(RuleParams):
    """Common fields; not bound to a rule itself."""

    warn_days: int = param(
        30,
        unit="d",
        ge=1,
        le=3650,
        description="Days before the expiry date from which a warning is reported.",
    )
    urgent_days: int = param(
        7,
        unit="d",
        ge=0,
        le=3650,
        description="Days before the expiry date from which the warning is an error (an "
        "expired certificate is always an error).",
    )


class HttpsExpiryParams(CertificateExpiryParams):
    """``security.certificate-expiry``."""


class VpnExpiringParams(CertificateExpiryParams):
    """``cert.vpn-expiring``."""


class CaExpiringParams(CertificateExpiryParams):
    """``cert.ca-expiring``."""
