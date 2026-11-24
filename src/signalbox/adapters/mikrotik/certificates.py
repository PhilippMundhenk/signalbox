"""MikroTik certificates (#330): ``/rest/certificate`` and who uses them.

Only public data is read. The menu lists a ``private-key`` flag (whether the router holds the
key); the key, its passphrase and exports are never requested (that needs the ``sensitive``
policy, which Signalbox's read user does not have). Rows are copied field by field into the
model; ``vendor_extra`` stays empty, so nothing unknown can carry key material along.

*Guess until a CHR run says otherwise (#21)*: the date format of ``invalid-after`` (ISO
``2027-11-24T10:00:00`` and the CLI's ``nov/24/2027 10:00:00`` are both accepted, taken as
UTC) and the exact values of ``key-size`` for elliptic curves.
"""

from __future__ import annotations

import contextlib
from datetime import UTC, datetime
from typing import Any

from signalbox.adapters.https import normalise_fingerprint
from signalbox.model import Certificate, CertificateUse, KeyType, object_id

#: ``/ip/service`` entries that carry a ``certificate``.
SERVICE_CERTIFICATES = {"www-ssl", "api-ssl"}
#: Menus that name the certificate of a VPN or RADIUS server: ``(endpoint, use, single)``.
#: ``single``: the menu is one object, not a list of rows.
USERS: tuple[tuple[str, CertificateUse, bool], ...] = (
    ("/rest/ip/ipsec/identity", CertificateUse.VPN, False),
    ("/rest/interface/ovpn-server/server", CertificateUse.VPN, True),
    ("/rest/interface/sstp-server/server", CertificateUse.VPN, True),
    ("/rest/user-manager", CertificateUse.RADIUS, True),
)
_CURVE_BITS = {"prime256v1": 256, "secp256r1": 256, "secp384r1": 384, "secp521r1": 521}


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _flag(value: Any) -> bool:
    return value is True or _text(value).lower() in ("true", "yes", "on")


def _when(value: Any) -> datetime | None:
    text = _text(value)
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%b/%d/%Y %H:%M:%S"):
        with contextlib.suppress(ValueError):
            return datetime.strptime(text, fmt).replace(tzinfo=UTC)
    return None


def _key(row: dict[str, Any]) -> tuple[KeyType, int]:
    kind = _text(row.get("key-type")).lower()
    size = _text(row.get("key-size")).lower()
    if kind == "rsa":
        digits = "".join(c for c in size if c.isdigit())
        return KeyType.RSA, int(digits) if digits else 0
    if kind in ("ec", "ecdsa") or size in _CURVE_BITS:
        return KeyType.EC, _CURVE_BITS.get(size, 0)
    if kind == "ed25519":
        return KeyType.ED25519, 256
    return KeyType.OTHER, 0


def _subject(row: dict[str, Any]) -> str:
    fields = (
        ("CN", "common-name"),
        ("OU", "unit"),
        ("O", "organization"),
        ("L", "locality"),
        ("ST", "state"),
        ("C", "country"),
    )
    return ",".join(f"{k}={v}" for k, name in fields if (v := _text(row.get(name))))


def _san(row: dict[str, Any]) -> list[str]:
    out = []
    for part in _text(row.get("subject-alt-name")).split(","):
        _, _, value = part.strip().partition(":")
        if value.strip():
            out.append(value.strip())
    return out


def parse(device_id: str, row: dict[str, Any]) -> Certificate | None:
    """One row of ``/certificate`` as a :class:`Certificate`; ``None`` for a row without a name
    or validity (a request that is not signed yet)."""
    name = _text(row.get("name"))
    not_after = _when(row.get("invalid-after"))
    if not name or not_after is None:
        return None
    subject = _subject(row)
    akid, skid = _text(row.get("akid")), _text(row.get("skid"))
    issuer = _text(row.get("issuer"))
    self_signed = issuer == subject if issuer else bool(akid and akid == skid)
    if not issuer and self_signed:
        issuer = subject
    kind, bits = _key(row)
    return Certificate(
        id=object_id(device_id, "cert", name),
        device_id=device_id,
        name=name,
        fingerprint_sha256=normalise_fingerprint(_text(row.get("fingerprint"))),
        subject=subject,
        issuer=issuer,
        self_signed=self_signed,
        not_before=_when(row.get("invalid-before")) or not_after,
        not_after=not_after,
        key_type=kind,
        key_bits=bits,
        signature_algorithm=_text(row.get("digest-algorithm")),
        san=_san(row),
        ca=_flag(row.get("authority")) or "key-cert-sign" in _text(row.get("key-usage")),
        has_private_key=_flag(row["private-key"]) if "private-key" in row else None,
        trusted_on_device=_flag(row["trusted"]) if "trusted" in row else None,
    )


def attach_users(
    certs: list[Certificate],
    device_id: str,
    services: list[dict[str, Any]],
    named: list[tuple[str, CertificateUse]],
) -> list[Certificate]:
    """Fill ``used_by`` (the ``www-ssl`` and ``api-ssl`` services, as service ids) and
    ``uses`` (those and VPN or RADIUS servers: ``named`` is ``(certificate name, use)`` of
    their menus)."""
    used: dict[str, list[str]] = {}
    uses: dict[str, set[CertificateUse]] = {}
    for row in services:
        name, cert = _text(row.get("name")), _text(row.get("certificate"))
        if (
            name in SERVICE_CERTIFICATES
            and cert not in ("", "none")
            and not _flag(row.get("dynamic"))
        ):
            used.setdefault(cert, []).append(object_id(device_id, "service", name))
            uses.setdefault(cert, set()).add(CertificateUse.MANAGEMENT)
    for cert, use in named:
        if cert not in ("", "none"):
            uses.setdefault(cert, set()).add(use)
    return [
        c.model_copy(
            update={
                "used_by": sorted(used.get(c.name, [])),
                "uses": sorted(uses.get(c.name, set()), key=lambda u: u.value),
                "in_use": True if c.name in uses else None,
            }
        )
        for c in certs
    ]
