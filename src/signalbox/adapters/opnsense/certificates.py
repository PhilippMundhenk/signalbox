"""OPNsense certificates (#330): the grids ``/api/trust/cert/search`` and ``/api/trust/ca/search``.

Only public data is read. The search rows describe the certificate (name, dates, subject);
``/api/trust/cert/get/<uuid>`` and the export calls answer private keys and are never called.
Rows are copied field by field into the model; ``prv_payload``, ``prv`` and ``csr_payload`` are
never looked at, and ``vendor_extra`` stays empty. When a row carries the PEM of the public
certificate (``crt_payload``), the key type, size, signature and fingerprint come from it and the
text is dropped at once.

*Guess until the 26.7 image says otherwise (#21)*: which of ``valid_from``, ``valid_to``,
``commonname``, ``caref``, ``refid``, ``in_use`` the search rows carry and whether dates are epoch
seconds or text; fields that are missing stay empty.
"""

from __future__ import annotations

import contextlib
from datetime import UTC, datetime
from typing import Any

from signalbox.adapters.https import normalise_fingerprint
from signalbox.certificates import describe_pem
from signalbox.model import Certificate, CertificateFacts, KeyType, object_id

#: Privileges of the two grids (core ACL), for the fix text of a refused read.
CERT_PRIVILEGE = "System: Certificate Manager (page-system-certmanager)"
CA_PRIVILEGE = "System: Authority Manager (page-system-camanager)"


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _when(value: Any) -> datetime | None:
    if isinstance(value, bool):
        return None
    text = str(value).strip() if value is not None else ""
    if text.isdigit():
        with contextlib.suppress(OverflowError, OSError, ValueError):
            return datetime.fromtimestamp(int(text), UTC)
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        with contextlib.suppress(ValueError):
            when = datetime.strptime(text, fmt)
            return when if when.tzinfo else when.replace(tzinfo=UTC)
    return None


def parse(
    device_id: str, rows: list[dict[str, Any]], *, ca: bool, issuers: dict[str, str]
) -> list[Certificate]:
    """The rows of one grid as certificates. ``issuers`` maps the ``refid`` of the authorities
    to their subject (``caref`` of a row names its issuer); a row without ``caref`` is taken as
    self-signed."""
    out: list[Certificate] = []
    names: set[str] = set()
    for row in rows:
        not_after = _when(row.get("valid_to"))
        if not_after is None:
            continue
        common = _text(row.get("commonname"))
        label = _text(row.get("descr")) or common or _text(row.get("name"))
        if not label:
            continue
        if label in names:  # OPNsense does not keep descriptions unique
            label = f"{label}-{_text(row.get('refid')) or _text(row.get('uuid'))[:8]}"
        names.add(label)
        subject = f"CN={common}" if common else _text(row.get("name"))
        caref = _text(row.get("caref"))
        issuer = issuers.get(caref, "") if caref else subject
        facts = CertificateFacts(
            fingerprint_sha256="",
            subject=subject,
            issuer=issuer,
            self_signed=not caref or issuer == subject,
            not_before=_when(row.get("valid_from")) or not_after,
            not_after=not_after,
            key_type=KeyType.OTHER,
            key_bits=0,
            signature_algorithm="",
            san=[
                *(v for v in _text(row.get("san_dns")).replace(",", "\n").split() if v),
                *(v for v in _text(row.get("san_ip")).replace(",", "\n").split() if v),
            ],
        )
        is_ca = ca
        pem = row.get("crt_payload")
        if isinstance(pem, str):
            parsed = describe_pem(pem)
            if parsed is not None:
                facts, is_ca = parsed[0], ca or parsed[1]
        flag = row.get("in_use")
        out.append(
            Certificate(
                id=object_id(device_id, "cert", label),
                device_id=device_id,
                name=label,
                ca=is_ca,
                in_use=None if flag is None else str(flag) in ("1", "true", "True"),
                **{
                    **facts.model_dump(),
                    "fingerprint_sha256": normalise_fingerprint(facts.fingerprint_sha256),
                },
            )
        )
    return out


def issuer_names(rows: list[dict[str, Any]]) -> dict[str, str]:
    """``refid`` to subject of the authority rows."""
    out: dict[str, str] = {}
    for row in rows:
        refid, common = _text(row.get("refid")), _text(row.get("commonname"))
        if refid:
            out[refid] = f"CN={common}" if common else _text(row.get("name"))
    return out
