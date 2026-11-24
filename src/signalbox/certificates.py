"""Reading the TLS certificate a device presents (#174).

:class:`~signalbox.adapters.https.DeviceHttp` sees the certificate during its pinning handshake
and hands the DER bytes to the *certificate sink* of the running observation
(:func:`collecting`), so every HTTPS integration provides it without code of its own.
:func:`describe` turns it into :class:`~signalbox.model.CertificateInfo`.
"""

from __future__ import annotations

import contextlib
import contextvars
from collections.abc import Iterator
from ipaddress import ip_address

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import NameOID

from signalbox.model import CertificateInfo, KeyType

_SINK: contextvars.ContextVar[dict[tuple[str, int], bytes] | None] = contextvars.ContextVar(
    "certificate_sink", default=None
)


@contextlib.contextmanager
def collecting() -> Iterator[dict[tuple[str, int], bytes]]:
    """Collect the certificates probed in this block (and its tasks): ``(host, port)`` to DER,
    in the order they were seen."""
    seen: dict[tuple[str, int], bytes] = {}
    token = _SINK.set(seen)
    try:
        yield seen
    finally:
        _SINK.reset(token)


def report(host: str, port: int, der: bytes) -> None:
    """Called by the HTTPS helper for every probe."""
    seen = _SINK.get()
    if seen is not None:
        seen.setdefault((host, port), der)


def _rfc4514(name: x509.Name) -> str:
    return name.rfc4514_string()


def _names(cert: x509.Certificate) -> tuple[list[str], list[str]]:
    """SAN entries (DNS names and IP addresses) and the common names."""
    san: list[str] = []
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        pass
    else:
        san = [
            *ext.get_values_for_type(x509.DNSName),
            *map(str, ext.get_values_for_type(x509.IPAddress)),
        ]
    cns = [str(a.value) for a in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)]
    return san, cns


def covers(names: list[str], host: str) -> bool:
    """One of the certificate names (DNS with a leading ``*.`` wildcard, or an IP) is ``host``."""
    host = host.strip().strip("[]").lower()
    try:
        want = ip_address(host)
    except ValueError:
        want = None
    for name in names:
        n = name.lower()
        if want is not None:
            try:
                if ip_address(n) == want:
                    return True
            except ValueError:
                pass
            continue
        if n == host:
            return True
        if n.startswith("*.") and "." in host and host.split(".", 1)[1] == n[2:]:
            return True
    return False


def describe(der: bytes, address: str | None) -> CertificateInfo:
    """The certificate facts; ``address`` is the host to check against the names (or ``None``)."""
    from signalbox.adapters.https import fingerprint  # local: https imports this module

    cert = x509.load_der_x509_certificate(der)
    pub = cert.public_key()
    key_type, bits = KeyType.OTHER, 0
    if isinstance(pub, rsa.RSAPublicKey):
        key_type, bits = KeyType.RSA, pub.key_size
    elif isinstance(pub, ec.EllipticCurvePublicKey):
        key_type, bits = KeyType.EC, pub.curve.key_size
    elif isinstance(pub, ed25519.Ed25519PublicKey):
        key_type, bits = KeyType.ED25519, 256
    oid = cert.signature_algorithm_oid
    algorithm = getattr(oid, "_name", "") or oid.dotted_string
    san, cns = _names(cert)
    return CertificateInfo(
        fingerprint_sha256=fingerprint(der),
        subject=_rfc4514(cert.subject),
        issuer=_rfc4514(cert.issuer),
        self_signed=cert.subject == cert.issuer,
        not_before=cert.not_valid_before_utc,
        not_after=cert.not_valid_after_utc,
        key_type=key_type,
        key_bits=bits,
        signature_algorithm=algorithm,
        san=san,
        matches_management_address=covers(san or cns, address) if address else None,
    )


def weak_signature(algorithm: str) -> bool:
    """SHA-1 or MD5 signature."""
    low = algorithm.lower()
    return "sha1" in low or "md5" in low
