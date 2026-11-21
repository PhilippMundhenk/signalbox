"""Run a simulator (any ASGI app) on 127.0.0.1, optionally with a self-signed certificate.

::

    tls = self_signed_certificate(tmp_path)
    with serve(app, tls=tls) as url:  # https://127.0.0.1:<free port>
        ...  # tls.fingerprint is what an adapter must have pinned
"""

from __future__ import annotations

import datetime
import ipaddress
import socket
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import uvicorn
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from signalbox.adapters.https import fingerprint


@dataclass(frozen=True)
class TlsFiles:
    cert: Path
    key: Path
    #: SHA-256 of the certificate, as :mod:`signalbox.adapters.https` computes it.
    fingerprint: str


def self_signed_certificate(directory: Path, name: str = "simulator") -> TlsFiles:
    """A fresh self-signed certificate for 127.0.0.1 (like a device's factory certificate)."""
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    directory.mkdir(parents=True, exist_ok=True)
    cert_path, key_path = directory / f"{name}.crt", directory / f"{name}.key"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return TlsFiles(cert_path, key_path, fingerprint(cert.public_bytes(serialization.Encoding.DER)))


def free_port() -> int:
    """A port nothing listens on right now (for "unreachable" tests)."""
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port: int = sock.getsockname()[1]
        return port


@contextmanager
def serve(app: Any, *, tls: TlsFiles | None = None) -> Iterator[str]:
    """Serve ``app`` in a background thread; yields its base URL and stops it afterwards."""
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    config = uvicorn.Config(
        app,
        log_level="warning",
        lifespan="off",
        ssl_certfile=str(tls.cert) if tls else None,
        ssl_keyfile=str(tls.key) if tls else None,
    )
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    while not server.started:
        if time.monotonic() > deadline or not thread.is_alive():  # pragma: no cover
            raise RuntimeError("simulator did not start")
        time.sleep(0.01)
    try:
        yield f"{'https' if tls else 'http'}://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        thread.join(timeout=10)
        sock.close()
