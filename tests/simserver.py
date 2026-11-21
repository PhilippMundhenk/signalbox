"""Serve a simulator ASGI app on 127.0.0.1 (free port), optionally over TLS with a fresh
self-signed certificate."""

from __future__ import annotations

import socket
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address
from pathlib import Path
from typing import Any

import uvicorn
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


@dataclass(frozen=True)
class Cert:
    certfile: Path
    keyfile: Path
    fingerprint: str  # SHA-256 of the DER, lower-case hex


def self_signed(directory: Path, name: str = "cert") -> Cert:
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "OpenWrt")])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ip_address("127.0.0.1"))]), False
        )
        .sign(key, hashes.SHA256())
    )
    certfile, keyfile = directory / f"{name}.pem", directory / f"{name}.key"
    certfile.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    keyfile.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return Cert(certfile, keyfile, cert.fingerprint(hashes.SHA256()).hex())


@contextmanager
def serve(app: Any, cert: Cert | None = None) -> Iterator[str]:
    """Run ``app`` in a thread; yields the base URL (``https://127.0.0.1:<port>``)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    config = uvicorn.Config(
        app,
        log_level="warning",
        lifespan="off",
        ssl_certfile=str(cert.certfile) if cert else None,
        ssl_keyfile=str(cert.keyfile) if cert else None,
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
        yield f"{'https' if cert else 'http'}://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        thread.join(5)
        sock.close()
