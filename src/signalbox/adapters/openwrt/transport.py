"""HTTPS with trust on first use: the device certificate is pinned by its SHA-256 fingerprint.

Home routers almost always present a self-signed certificate, so the usual CA check cannot
work. Instead :meth:`Transport.verify` opens one TLS connection without verification, reads the
peer certificate and compares its fingerprint with the pinned one *before* any credentials are
sent. Every answer is checked again against the pin, so a certificate swapped between the check
and the request is noticed too. ``http://`` is only accepted when explicitly allowed and is then
marked :attr:`Transport.insecure`.
"""

from __future__ import annotations

import asyncio
import hashlib
import ssl
from typing import Any
from urllib.parse import urlsplit

import httpx

from signalbox.adapters import AdapterError, Unreachable, UntrustedCertificate


def fingerprint(der: bytes) -> str:
    """SHA-256 of a DER certificate, lower-case hex without separators."""
    return hashlib.sha256(der).hexdigest()


def _normalise(fp: str) -> str:
    return fp.replace(":", "").strip().lower()


def _noverify() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _peer_der(ssl_object: Any) -> bytes | None:
    if ssl_object is None:
        return None
    der = ssl_object.getpeercert(binary_form=True)
    return der if isinstance(der, bytes) else None


async def peer_fingerprint(host: str, port: int, timeout: float) -> str:
    """Fingerprint of the certificate the server presents (not verified)."""
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=_noverify()), timeout
        )
    except (OSError, TimeoutError, ssl.SSLError) as exc:
        raise Unreachable(f"cannot connect to {host}:{port}: {exc or type(exc).__name__}") from exc
    try:
        der = _peer_der(writer.get_extra_info("ssl_object"))
    finally:
        writer.close()
    if der is None:  # pragma: no cover - TLS always yields a peer certificate
        raise Unreachable(f"{host}:{port} presented no certificate")
    return fingerprint(der)


class Transport:
    """POSTs JSON to one URL, over HTTPS pinned to ``pinned`` (or plain HTTP if allowed)."""

    def __init__(
        self, url: str, *, pinned: str | None, timeout: float, allow_http: bool = False
    ) -> None:
        parts = urlsplit(url)
        if parts.scheme not in ("https", "http") or not parts.hostname:
            raise AdapterError(f"not an http(s) URL: {url!r}")
        if parts.scheme == "http" and not allow_http:
            raise AdapterError(f"{url} is plain HTTP; use https:// or allow insecure HTTP")
        self.url = url
        self.host = parts.hostname
        self.port = parts.port or (443 if parts.scheme == "https" else 80)
        self.insecure = parts.scheme == "http"
        self.pinned = _normalise(pinned) if pinned else None
        self.timeout = timeout
        self._client = httpx.AsyncClient(verify=False, trust_env=False, timeout=timeout)

    def _check(self, fp: str) -> None:
        if self.pinned != fp:
            raise UntrustedCertificate(fp, self.pinned)

    async def verify(self) -> None:
        """Raise UntrustedCertificate unless the device presents the pinned certificate."""
        if not self.insecure:
            self._check(await peer_fingerprint(self.host, self.port, self.timeout))

    async def post(self, payload: Any) -> Any:
        """POST ``payload`` as JSON and return the decoded JSON answer."""
        try:
            response = await self._client.post(self.url, json=payload)
        except httpx.TimeoutException as exc:
            raise Unreachable(f"no answer from {self.host} within {self.timeout:g} s") from exc
        except httpx.HTTPError as exc:
            raise Unreachable(f"cannot reach {self.host}: {exc or type(exc).__name__}") from exc
        if not self.insecure:
            stream = response.extensions.get("network_stream")
            der = _peer_der(stream.get_extra_info("ssl_object") if stream else None)
            if der is not None:
                self._check(fingerprint(der))
        if response.status_code != 200:
            raise AdapterError(f"{self.host} answered HTTP {response.status_code}")
        try:
            return response.json()
        except ValueError as exc:
            raise AdapterError(f"{self.host} sent an answer that is not JSON") from exc

    async def aclose(self) -> None:
        await self._client.aclose()
