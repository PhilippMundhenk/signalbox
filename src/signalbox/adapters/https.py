"""HTTP(S) access to devices with self-signed certificates: trust on first use, then pinning.

Network devices rarely have a certificate a public CA would sign, so ordinary verification is
useless and ``verify=False`` would be dangerous. Instead every adapter that talks HTTPS uses
:class:`DeviceHttp`:

1. **Probe.** A bare TLS handshake without verification (:func:`peer_certificate`) reads the
   certificate the device presents. Nothing is sent over this connection: no request, no
   credential.
2. **Compare.** Its SHA-256 fingerprint is compared with ``AdapterContext.pinned_fingerprint``.
   No pin yet, or a different one: :class:`~signalbox.adapters.UntrustedCertificate` is raised
   with the fingerprint, and the user decides in the UI whether to trust it. Credentials never
   leave the machine for a certificate that is not pinned.
3. **Connect.** Requests go over an :class:`ssl.SSLContext` that trusts exactly that one
   certificate (:func:`pinned_context`): verification stays on, but the only trust anchor is the
   pinned certificate. A device that swaps its certificate between probe and request fails the
   handshake, so there is no window in which credentials could reach another certificate.
   Host name and validity dates are not checked: the pin is the identity, and self-signed device
   certificates are often issued for a different name or have expired.

Plain ``http://`` is possible for simulators and tests, only when the adapter passes
``allow_insecure_http=True`` (from an explicit config switch): credentials then travel in clear
text, so the UI must show it as insecure.

Errors are mapped to the adapter API: connection problems and timeouts raise
:class:`~signalbox.adapters.Unreachable`, HTTP 401/403 :class:`~signalbox.adapters.AuthFailed`,
404 :class:`NotFound` (an :class:`~signalbox.adapters.AdapterError`, so adapters can treat an
absent optional component differently), every other non-2xx answer and invalid JSON
:class:`~signalbox.adapters.AdapterError`; each message names the endpoint.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import ssl
from collections.abc import Collection
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import httpx

from signalbox.adapters import AdapterError, AuthFailed, Unreachable, UntrustedCertificate

#: OpenSSL ``X509_V_FLAG_NO_CHECK_TIME``: the ssl module does not export it.
_NO_CHECK_TIME = 0x200000


class NotFound(AdapterError):
    """HTTP 404: the endpoint does not exist (API disabled, component not installed)."""


def device_url(value: str, *, port: int | None = None, path: str = "") -> str:
    """A device address as the user typed it, completed: no scheme means https, then the
    integration's default port (only for https) and path. Raises ValueError for the form."""
    text = value.strip().rstrip("/")
    if "://" not in text:
        text = f"https://{text}"
    parts = urlsplit(text)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError("give the device's address, for example https://192.0.2.1")
    if port is not None and parts.port is None and parts.scheme == "https":
        parts = parts._replace(netloc=f"{parts.netloc}:{port}")
    if path and parts.path in ("", "/"):
        parts = parts._replace(path=path)
    return urlunsplit(parts._replace(query="", fragment=""))


REACH_FIX = (
    "Check that the device is on, that the address and port in the settings are right, and "
    "that Signalbox can reach it (same network or routed, no firewall in between)."
)


def fingerprint(der: bytes) -> str:
    """SHA-256 fingerprint of a DER certificate, lower-case hex without separators."""
    return hashlib.sha256(der).hexdigest()


def normalise_fingerprint(value: str) -> str:
    """Accept ``AB:CD:...`` or ``abcd...`` (as copied from a browser or a device page)."""
    return "".join(c for c in value.lower() if c in "0123456789abcdef")


async def peer_certificate(host: str, port: int, timeout: float) -> bytes:
    """DER certificate the server presents, read with an unverified handshake.

    Sends nothing after the handshake. Raises :class:`Unreachable` when no TLS connection can
    be made.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    where = f"{host}:{port}"
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ctx), timeout=timeout
        )
    except TimeoutError as exc:
        raise Unreachable(f"{where}: no TLS answer within {timeout:g} s", fix=REACH_FIX) from exc
    except (OSError, ssl.SSLError) as exc:
        raise Unreachable(
            f"cannot open a TLS connection to {where}: {_reason(exc)}", fix=REACH_FIX
        ) from exc
    try:
        der = writer.get_extra_info("ssl_object").getpeercert(binary_form=True)
    finally:
        writer.close()
        with contextlib.suppress(OSError, ssl.SSLError):
            await writer.wait_closed()
    if not der:  # pragma: no cover - a TLS server always presents a certificate here
        raise Unreachable(f"{where} presented no certificate")
    return bytes(der)


def pinned_context(der: bytes) -> ssl.SSLContext:
    """Client context whose only trust anchor is this certificate (names and dates unchecked)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_verify_locations(cadata=der)
    ctx.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN | _NO_CHECK_TIME
    return ctx


def _reason(exc: BaseException) -> str:
    return str(exc) or type(exc).__name__


class DeviceHttp:
    """JSON (or, with :meth:`request`, anything) over HTTP(S) to one device, with pinning.

    Create one per adapter instance. Call :meth:`reset` at the start of every observation (the
    adapter's ``read_system``) so that the certificate is probed and compared again; requests
    after that reuse the verified connection. ``auth`` and ``headers`` are passed to
    :class:`httpx.AsyncClient`.
    """

    def __init__(
        self,
        url: str,
        *,
        pinned_fingerprint: str | None,
        timeout: float,
        auth: httpx.Auth | tuple[str, str] | None = None,
        headers: dict[str, str] | None = None,
        allow_insecure_http: bool = False,
    ) -> None:
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise AdapterError(f"not an http(s) URL: {url!r}")
        if parts.scheme == "http" and not allow_insecure_http:
            raise AdapterError(
                f"{url}: plain http sends credentials unencrypted; use https "
                "(or enable insecure http explicitly, for simulators only)"
            )
        self.base_url = url.rstrip("/")
        self.host = parts.hostname
        self.port = parts.port or (443 if parts.scheme == "https" else 80)
        self.secure = parts.scheme == "https"
        self.pinned = normalise_fingerprint(pinned_fingerprint) if pinned_fingerprint else None
        self.timeout = timeout
        self._auth = auth
        self._headers = headers or {}
        self._client: httpx.AsyncClient | None = None
        #: Fingerprint seen at the last probe (also when it was refused).
        self.fingerprint: str | None = None

    async def connect(self) -> None:
        """Probe and compare the certificate (https), then open the client. Idempotent."""
        if self._client is not None:
            return
        verify: ssl.SSLContext | bool = False
        if self.secure:
            der = await peer_certificate(self.host, self.port, self.timeout)
            self.fingerprint = fingerprint(der)
            if self.pinned != self.fingerprint:
                raise UntrustedCertificate(self.fingerprint, self.pinned)
            verify = pinned_context(der)
        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            auth=self._auth,
            headers={"Accept": "application/json", **self._headers},
            timeout=self.timeout,
            verify=verify,
            trust_env=False,  # never route device traffic through a configured proxy
            follow_redirects=False,
        )

    async def reset(self) -> None:
        """Close the connection; the next request probes the certificate again."""
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    close = reset

    async def get_json(self, path: str, params: dict[str, Any] | None = None) -> Any:
        return await self.request_json("GET", path, params=params)

    async def post_json(self, path: str, body: Any = None) -> Any:
        return await self.request_json("POST", path, json=body)

    async def request_json(self, method: str, path: str, **kw: Any) -> Any:
        response = await self.request(method, path, **kw)
        try:
            return response.json()
        except ValueError as exc:
            raise AdapterError(f"{path}: answer is not valid JSON") from exc

    async def request(
        self, method: str, path: str, *, accept: Collection[int] = (), **kw: Any
    ) -> httpx.Response:
        """Send a request and return the raw response (for protocols other than JSON).

        Errors are mapped as for :meth:`request_json`; statuses in ``accept`` are returned
        instead (SOAP, for example, reports faults with HTTP 500 and a body).
        """
        await self.connect()
        assert self._client is not None
        try:
            response = await self._client.request(method, path, **kw)
        except httpx.TimeoutException as exc:
            raise Unreachable(
                f"{path}: no answer within {self.timeout:g} s", fix=REACH_FIX
            ) from exc
        except httpx.HTTPError as exc:
            await self.reset()
            raise Unreachable(
                f"{path}: cannot reach {self.base_url}: {_reason(exc)}", fix=REACH_FIX
            ) from exc
        code = response.status_code
        if code in accept:
            return response
        if code == 401:
            raise AuthFailed(
                f"{path}: the device refused the credentials (HTTP 401)",
                fix="Check the user name and password (or API key and secret) in the settings.",
            )
        if code == 403:
            raise AuthFailed(
                f"{path}: access denied (HTTP 403); check the user's privileges",
                fix="The login works but may not read this. Give the user the privileges the "
                "setup guide of this integration lists (the link is in the device settings).",
            )
        if code == 404:
            raise NotFound(
                f"{path}: not found (HTTP 404); is the API enabled?",
                fix="Check that the address points to the device itself (with the right port "
                "and path) and that its API is enabled; some parts need an extra package.",
            )
        if not 200 <= code < 300:
            raise AdapterError(f"{path}: HTTP {code} {response.reason_phrase}".rstrip())
        return response
