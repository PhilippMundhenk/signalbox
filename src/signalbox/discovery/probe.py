"""What an integration's discovery probe gets and returns (see docs/DISCOVERY.md).

A probe answers one question: "is there a device of my kind at this address?" It may only
send unauthenticated, read-only requests, through :class:`HostProbe` (HTTP and HTTPS) or, for
broadcast protocols, with :class:`NetworkProbe`'s rate limiter. Both enforce the rules every
probe must follow:

- **No credentials.** The HTTP client has no authentication, keeps no cookies between
  requests and never uses a configured proxy.
- **TLS is not verified and nothing is pinned.** A probe only reads a public page; the
  certificate is checked (trust on first use) when the user adds the device and Signalbox
  first logs in. Nothing a probe sees is trusted beyond being shown as a suggestion.
- **Short timeouts, small answers.** Every request has the run's timeout, an answer is read up
  to :data:`MAX_BYTES` and no further, redirects are not followed.
- **Rate-limited, bounded.** Every new request waits for the run's rate limiter; the engine
  bounds how many addresses are probed at once.

An address that does not answer at all (two ports timed out, or no route to the host) is
marked *silent*: the remaining requests for it return ``None`` at once, so a sweep over empty
addresses does not wait for every integration's timeout.
"""

from __future__ import annotations

import asyncio
import contextlib
import errno
import ipaddress
import json
import re
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

import httpx
from pydantic import BaseModel, ConfigDict, Field, field_validator

from signalbox.model import DeviceRole

#: Largest answer body a probe reads; the rest is cut off (``ProbeResponse.truncated``).
MAX_BYTES = 256 * 1024
#: Longest text a candidate keeps from a device (model, name, firmware): device answers are
#: untrusted and only ever shown as text.
MAX_TEXT = 80
USER_AGENT = "Signalbox discovery"

_CONTROL = re.compile("[\\x00-\\x1f\\x7f-\\x9f\\u200b-\\u200f\\u2028-\\u202e\\u2066-\\u2069]+")


def clean(value: object, limit: int = MAX_TEXT) -> str | None:
    """Device-provided text as a short plain string: no control or bidi characters, spaces
    collapsed, at most ``limit`` characters; None when nothing is left."""
    if value is None:
        return None
    text = " ".join(_CONTROL.sub(" ", str(value)).split())
    if len(text) > limit:
        text = text[: limit - 1].rstrip() + "…"
    return text or None


ConfigValue = str | int | bool


class Candidate(BaseModel):
    """A device a probe found: a suggestion for the device form, never trusted data.

    ``config`` holds the non-secret settings to prefill (the address field of the integration,
    for example ``{"url": "https://192.0.2.1:49443"}``); the engine drops keys the
    integration's settings do not have and every secret field. ``adapter`` is filled in by the
    engine.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    address: str = Field(min_length=1, max_length=255)
    adapter: str = ""
    role: DeviceRole
    config: dict[str, ConfigValue] = Field(default_factory=dict)
    #: Suggested device name; the engine uses the model or the integration's name if empty.
    name: str | None = None
    vendor: str | None = None
    model: str | None = None
    firmware: str | None = None
    mac: str | None = None
    #: What answered, in a few words ("TR-064 description on port 49000").
    evidence: str | None = None
    #: What to do on the device before adding it, if anything.
    note: str | None = None

    @field_validator("name", "vendor", "model", "firmware", "mac", mode="before")
    @classmethod
    def _short(cls, value: object) -> str | None:
        return clean(value)

    @field_validator("evidence", "note", mode="before")
    @classmethod
    def _sentence(cls, value: object) -> str | None:
        return clean(value, 300)

    @field_validator("config")
    @classmethod
    def _config(cls, value: dict[str, ConfigValue]) -> dict[str, ConfigValue]:
        return {k: (clean(v, 255) or "") if isinstance(v, str) else v for k, v in value.items()}


@dataclass(frozen=True)
class BroadcastResult:
    """What a broadcast probe found, and a note for the user when that may be incomplete
    ("no switch answered: in Docker this needs host networking")."""

    candidates: list[Candidate] = field(default_factory=list)
    note: str | None = None


class RateLimiter:
    """At most ``rate`` new requests per second, spaced evenly, shared by a whole run."""

    def __init__(self, rate: float) -> None:
        self.interval = 1.0 / rate if rate > 0 else 0.0
        self._next = 0.0
        self._lock = asyncio.Lock()
        self.count = 0

    async def acquire(self) -> None:
        async with self._lock:
            now = time.monotonic()
            start = max(now, self._next)
            self._next = start + self.interval
            self.count += 1
        if start > now:
            await asyncio.sleep(start - now)


@dataclass(frozen=True)
class ProbeResponse:
    status: int
    headers: Mapping[str, str]
    body: bytes
    #: The body was longer than :data:`MAX_BYTES` and was cut off.
    truncated: bool = False

    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")

    def json(self) -> Any:
        """The body as JSON, or None when it is not JSON (or was cut off)."""
        if self.truncated:
            return None
        try:
            return json.loads(self.body)
        except ValueError:
            return None


_SILENT_ERRNOS = {errno.EHOSTUNREACH, errno.ENETUNREACH, errno.EHOSTDOWN}


def _no_route(exc: BaseException) -> bool:
    seen: BaseException | None = exc
    for _ in range(6):
        if seen is None:
            return False
        if isinstance(seen, OSError) and seen.errno in _SILENT_ERRNOS:
            return True
        seen = seen.__cause__ or seen.__context__
    return False


def _netloc(host: str, port: int) -> str:
    try:
        is_v6 = ipaddress.ip_address(host).version == 6
    except ValueError:
        is_v6 = False
    return f"[{host}]:{port}" if is_v6 else f"{host}:{port}"


class HostProbe:
    """Unauthenticated HTTP(S) requests to one address, for the probes of every integration.

    ``extra`` holds settings for tests and simulators (``{"ports": {"fritzbox.upnp": 8123}}``);
    in normal operation it is empty and probes use the devices' standard ports.
    """

    def __init__(
        self,
        host: str,
        *,
        timeout: float,
        limiter: RateLimiter,
        extra: Mapping[str, Any] | None = None,
        max_bytes: int = MAX_BYTES,
    ) -> None:
        self.host = host
        self.timeout = timeout
        self.limiter = limiter
        self.extra: Mapping[str, Any] = extra or {}
        self.max_bytes = max_bytes
        self.requests = 0
        #: No answer at all from this address: further requests are not sent.
        self.silent = False
        self._answered = False
        self._dead_ports: set[int] = set()
        self._cache: dict[tuple[str, int, str], ProbeResponse | None] = {}
        self._client: httpx.AsyncClient | None = None

    def port(self, key: str, default: int) -> int:
        """The port for ``key`` (``"<adapter>.<name>"``): the standard one unless a test or
        simulator overrides it through ``extra["ports"]``."""
        ports = self.extra.get("ports") or {}
        return int(ports.get(key, default))

    def url(self, scheme: str, port: int, path: str) -> str:
        return f"{scheme}://{_netloc(self.host, port)}{path}"

    def origin(self, scheme: str, port: int) -> str:
        """``https://<host>[:port]`` for the device form, without the scheme's own port."""
        standard = {"https": 443, "http": 80}.get(scheme)
        url = self.url(scheme, port, "")
        return url.rsplit(":", 1)[0] if port == standard else url

    async def get(self, scheme: str, port: int, path: str) -> ProbeResponse | None:
        """GET, answered from this probe's cache when another integration asked the same."""
        key = (scheme, port, path)
        if key not in self._cache:
            self._cache[key] = await self.request("GET", scheme, port, path)
        return self._cache[key]

    async def post(
        self,
        scheme: str,
        port: int,
        path: str,
        *,
        content: bytes,
        headers: Mapping[str, str] | None = None,
    ) -> ProbeResponse | None:
        return await self.request("POST", scheme, port, path, content=content, headers=headers)

    async def request(
        self,
        method: str,
        scheme: str,
        port: int,
        path: str,
        *,
        content: bytes | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> ProbeResponse | None:
        """One request; None when the address or port does not answer (any network error)."""
        if scheme not in ("http", "https") or not path.startswith("/"):
            raise ValueError(f"probe request must be http(s) with a path, not {scheme} {path}")
        if self.silent or port in self._dead_ports:
            return None
        await self.limiter.acquire()
        self.requests += 1
        client = self._http()
        try:
            async with asyncio.timeout(self.timeout * 2):
                return await self._send(
                    client, method, self.url(scheme, port, path), content, headers
                )
        except httpx.ConnectTimeout:
            self._timed_out(port)
        except httpx.ConnectError as exc:
            if _no_route(exc):
                self.silent = True
            else:
                self._answered = True  # refused, or TLS spoken differently: someone is there
        except (httpx.HTTPError, TimeoutError, OSError):
            self._answered = True
        finally:
            client.cookies.clear()
        return None

    async def _send(
        self,
        client: httpx.AsyncClient,
        method: str,
        url: str,
        content: bytes | None,
        headers: Mapping[str, str] | None,
    ) -> ProbeResponse:
        async with client.stream(method, url, content=content, headers=dict(headers or {})) as r:
            self._answered = True
            body = bytearray()
            truncated = False
            async for chunk in r.aiter_bytes():
                body.extend(chunk)
                if len(body) > self.max_bytes:
                    del body[self.max_bytes :]
                    truncated = True
                    break
            return ProbeResponse(
                status=r.status_code,
                headers={k.lower(): v for k, v in r.headers.items()},
                body=bytes(body),
                truncated=truncated,
            )

    def _timed_out(self, port: int) -> None:
        self._dead_ports.add(port)
        if not self._answered and len(self._dead_ports) >= 2:
            self.silent = True

    def _http(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                verify=False,
                trust_env=False,
                follow_redirects=False,
                timeout=httpx.Timeout(self.timeout),
                limits=httpx.Limits(max_connections=2, max_keepalive_connections=0),
                headers={"User-Agent": USER_AGENT, "Accept-Encoding": "identity"},
            )
        return self._client

    async def close(self) -> None:
        if self._client is not None:
            with contextlib.suppress(Exception):
                await self._client.aclose()
            self._client = None


@dataclass
class NetworkProbe:
    """What a broadcast probe gets: the run's timeout, rate limiter and test settings."""

    timeout: float
    limiter: RateLimiter
    extra: Mapping[str, Any] = field(default_factory=dict)

    def settings(self, adapter_id: str) -> Mapping[str, Any]:
        """Test and simulator settings of one integration (``extra[adapter_id]``)."""
        value = self.extra.get(adapter_id) or {}
        return value if isinstance(value, Mapping) else {}
