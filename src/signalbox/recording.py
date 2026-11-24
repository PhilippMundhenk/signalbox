"""Record a real device's HTTP answers, neutralise them, and replay them as a simulator.

A contributor with a device whose answers Signalbox has never seen (#21) runs
``tools/record_device.py``: the adapter observes the device once (read only, nothing is
changed), every HTTP exchange of its :class:`~signalbox.adapters.https.DeviceHttp` is
recorded, private data is neutralised (:class:`Neutraliser`), and the result is a JSON file
that is safe to publish. Committed under ``tests/fixtures/recordings/``, it is a regression
test (``tests/test_recordings.py``): :func:`create_app` answers the adapter's requests from the
recording, and the adapter must produce the snapshot stored with it.

File format (``format: signalbox-recording``, ``version: 1``)::

    {"format": "signalbox-recording", "version": 1, "adapter": "fritzbox",
     "recorded": "2026-11-22", "role": "gateway", "path": "", "settings": {...},
     "device": {"model": "...", "firmware": "..."}, "note": "...",
     "exchanges": [{"method": "POST", "path": "/upnp/control/deviceinfo",
                    "headers": {"soapaction": "..."}, "body": "<...>",
                    "status": 200, "content_type": "text/xml", "response": "<...>"}],
     "snapshot": {...}}

``settings`` are the adapter settings without URL and secrets: at replay every secret setting
is :data:`PLACEHOLDER_SECRET` and the user name (if any) :data:`PLACEHOLDER_USER`, the same
values the neutraliser put into the recorded requests. ``snapshot`` is what the adapter made
of the neutralised recording when it was taken (without the observation time).
"""

from __future__ import annotations

import base64
import hashlib
import html
import ipaddress
import json
import os
import re
import tempfile
from collections import defaultdict, deque
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, unquote_plus, urlencode, urlsplit
from xml.sax.saxutils import escape

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import Response
from pydantic import SecretStr

from signalbox.adapters import Adapter, AdapterContext, load_adapters
from signalbox.adapters.https import DeviceHttp
from signalbox.model import DeviceRole

FORMAT = "signalbox-recording"
VERSION = 1
PLACEHOLDER_SECRET = "recorded-secret"
PLACEHOLDER_USER = "recorded-user"
#: request headers that select an answer (everything else, credentials above all, is dropped)
KEPT_HEADERS = ("soapaction", "content-type")
#: snapshot keys that change with every observation (boot time, clock read time and its
#: uncertainty are derived from the moment of the replay, an uplink's ``since`` from the
#: recorded uptime; the recorded clock itself is kept)
VOLATILE = {
    "observed_at",
    "taken_at",
    "boot_time",
    "read_at",
    "uncertainty_seconds",
    "since",
    "expires",  # DHCP leases: a countdown from the observation time (#183)
    "certificate",  # the replay's own generated certificate (#174)
    "management_port",  # the replay server's free port (#387)
}

#: field (XML element, JSON key, query parameter) names whose values are secrets or identify
#: the device: replaced by ``redacted-secret-<n>``, consistently (not the rules for one:
#: ``NewMinCharsPassword`` is a number)
SECRET_FIELDS = re.compile(
    r"(?<!chars)password(?!active)|passphrase|passwd|secret|token|session|cookie"
    r"|^(new)?(x_avm-de_)?(presharedkey|wepkey\d*|key|psk|apikey|api_key|privatekey"
    r"|private_key|privkey|private-key|preshared_key|preshared-key|serialnumber|serial|sid|client_id|clientid|omadac_id|omadacid)$",
    re.IGNORECASE,
)
#: field names whose values are names people chose: replaced by ``name-<n>``
NAME_FIELDS = re.compile(
    r"^(new)?(x_avm-de_)?(ssid|hostname|host_name|host-name|friendlyname|friendly_name"
    r"|devicename|device_name|comment|description|domain|domainname|location|contact"
    r"|username|user|currentusername)$",
    re.IGNORECASE,
)
#: field names whose values are dropped (free text with anything in it)
DROP_FIELDS = re.compile(r"log$", re.IGNORECASE)
#: values of name fields that are vendor defaults, not chosen by anyone
DEFAULT_NAMES = {"fritz.box", "lan", "localdomain", "home.arpa", "local", "", "none"}

_IPV4 = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])")
_IPV6 = re.compile(r"(?<![0-9A-Fa-f:])([0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7})(?![0-9A-Fa-f:])")
#: a WireGuard key (32 bytes in base64), public or private: replaced by a placeholder key (#239)
_WG_KEY = re.compile(r"(?<![A-Za-z0-9+/])([A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=)(?![A-Za-z0-9+/=])")
_MAC = re.compile(
    r"(?<![0-9A-Fa-f:-])([0-9A-Fa-f]{2}([:-])(?:[0-9A-Fa-f]{2}\2){4}[0-9A-Fa-f]{2})"
    r"(?![0-9A-Fa-f:-])"
)
_XML_LEAF = re.compile(r"<((?:[\w.-]+:)?([\w.-]+))(\s[^<>]*)?>([^<]*)</\1>")
_QUERY = re.compile(r"([?&](?:sid|session|token|auth)=)([^&\s<>\"']+)", re.IGNORECASE)
#: documentation /24 networks first (RFC 5737), then the benchmarking range (RFC 2544)
_V4_NETS = [
    "192.0.2",
    "198.51.100",
    "203.0.113",
    *(f"198.{18 + i // 256}.{i % 256}" for i in range(512)),
]
_KEPT_V4 = [
    *(ipaddress.ip_network(f"{n}.0/24") for n in _V4_NETS[:3]),
    ipaddress.ip_network("198.18.0.0/15"),
]
_DOC_V6 = ipaddress.ip_network("2001:db8::/32")


@dataclass
class Exchange:
    method: str
    path: str
    headers: dict[str, str]
    body: str
    status: int
    content_type: str
    response: str

    def as_json(self) -> dict[str, Any]:
        return {
            "method": self.method,
            "path": self.path,
            "headers": self.headers,
            "body": self.body,
            "status": self.status,
            "content_type": self.content_type,
            "response": self.response,
        }

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> Exchange:
        return cls(
            method=str(data["method"]),
            path=str(data["path"]),
            headers={str(k): str(v) for k, v in dict(data.get("headers", {})).items()},
            body=str(data.get("body", "")),
            status=int(data["status"]),
            content_type=str(data.get("content_type", "")),
            response=str(data.get("response", "")),
        )


# --- recording -------------------------------------------------------------------------------


@contextmanager
def recording(exchanges: list[Exchange]) -> Iterator[None]:
    """While active, every response a DeviceHttp client receives is appended to ``exchanges``.

    Digest challenges (401 with ``WWW-Authenticate``) are left out: the replay does not check
    credentials, so a client never needs them.
    """
    original = DeviceHttp.connect

    async def hook(response: httpx.Response) -> None:
        await response.aread()
        if response.status_code == 401 and "www-authenticate" in response.headers:
            return
        request = response.request
        path = request.url.raw_path.decode()
        exchanges.append(
            Exchange(
                method=request.method,
                path=path,
                headers={k: request.headers[k] for k in KEPT_HEADERS if k in request.headers},
                body=request.content.decode("utf-8", "replace"),
                status=response.status_code,
                content_type=response.headers.get("content-type", ""),
                response=response.text,
            )
        )

    async def connect(self: DeviceHttp) -> None:
        had = self._client is not None
        await original(self)
        if not had and self._client is not None:
            self._client.event_hooks["response"].append(hook)

    DeviceHttp.connect = connect  # type: ignore[method-assign]
    try:
        yield
    finally:
        DeviceHttp.connect = original  # type: ignore[method-assign]


# --- neutralising ----------------------------------------------------------------------------


@dataclass
class Neutraliser:
    """Replaces private data consistently: the same value always gets the same placeholder.

    - IPv4 addresses: each /24 network becomes a documentation network (192.0.2.0/24,
      198.51.100.0/24, 203.0.113.0/24, then 198.18.0.0/15), the last octet is kept, so
      addresses stay in their subnets. Masks, 0.0.0.0, loopback, multicast, broadcast and
      documentation addresses are kept.
    - IPv6 addresses: each /64 becomes ``2001:db8:<n>::/64``, each interface id ``::<n>``
      (link-local ``fe80::<n>``); loopback, unspecified, multicast and 2001:db8::/32 are kept.
    - MAC addresses (``:`` or ``-``): ``00:00:5e:00:53:<n>`` (RFC 7042 documentation range),
      beyond 256 ``02:00:5e:00:<n>``; all-zero, broadcast and documentation MACs are kept.
    - WireGuard keys (any 32-byte base64 value): a placeholder key, the same for the same key
      (#239), so the ends of a tunnel still match; private and pre-shared key fields are
      secrets anyway;
    - secrets (fields matching :data:`SECRET_FIELDS`, ``sid=`` in URLs, the given password):
      ``redacted-secret-<n>``; the password and user name given to the recorder become
      :data:`PLACEHOLDER_SECRET` and :data:`PLACEHOLDER_USER` wherever they appear as a whole
      value;
    - names (fields matching :data:`NAME_FIELDS`): ``name-<n>``, unless a vendor default;
    - free text (fields matching :data:`DROP_FIELDS`, such as a device log): emptied.

    Names inside other free text, and MACs written without separators, are not found: read the
    recording before publishing it.
    """

    secrets: dict[str, str] = field(default_factory=dict)
    names: dict[str, str] = field(default_factory=dict)
    v4_nets: dict[str, str] = field(default_factory=dict)
    v6_prefixes: dict[int, int] = field(default_factory=dict)
    v6_ids: dict[int, int] = field(default_factory=dict)
    macs: dict[str, str] = field(default_factory=dict)
    wg_keys: dict[str, str] = field(default_factory=dict)
    #: every address placeholder handed out (kept as they are when seen again)
    produced: set[str] = field(default_factory=set)

    def given(self, password: str | list[str] | None = None, username: str | None = None) -> None:
        for value in [password] if isinstance(password, str) else password or []:
            if value:
                self.secrets[value] = PLACEHOLDER_SECRET
        if username:
            self.names[username] = PLACEHOLDER_USER

    # values ---------------------------------------------------------------------------

    def secret(self, value: str) -> str:
        if not value or value in self.secrets.values():
            return value
        if value not in self.secrets:
            self.secrets[value] = f"redacted-secret-{len(self.secrets) + 1:02d}"
        return self.secrets[value]

    def name(self, value: str) -> str:
        if value.strip().lower() in DEFAULT_NAMES or value in self.names.values():
            return value
        if value not in self.names:
            self.names[value] = f"name-{len(self.names) + 1}"
        return self.names[value]

    def field(self, key: str, value: str) -> str:
        """A value by the name of its field."""
        if DROP_FIELDS.search(key):
            return ""
        if value in self.secrets:
            return self.secrets[value]
        if SECRET_FIELDS.search(key):
            return self.secret(value)
        if NAME_FIELDS.search(key):
            return self.name(value)
        return self.addresses(value)

    def ipv4(self, match: re.Match[str]) -> str:
        text = match.group(1)
        try:
            address = ipaddress.IPv4Address(text)
        except ValueError:
            return text
        inverted = ~int(address) & 0xFFFFFFFF
        mask = text.startswith("255.") and (inverted + 1) & inverted == 0
        if (
            mask
            or address.is_loopback
            or address.is_multicast
            or address.is_unspecified
            or any(address in net for net in _KEPT_V4)
        ):
            return text
        net, _, host = text.rpartition(".")
        if net not in self.v4_nets:
            used = set(self.v4_nets.values())
            self.v4_nets[net] = next(n for n in _V4_NETS if n not in used)
        return f"{self.v4_nets[net]}.{host}"

    def ipv6(self, match: re.Match[str]) -> str:
        text = match.group(1)
        if text.count(":") < 2:
            return text
        try:
            address = ipaddress.IPv6Address(text)
        except ValueError:
            return text
        if (
            address.is_loopback
            or address.is_unspecified
            or address.is_multicast
            or address in _DOC_V6
            or str(address) in self.produced
        ):
            return text
        number = int(address)
        iid = self.v6_ids.setdefault(number & (2**64 - 1), len(self.v6_ids) + 1)
        if address.is_link_local:
            new = str(ipaddress.IPv6Address((0xFE80 << 112) | iid))
        else:
            prefix = self.v6_prefixes.setdefault(number >> 64, len(self.v6_prefixes) + 1)
            new = str(ipaddress.IPv6Address((0x20010DB8 << 96) | (prefix << 80) | iid))
        self.produced.add(new)
        return new

    def mac(self, match: re.Match[str]) -> str:
        text, sep = match.group(1), match.group(2)
        key = text.lower().replace("-", ":")
        if (
            key in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff")
            or key.startswith("00:00:5e:00:53:")
            or key in self.produced
        ):
            return text
        if key not in self.macs:
            n = len(self.macs)
            self.macs[key] = (
                f"00:00:5e:00:53:{n:02x}" if n < 256 else f"02:00:5e:00:{n >> 8:02x}:{n & 255:02x}"
            )
            self.produced.add(self.macs[key])
        new = self.macs[key].replace(":", sep)
        return new.upper() if any(c.isupper() for c in text) else new

    def wg_key(self, match: re.Match[str]) -> str:
        """A WireGuard key: the same placeholder key (valid, from a counter) for the same key,
        so that the two ends of a recorded tunnel still match."""
        text = match.group(1)
        if text in self.produced:
            return text
        if text not in self.wg_keys:
            seed = f"signalbox-recorded-key-{len(self.wg_keys) + 1}".encode()
            self.wg_keys[text] = base64.b64encode(hashlib.sha256(seed).digest()).decode()
            self.produced.add(self.wg_keys[text])
        return self.wg_keys[text]

    def addresses(self, text: str) -> str:
        text = _WG_KEY.sub(self.wg_key, text)
        text = _MAC.sub(self.mac, text)
        text = _IPV6.sub(self.ipv6, text)
        return _IPV4.sub(self.ipv4, text)

    # documents ------------------------------------------------------------------------

    def url(self, path: str) -> str:
        """A request path with its query (``sid=`` and the like are secrets)."""
        path = self._literal(self._query(path))
        parts = urlsplit(path)
        if not parts.query:
            return self.addresses(path)
        query = urlencode(
            [(k, self.field(k, v)) for k, v in parse_qsl(parts.query, keep_blank_values=True)],
            safe=":/",
        )
        return f"{self.addresses(parts.path)}?{query}"

    def document(self, text: str, content_type: str = "") -> str:
        """A request or response body: JSON by key, XML by element, anything else by text."""
        stripped = text.lstrip()
        if stripped[:1] in ("{", "[") or "json" in content_type:
            try:
                data = json.loads(text)
            except ValueError:
                pass
            else:
                return json.dumps(self._json(data), separators=(",", ":"), ensure_ascii=False)
        if stripped.startswith("<"):
            text = self._query(text)
            text = _XML_LEAF.sub(self._xml_leaf, text)
            return self._literal(text)
        return self._literal(self.addresses(text))

    def _xml_leaf(self, match: re.Match[str]) -> str:
        tag, local, attrs, value = (
            match.group(1),
            match.group(2),
            match.group(3) or "",
            match.group(4),
        )
        if "&lt;" in value:  # an XML document in a string (FRITZ!Box user list, #175)
            inner = _XML_LEAF.sub(self._xml_leaf, html.unescape(value))
            return f"<{tag}{attrs}>{escape(inner)}</{tag}>"
        return f"<{tag}{attrs}>{self.field(local, value)}</{tag}>"

    def _json(self, data: Any, key: str = "") -> Any:
        if isinstance(data, dict):
            return {k: self._json(v, str(k)) for k, v in data.items()}
        if isinstance(data, list):
            return [self._json(v, key) for v in data]
        if isinstance(data, str):
            return self._literal(self.field(key, self._query(data)))
        return data

    def _query(self, text: str) -> str:
        return _QUERY.sub(lambda m: m.group(1) + self.secret(m.group(2)), text)

    def _literal(self, text: str) -> str:
        """Secrets of 6 and more characters, wherever they still appear."""
        for value, placeholder in sorted(self.secrets.items(), key=lambda kv: -len(kv[0])):
            if len(value) >= 6 and value in text:
                text = text.replace(value, placeholder)
        return self.addresses(text)

    def exchange(self, e: Exchange) -> Exchange:
        return Exchange(
            method=e.method,
            path=self.url(e.path),
            headers=dict(e.headers),
            body=self.document(e.body, e.headers.get("content-type", "")),
            status=e.status,
            content_type=e.content_type,
            response=self.document(e.response, e.content_type),
        )

    def all(self, exchanges: list[Exchange]) -> list[Exchange]:
        """Neutralise every exchange; twice, so values first seen late are replaced early too."""
        for e in exchanges:
            self.exchange(e)
        return [self.exchange(e) for e in exchanges]


# --- replaying -------------------------------------------------------------------------------


def _canonical(body: str) -> str:
    text = body.strip()
    if text[:1] in ("{", "["):
        try:
            data = json.loads(text)
        except ValueError:
            return text
        if isinstance(data, dict):
            data.pop("id", None)  # JSON-RPC request ids count up
        return json.dumps(data, sort_keys=True)
    return re.sub(r">\s+<", "><", text)


def _key(method: str, path: str, headers: dict[str, str], body: str) -> tuple[str, str, str, str]:
    action = headers.get("soapaction", "").strip().strip('"')
    return method.upper(), unquote_plus(path), action, _canonical(body)


@dataclass
class Replay:
    """The answers of a recording, by request; repeated requests get the answers in order."""

    exchanges: list[Exchange]
    unmatched: list[str] = field(default_factory=list)
    queues: dict[tuple[str, str, str, str], deque[Exchange]] = field(default_factory=dict)
    last: dict[tuple[str, str, str, str], Exchange] = field(default_factory=dict)

    def __post_init__(self) -> None:
        grouped: dict[tuple[str, str, str, str], deque[Exchange]] = defaultdict(deque)
        for e in self.exchanges:
            grouped[_key(e.method, e.path, e.headers, e.body)].append(e)
        self.queues = dict(grouped)

    def answer(self, method: str, path: str, headers: dict[str, str], body: str) -> Exchange | None:
        key = _key(method, path, headers, body)
        queue = self.queues.get(key)
        if queue:
            self.last[key] = queue.popleft()
        found = self.last.get(key)
        if found is None:
            self.unmatched.append(f"{method} {path} {headers.get('soapaction', '')}".rstrip())
        return found


def load(path: Path | str) -> dict[str, Any]:
    data = json.loads(Path(path).read_text())
    if data.get("format") != FORMAT or data.get("version") != VERSION:
        raise ValueError(f"{path}: not a {FORMAT} version {VERSION} file")
    return dict(data)


def create_app(source: dict[str, Any] | Path | str | None = None) -> FastAPI:
    """An ASGI app that answers like the recorded device.

    ``uvicorn --factory signalbox.recording:create_app`` with ``SIGNALBOX_REPLAY`` naming
    the recording. Unknown requests are answered with 501 and listed in
    ``app.state.replay.unmatched``; credentials are not checked.
    """
    if source is None:
        source = os.environ.get("SIGNALBOX_REPLAY", "")
        if not source:
            raise ValueError("SIGNALBOX_REPLAY must name a recording")
    data = source if isinstance(source, dict) else load(source)
    replay = Replay([Exchange.from_json(e) for e in data["exchanges"]])
    app = FastAPI(title="Signalbox replay", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.replay = replay

    @app.api_route(
        "/{rest:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]
    )
    async def answer(rest: str, request: Request) -> Response:
        path = request.url.path + (f"?{request.url.query}" if request.url.query else "")
        headers = {k: request.headers[k] for k in KEPT_HEADERS if k in request.headers}
        body = (await request.body()).decode("utf-8", "replace")
        found = replay.answer(request.method, path, headers, body)
        if found is None:
            return Response(f"not in the recording: {request.method} {path}", status_code=501)
        return Response(
            found.response, status_code=found.status, media_type=found.content_type or None
        )

    return app


# --- the adapter around it -------------------------------------------------------------------


def adapter_for(data: dict[str, Any], url: str, pinned: str | None) -> Adapter:
    """The recorded adapter, configured with the placeholders, talking to ``url``."""
    cls = load_adapters()[data["adapter"]]
    config_type = cls.manifest.config
    settings: dict[str, Any] = dict(data.get("settings", {}))
    for name, info in config_type.model_fields.items():
        given = data.get("secret_settings")  # older files: every secret setting
        if "SecretStr" in str(info.annotation) and (given is None or name in given):
            settings[name] = SecretStr(PLACEHOLDER_SECRET)
        elif name == "username":
            settings[name] = PLACEHOLDER_USER
    settings["url"] = url.rstrip("/") + data.get("path", "")
    if url.startswith("http://") and "allow_insecure_http" in config_type.model_fields:
        settings["allow_insecure_http"] = True
    context = AdapterContext(
        site_id="home",
        device_id="recorded",
        device_name="recorded device",
        role=DeviceRole(data.get("role", "gateway")),
        config=config_type(**settings),
        pinned_fingerprint=pinned,
    )
    return cls(context)


def stable(snapshot: Any) -> Any:
    """A snapshot as JSON without the values that change with every observation."""

    def strip(value: Any) -> Any:
        if isinstance(value, dict):
            return {k: strip(v) for k, v in value.items() if k not in VOLATILE}
        if isinstance(value, list):
            return [strip(v) for v in value]
        return value

    return strip(snapshot.model_dump(mode="json"))


async def replay_snapshot(data: dict[str, Any]) -> tuple[Any, list[str]]:
    """Observe the recording through its adapter over pinned TLS; the stable snapshot and
    the requests the recording could not answer."""
    from signalbox.sim.server import self_signed_certificate, serve

    app = create_app(data)
    with tempfile.TemporaryDirectory() as tmp:
        tls = self_signed_certificate(Path(tmp), "replay")
        with serve(app, tls=tls) as url:
            adapter = adapter_for(data, url, tls.fingerprint)
            try:
                snapshot = await adapter.observe()
            finally:
                await adapter.close()
    return stable(snapshot), list(app.state.replay.unmatched)


def build(
    adapter_id: str,
    exchanges: list[Exchange],
    *,
    role: str,
    path: str,
    settings: dict[str, Any],
    password: str | list[str] | None,
    username: str | None,
    note: str = "",
    device: dict[str, str] | None = None,
    secret_names: list[str] | None = None,
    today: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> dict[str, Any]:
    """The recording document (without the snapshot) from raw exchanges."""
    neutral = Neutraliser()
    neutral.given(password=password, username=username)
    clean_settings = {  # first: their secrets (an id in URLs, say) are then known
        k: neutral.field(k, str(v)) if isinstance(v, str) else v for k, v in settings.items()
    }
    clean = neutral.all(exchanges)
    return {
        "format": FORMAT,
        "version": VERSION,
        "adapter": adapter_id,
        "recorded": today().date().isoformat(),
        "role": role,
        "path": neutral.addresses(path),
        "settings": clean_settings,
        **({} if secret_names is None else {"secret_settings": secret_names}),
        "device": {k: neutral.addresses(v) for k, v in (device or {}).items()},
        "note": note,
        "exchanges": [e.as_json() for e in clean],
    }
