"""Web Push for the browser channel (#372): notifications with no tab open.

Opt-in at three levels: the optional ``pywebpush`` package must be installed, a ``browser``
channel must be enabled, and a person must press *Subscribe* in a browser. The browser vendor's
push service (a third party) carries the message; it is encrypted for the browser (RFC 8291).

The VAPID key pair is made on first use. The private key is encrypted with the vault like every
other secret, is never part of an API answer, an export or a log line. A subscription's endpoint
is a bearer URL for that browser, so the list is encrypted as well and the API shows only the
host. A payload holds the digest text and a link, nothing else.
"""

from __future__ import annotations

import base64
import importlib.util
import ipaddress
import json
import logging
import sys
import threading
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from pydantic import BaseModel, Field

from signalbox.store import Store

log = logging.getLogger(__name__)

PRIVATE_KEY = "webpush:vapid-private"  # encrypted PEM
PUBLIC_KEY = "webpush:vapid-public"  # base64url, the "application server key"
SUBSCRIPTIONS_KEY = "webpush:subscriptions"  # encrypted JSON
MAX_SUBSCRIPTIONS = 50
MAX_BODY = 600  # characters; a push message holds about 4 KB
# The VAPID "sub" claim: a mailto: or an https origin (no path), checked by py_vapid.
PROJECT_URL = "https://github.com"


class SubscriptionKeys(BaseModel):
    p256dh: str = Field(min_length=20, max_length=200)
    auth: str = Field(min_length=8, max_length=100)


class SubscriptionIn(BaseModel):
    endpoint: str = Field(min_length=10, max_length=2000)
    keys: SubscriptionKeys
    label: str = Field(default="", max_length=80)


class WebPushError(Exception):
    """Text is safe to show: it never holds a key or an endpoint."""


def available() -> bool:
    """The optional ``pywebpush`` package is installed."""
    if "pywebpush" in sys.modules:
        return sys.modules["pywebpush"] is not None
    try:
        return importlib.util.find_spec("pywebpush") is not None
    except (ImportError, ValueError):
        return False


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def check_endpoint(endpoint: str) -> str:
    """The endpoint must be https (a browser's push service); http only for a loopback host."""
    parts = urlsplit(endpoint)
    host = parts.hostname or ""
    if parts.scheme == "https" and host:
        return host
    if parts.scheme == "http" and host:
        if host == "localhost":
            return host
        try:
            if ipaddress.ip_address(host).is_loopback:
                return host
        except ValueError:
            pass
    raise WebPushError("The endpoint must be an https URL.")


@dataclass(frozen=True)
class Subscription:
    id: str
    endpoint: str
    p256dh: str
    auth: str
    label: str
    created: str

    @property
    def host(self) -> str:
        return urlsplit(self.endpoint).hostname or ""

    def info(self) -> dict[str, Any]:
        return {"endpoint": self.endpoint, "keys": {"p256dh": self.p256dh, "auth": self.auth}}


class WebPush:
    def __init__(self, store: Store, base_url: str = "") -> None:
        self.store = store
        self.base_url = base_url
        self._lock = threading.Lock()

    # VAPID keys ---------------------------------------------------------------------------

    def public_key(self) -> str:
        """The public key for ``pushManager.subscribe``; the pair is made on first use."""
        with self._lock:
            known = self.store.get_setting(PUBLIC_KEY)
            if known and self.store.get_setting(PRIVATE_KEY):
                return known
            key = ec.generate_private_key(ec.SECP256R1())
            pem = key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ).decode()
            public = _b64(
                key.public_key().public_bytes(
                    serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
                )
            )
            self.store.set_setting(PRIVATE_KEY, self.store.vault.encrypt(pem))
            self.store.set_setting(PUBLIC_KEY, public)
            return public

    def _vapid(self) -> Any:
        from py_vapid import Vapid01  # a dependency of pywebpush

        self.public_key()
        stored = self.store.get_setting(PRIVATE_KEY) or ""
        return Vapid01.from_pem(self.store.vault.decrypt(stored).encode())

    def _contact(self) -> str:
        parts = urlsplit(self.base_url)
        if parts.scheme == "https" and parts.hostname and "." in parts.hostname:
            return f"https://{parts.hostname}"
        return PROJECT_URL

    # subscriptions ------------------------------------------------------------------------

    def _load(self) -> dict[str, dict[str, str]]:
        text = self.store.get_setting(SUBSCRIPTIONS_KEY)
        if not text:
            return {}
        try:
            data = json.loads(self.store.vault.decrypt(text))
        except Exception:
            log.warning("the stored push subscriptions are unusable")
            return {}
        return data if isinstance(data, dict) else {}

    def _save(self, data: dict[str, dict[str, str]]) -> None:
        if data:
            self.store.set_setting(SUBSCRIPTIONS_KEY, self.store.vault.encrypt(json.dumps(data)))
        else:
            self.store.delete_setting(SUBSCRIPTIONS_KEY)

    def subscriptions(self) -> list[Subscription]:
        return [Subscription(sid, **item) for sid, item in sorted(self._load().items())]

    def add(self, body: SubscriptionIn) -> Subscription:
        check_endpoint(body.endpoint)
        with self._lock:
            data = self._load()
            for sid, item in list(data.items()):  # the same browser subscribing again
                if item["endpoint"] == body.endpoint:
                    del data[sid]
            if len(data) >= MAX_SUBSCRIPTIONS:
                raise WebPushError("Too many subscribed browsers; delete one first.")
            sub = Subscription(
                uuid.uuid4().hex[:12],
                body.endpoint,
                body.keys.p256dh,
                body.keys.auth,
                body.label.strip(),
                datetime.now(UTC).isoformat(timespec="seconds"),
            )
            data[sub.id] = {
                "endpoint": sub.endpoint,
                "p256dh": sub.p256dh,
                "auth": sub.auth,
                "label": sub.label,
                "created": sub.created,
            }
            self._save(data)
            return sub

    def remove(self, sid: str) -> bool:
        with self._lock:
            data = self._load()
            if sid not in data:
                return False
            del data[sid]
            self._save(data)
            return True

    # sending ------------------------------------------------------------------------------

    def payload(self, subject: str, lines: list[str], link: str) -> str:
        """Only the digest text and a link back."""
        body = "\n".join(lines)
        if len(body) > MAX_BODY:
            body = body[: MAX_BODY - 1] + "…"
        return json.dumps({"title": subject, "body": body, "url": link or "./#/"})

    def send(self, subject: str, lines: list[str], link: str, timeout: float = 10.0) -> int:
        """Send to every subscribed browser; returns how many accepted it. Gone subscriptions
        (404/410) are deleted. Never raises, never logs an endpoint or a key."""
        try:
            subs = self.subscriptions()
            if not subs or not available():
                return 0
            from pywebpush import WebPushException, webpush

            data = self.payload(subject, lines, link)
            vapid = self._vapid()
        except Exception as exc:
            log.warning("web push is unusable: %s", type(exc).__name__)
            return 0
        sent = 0
        for sub in subs:
            try:
                webpush(
                    sub.info(),
                    data=data,
                    vapid_private_key=vapid,
                    vapid_claims={"sub": self._contact()},
                    ttl=3600,
                    timeout=timeout,
                )
                sent += 1
            except WebPushException as exc:
                status = getattr(exc.response, "status_code", None)
                if status in (404, 410):
                    self.remove(sub.id)
                log.warning("web push to %s failed (HTTP %s)", sub.host, status)
            except Exception as exc:
                log.warning("web push to %s failed: %s", sub.host, type(exc).__name__)
        return sent
