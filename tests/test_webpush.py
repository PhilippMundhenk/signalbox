"""Web Push for the browser channel (#372): VAPID storage, subscriptions, sending to a fake push
service, the service worker and the strict CSP."""

from __future__ import annotations

import base64
import json
import os
import sys
import threading
from collections.abc import Iterator
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient

from signalbox import webpush
from signalbox.service import Services, build
from signalbox.web.app import create_app
from signalbox.webpush import SubscriptionIn, WebPush, WebPushError

PW = "correct horse battery staple"


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def browser_keys() -> dict[str, str]:
    """What a browser's PushSubscription holds: a P-256 public key and a 16-byte auth secret."""
    key = ec.generate_private_key(ec.SECP256R1())
    public = key.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )
    return {"p256dh": b64(public), "auth": b64(os.urandom(16))}


@dataclass
class PushService:
    """A fake browser push service."""

    url: str
    requests: list[dict[str, Any]] = field(default_factory=list)
    statuses: list[int] = field(default_factory=list)


@pytest.fixture(autouse=True)
def _local_http(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NO_PROXY", "127.0.0.1,localhost")
    monkeypatch.setenv("no_proxy", "127.0.0.1,localhost")


@pytest.fixture
def push_service() -> Iterator[PushService]:
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            size = int(self.headers.get("content-length") or 0)
            body = self.rfile.read(size)
            state: PushService = self.server.state  # type: ignore[attr-defined]
            state.requests.append(
                {
                    "path": self.path,
                    "headers": {k.lower(): v for k, v in self.headers.items()},
                    "body": body,
                }
            )
            code = state.statuses.pop(0) if state.statuses else 201
            self.send_response(code)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *args: Any) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    state = PushService(f"http://127.0.0.1:{server.server_address[1]}")
    server.state = state  # type: ignore[attr-defined]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield state
    server.shutdown()
    server.server_close()


class Inline:
    def submit(self, fn: Any, *args: Any) -> None:
        fn(*args)

    def shutdown(self, **kw: Any) -> None:
        return None


@pytest.fixture
def services(tmp_path: Path) -> Iterator[Services]:
    svc = build(
        tmp_path, env={"SIGNALBOX_AUTH_PASSWORD": PW}, adapters={}, rules=[], link_sources=[]
    )
    yield svc
    svc.close()


@pytest.fixture
def api(services: Services) -> Iterator[TestClient]:
    with TestClient(create_app(services, run_background=False)) as c:
        assert c.post("/api/login", json={"password": PW}).status_code == 200
        c.app.state.notifier.executor = Inline()  # type: ignore[attr-defined]
        yield c


def subscribe(api: TestClient, endpoint: str) -> dict[str, Any]:
    res = api.post(
        "/api/notifications/webpush/subscriptions",
        json={"endpoint": endpoint, "keys": browser_keys(), "label": "test"},
    )
    assert res.status_code == 200, res.text
    out: dict[str, Any] = res.json()
    return out


# VAPID keys ---------------------------------------------------------------------------------


def test_vapid_keys_are_made_on_first_use_and_the_private_key_is_encrypted(
    services: Services,
) -> None:
    assert services.store.get_setting(webpush.PUBLIC_KEY) is None
    wp = WebPush(services.store)
    public = wp.public_key()
    assert len(base64.urlsafe_b64decode(public + "==")) == 65  # uncompressed P-256 point
    assert wp.public_key() == public  # stable
    stored = services.store.get_setting(webpush.PRIVATE_KEY)
    assert stored and "PRIVATE KEY" not in stored
    assert "PRIVATE KEY" in services.store.vault.decrypt(stored)


def test_the_api_never_returns_the_private_key_or_an_endpoint(api: TestClient) -> None:
    state = api.get("/api/notifications/webpush").json()
    assert state["available"] is True and len(state["public_key"]) == 87
    sub = subscribe(api, "https://push.example.net/send/secret-token-123")
    state = api.get("/api/notifications/webpush").json()
    text = json.dumps(state) + json.dumps(sub)
    assert "secret-token-123" not in text and "PRIVATE" not in text
    assert state["subscriptions"][0]["host"] == "push.example.net"
    export = api.get("/api/notifications").text
    assert "secret-token-123" not in export


def test_without_the_package_nothing_is_offered(
    api: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setitem(sys.modules, "pywebpush", None)
    state = api.get("/api/notifications/webpush").json()
    assert state == {"available": False, "public_key": "", "subscriptions": []}
    res = api.post(
        "/api/notifications/webpush/subscriptions",
        json={"endpoint": "https://push.example.net/x", "keys": browser_keys()},
    )
    assert res.status_code == 409


# subscriptions ------------------------------------------------------------------------------


def test_subscriptions_are_stored_encrypted_and_deleting_one_removes_it(
    api: TestClient, services: Services
) -> None:
    first = subscribe(api, "https://push.example.net/send/aaa-bbb-ccc")
    second = subscribe(api, "https://updates.example.org/push/ddd-eee-fff")
    raw = services.store.get_setting(webpush.SUBSCRIPTIONS_KEY) or ""
    assert "example.net" not in raw  # encrypted at rest
    listed = api.get("/api/notifications/webpush").json()["subscriptions"]
    assert {s["id"] for s in listed} == {first["id"], second["id"]}
    assert api.delete(f"/api/notifications/webpush/subscriptions/{first['id']}").status_code == 204
    listed = api.get("/api/notifications/webpush").json()["subscriptions"]
    assert [s["id"] for s in listed] == [second["id"]]
    assert api.delete(f"/api/notifications/webpush/subscriptions/{first['id']}").status_code == 404
    api.delete(f"/api/notifications/webpush/subscriptions/{second['id']}")
    assert services.store.get_setting(webpush.SUBSCRIPTIONS_KEY) is None


def test_subscribing_the_same_browser_again_replaces_it(api: TestClient) -> None:
    subscribe(api, "https://push.example.net/send/same")
    subscribe(api, "https://push.example.net/send/same")
    assert len(api.get("/api/notifications/webpush").json()["subscriptions"]) == 1


@pytest.mark.parametrize(
    "endpoint", ["http://push.example.net/x", "ftp://127.0.0.1/x", "https:///x", "nonsense-url"]
)
def test_an_endpoint_must_be_https_or_loopback(api: TestClient, endpoint: str) -> None:
    res = api.post(
        "/api/notifications/webpush/subscriptions",
        json={"endpoint": endpoint, "keys": browser_keys()},
    )
    assert res.status_code == 422


def test_bad_keys_are_refused_and_the_number_is_limited(
    api: TestClient, services: Services
) -> None:
    res = api.post(
        "/api/notifications/webpush/subscriptions",
        json={"endpoint": "https://push.example.net/x", "keys": {"p256dh": "x", "auth": "y"}},
    )
    assert res.status_code == 422
    wp = WebPush(services.store)
    for n in range(webpush.MAX_SUBSCRIPTIONS):
        wp.add(SubscriptionIn(endpoint=f"https://push.example.net/{n}", keys=browser_keys()))  # type: ignore[arg-type]
    with pytest.raises(WebPushError):
        wp.add(SubscriptionIn(endpoint="https://push.example.net/more", keys=browser_keys()))  # type: ignore[arg-type]


# sending ------------------------------------------------------------------------------------


def test_a_browser_message_is_pushed_encrypted_with_vapid(
    api: TestClient, push_service: PushService
) -> None:
    subscribe(api, f"{push_service.url}/send/abc")
    api.put("/api/notifications/channels/tab", json={"kind": "browser", "enabled": True})
    assert api.post("/api/notifications/channels/tab/test").json()["ok"] is True
    (req,) = push_service.requests
    assert req["path"] == "/send/abc"
    assert req["headers"]["authorization"].lower().startswith("vapid ")
    assert req["headers"]["content-encoding"] == "aes128gcm"
    assert req["headers"]["ttl"] == "3600"
    assert b"Signalbox" not in req["body"] and b"test message" not in req["body"]  # encrypted


def test_a_disabled_or_missing_browser_channel_pushes_nothing(
    api: TestClient, push_service: PushService
) -> None:
    subscribe(api, f"{push_service.url}/send/abc")
    assert api.post("/api/notifications/channels/none/test").status_code == 404
    api.put("/api/notifications/channels/hook", json={"kind": "webhook", "enabled": True})
    assert push_service.requests == []


def test_a_gone_subscription_is_deleted_and_the_others_still_get_the_message(
    api: TestClient, push_service: PushService
) -> None:
    subscribe(api, f"{push_service.url}/send/gone")
    subscribe(api, f"{push_service.url}/send/ok")
    push_service.statuses = [410, 201]
    notifier = api.app.state.notifier  # type: ignore[attr-defined]
    sent = notifier.webpush.send("subject", ["line"], "https://sb.example.net/#/")
    assert sent == 1
    left = api.get("/api/notifications/webpush").json()["subscriptions"]
    assert len(left) == 1


def test_a_failing_push_service_is_logged_without_endpoint_or_key(
    api: TestClient, push_service: PushService, caplog: pytest.LogCaptureFixture
) -> None:
    subscribe(api, f"{push_service.url}/send/secret-token-xyz")
    push_service.statuses = [500]
    notifier = api.app.state.notifier  # type: ignore[attr-defined]
    with caplog.at_level("DEBUG"):
        assert notifier.webpush.send("s", ["l"], "") == 0
    ours = "\n".join(r.getMessage() for r in caplog.records if r.name.startswith("signalbox"))
    assert "HTTP 500" in ours
    assert "secret-token-xyz" not in ours and "PRIVATE" not in caplog.text
    assert len(api.get("/api/notifications/webpush").json()["subscriptions"]) == 1  # kept


def test_the_payload_has_only_the_digest_text_and_a_link(services: Services) -> None:
    wp = WebPush(services.store)
    data = json.loads(wp.payload("Subject", ["one", "two"], "https://sb.example.net/#/"))
    assert data == {"title": "Subject", "body": "one\ntwo", "url": "https://sb.example.net/#/"}
    assert json.loads(wp.payload("s", ["x"], ""))["url"] == "./#/"
    long = json.loads(wp.payload("s", ["y" * 5000], ""))
    assert len(long["body"]) <= webpush.MAX_BODY


def test_sending_without_subscribers_or_package_does_nothing(
    services: Services, monkeypatch: pytest.MonkeyPatch
) -> None:
    wp = WebPush(services.store)
    assert wp.send("s", ["l"], "") == 0
    assert services.store.get_setting(webpush.PRIVATE_KEY) is None  # no keys for nothing
    wp.add(SubscriptionIn(endpoint="https://push.example.net/a", keys=browser_keys()))  # type: ignore[arg-type]
    monkeypatch.setitem(sys.modules, "pywebpush", None)
    assert wp.send("s", ["l"], "") == 0


# the service worker and the strict CSP --------------------------------------------------------


def test_the_service_worker_is_served_with_scope_and_strict_csp(api: TestClient) -> None:
    res = api.get("/sw.js")
    assert res.status_code == 200
    assert "javascript" in res.headers["content-type"]
    assert res.headers["service-worker-allowed"] == "/"
    csp = res.headers["content-security-policy"]
    assert "script-src 'self'" in csp and "unsafe-inline" not in csp and "unsafe-eval" not in csp
    assert "showNotification" in res.text
    assert "service-worker-allowed" not in api.get("/app.js").headers


def test_the_service_worker_is_reachable_without_a_login(services: Services) -> None:
    with TestClient(create_app(services, run_background=False)) as anonymous:
        assert anonymous.get("/sw.js").status_code == 200
        assert anonymous.get("/api/notifications/webpush").status_code == 401
