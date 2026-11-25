"""Notifications (#367): events, digests, every channel against a fake server, secrets."""

from __future__ import annotations

import asyncio
import json
import logging
import smtplib
import socket
import sys
import threading
import types
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import datetime
from email import message_from_bytes
from email.policy import default as default_policy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest
from aiosmtpd.controller import Controller
from fastapi.testclient import TestClient
from pydantic import ValidationError

from factories import device
from signalbox import config as cfgmod
from signalbox import notifications as nt
from signalbox.config import ChannelSpec, EventKind, NotificationsConfig
from signalbox.model import DeviceStatus, Network
from signalbox.rules import Finding, Severity
from signalbox.service import Services, build
from signalbox.web.app import create_app

PW = "correct horse battery staple"


def secret_value() -> str:
    """A token-like value built at runtime, so no scanner sees a literal."""
    return "tk" + "".join(["a1", "b2", "c3", "d4", "e5"]) + str(id(object()))


# fake servers -----------------------------------------------------------------------------


@dataclass
class Req:
    method: str
    path: str
    headers: dict[str, str]
    body: Any


@dataclass
class Stub:
    url: str
    requests: list[Req] = field(default_factory=list)
    statuses: list[int] = field(default_factory=list)


@pytest.fixture(autouse=True)
def _local_http(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NO_PROXY", "127.0.0.1,localhost")
    monkeypatch.setenv("no_proxy", "127.0.0.1,localhost")


@pytest.fixture
def stub() -> Iterator[Stub]:
    class Handler(BaseHTTPRequestHandler):
        def _any(self) -> None:
            size = int(self.headers.get("content-length") or 0)
            raw = self.rfile.read(size)
            state: Stub = self.server.stub  # type: ignore[attr-defined]
            headers = {k.lower(): v for k, v in self.headers.items()}
            state.requests.append(
                Req(self.command, self.path, headers, json.loads(raw) if raw else None)
            )
            code = state.statuses.pop(0) if state.statuses else 200
            self.send_response(code)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"{}")

        do_POST = do_PUT = _any

        def log_message(self, *args: Any) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    state = Stub(f"http://127.0.0.1:{server.server_address[1]}")
    server.stub = state  # type: ignore[attr-defined]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield state
    server.shutdown()
    server.server_close()


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


class Collect:
    def __init__(self) -> None:
        self.mails: list[Any] = []

    async def handle_DATA(self, server: Any, session: Any, envelope: Any) -> str:
        self.mails.append(envelope)
        return "250 OK"


@pytest.fixture
def smtp() -> Iterator[tuple[int, Collect]]:
    handler = Collect()
    port = free_port()
    controller = Controller(handler, hostname="127.0.0.1", port=port)
    controller.start()
    yield port, handler
    controller.stop()


def message(severity: Severity = Severity.WARNING, lines: list[str] | None = None) -> nt.Message:
    lines = lines or ["Something happened on the gateway"]
    return nt.Message(
        "Signalbox: notifications (1)",
        lines,
        severity,
        [{"kind": "finding", "severity": severity.value, "text": lines[0]}],
        "en",
        "https://signalbox.example.org/#/",
    )


def spec(kind: str, **kw: Any) -> ChannelSpec:
    return ChannelSpec.model_validate({"kind": kind, "enabled": True, **kw})


def no_sleep(_: float) -> None:
    return None


# events ------------------------------------------------------------------------------------


def finding(fid: str, severity: Severity = Severity.WARNING, rule: str = "x.rule") -> Finding:
    return Finding(
        id=fid, rule_id=rule, severity=severity, title=f"Title {fid}", message=f"Message {fid}"
    )


def network(**statuses: DeviceStatus) -> Network:
    return Network(
        devices=[device(d, name=d.upper()) for d in statuses],
        statuses=dict(statuses),
    )


def test_the_first_round_is_a_baseline_and_sends_nothing() -> None:
    state, events = nt.diff_round(
        None, network(gw=DeviceStatus.UNREACHABLE), [finding("a")], [("c1", "applied")]
    )
    assert events == []
    assert "a" in state.findings and state.devices == {"gw": "unreachable"}
    assert state.changes == ["c1"]


def test_new_and_resolved_findings_drift_devices_and_deploys() -> None:
    old, _ = nt.diff_round(
        None, network(gw=DeviceStatus.OK, ap=DeviceStatus.OK), [finding("old")], [("c0", "applied")]
    )
    findings = [
        finding("new", Severity.ERROR),
        finding("d", Severity.WARNING, rule="drift.wlan"),
    ]
    state, events = nt.diff_round(
        old,
        network(gw=DeviceStatus.UNREACHABLE, ap=DeviceStatus.PARTIAL),
        findings,
        [("c0", "applied"), ("c1", "failed"), ("c2", "planned")],
    )
    got = {(e.kind, e.mid) for e in events}
    assert got == {
        (EventKind.FINDING, "notify.finding.new"),
        (EventKind.FINDING, "notify.finding.resolved"),
        (EventKind.DRIFT, "notify.drift"),
        (EventKind.DEVICE, "notify.device.unreachable"),
        (EventKind.DEVICE, "notify.device.partial"),
        (EventKind.DEPLOY, "notify.deploy.failed"),
    }
    deploy = next(e for e in events if e.kind is EventKind.DEPLOY)
    assert deploy.severity is Severity.ERROR and deploy.params == {"id": "c1"}
    assert state.changes == ["c0", "c1"]


def _special(
    fid: str,
    rule: str,
    mid: str,
    params: dict[str, str | int],
    severity: Severity = Severity.WARNING,
) -> Finding:
    return finding(fid, severity, rule).model_copy(update={"message_id": mid, "params": params})


def test_certificate_and_rogue_ssid_events_are_sent_once_and_leak_no_foreign_names() -> None:
    old, _ = nt.diff_round(None, network(), [], [])
    found = [
        _special(
            "c1",
            "security.certificate-expiry",
            "certificate.expiring",
            {"device": "gw", "date": "2027-01-01", "days": 12},
        ),
        _special(
            "c2",
            "cert.ca-expiring",
            "certificate.caExpired",
            {"device": "gw", "name": "Home CA", "date": "2026-01-01"},
            Severity.ERROR,
        ),
        _special(
            "r1",
            "wifi.rogue-ssid",
            "wifiNeighbours.rogue",
            {"ssid": "'Home'", "heard": "ap radio", "device": "ap", "channel": 6, "signal": -40},
        ),
        _special(
            "r2", "wifi.rogue-ssid", "wifiNeighbours.rogueOpen", {"ssid": "'Home'", "device": "ap"}
        ),
    ]
    state, events = nt.diff_round(old, network(), found, [])
    assert [(e.kind, e.mid) for e in events] == [
        (EventKind.CERTIFICATE, "notify.certificate.expiring"),
        (EventKind.CERTIFICATE, "notify.certificate.expired"),
        (EventKind.ROGUE_SSID, "notify.rogue"),
        (EventKind.ROGUE_SSID, "notify.rogue.open"),
    ]
    assert events[0].params == {"what": "gw", "date": "2027-01-01", "days": 12}
    assert events[1].params["what"] == "Home CA (gw)"
    assert events[2].params == {"ssid": "'Home'", "device": "ap"}
    tr = nt.Translator()
    for code in ("en", "de"):
        texts = [tr.text(code, e.mid, e.params) for e in events]
        assert all("{" not in t and "notify." not in t for t in texts)
    # the same findings in the next round, and their resolution, send nothing
    state2, again = nt.diff_round(state, network(), found, [])
    assert again == []
    _, gone = nt.diff_round(state2, network(), [], [])
    assert gone == []


def test_recovery_resolution_of_drift_and_unchanged_rounds() -> None:
    first, _ = nt.diff_round(
        None, network(gw=DeviceStatus.UNREACHABLE), [finding("d", rule="drift.port")], []
    )
    same, events = nt.diff_round(first, network(gw=DeviceStatus.UNREACHABLE), [], [])
    assert {e.mid for e in events} == {"notify.drift.resolved"}
    _, events = nt.diff_round(same, network(gw=DeviceStatus.OK), [], [])
    assert [e.mid for e in events] == ["notify.device.recovered"]
    _, quiet = nt.diff_round(same, network(gw=DeviceStatus.UNREACHABLE), [], [])
    assert quiet == []


def test_acknowledged_and_incomplete_findings_are_not_problems() -> None:
    soft = finding("i").model_copy(update={"incomplete": True})
    old, _ = nt.diff_round(None, network(), [], [])
    _, events = nt.diff_round(old, network(), [soft], [])
    assert events == []


# messages, language, links -----------------------------------------------------------------


def test_digest_text_in_the_configured_language_with_links() -> None:
    tr = nt.Translator()
    events = [
        nt.Event(
            EventKind.FINDING,
            Severity.ERROR,
            "notify.finding.new",
            {"severity": "error", "title": "T", "message": "M"},
        ),
        nt.Event(
            EventKind.DEPLOY, Severity.ERROR, "notify.deploy.failed", {"id": "c1"}, "#/changes"
        ),
    ]
    de = nt.build_message(events, "de", tr, "https://signalbox.example.org/")
    assert "Fehler" in de.lines[0] and "Sie" in de.lines[1]
    assert de.events[1]["url"] == "https://signalbox.example.org/#/changes"
    assert de.link == "https://signalbox.example.org/#/" and de.severity is Severity.ERROR
    assert "(2)" in de.subject
    plain = nt.build_message(events, "en", tr)
    assert plain.link == "" and "url" not in plain.events[0]
    unknown = nt.build_message(events, "xx", tr)
    assert "Failed" not in unknown.lines[0] and "error" in unknown.lines[0]


def test_a_long_digest_is_cut_with_a_count() -> None:
    events = [
        nt.Event(EventKind.DEVICE, Severity.ERROR, "notify.device.partial", {"device": f"d{i}"})
        for i in range(nt.MAX_LINES + 5)
    ]
    msg = nt.build_message(events, "en", nt.Translator())
    assert len(msg.lines) == nt.MAX_LINES + 1 and "5 more" in msg.lines[-1]


def test_quiet_hours_may_span_midnight() -> None:
    night = spec("ntfy", quiet_start="22:00", quiet_end="07:00")
    day = spec("ntfy", quiet_start="09:00", quiet_end="17:00")
    at = lambda h, m=0: datetime(2026, 1, 15, h, m)  # noqa: E731
    assert nt.in_quiet_hours(night, at(23)) and nt.in_quiet_hours(night, at(6, 59))
    assert not nt.in_quiet_hours(night, at(7)) and not nt.in_quiet_hours(night, at(12))
    assert nt.in_quiet_hours(day, at(12)) and not nt.in_quiet_hours(day, at(8))
    assert not nt.in_quiet_hours(spec("ntfy"), at(3))


def test_channel_settings_are_validated() -> None:
    with pytest.raises(ValidationError):
        spec("ntfy", quiet_start="25:00", quiet_end="07:00")
    with pytest.raises(ValidationError):
        spec("ntfy", url="ftp://example.org")
    with pytest.raises(ValidationError):
        spec("carrier-pigeon")
    with pytest.raises(ValidationError):
        NotificationsConfig(channels={"Bad Name": spec("ntfy")})


# channels against fake servers -------------------------------------------------------------


def test_ntfy(stub: Stub) -> None:
    token = secret_value()
    ch = spec("ntfy", url=stub.url, topic="signalbox", secret=token)
    nt.deliver(ch, message(Severity.ERROR), 5, 0)
    (req,) = stub.requests
    assert req.method == "POST" and req.headers["authorization"] == f"Bearer {token}"
    assert req.body["topic"] == "signalbox" and req.body["priority"] == 5
    assert "Something happened" in req.body["message"]
    assert req.body["click"] == "https://signalbox.example.org/#/"


def test_ntfy_without_a_token_sends_no_authorization(stub: Stub) -> None:
    nt.deliver(spec("ntfy", url=stub.url, topic="t"), message(), 5, 0)
    assert "authorization" not in stub.requests[0].headers


def test_matrix(stub: Stub) -> None:
    token = secret_value()
    ch = spec("matrix", url=stub.url, room_id="!room:example.org", secret=token)
    nt.deliver(ch, message(), 5, 0)
    (req,) = stub.requests
    assert req.method == "PUT"
    assert req.path.startswith(
        "/_matrix/client/v3/rooms/%21room%3Aexample.org/send/m.room.message/"
    )
    assert req.headers["authorization"] == f"Bearer {token}"
    assert req.body["msgtype"] == "m.text" and "Something happened" in req.body["body"]


def test_telegram(stub: Stub) -> None:
    token = secret_value()
    ch = spec("telegram", url=stub.url, chat_id="12345", secret=token)
    nt.deliver(ch, message(), 5, 0)
    (req,) = stub.requests
    assert req.path == f"/bot{token}/sendMessage"
    assert req.body["chat_id"] == "12345" and "Something happened" in req.body["text"]


def test_gotify(stub: Stub) -> None:
    token = secret_value()
    nt.deliver(spec("gotify", url=stub.url + "/", secret=token), message(Severity.INFO), 5, 0)
    (req,) = stub.requests
    assert req.path == "/message" and req.headers["x-gotify-key"] == token
    assert req.body["priority"] == 3 and req.body["title"].startswith("Signalbox")


def test_webhook(stub: Stub) -> None:
    token = secret_value()
    nt.deliver(spec("webhook", url=stub.url + "/hook", secret=token), message(), 5, 0)
    (req,) = stub.requests
    assert req.path == "/hook" and req.headers["authorization"] == f"Bearer {token}"
    assert req.body["version"] == 1 and req.body["severity"] == "warning"
    assert req.body["language"] == "en" and req.body["events"][0]["kind"] == "finding"
    assert "Something happened" in req.body["text"]


def test_email_plain(smtp: tuple[int, Collect]) -> None:
    port, got = smtp
    ch = spec(
        "email",
        host="127.0.0.1",
        port=port,
        security="none",
        sender="signalbox@example.org",
        recipients=["ops@example.org", "me@example.net"],
    )
    nt.deliver(ch, message(lines=["Gateway is down: äöü", "Second line"]), 5, 0)
    (env,) = got.mails
    assert env.mail_from == "signalbox@example.org"
    assert env.rcpt_tos == ["ops@example.org", "me@example.net"]
    mail = message_from_bytes(env.content, policy=default_policy)
    assert mail["Subject"].startswith("Signalbox")
    body = mail.get_body().get_content()  # type: ignore[union-attr]
    assert "Gateway is down: äöü" in body and "https://signalbox.example.org/#/" in body


class FakeSMTP:
    calls: list[tuple[str, Any]] = []

    def __init__(self, host: str, port: int, **kw: Any) -> None:
        FakeSMTP.calls = [("connect", (host, port, type(self).__name__))]

    def __enter__(self) -> FakeSMTP:
        return self

    def __exit__(self, *exc: Any) -> None:
        return None

    def starttls(self, context: Any = None) -> None:
        FakeSMTP.calls.append(("starttls", context is not None))

    def login(self, user: str, password: str) -> None:
        FakeSMTP.calls.append(("login", (user, password)))

    def send_message(self, mail: Any) -> None:
        FakeSMTP.calls.append(("send", mail["To"]))


class FakeSMTPSSL(FakeSMTP):
    pass


def test_email_starttls_and_ssl_use_the_right_port_and_log_in(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(smtplib, "SMTP", FakeSMTP)
    monkeypatch.setattr(smtplib, "SMTP_SSL", FakeSMTPSSL)
    password = secret_value()
    base: dict[str, Any] = {
        "host": "mail.example.org",
        "username": "user",
        "secret": password,
        "sender": "a@example.org",
        "recipients": ["b@example.org"],
    }
    nt.deliver(spec("email", **base), message(), 5, 0)
    assert FakeSMTP.calls == [
        ("connect", (("mail.example.org", 587, "FakeSMTP"))),
        ("starttls", True),
        ("login", ("user", password)),
        ("send", "b@example.org"),
    ]
    nt.deliver(spec("email", security="ssl", verify_tls=False, **base), message(), 5, 0)
    assert FakeSMTP.calls[0] == ("connect", ("mail.example.org", 465, "FakeSMTPSSL"))
    assert ("starttls", True) not in FakeSMTP.calls


def test_email_failures_are_explained_without_secrets(smtp: tuple[int, Collect]) -> None:
    ch = spec("email", host="127.0.0.1", port=free_port(), security="none", sender="a@example.org")
    with pytest.raises(nt.SendError, match="recipients"):
        nt.deliver(ch, message(), 5, 0)
    ch = spec(
        "email",
        host="127.0.0.1",
        port=free_port(),
        security="none",
        sender="a@example.org",
        recipients=["b@example.org"],
    )
    with pytest.raises(nt.SendError) as err:
        nt.deliver(ch, message(), 2, 0)
    assert err.value.retry


def test_apprise_is_optional(monkeypatch: pytest.MonkeyPatch) -> None:
    secret = "mailto://user:pw@example.org"
    monkeypatch.setitem(sys.modules, "apprise", None)
    assert not nt.apprise_available()
    with pytest.raises(nt.SendError, match="not installed"):
        nt.deliver(spec("apprise", secret=secret), message(), 5, 0)
    sent: list[tuple[str, str, str]] = []

    class App:
        def add(self, url: str) -> bool:
            sent.append(("add", url, ""))
            return True

        def notify(self, title: str, body: str) -> bool:
            sent.append(("notify", title, body))
            return True

    fake = types.ModuleType("apprise")
    fake.Apprise = App  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "apprise", fake)
    assert nt.apprise_available()
    nt.deliver(spec("apprise", secret=secret), message(), 5, 0)
    assert sent[0] == ("add", secret, "") and sent[1][0] == "notify"
    assert "Something happened" in sent[1][2]


def test_missing_settings_are_reported() -> None:
    for kind, word in [("ntfy", "url"), ("matrix", "room_id"), ("telegram", "chat_id")]:
        with pytest.raises(nt.SendError, match=word):
            nt.deliver(spec(kind), message(), 5, 0)
    with pytest.raises(nt.SendError, match="secret"):
        nt.deliver(spec("gotify", url="https://gotify.example.org"), message(), 5, 0)


# retries, timeouts, secrets in errors --------------------------------------------------------


def test_a_server_error_is_retried_with_the_same_matrix_transaction(stub: Stub) -> None:
    stub.statuses = [503, 200]
    waits: list[float] = []
    ch = spec("matrix", url=stub.url, room_id="!r:example.org", secret=secret_value())
    nt.deliver(ch, message(), 5, 2, sleep=waits.append)
    assert len(stub.requests) == 2 and stub.requests[0].path == stub.requests[1].path
    assert waits == [2.0]


def test_retries_are_bounded_and_client_errors_are_not_retried(stub: Stub) -> None:
    stub.statuses = [500] * 10
    ch = spec("webhook", url=stub.url)
    with pytest.raises(nt.SendError, match="HTTP 500"):
        nt.deliver(ch, message(), 5, 2, sleep=no_sleep)
    assert len(stub.requests) == 3
    stub.requests.clear()
    stub.statuses = [404]
    with pytest.raises(nt.SendError, match="HTTP 404"):
        nt.deliver(ch, message(), 5, 3, sleep=no_sleep)
    assert len(stub.requests) == 1


def test_a_refused_connection_gives_up_quickly_and_names_no_secret() -> None:
    token = secret_value()
    ch = spec("telegram", url=f"http://127.0.0.1:{free_port()}", chat_id="1", secret=token)
    with pytest.raises(nt.SendError) as err:
        nt.deliver(ch, message(), 1, 1, sleep=no_sleep)
    assert token not in str(err.value)


# notifier: rounds, filters, quiet hours, failures ----------------------------------------------


class Inline:
    """An executor that runs the delivery at once."""

    def submit(self, fn: Any, *args: Any) -> None:
        fn(*args)

    def shutdown(self, **kw: Any) -> None:
        return None


@pytest.fixture
def services(tmp_path: Path) -> Iterator[Services]:
    svc = build(
        tmp_path,
        env={"SIGNALBOX_AUTH_PASSWORD": PW},
        adapters={},
        rules=[],
        link_sources=[],
    )
    yield svc
    svc.close()


@pytest.fixture
def api(services: Services) -> Iterator[TestClient]:
    with TestClient(create_app(services, run_background=False)) as c:
        assert c.post("/api/login", json={"password": PW}).status_code == 200
        c.notifier = c.app.state.notifier  # type: ignore[attr-defined]
        c.notifier.executor = Inline()
        c.notifier.sleep = no_sleep
        yield c


def put_channel(api: TestClient, name: str, **kw: Any) -> dict[str, Any]:
    res = api.put(f"/api/notifications/channels/{name}", json={"enabled": True, **kw})
    assert res.status_code == 200, res.text
    out: dict[str, Any] = res.json()
    return out


def run_rounds(api: TestClient, *rounds: tuple[Network, list[Finding]]) -> None:
    for net, findings in rounds:
        api.notifier.on_round(net, findings)  # type: ignore[attr-defined]


def test_a_channel_gets_one_message_per_round(api: TestClient, stub: Stub) -> None:
    put_channel(api, "hook", kind="webhook", url=stub.url)
    run_rounds(api, (network(gw=DeviceStatus.OK), []))
    assert stub.requests == []  # baseline
    run_rounds(
        api,
        (
            network(gw=DeviceStatus.UNREACHABLE),
            [finding("a", Severity.ERROR), finding("b", Severity.WARNING)],
        ),
    )
    (req,) = stub.requests
    assert len(req.body["events"]) == 3
    assert req.body["severity"] == "error" and "(3)" in req.body["subject"]
    run_rounds(
        api, (network(gw=DeviceStatus.UNREACHABLE), [finding("a", Severity.ERROR), finding("b")])
    )
    assert len(stub.requests) == 1  # nothing changed: nothing sent


def test_severity_and_event_kinds_filter_per_channel(api: TestClient, stub: Stub) -> None:
    put_channel(
        api, "errors", kind="webhook", url=stub.url, min_severity="error", events=["device"]
    )
    run_rounds(api, (network(gw=DeviceStatus.OK), []))
    run_rounds(api, (network(gw=DeviceStatus.OK), [finding("a", Severity.ERROR)]))
    assert stub.requests == []  # a finding, not a device event
    run_rounds(api, (network(gw=DeviceStatus.PARTIAL), [finding("a", Severity.ERROR)]))
    assert stub.requests == []  # partly read is a warning
    run_rounds(api, (network(gw=DeviceStatus.UNREACHABLE), [finding("a", Severity.ERROR)]))
    assert len(stub.requests) == 1


def test_a_disabled_channel_sends_nothing_and_everything_is_off_by_default(
    api: TestClient, stub: Stub
) -> None:
    assert ChannelSpec(kind="ntfy").enabled is False
    put_channel(api, "off", kind="webhook", url=stub.url, enabled=False)
    run_rounds(api, (network(), []), (network(), [finding("a", Severity.ERROR)]))
    assert stub.requests == []


def test_events_in_the_quiet_hours_wait_and_are_sent_together(api: TestClient, stub: Stub) -> None:
    put_channel(api, "night", kind="webhook", url=stub.url, quiet_start="22:00", quiet_end="07:00")
    notifier: nt.Notifier = api.notifier  # type: ignore[attr-defined]
    notifier.clock = lambda: datetime(2026, 1, 15, 23, 30)
    run_rounds(api, (network(), []))
    run_rounds(api, (network(), [finding("a")]))
    assert stub.requests == [] and len(notifier.held["night"]) == 1
    notifier.clock = lambda: datetime(2026, 1, 16, 7, 5)
    run_rounds(api, (network(), [finding("a"), finding("b")]))
    (req,) = stub.requests
    assert len(req.body["events"]) == 2
    assert notifier.held == {}


def test_a_failing_channel_never_raises_and_the_next_one_still_sends(
    api: TestClient, stub: Stub, caplog: pytest.LogCaptureFixture
) -> None:
    token = secret_value()
    put_channel(
        api,
        "a-bad",
        kind="telegram",
        url=f"http://127.0.0.1:{free_port()}",
        chat_id="1",
        secret=token,
    )
    put_channel(api, "b-good", kind="webhook", url=stub.url)
    caplog.set_level(logging.DEBUG)
    run_rounds(api, (network(), []), (network(), [finding("a", Severity.ERROR)]))
    assert len(stub.requests) == 1
    info = {c["name"]: c for c in api.get("/api/notifications").json()["channels"]}
    assert info["a-bad"]["last_error"] and token not in info["a-bad"]["last_error"]
    assert info["b-good"]["last_ok"] and info["b-good"]["last_error"] is None
    assert token not in caplog.text


def test_the_round_listener_is_wired_into_the_runner(api: TestClient, services: Services) -> None:
    assert api.notifier.on_round in services.runner.round_listeners  # type: ignore[attr-defined]
    asyncio.run(services.runner.observe_all())
    assert services.store.get_setting(nt.STATE_KEY) is not None


def test_a_damaged_state_counts_as_a_baseline(api: TestClient, stub: Stub) -> None:
    put_channel(api, "hook", kind="webhook", url=stub.url)
    api.notifier.store.set_setting(nt.STATE_KEY, "{not json")  # type: ignore[attr-defined]
    run_rounds(api, (network(), [finding("a", Severity.ERROR)]))
    assert stub.requests == []


def test_a_telegram_token_does_not_reach_the_log(
    stub: Stub, caplog: pytest.LogCaptureFixture
) -> None:
    token = secret_value()
    caplog.set_level(logging.DEBUG)
    nt.deliver(spec("telegram", url=stub.url, chat_id="1", secret=token), message(), 5, 0)
    assert len(stub.requests) == 1 and token not in caplog.text


# the settings API and secrets -----------------------------------------------------------------


def test_secrets_are_encrypted_write_only_and_not_exported(
    api: TestClient, services: Services, stub: Stub
) -> None:
    token = secret_value()
    out = put_channel(api, "phone", kind="ntfy", url=stub.url, topic="t", secret=token)
    assert out["secret_set"] is True and "secret" not in out
    listing = api.get("/api/notifications")
    assert token not in listing.text and listing.json()["channels"][0]["secret_set"] is True
    raw = services.store.get_setting(nt.SECRET_KEY + "phone")
    assert raw and token not in raw
    assert token not in (services.store.get_setting(nt.CHANNELS_KEY) or "")
    assert services.store.secret_names() == []  # not a desired-state secret
    assert services.store.vault.decrypt(raw) == token
    for path in ("/api/network", "/api/findings", "/api/health"):
        assert token not in api.get(path).text
    # an empty secret keeps the stored one; clear_secret removes it
    again = put_channel(api, "phone", kind="ntfy", url=stub.url, topic="t2")
    assert again["secret_set"] is True and again["topic"] == "t2"
    cleared = put_channel(api, "phone", kind="ntfy", url=stub.url, topic="t2", clear_secret=True)
    assert cleared["secret_set"] is False
    assert services.store.get_setting(nt.SECRET_KEY + "phone") is None


def test_channels_can_be_deleted_and_names_are_checked(api: TestClient, stub: Stub) -> None:
    put_channel(api, "gone", kind="webhook", url=stub.url)
    assert api.delete("/api/notifications/channels/gone").status_code == 204
    assert api.get("/api/notifications").json()["channels"] == []
    bad = api.put("/api/notifications/channels/Bad Name", json={"kind": "webhook"})
    assert bad.status_code == 422
    bad = api.put("/api/notifications/channels/ok", json={"kind": "ntfy", "url": "ftp://x"})
    assert bad.status_code == 422
    assert api.put("/api/notifications/channels/ok", json={"kind": "nope"}).status_code == 422


def test_the_send_test_button(api: TestClient, stub: Stub) -> None:
    put_channel(api, "hook", kind="webhook", url=stub.url, enabled=False, language="de")
    res = api.post("/api/notifications/channels/hook/test")
    assert res.json() == {"ok": True, "error": None}
    assert "Testnachricht" in stub.requests[0].body["text"]
    stub.statuses = [401]
    res = api.post("/api/notifications/channels/hook/test").json()
    assert res["ok"] is False and "401" in res["error"]
    assert api.post("/api/notifications/channels/none/test").status_code == 404


def test_channels_from_the_config_file_are_listed_testable_and_read_only(
    tmp_path: Path, stub: Stub
) -> None:
    token = secret_value()
    (tmp_path / "signalbox.yaml").write_text(
        cfgmod.TEMPLATE.replace(
            "  channels: {}",
            "  channels:\n"
            "    filehook:\n"
            "      kind: gotify\n"
            "      enabled: true\n"
            f"      url: {stub.url}\n"
            f"      secret: {token}\n",
        )
    )
    svc = build(
        tmp_path, env={"SIGNALBOX_AUTH_PASSWORD": PW}, adapters={}, rules=[], link_sources=[]
    )
    try:
        with TestClient(create_app(svc, run_background=False)) as api:
            api.post("/api/login", json={"password": PW})
            (ch,) = api.get("/api/notifications").json()["channels"]
            assert ch["source"] == "config" and ch["secret_set"] and token not in str(ch)
            assert api.post("/api/notifications/channels/filehook/test").json()["ok"] is True
            assert stub.requests[0].headers["x-gotify-key"] == token
            assert api.delete("/api/notifications/channels/filehook").status_code == 409
            res = api.put("/api/notifications/channels/filehook", json={"kind": "gotify"})
            assert res.status_code == 409
    finally:
        svc.close()


def test_the_browser_channel_queues_messages_for_the_page(api: TestClient) -> None:
    put_channel(api, "tab", kind="browser")
    assert api.get("/api/notifications/browser").json() == []
    run_rounds(api, (network(), []), (network(), [finding("a", Severity.ERROR)]))
    (msg,) = api.get("/api/notifications/browser?after=0").json()
    assert msg["id"] == 1 and "Title a" in msg["lines"][0] and msg["severity"] == "error"
    assert api.get("/api/notifications/browser?after=1").json() == []
    assert api.post("/api/notifications/channels/tab/test").json()["ok"] is True
    assert len(api.get("/api/notifications/browser?after=1").json()) == 1


def test_apprise_is_offered_only_when_installed(
    api: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setitem(sys.modules, "apprise", None)
    assert "apprise" not in api.get("/api/notifications").json()["kinds"]
    monkeypatch.setitem(sys.modules, "apprise", types.ModuleType("apprise"))
    assert "apprise" in api.get("/api/notifications").json()["kinds"]


def test_everything_is_off_by_default(tmp_path: Path) -> None:
    config = cfgmod.load(tmp_path, env={})
    assert config.notifications.channels == {} and config.notifications.language == "en"
    svc = build(
        tmp_path, env={"SIGNALBOX_AUTH_PASSWORD": PW}, adapters={}, rules=[], link_sources=[]
    )
    try:
        assert nt.Notifier(config.notifications, svc.store).all_channels() == {}
    finally:
        svc.close()
