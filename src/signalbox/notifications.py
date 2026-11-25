"""Notifications to common systems (#367): e-mail, ntfy, Matrix, Telegram, Gotify, a JSON
webhook, the browser while the UI is open and, when the package is installed, Apprise.

Everything is off by default and outbound only. After every observation round the notifier
compares the network with the round before and turns the differences into events (a new or
resolved finding, a device that cannot be read or only partly, drift from the desired state,
the result of a deployment). Every channel gets at most one message per round with the events
it asked for (digest). Sending happens on a worker thread with a bounded timeout and a bounded
number of retries: a failing channel never delays a read.

Tokens and passwords are encrypted like device credentials, are write-only in the API and never
appear in a log line, an error text, an export or MQTT.
"""

from __future__ import annotations

import contextlib
import importlib.util
import json
import logging
import re
import smtplib
import ssl
import sys
import threading
import time
import uuid
from collections import deque
from collections.abc import Callable, Iterable, Mapping
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import UTC, datetime
from email.message import EmailMessage
from pathlib import Path
from typing import Any
from urllib.parse import quote

import httpx
from pydantic import BaseModel, Field, SecretStr

from signalbox.config import (
    ChannelSpec,
    EventKind,
    NotificationsConfig,
    parse_clock,
)
from signalbox.model import DeviceStatus, Network
from signalbox.rules import SEVERITY_ORDER, Finding, Severity
from signalbox.store import Store
from signalbox.webpush import WebPush

log = logging.getLogger(__name__)


class _HideBotTokens(logging.Filter):
    """httpx logs every request URL at INFO; a Telegram URL contains the bot token."""

    def filter(self, record: logging.LogRecord) -> bool:
        return "/bot" not in record.getMessage()


logging.getLogger("httpx").addFilter(_HideBotTokens())

I18N = Path(__file__).parent / "web" / "static" / "i18n"
NAME = re.compile(r"^[a-z0-9][a-z0-9_-]{0,39}$")
MAX_LINES = 20
MAX_HELD = 200
STATE_KEY = "notify:state"
CHANNELS_KEY = "notify:channels"
SECRET_KEY = "notify-secret:"


def severity_rank(severity: Severity) -> int:
    """Bigger is more severe."""
    return 2 - SEVERITY_ORDER[severity]


def in_quiet_hours(spec: ChannelSpec, now: datetime) -> bool:
    """True inside the quiet hours (they may span midnight)."""
    if not spec.quiet:
        return False
    start, end, here = parse_clock(spec.quiet_start), parse_clock(spec.quiet_end), now.time()
    if start == end:
        return False
    if start < end:
        return start <= here < end
    return here >= start or here < end


# events -------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Event:
    kind: EventKind
    severity: Severity
    mid: str  # catalogue id msg.<mid>
    params: Mapping[str, str | int] = field(default_factory=dict)
    path: str = "#/"  # page of the UI the message links to


class Translator:
    """Server-side texts from the UI's catalogues; English is the fallback."""

    def __init__(self, directory: Path = I18N) -> None:
        self.directory = directory
        self._cache: dict[str, dict[str, str]] = {}

    def catalogue(self, code: str) -> dict[str, str]:
        if not re.fullmatch(r"[a-z]{2,3}", code):
            code = "en"
        if code not in self._cache:
            try:
                data = json.loads((self.directory / f"{code}.json").read_text(encoding="utf-8"))
            except (OSError, ValueError):
                data = {}
            self._cache[code] = data if isinstance(data, dict) else {}
        return self._cache[code]

    def text(self, code: str, mid: str, params: Mapping[str, str | int] | None = None) -> str:
        key = f"msg.{mid}"
        raw = self.catalogue(code).get(key) or self.catalogue("en").get(key) or key
        values = params or {}
        return re.sub(r"\{(\w+)\}", lambda m: str(values.get(m.group(1), m.group(0))), raw)


@dataclass(frozen=True)
class Message:
    subject: str
    lines: list[str]
    severity: Severity
    events: list[dict[str, str]]
    language: str
    link: str = ""

    @property
    def text(self) -> str:
        body = "\n".join(f"- {line}" for line in self.lines)
        return f"{self.subject}\n\n{body}" + (f"\n\n{self.link}" if self.link else "")


def build_message(
    events: list[Event], language: str, tr: Translator, base_url: str = ""
) -> Message:
    shown = events[:MAX_LINES]
    base = base_url.rstrip("/")
    lines: list[str] = []
    out: list[dict[str, str]] = []
    for ev in shown:
        params = {**ev.params}
        if "severity" in params:
            params["severity"] = tr.text(language, f"notify.severity.{params['severity']}")
        text = tr.text(language, ev.mid, params)
        lines.append(text)
        item = {"kind": ev.kind.value, "severity": ev.severity.value, "text": text}
        if base:
            item["url"] = f"{base}/{ev.path}"
        out.append(item)
    if len(events) > len(shown):
        lines.append(tr.text(language, "notify.more", {"count": len(events) - len(shown)}))
    top = max((e.severity for e in events), key=severity_rank)
    link = f"{base}/#/" if base else ""
    subject = tr.text(language, "notify.subject", {"count": len(events)})
    return Message(subject, lines, top, out, language, link)


class RoundState(BaseModel):
    """What the previous round looked like (persisted: a restart sends no flood)."""

    findings: dict[str, dict[str, str]] = Field(default_factory=dict)
    devices: dict[str, str] = Field(default_factory=dict)
    changes: list[str] = Field(default_factory=list)


#: Change states that are a deployment result.
DEPLOY_DONE = {"applied": Severity.INFO, "rolled-back": Severity.WARNING, "failed": Severity.ERROR}


def diff_round(
    old: RoundState | None,
    net: Network,
    findings: Iterable[Finding],
    changes: Iterable[tuple[str, str]],
) -> tuple[RoundState, list[Event]]:
    """The new state and the events since ``old`` (none for the very first round)."""
    events: list[Event] = []
    current: dict[str, dict[str, str]] = {}
    for f in findings:
        if f.problem:
            current[f.id] = {"title": f.title, "severity": f.severity.value, "rule": f.rule_id}
    names = {d.id: d.name for d in net.devices}
    devices = {did: st.value for did, st in net.statuses.items() if did in names}
    done = [cid for cid, status in changes if status in DEPLOY_DONE]
    state = RoundState(findings=current, devices=devices, changes=done[-200:])
    if old is None:
        return state, events
    by_id = {f.id: f for f in findings}
    for fid, info in current.items():
        if fid in old.findings:
            continue
        drift = info["rule"].startswith("drift.")
        events.append(
            Event(
                EventKind.DRIFT if drift else EventKind.FINDING,
                Severity(info["severity"]),
                "notify.drift" if drift else "notify.finding.new",
                {
                    "severity": info["severity"],
                    "title": info["title"],
                    "message": by_id[fid].message,
                },
            )
        )
    for fid, info in old.findings.items():
        if fid not in current:
            drift = info["rule"].startswith("drift.")
            events.append(
                Event(
                    EventKind.DRIFT if drift else EventKind.FINDING,
                    Severity(info["severity"]),
                    "notify.drift.resolved" if drift else "notify.finding.resolved",
                    {"title": info["title"]},
                )
            )
    for did, status in devices.items():
        before = old.devices.get(did)
        if before is None or before == status:
            continue
        name = names[did]
        if status == DeviceStatus.PARTIAL.value:
            events.append(
                Event(
                    EventKind.DEVICE,
                    Severity.WARNING,
                    "notify.device.partial",
                    {"device": name},
                    "#/devices",
                )
            )
        elif status == DeviceStatus.OK.value:
            events.append(
                Event(
                    EventKind.DEVICE,
                    Severity.INFO,
                    "notify.device.recovered",
                    {"device": name},
                    "#/devices",
                )
            )
        else:
            events.append(
                Event(
                    EventKind.DEVICE,
                    Severity.ERROR,
                    "notify.device.unreachable",
                    {"device": name, "status": status},
                    "#/devices",
                )
            )
    for cid, status in changes:
        if status in DEPLOY_DONE and cid not in old.changes:
            events.append(
                Event(
                    EventKind.DEPLOY,
                    DEPLOY_DONE[status],
                    f"notify.deploy.{status}",
                    {"id": cid},
                    "#/changes",
                )
            )
    return state, events


# channels -----------------------------------------------------------------------------------


class SendError(Exception):
    """A delivery failed; the text never contains a secret. ``retry``: trying again can help."""

    def __init__(self, message: str, retry: bool = False) -> None:
        super().__init__(message)
        self.retry = retry


HTTP_PRIORITY = {Severity.INFO: 2, Severity.WARNING: 3, Severity.ERROR: 5}


def _secret(spec: ChannelSpec) -> str:
    return spec.secret.get_secret_value() if spec.secret else ""


def _http(
    method: str, url: str, timeout: float, *, headers: dict[str, str] | None = None, **kw: Any
) -> None:
    try:
        with httpx.Client(timeout=timeout, follow_redirects=False) as client:
            res = client.request(method, url, headers=headers, **kw)
    except httpx.HTTPError as exc:
        raise SendError(f"{type(exc).__name__}", retry=True) from None
    if res.status_code >= 400:
        raise SendError(
            f"HTTP {res.status_code}", retry=res.status_code >= 500 or res.status_code == 429
        )


def _need(spec: ChannelSpec, *names: str) -> None:
    missing = [n for n in names if not (_secret(spec) if n == "secret" else getattr(spec, n))]
    if missing:
        raise SendError("missing settings: " + ", ".join(missing))


def send_email(spec: ChannelSpec, msg: Message, timeout: float, txn: str) -> None:
    _need(spec, "host", "sender")
    if not spec.recipients:
        raise SendError("missing settings: recipients")
    mail = EmailMessage()
    mail["Subject"] = msg.subject
    mail["From"] = spec.sender
    mail["To"] = ", ".join(spec.recipients)
    mail["Message-ID"] = f"<{txn}@signalbox.invalid>"
    mail.set_content(msg.text)
    port = spec.port or {"ssl": 465, "starttls": 587, "none": 25}[spec.security]
    context = ssl.create_default_context()
    if not spec.verify_tls:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    try:
        if spec.security == "ssl":
            smtp: smtplib.SMTP = smtplib.SMTP_SSL(spec.host, port, timeout=timeout, context=context)
        else:
            smtp = smtplib.SMTP(spec.host, port, timeout=timeout)
        with smtp:
            if spec.security == "starttls":
                smtp.starttls(context=context)
            if spec.username:
                smtp.login(spec.username, _secret(spec))
            smtp.send_message(mail)
    except smtplib.SMTPAuthenticationError:
        raise SendError("the SMTP server refused the login") from None
    except smtplib.SMTPRecipientsRefused:
        raise SendError("the SMTP server refused the recipients") from None
    except (OSError, smtplib.SMTPException) as exc:
        raise SendError(type(exc).__name__, retry=True) from None


def _bearer(spec: ChannelSpec) -> dict[str, str]:
    return {"Authorization": f"Bearer {_secret(spec)}"} if _secret(spec) else {}


def send_ntfy(spec: ChannelSpec, msg: Message, timeout: float, txn: str) -> None:
    _need(spec, "url", "topic")
    body: dict[str, Any] = {
        "topic": spec.topic,
        "title": msg.subject,
        "message": "\n".join(f"- {line}" for line in msg.lines),
        "priority": HTTP_PRIORITY[msg.severity],
    }
    if msg.link:
        body["click"] = msg.link
    _http("POST", spec.url.rstrip("/") + "/", timeout, headers=_bearer(spec), json=body)


def send_matrix(spec: ChannelSpec, msg: Message, timeout: float, txn: str) -> None:
    _need(spec, "url", "room_id", "secret")
    url = (
        f"{spec.url.rstrip('/')}/_matrix/client/v3/rooms/{quote(spec.room_id, safe='')}"
        f"/send/m.room.message/{txn}"
    )
    _http("PUT", url, timeout, headers=_bearer(spec), json={"msgtype": "m.text", "body": msg.text})


def send_telegram(spec: ChannelSpec, msg: Message, timeout: float, txn: str) -> None:
    _need(spec, "chat_id", "secret")
    base = (spec.url or "https://api.telegram.org").rstrip("/")
    body = {"chat_id": spec.chat_id, "text": msg.text, "disable_web_page_preview": True}
    _http("POST", f"{base}/bot{_secret(spec)}/sendMessage", timeout, json=body)


def send_gotify(spec: ChannelSpec, msg: Message, timeout: float, txn: str) -> None:
    _need(spec, "url", "secret")
    body = {
        "title": msg.subject,
        "message": "\n".join(f"- {line}" for line in msg.lines),
        "priority": HTTP_PRIORITY[msg.severity] * 2 - 1,
    }
    _http(
        "POST",
        spec.url.rstrip("/") + "/message",
        timeout,
        headers={"X-Gotify-Key": _secret(spec)},
        json=body,
    )


def send_webhook(spec: ChannelSpec, msg: Message, timeout: float, txn: str) -> None:
    _need(spec, "url")
    body = {
        "version": 1,
        "id": txn,
        "subject": msg.subject,
        "text": msg.text,
        "severity": msg.severity.value,
        "language": msg.language,
        "events": msg.events,
    }
    _http("POST", spec.url, timeout, headers=_bearer(spec), json=body)


def apprise_available() -> bool:
    """The optional ``apprise`` package is installed."""
    if "apprise" in sys.modules:
        return sys.modules["apprise"] is not None
    try:
        return importlib.util.find_spec("apprise") is not None
    except (ImportError, ValueError):
        return False


def send_apprise(spec: ChannelSpec, msg: Message, timeout: float, txn: str) -> None:
    _need(spec, "secret")
    if not apprise_available():
        raise SendError("the apprise package is not installed")
    import apprise  # type: ignore[import-not-found,unused-ignore]  # optional extra

    app = apprise.Apprise()
    if not app.add(_secret(spec)):
        raise SendError("not an Apprise URL")
    if not app.notify(title=msg.subject, body="\n".join(f"- {line}" for line in msg.lines)):
        raise SendError("Apprise could not deliver", retry=True)


Sender = Callable[[ChannelSpec, Message, float, str], None]
SENDERS: dict[str, Sender] = {
    "email": send_email,
    "ntfy": send_ntfy,
    "matrix": send_matrix,
    "telegram": send_telegram,
    "gotify": send_gotify,
    "webhook": send_webhook,
    "apprise": send_apprise,
}


def deliver(
    spec: ChannelSpec,
    msg: Message,
    timeout: float,
    retries: int,
    sleep: Callable[[float], None] = time.sleep,
) -> None:
    """Send with a bounded number of attempts; the message id (Matrix transaction) is the same
    for every attempt, so a retry never doubles a message."""
    sender = SENDERS[spec.kind]
    txn = uuid.uuid4().hex
    attempt = 0
    while True:
        try:
            sender(spec, msg, timeout, txn)
            return
        except SendError as exc:
            if not exc.retry or attempt >= retries:
                raise
        attempt += 1
        sleep(min(2.0**attempt, 30.0))


@dataclass
class ChannelStatus:
    last_ok: str | None = None
    last_error: str | None = None
    sent: int = 0


@dataclass
class BrowserMessage:
    id: int
    subject: str
    lines: list[str]
    severity: str
    link: str


class ChannelStore:
    """Channels made in the UI: settings in the database, secrets encrypted with the vault."""

    def __init__(self, store: Store) -> None:
        self.store = store

    def _raw(self) -> dict[str, Any]:
        text = self.store.get_setting(CHANNELS_KEY)
        data = json.loads(text) if text else {}
        return data if isinstance(data, dict) else {}

    def names(self) -> list[str]:
        return sorted(self._raw())

    def secret_set(self, name: str) -> bool:
        return self.store.get_setting(SECRET_KEY + name) is not None

    def get(self, name: str) -> ChannelSpec | None:
        data = self._raw().get(name)
        if data is None:
            return None
        spec = ChannelSpec.model_validate(data)
        stored = self.store.get_setting(SECRET_KEY + name)
        if stored:
            spec.secret = SecretStr(self.store.vault.decrypt(stored))
        return spec

    def put(self, name: str, spec: ChannelSpec, keep_secret: bool = True) -> None:
        """Save; a missing secret keeps the stored one unless ``keep_secret`` is false."""
        data = self._raw()
        data[name] = spec.model_dump(mode="json", exclude={"secret"})
        self.store.set_setting(CHANNELS_KEY, json.dumps(data))
        if spec.secret is not None and spec.secret.get_secret_value():
            self.store.set_setting(SECRET_KEY + name, self.store.vault.encrypt(_secret(spec)))
        elif not keep_secret:
            self.store.delete_setting(SECRET_KEY + name)

    def delete(self, name: str) -> bool:
        data = self._raw()
        if name not in data:
            return False
        del data[name]
        self.store.set_setting(CHANNELS_KEY, json.dumps(data))
        self.store.delete_setting(SECRET_KEY + name)
        return True


class Notifier:
    """Turns each observation round into digests and sends them."""

    def __init__(
        self,
        config: NotificationsConfig,
        store: Store,
        base_url: str = "",
        *,
        executor: Any | None = None,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], datetime] = lambda: datetime.now().astimezone(),
        translator: Translator | None = None,
    ) -> None:
        self.config = config
        self.store = store
        self.base_url = base_url
        self.channels = ChannelStore(store)
        self.webpush = WebPush(store, base_url)
        self.executor = executor or ThreadPoolExecutor(max_workers=2, thread_name_prefix="notify")
        self.sleep = sleep
        self.clock = clock
        self.tr = translator or Translator()
        self.status: dict[str, ChannelStatus] = {}
        self.held: dict[str, list[Event]] = {}
        self.browser: deque[BrowserMessage] = deque(maxlen=50)
        self._browser_id = 0
        self._lock = threading.Lock()

    # channels

    def all_channels(self) -> dict[str, tuple[str, ChannelSpec]]:
        """name -> (source, spec); a channel of the file wins over one of the UI."""
        out: dict[str, tuple[str, ChannelSpec]] = {}
        for name in self.channels.names():
            try:
                spec = self.channels.get(name)
            except Exception:
                log.warning("notification channel %s is unusable", name)
                continue
            if spec is not None:
                out[name] = ("ui", spec)
        for name, cfg in self.config.channels.items():
            out[name] = ("config", cfg)
        return out

    # rounds

    def _state(self) -> RoundState | None:
        text = self.store.get_setting(STATE_KEY)
        if not text:
            return None
        try:
            return RoundState.model_validate_json(text)
        except ValueError:
            return None

    def on_round(self, net: Network, findings: list[Finding]) -> None:
        """Runner round listener: never raises, never waits for a delivery."""
        try:
            changes = [(c.id, c.status.value) for c in reversed(self.store.changes(limit=200))]
            state, events = diff_round(self._state(), net, findings, changes)
            self.store.set_setting(STATE_KEY, state.model_dump_json())
            self.dispatch(events)
        except Exception:
            log.exception("notification round failed")

    def dispatch(self, events: list[Event]) -> None:
        now = self.clock()
        for name, (_source, spec) in self.all_channels().items():
            if not spec.enabled:
                continue
            wanted = [
                e
                for e in events
                if e.kind in spec.events
                and severity_rank(e.severity) >= severity_rank(spec.min_severity)
            ]
            with self._lock:
                pending = self.held.pop(name, []) + wanted
                if pending and in_quiet_hours(spec, now):
                    self.held[name] = pending[-MAX_HELD:]
                    continue
            if not pending:
                continue
            msg = build_message(
                pending, spec.language or self.config.language, self.tr, self.base_url
            )
            if spec.kind == "browser":
                self._to_browser(name, msg)
            else:
                self.executor.submit(self._send, name, spec, msg)

    def _to_browser(self, name: str, msg: Message) -> None:
        with self._lock:
            self._browser_id += 1
            self.browser.append(
                BrowserMessage(
                    self._browser_id, msg.subject, msg.lines, msg.severity.value, msg.link
                )
            )
        # Web Push (#372): browsers that subscribed get it with no tab open
        self.executor.submit(
            self.webpush.send, msg.subject, msg.lines, msg.link, self.config.timeout_seconds
        )
        self._mark(name, None)

    def browser_since(self, after: int) -> list[BrowserMessage]:
        with self._lock:
            return [m for m in self.browser if m.id > after]

    def _mark(self, name: str, error: str | None) -> None:
        st = self.status.setdefault(name, ChannelStatus())
        stamp = datetime.now(UTC).isoformat(timespec="seconds")
        if error is None:
            st.last_ok, st.last_error = stamp, None
            st.sent += 1
        else:
            st.last_error = error

    def _send(self, name: str, spec: ChannelSpec, msg: Message) -> str | None:
        """Deliver; returns the problem (without secrets) or None."""
        try:
            deliver(spec, msg, self.config.timeout_seconds, self.config.retries, self.sleep)
        except SendError as exc:
            problem = redact(str(exc), spec)
        except Exception as exc:  # a broken channel must not hurt anything else
            problem = redact(type(exc).__name__, spec)
        else:
            self._mark(name, None)
            return None
        log.warning("notification channel %s failed: %s", name, problem)
        self._mark(name, problem)
        return problem

    def test(self, name: str) -> str | None:
        """Send the test message now (in the caller's thread); None: delivered."""
        found = self.all_channels().get(name)
        if found is None:
            raise KeyError(name)
        spec = found[1]
        language = spec.language or self.config.language
        msg = Message(
            self.tr.text(language, "notify.subject", {"count": 1}),
            [self.tr.text(language, "notify.test")],
            Severity.INFO,
            [],
            language,
            f"{self.base_url.rstrip('/')}/#/" if self.base_url else "",
        )
        if spec.kind == "browser":
            self._to_browser(name, msg)
            return None
        return self._send(name, spec, msg)

    def close(self) -> None:
        with contextlib.suppress(Exception):
            self.executor.shutdown(wait=False, cancel_futures=True)


def redact(text: str, spec: ChannelSpec) -> str:
    secret = _secret(spec)
    return text.replace(secret, "***") if secret else text
