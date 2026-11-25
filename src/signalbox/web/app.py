"""The HTTP API and the static web interface."""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from datetime import timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from fastapi import APIRouter, FastAPI, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, SecretStr

from signalbox import __version__, oui
from signalbox.adapters import Adapter
from signalbox.deploy import Deployer
from signalbox.discovery.engine import Discovery
from signalbox.firewall import service_from_internet
from signalbox.model import (
    DeviceRole,
    DeviceStatus,
    Link,
    LinkKind,
    LinkOrigin,
    Network,
    Site,
    Snapshot,
    Verdict,
    normalise_mac,
)
from signalbox.mqtt import MqttBridge
from signalbox.neighbours import radio_neighbours, scan_rows
from signalbox.notifications import Notifier
from signalbox.power import powered_by
from signalbox.prober import Prober
from signalbox.secrets import SecretError
from signalbox.service import Services
from signalbox.sightings import History
from signalbox.store import DeviceRecord, StoreError, slug
from signalbox.tracer import Tracer
from signalbox.web.annotations_api import router as annotations_router
from signalbox.web.auth import COOKIE, Auth, Locked
from signalbox.web.changes_api import router as changes_router
from signalbox.web.desired_api import router as desired_router
from signalbox.web.discovery_api import router as discovery_router
from signalbox.web.manage_url import manage_url
from signalbox.web.notifications_api import router as notifications_router
from signalbox.web.probes_api import router as probes_router
from signalbox.web.rules_api import router as rules_router
from signalbox.web.traces_api import router as traces_router
from signalbox.wifimap import wifi_map

log = logging.getLogger(__name__)
STATIC = Path(__file__).parent / "static"
OPEN_PATHS = {"/api/login", "/api/session", "/api/health", "/health"}
MAX_BODY = 256 * 1024
CSP = (
    "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "
    "frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
)


def error(status: int, code: str, message: str, **extra: Any) -> JSONResponse:
    return JSONResponse({"error": code, "message": message, **extra}, status_code=status)


def error_ids(exc: Any, redact: Callable[[str], str]) -> dict[str, Any]:
    """Translation ids and values of an AdapterError for an error answer (#204); the English
    ``message`` and ``fix`` stay the source and the fallback."""
    out: dict[str, Any] = {}
    if getattr(exc, "message_id", None):
        out["message_id"] = exc.message_id
    if getattr(exc, "fix_id", None):
        out["fix_id"] = exc.fix_id
    params = getattr(exc, "params", None)
    if params and out:
        out["params"] = {k: redact(v) if isinstance(v, str) else v for k, v in params.items()}
    return out


class LoginBody(BaseModel):
    password: str = Field(max_length=200)


class PasswordBody(BaseModel):
    current: str = Field(max_length=200)
    new: str = Field(min_length=10, max_length=200)


class SiteBody(BaseModel):
    name: str = Field(min_length=1, max_length=100)


class DeviceBody(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    site_id: str
    role: DeviceRole
    adapter: str
    enabled: bool = True
    allow_writes: bool = False
    #: The device this one runs on, when its address does not show it (#387); empty: derived.
    hosted_on: str | None = Field(None, pattern=r"^[a-z0-9][a-z0-9-]{0,62}$")
    config: dict[str, Any] = Field(default_factory=dict)
    #: Stored secret settings to remove (optional ones only; the form's "Remove" box).
    clear_secrets: list[str] = Field(default_factory=list)
    #: A certificate fingerprint the user trusted while testing the form; pinned on save.
    trust_fingerprint: str | None = Field(None, pattern=r"^[0-9a-f]{64}$")


class DeviceTestBody(DeviceBody):
    """The device form, tested before it is saved."""

    #: The device being edited: empty secrets take its stored values, its pin is used.
    device_id: str | None = None


class TrustBody(BaseModel):
    fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")


class LinkBody(BaseModel):
    a: str = Field(min_length=1, max_length=300)
    b: str = Field(min_length=1, max_length=300)
    kind: LinkKind = LinkKind.CABLE


def public_network(net: Network, history: History | None = None) -> dict[str, Any]:
    """The network as JSON for the UI: passphrase fingerprints and digests never leave the server.

    Uplinks get the derived ``nat_class`` and ``upstream_device`` (the known router in front,
    #148), management services the segments that can reach them (``reach_segments``) and
    whether the internet can (``internet``, ``null``: the firewall decides, #173), clients the
    source of each address (``sources``, from leases where the client does not say) and the
    end of their active leases (``lease_expires``, #183), the vendor of the MAC address
    (``vendor``, offline IEEE registry, #84), ports whether a cable can end there
    (``external``, #252), who powers whom over PoE (devices ``powered_by``: the switch, its port and
    the power delivered; ports ``powers``: the device behind a PoE port, #468), tunnel peers the
    networks they route (``networks``), the read tunnel
    at their other end (``other_end``) and the handshake age at the reading (``handshake_age``,
    #239), firewalls the action per zone pair (``matrix``: one row per source zone, the
    device itself first, then each zone; ``null``: not known, #135), so that the UI does not
    repeat the derivation. The MAC address tables (``fdb``, #160) are left out: they can be
    large and are read with ``GET /api/fdb``; so are the scan results (``wifi_scan``, #169):
    neighbours' networks, read with ``GET /api/wifi-scan``. Each WLAN gets its BSSID's
    ``neighbours`` count and each radio ``neighbour_count`` and ``strongest_foreign_dbm`` on
    its channel (:func:`signalbox.neighbours.radio_neighbours`). Gateway groups get ``failovers``,
    how often their active member changed in the retained history (#150), where there is one.
    """
    data = net.model_dump(mode="json", exclude={"fdb", "wifi_scan", "held_sightings"})
    for radio, raw in zip(net.radios, data["radios"], strict=True):
        raw.update(radio_neighbours(net, radio))
    feeds = powered_by(net)
    for dev, raw in zip(net.devices, data["devices"], strict=True):
        feed = feeds.get(dev.id)
        raw["powered_by"] = (
            None
            if feed is None
            else {"device_id": feed.switch_id, "port_id": feed.port_id, "power_w": feed.power_w}
        )
    powers = {f.port_id: f.device_id for f in feeds.values()}
    for port, raw in zip(net.ports, data["ports"], strict=True):
        raw["external"] = port.external
        raw["powers"] = powers.get(port.id)
    for wlan in data["wlans"]:
        wlan.pop("passphrase_fingerprint", None)
        wlan.pop("passphrase_digest", None)
    for uplink, raw in zip(net.uplinks, data["uplinks"], strict=True):
        nat = uplink.nat_class()
        front = net.upstream_router(uplink)
        raw["nat_class"] = nat.value if nat else None
        raw["upstream_device"] = front.device_id if front else None
    if history is not None and history.now is not None:
        since = history.now - timedelta(days=history.days)
        for group, raw in zip(net.gateway_groups, data["gateway_groups"], strict=True):
            raw["failovers"] = history.failovers(group.id, since)
            raw["failover_days"] = history.days
    for service, raw in zip(net.services, data["services"], strict=True):
        raw["reach_segments"] = net.service_segments(service)
        internet = service_from_internet(net, service).verdict
        raw["internet"] = None if internet is Verdict.UNKNOWN else internet is Verdict.ALLOWED
    for client, raw in zip(net.clients, data["clients"], strict=True):
        sources = {str(a): net.address_source(client, a) for a in client.addresses}
        raw["sources"] = {a: s.value for a, s in sources.items() if s is not None}
        raw["vendor"] = oui.vendor(client.mac)
        ends = [
            lease.expires
            for srv in net.dhcp_servers
            for lease in srv.leases_of(client.mac)
            if lease.active() and lease.expires is not None
        ]
        raw["lease_expires"] = max(ends).isoformat() if ends else None
    for fw, raw in zip(net.firewalls, data["firewalls"], strict=True):
        names = [z.name for z in fw.zones]
        matrix = []
        for src in names:
            row = []
            for dst in (None, *names):
                # an unread rule set decides before the defaults: unknown, never "drop" (#379)
                action = (
                    fw.policy(src, dst) or (fw.input_policy if dst is None else fw.forward_policy)
                    if fw.rules_complete
                    else None
                )
                row.append(action.value if action else None)
            matrix.append(row)
        raw["matrix"] = matrix
    for tunnel, raw in zip(net.tunnels, data["tunnels"], strict=True):
        at = tunnel.observed_at
        for p, praw in zip(tunnel.peers, raw["peers"], strict=True):
            other = net.tunnel_end(tunnel, p)
            praw["networks"] = [str(n) for n in tunnel.remote_networks(p)]
            praw["other_end"] = other.id if other else None
            praw["handshake_age"] = p.handshake_age(at) if at else None
    return data


def adapter_info(cls: type[Adapter], setup: bool = True, fixes: bool = True) -> dict[str, Any]:
    """An integration for the UI; ``setup``: the automatic setup is on (``setup.enabled``),
    ``fixes``: *Fix it* is on too (``setup.fixes``, #215)."""
    m = cls.manifest
    schema = m.config.model_json_schema()
    secret = sorted(
        name
        for name, info in m.config.model_fields.items()
        if info.annotation is SecretStr or SecretStr in getattr(info.annotation, "__args__", ())
    )
    return {
        "id": m.id,
        "name": m.name,
        "version": m.version,
        "vendor": m.vendor,
        "description": m.description,
        "setup_url": m.setup_url,
        "setup_commands": m.setup_commands,
        "setup_steps": list(m.setup_steps),
        "admin_login": m.admin_login.model_dump() if m.admin_login and setup else None,
        "remedies": [r.model_dump() for r in m.remedies] if setup and fixes else [],
        "roles": sorted(r.value for r in m.roles),
        "capabilities": sorted(c.value for c in m.capabilities),
        "config_schema": schema,
        "secret_fields": secret,
    }


def create_app(services: Services, run_background: bool = True) -> FastAPI:
    store, runner, config = services.store, services.runner, services.config
    auth = Auth(
        store,
        config.auth.password.get_secret_value() if config.auth.password else None,
        config.auth.session_hours,
    )

    bridge = MqttBridge(
        config.mqtt,
        config.server.base_url,
        identity=config.exports.identity,
        wifi_clients=config.exports.wifi_clients,
    )
    bridge.counters_source = lambda: runner.history().counters
    notifier = Notifier(config.notifications, store, config.server.base_url)
    runner.round_listeners.append(notifier.on_round)
    discovery = Discovery(store, runner, services.adapters, config.discovery)
    tracer = Tracer(store, runner, services.adapters, config)
    prober = Prober(store, runner, config)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        bridge.start()
        if bridge.enabled:
            runner.listeners.append(bridge.publish)
        task = asyncio.create_task(runner.run_forever()) if run_background else None
        schedule = asyncio.create_task(tracer.run_forever()) if run_background else None
        probing = asyncio.create_task(prober.run_forever()) if run_background else None
        try:
            yield
        finally:
            runner.stop()
            await discovery.stop()
            await tracer.stop()
            await prober.stop()
            for background in (schedule, probing):
                if background is not None:
                    background.cancel()
                    with contextlib.suppress(asyncio.CancelledError):
                        await background
            await asyncio.to_thread(bridge.stop)
            notifier.close()
            if task is not None:
                with contextlib.suppress(asyncio.CancelledError):
                    await task

    app = FastAPI(
        title="Signalbox",
        version=__version__,
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url="/api/openapi.json",
    )
    app.state.services = services
    app.state.auth = auth
    app.state.discovery = discovery
    app.state.tracer = tracer
    app.state.prober = prober
    app.state.notifier = notifier

    @app.exception_handler(RequestValidationError)
    async def _invalid(request: Request, exc: RequestValidationError) -> JSONResponse:
        parts = []
        for e in exc.errors():
            loc = ".".join(str(x) for x in e["loc"] if x != "body")
            parts.append(f"{loc}: {e['msg']}" if loc else str(e["msg"]))
        return error(422, "invalid", "; ".join(parts))

    @app.exception_handler(StoreError)
    async def _store(request: Request, exc: StoreError) -> JSONResponse:
        return error(422, "invalid", str(exc))

    @app.middleware("http")
    async def guard(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        path = request.url.path
        if path.startswith("/api/"):
            if request.method not in ("GET", "HEAD", "OPTIONS"):
                origin = request.headers.get("origin")
                if origin and urlsplit(origin).netloc != request.headers.get("host"):
                    return error(403, "bad_origin", "Cross-site request refused.")
                site = request.headers.get("sec-fetch-site")
                if site and site not in ("same-origin", "none"):
                    return error(403, "bad_origin", "Cross-site request refused.")
                length = request.headers.get("content-length", "0")
                if not length.isdigit() or int(length) > MAX_BODY:
                    return error(413, "too_large", "Request body too large.")
                kind = request.headers.get("content-type", "").split(";")[0].strip().lower()
                if int(length) and kind != "application/json":
                    return error(415, "bad_content_type", "Send JSON.")
            if path not in OPEN_PATHS and not auth.valid(request.cookies.get(COOKIE)):
                return error(401, "login_required", "Please log in.")
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = CSP
        if path == "/sw.js":  # the Web Push service worker (#372); it controls the whole app
            response.headers["Service-Worker-Allowed"] = "/"
        response.headers["Cache-Control"] = "no-store" if path.startswith("/api/") else "no-cache"
        return response

    api = APIRouter(prefix="/api")

    # session ----------------------------------------------------------------------------

    def health() -> dict[str, Any]:
        """Liveness: version, number of devices, time of the last observation round."""
        return {
            "status": "ok",
            "version": __version__,
            "devices": len(store.devices()),
            "last_run": runner.last_run.isoformat() if runner.last_run else None,
            "mqtt": bridge.status["state"],
        }

    api.get("/health")(health)
    app.get("/health", include_in_schema=False)(health)

    @api.get("/session")
    def session(request: Request) -> dict[str, Any]:
        """Whether this browser is logged in."""
        return {
            "authenticated": auth.valid(request.cookies.get(COOKIE)),
            "password_fixed": auth.fixed,
            "version": __version__,
        }

    @api.post("/login", response_model=None)
    def login(body: LoginBody, request: Request) -> JSONResponse:
        """Log in with the password; sets the session cookie."""
        client = request.client.host if request.client else "?"
        try:
            token = auth.login(body.password, client)
        except Locked as exc:
            return error(
                429,
                "locked",
                f"Too many failed logins. Try again in {exc.seconds} seconds.",
                retry_after=exc.seconds,
            )
        if token is None:
            return error(401, "bad_password", "Wrong password.")
        response = JSONResponse({"authenticated": True})
        response.set_cookie(
            COOKIE,
            token,
            max_age=int(auth.session_seconds),
            httponly=True,
            samesite="strict",
            secure=request.url.scheme == "https",
        )
        return response

    @api.post("/logout")
    def logout(request: Request, response: Response) -> dict[str, bool]:
        """End the session."""
        auth.logout(request.cookies.get(COOKIE))
        response.delete_cookie(COOKIE)
        return {"authenticated": False}

    @api.post("/password", response_model=None)
    def change_password(body: PasswordBody) -> JSONResponse | dict[str, bool]:
        """Change the web interface password (ends all sessions)."""
        if auth.fixed:
            return error(
                409, "password_fixed", "The password is set by SIGNALBOX_AUTH_PASSWORD or the file."
            )
        if not auth.check(body.current):
            return error(403, "bad_password", "The current password is wrong.")
        auth.set_password(body.new)
        return {"changed": True}

    # adapters, rules ------------------------------------------------------------------

    @api.get("/adapters")
    def adapters() -> list[dict[str, Any]]:
        """Installed adapters with their settings form (JSON Schema)."""
        return [
            adapter_info(services.adapters[k], config.setup.enabled, config.setup.fixes)
            for k in sorted(services.adapters)
        ]

    # sites ------------------------------------------------------------------------------

    @api.get("/sites")
    def sites() -> list[Site]:
        """List sites."""
        return store.sites()

    @api.post("/sites", status_code=201)
    def add_site(body: SiteBody) -> Site:
        """Add a site."""
        site = Site(id=slug(body.name, [s.id for s in store.sites()]), name=body.name)
        store.put_site(site)
        return site

    @api.put("/sites/{site_id}", response_model=None)
    def rename_site(site_id: str, body: SiteBody) -> Site | JSONResponse:
        """Rename a site."""
        if site_id not in {s.id for s in store.sites()}:
            return error(404, "not_found", "No such site.")
        site = Site(id=site_id, name=body.name)
        store.put_site(site)
        return site

    @api.delete("/sites/{site_id}", status_code=204)
    def delete_site(site_id: str) -> None:
        """Delete a site without devices."""
        store.delete_site(site_id)

    # devices ----------------------------------------------------------------------------

    def device_json(
        rec: DeviceRecord, past: History | None = None, net: Network | None = None
    ) -> dict[str, Any]:
        net_status = runner_status().get(rec.id)
        seen = (past or runner.history()).devices.get(rec.id)
        net = net or runner.network()
        dev = net.device(rec.id)
        return {
            **rec.model_dump(mode="json"),
            "manage_url": manage_url(
                rec.adapter,
                rec.config,
                net.services_of(rec.id),
                dev.management_address if dev else None,
            ),
            "status": net_status,
            "first_seen": seen.first_seen.isoformat() if seen else None,
            "last_seen": seen.last_seen.isoformat() if seen else None,
            "last_ok": seen.last_ok.isoformat() if seen and seen.last_ok else None,
        }

    def runner_status() -> dict[str, str]:
        return {s.device.id: s.status.value for s in store.snapshots()}

    @api.get("/devices")
    def devices() -> list[dict[str, Any]]:
        """List devices with their last status and when they were first seen and last read."""
        past = runner.history()
        net = runner.network()
        return [device_json(d, past, net) for d in store.devices()]

    def save_device(device_id: str, body: DeviceBody) -> DeviceRecord | JSONResponse:
        cls = services.adapters.get(body.adapter)
        if cls is None:
            return error(422, "invalid", f"adapter {body.adapter!r} is not installed")
        if body.role not in cls.manifest.roles:
            roles = ", ".join(sorted(r.value for r in cls.manifest.roles))
            return error(422, "invalid", f"{cls.manifest.name} devices can be: {roles}")
        old = store.device(device_id)
        rec = DeviceRecord(
            id=device_id,
            site_id=body.site_id,
            name=body.name,
            role=body.role,
            adapter=body.adapter,
            enabled=body.enabled,
            allow_writes=body.allow_writes,
            hosted_on=body.hosted_on if body.hosted_on != device_id else None,
            pinned_fingerprint=body.trust_fingerprint or (old.pinned_fingerprint if old else None),
            pending_fingerprint=None
            if body.trust_fingerprint
            else (old.pending_fingerprint if old else None),
        )
        saved = store.put_device(rec, body.config, cls.manifest.config, set(body.clear_secrets))
        if old and (old.site_id, old.name, old.role) != (saved.site_id, saved.name, saved.role):
            # what the snapshot carries changed (#368): views follow at once, the read follows
            store.restamp_snapshot(saved)
            runner.trigger()
        return saved

    def test_json(snap: Snapshot, presented: str | None) -> dict[str, Any]:
        dev = snap.device
        return {
            "status": snap.status.value,
            "errors": [e.model_dump() for e in snap.errors],
            "pending_fingerprint": presented if snap.status is DeviceStatus.UNTRUSTED else None,
            "counts": {
                k: len(getattr(snap, k))
                for k in ("ports", "segments", "subnets", "wlans", "clients")
            },
            "device": {
                "vendor": dev.vendor,
                "model": dev.model,
                "firmware": dev.firmware.current if dev.firmware else None,
            },
        }

    @api.post("/devices/test", response_model=None)
    async def test_form(body: DeviceTestBody) -> dict[str, Any] | JSONResponse:
        """Read a device with the form's settings before saving; nothing is stored.

        With `device_id`, empty secret settings use that device's stored values and its
        trusted certificate. `trust_fingerprint` trusts a certificate for this test only.
        """
        cls = services.adapters.get(body.adapter)
        if cls is None:
            return error(422, "invalid", f"adapter {body.adapter!r} is not installed")
        if body.role not in cls.manifest.roles:
            roles = ", ".join(sorted(r.value for r in cls.manifest.roles))
            return error(422, "invalid", f"{cls.manifest.name} devices can be: {roles}")
        old = store.device(body.device_id) if body.device_id else None
        if body.device_id and old is None:
            return error(404, "not_found", "No such device.")
        try:
            cfg = store.form_config(
                old.id if old else None,
                body.config,
                cls.manifest.config,
                set(body.clear_secrets),
            )
        except SecretError as exc:  # pragma: no cover - a damaged vault
            return error(422, "invalid", str(exc))
        rec = DeviceRecord(
            id=old.id if old else slug(body.name, [d.id for d in store.devices()]),
            site_id=body.site_id,
            name=body.name,
            role=body.role,
            adapter=body.adapter,
            pinned_fingerprint=body.trust_fingerprint or (old.pinned_fingerprint if old else None),
        )
        snap, presented = await runner.read_device(rec, cfg)
        return test_json(snap, presented)

    @api.post("/devices", status_code=201, response_model=None)
    def add_device(body: DeviceBody) -> dict[str, Any] | JSONResponse:
        """Add a device; secrets in `config` are stored encrypted."""
        device_id = slug(body.name, [d.id for d in store.devices()])
        saved = save_device(device_id, body)
        return saved if isinstance(saved, JSONResponse) else device_json(saved)

    @api.get("/devices/{device_id}", response_model=None)
    def get_device(device_id: str) -> dict[str, Any] | JSONResponse:
        """One device."""
        rec = store.device(device_id)
        return error(404, "not_found", "No such device.") if rec is None else device_json(rec)

    @api.put("/devices/{device_id}", response_model=None)
    def update_device(device_id: str, body: DeviceBody) -> dict[str, Any] | JSONResponse:
        """Change a device; secret settings left empty keep their value."""
        if store.device(device_id) is None:
            return error(404, "not_found", "No such device.")
        saved = save_device(device_id, body)
        return saved if isinstance(saved, JSONResponse) else device_json(saved)

    @api.delete("/devices/{device_id}", status_code=204)
    def delete_device(device_id: str) -> None:
        """Remove a device and its last snapshot."""
        store.delete_device(device_id)

    @api.post("/devices/{device_id}/test", response_model=None)
    async def test_device(device_id: str) -> dict[str, Any] | JSONResponse:
        """Read the device now and report status, errors and what was found."""
        rec = store.device(device_id)
        if rec is None:
            return error(404, "not_found", "No such device.")
        try:
            snap = await runner.observe_device(rec)
        except SecretError as exc:  # pragma: no cover - observe_device reports it
            return error(422, "invalid", str(exc))
        after = store.device(device_id)
        return test_json(snap, after.pending_fingerprint if after else None)

    @api.post("/devices/{device_id}/trust")
    def trust(device_id: str, body: TrustBody) -> dict[str, bool]:
        """Trust the certificate the device presented (pending fingerprint)."""
        store.trust_fingerprint(device_id, body.fingerprint)
        runner.trigger()
        return {"trusted": True}

    @api.get("/devices/{device_id}/port-tree")
    def port_tree(device_id: str) -> list[dict[str, Any]]:
        """The internal structure of a device's ports (#252): CPU port with its switch ports,
        bridges with their members, VLAN interfaces, radios with Wi-Fi interfaces and SSIDs.
        Empty for a device that is not known or not read yet."""
        return [n.model_dump(mode="json") for n in runner.network().port_tree(device_id)]

    @api.get("/devices/{device_id}/port-counters")
    def port_counters(device_id: str) -> dict[str, dict[str, Any]]:
        """What the counters of a device's ports did between the last two reads (#158): the
        error and drop deltas and the seconds between the reads, per port id. Never the
        lifetime totals; a port without two reads is missing, one whose counters were reset
        has ``reset`` set."""
        out: dict[str, dict[str, Any]] = {}
        for pid, record in runner.history().counters.items():
            if pid.startswith(f"{device_id}/port/") and record.delta is not None:
                out[pid] = {
                    "seconds": record.delta.seconds,
                    "reset": record.delta.reset,
                    "errors": record.delta.errors,
                    "drops": record.delta.drops,
                }
        return out

    @api.get("/devices/{device_id}/port-series")
    def port_series(device_id: str) -> dict[str, list[dict[str, Any]]]:
        """The hourly traffic of a device's ports for the retention period (#471), oldest
        first: the hour, the seconds the reads cover and the average bit rates received and
        sent. Ports without recorded traffic are missing."""
        out: dict[str, list[dict[str, Any]]] = {}
        for pid, buckets in runner.history().series.items():
            if pid.startswith(f"{device_id}/port/"):
                out[pid] = [
                    {
                        "at": b.at.isoformat(),
                        "seconds": b.seconds,
                        "rx_bps": round(b.rx_bps),
                        "tx_bps": round(b.tx_bps),
                    }
                    for b in buckets
                ]
        return out

    # network, findings, links -----------------------------------------------------------

    @api.get("/network")
    def network() -> dict[str, Any]:
        """The merged network model without passphrase data; derived uplink and service values."""
        return public_network(runner.network(), runner.history())

    @api.get("/fdb", response_model=None)
    def fdb(
        device: str | None = None, mac: str | None = None
    ) -> list[dict[str, Any]] | JSONResponse:
        """MAC address table entries (#160): of one device (``?device=``, also the switches a
        controller manages), of one MAC address (``?mac=``), or all. Each with ``client``,
        the merged client of that address (``client/<mac>``) if there is one."""
        net = runner.network()
        wanted = None
        if mac is not None:
            try:
                wanted = normalise_mac(mac)
            except ValueError:
                return error(422, "invalid", "not a MAC address")
        clients = {c.mac for c in net.clients}
        out = []
        for e in net.fdb:
            if (device is not None and e.device_id != device) or (
                wanted is not None and e.mac != wanted
            ):
                continue
            raw = e.model_dump(mode="json")
            raw["client"] = f"client/{e.mac}" if e.mac in clients else None
            out.append(raw)
        return out

    @api.get("/wifi-scan")
    def wifi_scan(device: str | None = None) -> list[dict[str, Any]]:
        """Access points the radios heard (#169): of one device (``?device=``, also the
        access points a controller manages), or all. Each with ``own``: the BSSID is one of
        our WLANs, and ``own_ssid``: a foreign BSSID with one of our SSIDs. Other people's
        networks: shown on the device page only, never exported."""
        net = runner.network()
        return [
            r
            for r in scan_rows(net)
            if device is None or r["device_id"] == device or r["device_id"].startswith(f"{device}/")
        ]

    @api.get("/wifi-map")
    def wifi_map_data() -> dict[str, Any]:
        """The Wi-Fi map (#366): our radios, the neighbouring access points they hear as
        anonymous numbered nodes (band, channel, signal; never an SSID or a BSSID) and the
        signal between them in dBm. Positions are not part of it: the browser infers them."""
        return wifi_map(runner.network())

    @api.get("/findings")
    def findings(resolved: bool = False) -> list[dict[str, Any]]:
        """Current findings; `?resolved=true` includes resolved ones."""
        return [r.model_dump(mode="json") for r in store.findings(include_resolved=resolved)]

    @api.get("/history")
    def history() -> dict[str, Any]:
        """Observation history: first/last seen and changes of devices, clients and ports."""
        return runner.history().model_dump(mode="json", exclude={"series"})

    @api.post("/observe", status_code=202)
    def observe() -> dict[str, bool]:
        """Read all devices now."""
        runner.trigger()
        return {"started": True}

    @api.get("/topology")
    def topology() -> dict[str, Any]:
        """Devices, ports, links with the VLANs at each end, and clients per port."""
        from signalbox.topology import view

        return view(runner.network(), runner.config.rules)

    @api.get("/links")
    def links() -> list[Link]:
        """Manually entered links (cables)."""
        return store.links()

    @api.post("/links", status_code=201)
    def add_link(body: LinkBody) -> Link:
        """Add a link between two ports."""
        link = Link(
            id=slug(f"{body.a}-{body.b}", [x.id for x in store.links()]),
            a=body.a,
            b=body.b,
            kind=body.kind,
            origin=LinkOrigin.MANUAL,
        )
        store.put_link(link)
        return link

    @api.delete("/links/{link_id}", status_code=204)
    def delete_link(link_id: str) -> None:
        """Delete a link."""
        store.delete_link(link_id)

    app.include_router(api)
    app.include_router(desired_router(services))
    app.include_router(rules_router(services))
    app.include_router(notifications_router(notifier))
    app.include_router(annotations_router(services))
    app.include_router(changes_router(services, Deployer(runner)))
    app.include_router(discovery_router(discovery))
    app.include_router(traces_router(services, tracer))
    app.include_router(probes_router(services, prober))
    from signalbox.web.setup_api import router as setup_router  # it imports the form models

    app.include_router(setup_router(services, device_json))
    from signalbox.web.fix_api import router as fix_router

    app.include_router(fix_router(services, test_json))
    if STATIC.is_dir():
        app.mount("/", StaticFiles(directory=STATIC, html=True), name="static")
    return app
