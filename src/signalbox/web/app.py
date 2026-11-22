"""The HTTP API and the static web interface."""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from fastapi import APIRouter, FastAPI, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, SecretStr

from signalbox import __version__
from signalbox.adapters import Adapter
from signalbox.model import DeviceRole, Link, LinkKind, LinkOrigin, Network, Site
from signalbox.mqtt import MqttBridge
from signalbox.rules import READ_ERRORS
from signalbox.secrets import SecretError
from signalbox.service import Services
from signalbox.store import DeviceRecord, StoreError, slug
from signalbox.web.auth import COOKIE, Auth, Locked
from signalbox.web.desired_api import router as desired_router

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
    config: dict[str, Any] = Field(default_factory=dict)


class TrustBody(BaseModel):
    fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")


class LinkBody(BaseModel):
    a: str = Field(min_length=1, max_length=300)
    b: str = Field(min_length=1, max_length=300)
    kind: LinkKind = LinkKind.CABLE


def public_network(net: Network) -> dict[str, Any]:
    """The network as JSON for the UI: passphrase fingerprints never leave the server."""
    data = net.model_dump(mode="json")
    for wlan in data["wlans"]:
        wlan.pop("passphrase_fingerprint", None)
    return data


def adapter_info(cls: type[Adapter]) -> dict[str, Any]:
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

    bridge = MqttBridge(config.mqtt, config.server.base_url)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        bridge.start()
        if bridge.enabled:
            runner.listeners.append(bridge.publish)
        task = asyncio.create_task(runner.run_forever()) if run_background else None
        try:
            yield
        finally:
            runner.stop()
            await asyncio.to_thread(bridge.stop)
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
        return [adapter_info(services.adapters[k]) for k in sorted(services.adapters)]

    @api.get("/rules")
    def rules() -> list[dict[str, Any]]:
        """All rules with explanation, severity and whether they are enabled."""
        out = []
        for r in [READ_ERRORS, *services.rules]:
            s = config.rules.get(r.id)
            out.append(
                {
                    "id": r.id,
                    "title": r.title,
                    "explanation": r.explanation,
                    "severity": (s.severity if s and s.severity else r.severity).value,
                    "enabled": s.enabled if s else True,
                }
            )
        return out

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

    def device_json(rec: DeviceRecord) -> dict[str, Any]:
        net_status = runner_status().get(rec.id)
        return {**rec.model_dump(mode="json"), "status": net_status}

    def runner_status() -> dict[str, str]:
        return {s.device.id: s.status.value for s in store.snapshots()}

    @api.get("/devices")
    def devices() -> list[dict[str, Any]]:
        """List devices with their last status."""
        return [device_json(d) for d in store.devices()]

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
            pinned_fingerprint=old.pinned_fingerprint if old else None,
            pending_fingerprint=old.pending_fingerprint if old else None,
        )
        return store.put_device(rec, body.config, cls.manifest.config)

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
        return {
            "status": snap.status.value,
            "errors": [e.model_dump() for e in snap.errors],
            "pending_fingerprint": after.pending_fingerprint if after else None,
            "counts": {
                k: len(getattr(snap, k))
                for k in ("ports", "segments", "subnets", "wlans", "clients")
            },
        }

    @api.post("/devices/{device_id}/trust")
    def trust(device_id: str, body: TrustBody) -> dict[str, bool]:
        """Trust the certificate the device presented (pending fingerprint)."""
        store.trust_fingerprint(device_id, body.fingerprint)
        runner.trigger()
        return {"trusted": True}

    # network, findings, links -----------------------------------------------------------

    @api.get("/network")
    def network() -> dict[str, Any]:
        """The merged network model (passphrase fingerprints removed)."""
        return public_network(runner.network())

    @api.get("/findings")
    def findings(resolved: bool = False) -> list[dict[str, Any]]:
        """Current findings; `?resolved=true` includes resolved ones."""
        return [r.model_dump(mode="json") for r in store.findings(include_resolved=resolved)]

    @api.post("/observe", status_code=202)
    def observe() -> dict[str, bool]:
        """Read all devices now."""
        runner.trigger()
        return {"started": True}

    @api.get("/topology")
    def topology() -> dict[str, Any]:
        """Devices, ports, links with the VLANs at each end, and clients per port."""
        from signalbox.topology import view

        return view(runner.network())

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
    if STATIC.is_dir():
        app.mount("/", StaticFiles(directory=STATIC, html=True), name="static")
    return app
