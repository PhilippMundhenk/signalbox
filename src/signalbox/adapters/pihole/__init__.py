"""Pi-hole v6: DNS service, upstream servers and DHCP server, read only (#304).

Talks to the v6 REST API (``/api/...``). Signalbox logs in with ``POST /api/auth`` and an app
password, which gives a session id; every request carries it in the ``sid`` header; the
session is ended with ``DELETE /api/auth`` when the observation is over (:meth:`close`). The
session id lives in memory for that one observation only: it is never stored, logged or put
into an error. Pi-hole v5 has no such API: it is reported as an :class:`AdapterError` with a
fix. Endpoints and shapes: ``docs/adapters/pihole.md`` (public API documentation; not yet
confirmed on a real device, #21).
"""

from __future__ import annotations

import contextlib
from typing import Any

from pydantic import Field, SecretStr, field_validator, model_validator

from signalbox.adapters import (
    Adapter,
    AdapterConfig,
    AdapterContext,
    AdapterError,
    AuthFailed,
    Capability,
    Gap,
    Manifest,
    Observation,
    SystemInfo,
    Unreachable,
    dnsmap,
)
from signalbox.adapters.https import DeviceHttp, NotFound, device_url
from signalbox.model import (
    DNS_PORT,
    DeviceRole,
    Firmware,
    HostRecord,
    Reservation,
)

AUTH = "/api/auth"
VERSION = "/api/info/version"
CONFIG = "/api/config"
LEASES = "/api/dhcp/leases"
#: Pi-hole v5's API; only probed to say clearly that v5 is not supported.
V5_API = "/admin/api.php"

SETUP_URL = "https://github.com/PhilippMundhenk/signalbox/blob/main/docs/adapters/pihole.md#setup"
STEPS = (
    "Needs Pi-hole v6 (Pi-hole v5 has no REST API: update with pihole -up).",
    "In the Pi-hole web interface: Settings > Web interface / API > Configure app password > "
    "Enable app password. Copy the password it shows once (a Pi-hole login has no read-only "
    "role; Signalbox only reads, and you can disable the app password again at any time).",
    "Below: the address of the web interface (https on port 443 by default) and that app "
    "password. Then Test connection and trust the certificate.",
)

UPDATE_FIX = (
    "Update Pi-hole to v6 (pihole -up on the Pi-hole, or pull the v6 container image), then "
    "enter the address again. Pi-hole v5 is not supported."
)


class PiholeConfig(AdapterConfig):
    url: str = Field(
        description="Address of the web interface, for example 192.0.2.54 or "
        "https://pihole.lan (no scheme: https)",
        examples=["192.0.2.54"],
    )
    password: SecretStr = Field(description="App password (Settings > Web interface / API)")
    allow_insecure_http: bool = Field(
        json_schema_extra={"advanced": True},
        default=False,
        description="Allow plain http:// (simulators and tests only: sends the password "
        "unencrypted)",
    )

    @field_validator("url")
    @classmethod
    def _url(cls, value: str) -> str:
        return device_url(value)

    @model_validator(mode="after")
    def _http_needs_opt_in(self) -> PiholeConfig:
        if self.url.startswith("http://") and not self.allow_insecure_http:
            raise ValueError("plain http:// needs allow_insecure_http (the password is sent clear)")
        return self


def _obj(value: Any, where: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AdapterError(f"unexpected answer from {where}: not an object")
    return value


def _sub(value: dict[str, Any], key: str) -> dict[str, Any]:
    inner = value.get(key)
    return inner if isinstance(inner, dict) else {}


class PiholeAdapter(Adapter):
    manifest = Manifest(
        id="pihole",
        name="Pi-hole",
        version="0.1.0",
        api_version="1.4",
        vendor="Pi-hole",
        roles=frozenset({DeviceRole.OTHER}),
        capabilities=frozenset({Capability.DNS, Capability.DHCP}),
        config=PiholeConfig,
        description="Reads a Pi-hole v6 DNS filter through its REST API: DNS service, upstream "
        "servers, DHCP server and leases. Read only.",
        setup_url=SETUP_URL,
        setup_steps=STEPS,
    )

    def __init__(self, context: AdapterContext) -> None:
        super().__init__(context)
        cfg = context.config
        assert isinstance(cfg, PiholeConfig)
        self.config = cfg
        self.http = DeviceHttp(
            cfg.url,
            pinned_fingerprint=context.pinned_fingerprint,
            timeout=context.timeout,
            allow_insecure_http=cfg.allow_insecure_http,
        )
        self._sid: str | None = None
        self._cache: dict[str, Any] = {}

    # --- session ------------------------------------------------------------------------------

    async def _login(self) -> None:
        try:
            response = await self.http.request(
                "POST",
                AUTH,
                json={"password": self.config.password.get_secret_value()},
                accept=(401, 429),
            )
        except NotFound as exc:
            await self._not_v6(exc)
            raise  # pragma: no cover - _not_v6 always raises
        if response.status_code == 401:
            raise AuthFailed(
                f"{AUTH}: Pi-hole refused the password (HTTP 401)",
                fix="Create an app password (Settings > Web interface / API > Configure app "
                "password) and enter it in the settings; the normal login password does not "
                "work when two-factor authentication is on.",
            )
        if response.status_code == 429:
            raise AdapterError(
                f"{AUTH}: Pi-hole refuses new logins for now (HTTP 429)",
                fix="Pi-hole limits failed logins and the number of API sessions "
                "(webserver.api.max_sessions); wait a few minutes. Signalbox ends its session "
                "after every read.",
            )
        try:
            session = _sub(_obj(response.json(), AUTH), "session")
        except ValueError as exc:
            await self._not_v6(exc)
            raise  # pragma: no cover
        if not session.get("valid"):
            message = dnsmap.text(session.get("message")) or "login refused"
            raise AuthFailed(
                f"{AUTH}: {message}",
                fix="Use an app password (Settings > Web interface / API > Configure app "
                "password); a password with two-factor authentication cannot be used.",
            )
        sid = session.get("sid")
        self._sid = sid if isinstance(sid, str) and sid else None

    async def _not_v6(self, cause: Exception) -> None:
        """The login endpoint is missing: Pi-hole v5, or not a Pi-hole at all."""
        try:
            response = await self.http.request("GET", V5_API, accept=(401, 403))
            data = response.json()
        except (AdapterError, ValueError):
            data = None
        if isinstance(data, dict) and ("domains_being_blocked" in data or "status" in data):
            raise AdapterError(
                "this is Pi-hole v5: Signalbox needs the v6 REST API (/api/)",
                fix=UPDATE_FIX,
            ) from cause
        raise AdapterError(
            f"{AUTH}: not found; this does not look like Pi-hole v6",
            fix="Check that the address is the Pi-hole web interface and that it runs v6. "
            + UPDATE_FIX,
        ) from cause

    async def close(self) -> None:
        sid, self._sid = self._sid, None
        if sid:
            # a failed logout is not an error: the session expires by itself
            with contextlib.suppress(AdapterError):
                await self.http.request("DELETE", AUTH, headers={"sid": sid}, accept=(401, 404))
        await self.http.close()

    async def _get(self, path: str) -> Any:
        if path not in self._cache:
            headers = {"sid": self._sid} if self._sid else {}
            self._cache[path] = await self.http.request_json("GET", path, headers=headers)
        return self._cache[path]

    # --- system -------------------------------------------------------------------------------

    async def read_system(self) -> SystemInfo:
        await self.http.reset()
        self._cache.clear()
        self._sid = None
        await self._login()
        data = _sub(_obj(await self._get(VERSION), VERSION), "version")
        ftl = _sub(_sub(data, "ftl"), "local")
        core = _sub(_sub(data, "core"), "local")
        current = dnsmap.text(ftl.get("version")) or dnsmap.text(core.get("version"))
        if not current:
            raise AdapterError(f"unexpected answer from {VERSION}: no version")
        if current.lstrip("v").startswith(("3", "4", "5")):
            raise AdapterError(
                f"Pi-hole {current} is not supported: Signalbox needs v6", fix=UPDATE_FIX
            )
        remote = _sub(_sub(data, "ftl"), "remote")
        latest = dnsmap.text(remote.get("version"))
        newer = latest and latest != current
        extra: dict[str, Any] = {}
        if core.get("version"):
            extra["core_version"] = dnsmap.text(core.get("version"))
        return SystemInfo(
            vendor="Pi-hole",
            model="Pi-hole",
            firmware=Firmware(
                current=current.lstrip("v"), available=latest.lstrip("v") if newer else None
            ),
            management_address=self.http.host,
            transport_encrypted=self.http.secure,
            vendor_extra=extra,
        )

    async def _config(self) -> dict[str, Any]:
        return _sub(_obj(await self._get(CONFIG), CONFIG), "config")

    # --- DNS ----------------------------------------------------------------------------------

    async def read_dns(self) -> Observation:
        cfg = await self._config()
        dns = _sub(cfg, "dns")
        upstream = dns.get("upstreams")
        if not isinstance(upstream, list):
            raise AdapterError(f"unexpected answer from {CONFIG}: no dns.upstreams")
        upstreams = dnsmap.parse_upstreams([str(x) for x in upstream])
        # conditional forwarding: "true,192.0.2.0/24,192.0.2.1,lan" (on, network, server, domain)
        reverse: dict[str, list[str]] = {}
        for entry in dns.get("revServers") or []:
            parts = [p.strip() for p in str(entry).split(",")]
            if len(parts) >= 3 and parts[0].lower() == "true":
                reverse.setdefault(
                    parts[3] if len(parts) > 3 and parts[3] else parts[1], []
                ).append(parts[2])
        for domain, servers in reverse.items():
            upstreams.domains.setdefault(domain, []).extend(servers)
        records: list[HostRecord] = []
        for line in dns.get("hosts") or []:
            fields = str(line).split("#", 1)[0].split()
            a = dnsmap.address(fields[0]) if fields else None
            if a is not None:
                records += [HostRecord(name=name, address=a) for name in fields[1:]]
        port = dns.get("port")
        blocking = _sub(dns, "blocking")
        extra: dict[str, Any] = {"filtering_enabled": bool(blocking.get("active", True))}
        for key in ("listeningMode", "interface", "domain"):
            value = dns.get(key)
            if isinstance(value, str | dict) and value:
                extra[key] = value
        service = dnsmap.dns_service(
            self.context.device_id,
            "pihole",
            upstreams=upstreams,
            port=port if isinstance(port, int) and 1 <= port <= 65535 else DNS_PORT,
            host_records=records,
            extra=extra,
        )
        return Observation(dns_services=[service])

    # --- DHCP ---------------------------------------------------------------------------------

    async def read_dhcp(self) -> Observation:
        dhcp = _sub(await self._config(), "dhcp")
        if not dhcp.get("active"):
            return Observation()
        reservations: list[Reservation] = []
        for entry in dhcp.get("hosts") or []:
            # dnsmasq dhcp-host: "02:00:5e:00:53:01,192.0.2.20,name,12h" (any order)
            parts = [p.strip() for p in str(entry).split(",")]
            m = next((x for p in parts if (x := dnsmap.mac(p))), None)
            a = next((y for p in parts if (y := dnsmap.address(p))), None)
            if m is not None and a is not None:
                name = next(
                    (p for p in parts if p and dnsmap.mac(p) is None and dnsmap.address(p) is None),
                    "",
                )
                reservations.append(
                    Reservation(
                        mac=m, address=a, hostname=None if name[:1].isdigit() else name or None
                    )
                )
        gaps: list[Gap] = []
        leases = None
        try:
            rows = _obj(await self._get(LEASES), LEASES).get("leases")
            leases = []
            for row in rows if isinstance(rows, list) else []:
                if not isinstance(row, dict):
                    continue
                made = dnsmap.lease(
                    row.get("ip"),
                    row.get("hwaddr"),
                    row.get("name"),
                    dnsmap.epoch(row.get("expires")),
                    client_id=row.get("clientid"),
                )
                if made is not None:
                    reserved = any(
                        r.mac == made.mac and r.address == made.address for r in reservations
                    )
                    leases.append(made.model_copy(update={"reserved": reserved}))
        except (Unreachable, AuthFailed):
            raise
        except AdapterError as exc:
            gaps.append(
                Gap(
                    message=f"the DHCP lease table was not read: {exc}",
                    fix="Check that Pi-hole answers /api/dhcp/leases (Pi-hole v6.0 or newer).",
                )
            )
        domain = dnsmap.text(_sub(_sub(await self._config(), "dns"), "domain").get("name"))
        extra: dict[str, Any] = {}
        if dhcp.get("netmask"):
            extra["netmask"] = dnsmap.text(dhcp.get("netmask"))
        server, segment = dnsmap.dhcp_server(
            self.context.device_id,
            self.context.site_id,
            "pihole",
            start=dhcp.get("start"),
            end=dhcp.get("end"),
            router=dhcp.get("router"),
            lease_time=dnsmap.lease_seconds(dhcp.get("leaseTime")),
            reservations=reservations,
            leases=leases,
            domain=domain,
            extra=extra,
        )
        return Observation(dhcp_servers=[server], segments=[segment], incomplete=gaps)
