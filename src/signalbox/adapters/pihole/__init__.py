"""Pi-hole v6 and v5: DNS service, upstream servers, DHCP server and clients, read only (#304,
#314, #385).

Pi-hole v5 (legacy ``/admin/api.php``, API token) is the second reader further down; the first
request decides: ``POST /api/auth`` answers 404 on v5 and ``/admin/api.php?versions`` then
names it. Talks to the v6 REST API (``/api/...``). Signalbox logs in with ``POST /api/auth`` and
an app password, which gives a session id; every request carries it in the ``sid`` header; the
session is ended with ``DELETE /api/auth`` when the observation is over (:meth:`close`). The
session id lives in memory for that one observation only: it is never stored, logged or put
into an error. Pi-hole v5 takes the API token in the query string (``auth=``); it is removed
from every error. Endpoints and shapes: ``docs/adapters/pihole.md`` (public API documentation;
not yet confirmed on a real device, #21).
"""

from __future__ import annotations

import contextlib
import logging
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
    UntrustedCertificate,
    dnsmap,
    unexpected_answer,
)
from signalbox.adapters.https import DeviceHttp, NotFound, device_url
from signalbox.adapters.pihole import discovery as _discovery
from signalbox.discovery import Candidate, HostProbe
from signalbox.model import (
    DNS_PORT,
    Blocklist,
    Client,
    DeviceRole,
    Firmware,
    HostRecord,
    IPAddress,
    Reservation,
    object_id,
)

AUTH = "/api/auth"
VERSION = "/api/info/version"
log = logging.getLogger(__name__)

CONFIG = "/api/config"
LISTS = "/api/lists"
LEASES = "/api/dhcp/leases"
DEVICES = "/api/network/devices"
#: Pi-hole v5's legacy API (web interface ``api.php``, ``api_FTL.php``) and its database API.
V5_API = "/admin/api.php"
V5_DB = "/admin/api_db.php"
#: forward destinations of v5 that are no upstream servers
V5_NOT_UPSTREAM = frozenset({"blocklist", "cache", "other"})
#: DNSSEC states FTL v5 shows in a query's row when it validates (#182).
V5_DNSSEC_STATES = frozenset({"SECURE", "INSECURE", "BOGUS", "ABANDONED", "UNKNOWN"})
V5_TOKEN_HELP = "Settings > API > Show API token"

SETUP_URL = "https://github.com/PhilippMundhenk/signalbox/blob/main/docs/adapters/pihole.md#setup"
STEPS = (
    "Pi-hole v6 (REST API) or Pi-hole v5 (legacy API): Signalbox detects which one runs.",
    "In the Pi-hole web interface: Settings > Web interface / API > Configure app password > "
    "Enable app password. Copy the password it shows once (a Pi-hole login has no read-only "
    "role; Signalbox only reads, and you can disable the app password again at any time).",
    "Pi-hole v5: in the web interface Settings > API > Show API token; copy the token (a long "
    "hexadecimal string, not the password). Signalbox sends it in the address of each request, "
    "so use https.",
    "Below: the address of the web interface (https on port 443 by default) and the app "
    "password (v6) or the API token (v5). Then Test connection and trust the certificate.",
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
    password: SecretStr | None = Field(
        None, description="App password of Pi-hole v6 (Settings > Web interface / API)"
    )
    api_token: SecretStr | None = Field(
        None,
        description="API token of Pi-hole v5 (Settings > API > Show API token), used instead of "
        "the app password. Sent in the query string of each request: use https",
    )
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
            raise ValueError(
                "plain http:// needs allow_insecure_http (the password or API token is sent clear)"
            )
        return self

    @model_validator(mode="after")
    def _a_credential(self) -> PiholeConfig:
        if self.password is None and self.api_token is None:
            raise ValueError("enter the app password (Pi-hole v6) or the API token (Pi-hole v5)")
        return self


def _obj(value: Any, where: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise unexpected_answer(where, "not an object")
    return value


def _sub(value: dict[str, Any], key: str) -> dict[str, Any]:
    inner = value.get(key)
    return inner if isinstance(inner, dict) else {}


def _v6_settings(dns: dict[str, Any]) -> dict[str, Any]:
    """Cache size (``dns.cache.size``, entries) and the local domain (``dns.domain``: a name or
    ``{"name": ..., "local": ...}``) of the v6 configuration."""
    out: dict[str, Any] = {}
    size = _sub(dns, "cache").get("size")
    if isinstance(size, int) and not isinstance(size, bool) and size >= 0:
        out["cache_size"] = size
    domain = dns.get("domain")
    name = domain.get("name") if isinstance(domain, dict) else domain
    if isinstance(name, str) and name.strip():
        out["local_domain"] = name.strip().strip(".").lower()
    return out


def _epoch(value: Any) -> float:
    return float(value) if isinstance(value, int | float) and not isinstance(value, bool) else 0.0


class PiholeAdapter(Adapter):
    manifest = Manifest(
        id="pihole",
        name="Pi-hole",
        version="0.1.0",
        api_version="1.4",
        vendor="Pi-hole",
        roles=frozenset({DeviceRole.OTHER}),
        capabilities=frozenset({Capability.DNS, Capability.DHCP, Capability.CLIENTS}),
        config=PiholeConfig,
        description="Reads a Pi-hole DNS filter, v6 through its REST API and v5 through its "
        "legacy API with the API token: DNS service, upstream servers, DHCP server and leases "
        "(v6 only) and network clients. Read only.",
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
        #: the box answered as Pi-hole v5 (set by :meth:`read_system`) and what ?versions said
        self._v5 = False
        self._versions: dict[str, Any] = {}

    # --- session ------------------------------------------------------------------------------

    async def _login(self, password: SecretStr) -> None:
        """Log in to v6. A 404 means no v6 REST API: :meth:`_not_v6` decides about v5."""
        try:
            response = await self.http.request(
                "POST",
                AUTH,
                json={"password": password.get_secret_value()},
                accept=(401, 429),
            )
        except NotFound as exc:
            await self._not_v6(exc)
            return
        if response.status_code == 401:
            raise AuthFailed(
                f"{AUTH}: Pi-hole refused the password (HTTP 401)",
                fix="Create an app password (Settings > Web interface / API > Configure app "
                "password) and enter it in the settings; the normal login password does not "
                "work when two-factor authentication is on.",
                message_id="pihole.password401",
                fix_id="pihole.password401.fix",
                params={"path": AUTH},
            )
        if response.status_code == 429:
            raise AdapterError(
                f"{AUTH}: Pi-hole refuses new logins for now (HTTP 429)",
                fix="Pi-hole limits failed logins and the number of API sessions "
                "(webserver.api.max_sessions); wait a few minutes. Signalbox ends its session "
                "after every read.",
                message_id="pihole.rateLimited",
                fix_id="pihole.rateLimited.fix",
                params={"path": AUTH},
            )
        try:
            session = _sub(_obj(response.json(), AUTH), "session")
        except ValueError as exc:
            await self._not_v6(exc)
            return
        if not session.get("valid"):
            message = dnsmap.text(session.get("message")) or "login refused"
            raise AuthFailed(
                f"{AUTH}: {message}",
                message_id="pihole.loginRefusedWith",
                params={"endpoint": AUTH, "detail": message},
                fix="Use an app password (Settings > Web interface / API > Configure app "
                "password); a password with two-factor authentication cannot be used.",
                fix_id="pihole.loginRefused.fix",
            )
        sid = session.get("sid")
        self._sid = sid if isinstance(sid, str) and sid else None

    async def _not_v6(self, cause: Exception | None) -> None:
        """No v6 login endpoint: Pi-hole v5 (``?versions`` answers, and the API token is
        needed), or not a Pi-hole at all. Returns only for v5 with a token."""
        try:
            data = await self._v5_get(V5_API, {"versions": ""})
        except (Unreachable, UntrustedCertificate):
            raise
        except AdapterError:
            data = None
        if isinstance(data, dict) and ("core_current" in data or "FTL_current" in data):
            if self.config.api_token is None:
                raise AdapterError(
                    "this is Pi-hole v5: Signalbox needs its API token",
                    fix=f"Enter the API token: in the Pi-hole web interface {V5_TOKEN_HELP} (a "
                    "long hexadecimal string, not the password). Or update Pi-hole to v6 "
                    "(pihole -up) and use an app password.",
                    message_id="pihole.v5Token",
                    fix_id="pihole.v5Token.fix",
                ) from cause
            self._v5 = True
            self._versions = data
            return
        raise AdapterError(
            f"{AUTH}: not found; this does not look like Pi-hole v6 or v5",
            fix="Check that the address is the Pi-hole web interface. Pi-hole v6 needs the app "
            f"password, Pi-hole v5 the API token ({V5_TOKEN_HELP}).",
            message_id="pihole.notPihole",
            fix_id="pihole.notPihole.fix",
            params={"path": AUTH},
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
        self._v5, self._versions = False, {}
        if self.config.password is None:
            await self._not_v6(None)
        else:
            await self._login(self.config.password)
        if self._v5:
            return self._system_v5()
        data = _sub(_obj(await self._get(VERSION), VERSION), "version")
        ftl = _sub(_sub(data, "ftl"), "local")
        core = _sub(_sub(data, "core"), "local")
        current = dnsmap.text(ftl.get("version")) or dnsmap.text(core.get("version"))
        if not current:
            raise unexpected_answer(VERSION, "no version")
        if current.lstrip("v").startswith(("3", "4", "5")):
            raise AdapterError(
                f"Pi-hole {current} is not supported: Signalbox needs v6",
                fix=UPDATE_FIX,
                message_id="pihole.unsupported",
                fix_id="pihole.update.fix",
                params={"version": current},
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

    def _system_v5(self) -> SystemInfo:
        data = self._versions
        current = dnsmap.text(data.get("core_current"))
        if not current or current.upper() == "N/A":
            raise unexpected_answer(V5_API, "no version")
        latest = dnsmap.text(data.get("core_latest"))
        extra: dict[str, Any] = {"api": "v5"}
        for key, name in (("web_current", "web_version"), ("FTL_current", "ftl_version")):
            if value := dnsmap.text(data.get(key)):
                extra[name] = value.lstrip("v")
        newer = data.get("core_update") is True and latest and latest.upper() != "N/A"
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

    # --- Pi-hole v5 ---------------------------------------------------------------------------

    def _scrub(self, text: str) -> str:
        token = self.config.api_token
        return text.replace(token.get_secret_value(), "***") if token else text

    async def _v5_get(self, path: str, params: dict[str, str], *, token: bool = False) -> Any:
        """``GET <path>?<params>[&auth=<token>]``. The token travels in the query (that is how v5
        takes it); the path in errors never has the query, and a token that still shows up in
        an error is removed."""
        query = dict(params)
        secret = self.config.api_token
        if token and secret is not None:
            query["auth"] = secret.get_secret_value()
        try:
            return await self.http.request_json("GET", path, params=query)
        except AdapterError as exc:
            if secret is not None and secret.get_secret_value() in (
                str(exc) + "".join(str(v) for v in exc.params.values())
            ):
                raise exc.redacted(self._scrub) from None
            raise

    def _v5_refused(self, path: str) -> AuthFailed:
        return AuthFailed(
            f"{path}: Pi-hole v5 did not accept the API token",
            fix=f"Copy the token again ({V5_TOKEN_HELP}) without spaces; it changes when the "
            "web interface password is changed.",
            message_id="pihole.v5TokenRefused",
            fix_id="pihole.v5TokenRefused.fix",
            params={"path": path},
        )

    async def _dns_v5(self) -> Observation:
        data = await self._v5_get(V5_API, {"getForwardDestinations": ""}, token=True)
        # a wrong token is answered with an empty list instead of an error (guess, #21)
        dest = _sub(data, "forward_destinations") if isinstance(data, dict) else {}
        if not dest:
            raise self._v5_refused(V5_API)
        names = [
            ip
            for key in dest
            if (parts := str(key).rsplit("|", 1))[0] not in V5_NOT_UPSTREAM
            and (ip := parts[-1].strip())
        ]
        upstreams = dnsmap.parse_upstreams(names)
        extra: dict[str, Any] = {"api": "v5"}
        try:
            status = await self._v5_get(V5_API, {"status": ""})
            extra["filtering_enabled"] = (
                isinstance(status, dict) and status.get("status") == "enabled"
            )
        except (Unreachable, AuthFailed):
            raise
        except AdapterError:
            pass  # the blocking state is a detail
        service = dnsmap.dns_service(
            self.context.device_id,
            "pihole",
            upstreams=upstreams,
            port=DNS_PORT,
            host_records=[],
            extra=extra,
            dnssec=await self._dnssec_v5(),
        )
        return Observation(dns_services=[service])

    async def _dnssec_v5(self) -> bool | None:
        """Whether Pi-hole v5 validates DNSSEC. v5 has no API for the setting: the recent
        queries say it (a ``dnssec`` status such as SECURE or INSECURE appears only when
        validation is on, ``N/A`` or nothing when it is off). *Guess* for the field's place and
        spelling (#21); too few queries or an unexpected answer: None."""
        try:
            data = await self._v5_get(V5_API, {"getAllQueries": "100"}, token=True)
        except (Unreachable, AuthFailed):
            raise
        except AdapterError:
            return None
        rows = data.get("data") if isinstance(data, dict) else None
        if not isinstance(rows, list):
            return None
        cells = {str(c).upper() for r in rows if isinstance(r, list) for c in r}
        if cells & V5_DNSSEC_STATES:
            return True
        return False if len(rows) >= 20 else None

    def _dhcp_v5(self) -> Observation:
        return Observation(
            incomplete=[
                Gap(
                    message="Pi-hole v5 has no API for DHCP settings: the DHCP server was not read",
                    fix="Upgrade to Pi-hole v6 (pihole -up) to let Signalbox read the DHCP "
                    "server, its leases and reservations.",
                    message_id="pihole.v5NoDhcp",
                    fix_id="pihole.v5NoDhcp.fix",
                    optional=True,
                )
            ]
        )

    async def _clients_v5(self) -> Observation:
        """``api_db.php?network``: one row per MAC (``hwaddr``) with ``ip`` and ``name`` lists.
        ``topClients`` is not used: it has names and addresses but no MAC, and the model keys a
        client by MAC."""
        try:
            data = await self._v5_get(V5_DB, {"network": ""}, token=True)
            rows = data.get("network") if isinstance(data, dict) else None
            if not isinstance(rows, list):
                raise self._v5_refused(V5_DB)
        except Unreachable:
            raise
        except AdapterError as exc:
            return Observation(
                incomplete=[
                    Gap(
                        message=f"the network table was not read: {exc}",
                        fix="Check the API token, and that Pi-hole's query database is on "
                        "(DBFILE in pihole-FTL.conf); without MAC addresses Signalbox lists no "
                        "clients.",
                        message_id="pihole.v5ClientsNotRead",
                        fix_id="pihole.v5ClientsNotRead.fix",
                        params={"cause": str(exc)},
                    )
                ]
            )
        dev = self.context.device_id
        out: dict[str, Client] = {}
        for row in rows:
            m = dnsmap.mac(row.get("hwaddr")) if isinstance(row, dict) else None
            if m is None:
                continue
            ips, names = row.get("ip"), row.get("name")
            ips = ips if isinstance(ips, list) else [ips]
            names = names if isinstance(names, list) else [names]
            out[m] = Client(
                id=object_id(dev, "client", m),
                mac=m,
                addresses=list(dict.fromkeys(a for i in ips if (a := dnsmap.address(i)))),
                hostname=next((n for x in names if (n := dnsmap.text(x))), None),
                last_seen=dnsmap.epoch(row.get("lastQuery")),
            )
        return Observation(clients=[out[m] for m in sorted(out)])

    async def _config(self) -> dict[str, Any]:
        return _sub(_obj(await self._get(CONFIG), CONFIG), "config")

    # --- DNS ----------------------------------------------------------------------------------

    async def read_dns(self) -> Observation:
        if self._v5:
            return await self._dns_v5()
        cfg = await self._config()
        dns = _sub(cfg, "dns")
        upstream = dns.get("upstreams")
        if not isinstance(upstream, list):
            raise unexpected_answer(CONFIG, "no dns.upstreams")
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
            upstreams.merge(dnsmap.parse_upstreams([f"[/{domain}/]{s}" for s in servers]))
        records: list[HostRecord] = []
        for line in dns.get("hosts") or []:
            fields = str(line).split("#", 1)[0].split()
            a = dnsmap.address(fields[0]) if fields else None
            if a is not None:
                records += [HostRecord(name=name, address=a) for name in fields[1:]]
        blocklists: list[Blocklist] = []
        try:
            # v6: {"lists": [{"address", "type": "block"|"allow", "enabled", "number"}]}
            for row in _obj(await self._get(LISTS), LISTS).get("lists") or []:
                if isinstance(row, dict) and row.get("type", "block") == "block":
                    number = row.get("number")
                    blocklists.append(
                        Blocklist(
                            name=dnsmap.list_host(row.get("address")),
                            entries=number if isinstance(number, int) else None,
                            enabled=bool(row.get("enabled", True)),
                            updated=dnsmap.epoch(row.get("date_updated")),
                        )
                    )
        except (Unreachable, AuthFailed):
            raise
        except AdapterError as exc:
            log.debug("%s: no block lists: %s", self.context.device_id, exc)  # optional extra
        dnssec = dns.get("dnssec")
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
            dnssec=dnssec if isinstance(dnssec, bool) else None,
            blocklists=blocklists,
            settings=_v6_settings(dns),
        )
        return Observation(dns_services=[service])

    # --- DHCP ---------------------------------------------------------------------------------

    async def read_dhcp(self) -> Observation:
        if self._v5:
            return self._dhcp_v5()
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
                    message_id="pihole.leasesNotRead",
                    fix_id="pihole.leasesNotRead.fix",
                    params={"cause": str(exc)},
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
            dns_servers=await self._dhcp_dns_servers(),
            extra=extra,
        )
        return Observation(dhcp_servers=[server], segments=[segment], incomplete=gaps)

    async def _dhcp_dns_servers(self) -> list[IPAddress]:
        """What Pi-hole's DHCP hands out as DNS server: itself, unless ``misc.dnsmasq_lines``
        has a ``dhcp-option=6,...`` line (guess: no field of its own in ``config.dhcp``, #21).
        Itself is the address Signalbox reaches it at; a host name does not tell it."""
        own = [a] if (a := dnsmap.address(self.http.host)) is not None else []
        lines = _sub(_sub(_obj(await self._get(CONFIG), CONFIG), "config"), "misc").get(
            "dnsmasq_lines"
        )
        told = dnsmap.dhcp_option_dns(lines if isinstance(lines, list) else [], own)
        return own if told is None else told

    # --- clients ------------------------------------------------------------------------------

    async def read_clients(self) -> Observation:
        """The network table (``/api/network/devices``): one row per MAC address with the
        addresses and names Pi-hole saw it use. A row without a real MAC (Pi-hole names a
        device it only knows by address ``ip-192.0.2.5``) is not listed: the model keys a
        client by MAC."""
        if self._v5:
            return await self._clients_v5()
        rows = _obj(await self._get(DEVICES), DEVICES).get("devices")
        dev = self.context.device_id
        out: dict[str, Client] = {}
        for row in rows if isinstance(rows, list) else []:
            m = dnsmap.mac(row.get("hwaddr")) if isinstance(row, dict) else None
            if m is None:
                continue
            ips = [i for i in row.get("ips") or [] if isinstance(i, dict)]
            ips.sort(key=lambda i: -_epoch(i.get("lastSeen")))
            addresses = list(
                dict.fromkeys(a for i in ips if (a := dnsmap.address(i.get("ip"))) is not None)
            )
            name = next((n for i in ips if (n := dnsmap.text(i.get("name")))), None)
            seen = [dnsmap.epoch(i.get("lastSeen")) for i in ips]
            seen.append(dnsmap.epoch(row.get("lastQuery")))
            out[m] = Client(
                id=object_id(dev, "client", m),
                mac=m,
                addresses=addresses,
                hostname=name,
                last_seen=max((t for t in seen if t is not None), default=None),
            )
        return Observation(clients=[out[m] for m in sorted(out)])

    @classmethod
    async def discover(cls, probe: HostProbe) -> Candidate | None:
        """``GET /api/info/login`` (or the ``/admin/`` page) without credentials."""
        return await _discovery.discover(probe)
