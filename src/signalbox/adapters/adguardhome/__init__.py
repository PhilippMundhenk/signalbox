"""AdGuard Home: DNS service, upstream servers, DHCP server and clients, read only (#304, #314).

Talks to the REST API (``/control/...``) with HTTP basic auth. Endpoints and the JSON shapes
assumed for them are listed in ``docs/adapters/adguardhome.md``; they come from the public
OpenAPI description of AdGuard Home and still need confirmation on a real device (#21).

The device is role ``other``. Its DNS service and upstreams, DHCP server (pool, leases, static
leases) and configured clients are mapped by :mod:`signalbox.adapters.dnsmap`. Nothing is
ever written: only GET requests are sent.
"""

from __future__ import annotations

from datetime import UTC, datetime
from ipaddress import ip_network
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
from signalbox.adapters.adguardhome import discovery as _discovery
from signalbox.adapters.https import DeviceHttp, NotFound, device_url
from signalbox.discovery import Candidate, HostProbe
from signalbox.model import (
    DNS_PORT,
    Client,
    DeviceRole,
    Firmware,
    HostRecord,
    IPAddress,
    LeaseState,
    Reservation,
    object_id,
)

STATUS = "/control/status"
DNS_INFO = "/control/dns_info"
DHCP_STATUS = "/control/dhcp/status"
CLIENTS = "/control/clients"
REWRITES = "/control/rewrite/list"

SETUP_URL = (
    "https://github.com/PhilippMundhenk/signalbox/blob/main/docs/adapters/adguardhome.md#setup"
)
STEPS = (
    "AdGuard Home has no read-only user. Create a user for Signalbox of its own, so you can "
    "remove it later: add an entry under users: in AdGuardHome.yaml (name and a bcrypt hash, "
    "for example from htpasswd -B -n -b signalbox <password>) and restart AdGuard Home.",
    "Below: the address of the web interface (with its port, 3000 or 80 unless you changed "
    "it), the user and the password.",
    "AdGuard Home serves plain http unless Settings > Encryption is set up. With plain http "
    "tick Allow plain http: the password then travels unencrypted, so use it only on a "
    "network you trust.",
)


class AdGuardHomeConfig(AdapterConfig):
    url: str = Field(
        description="Address of the web interface, for example 192.0.2.53:3000 or "
        "http://192.0.2.53 (no scheme: https)",
        examples=["https://192.0.2.53:3000"],
    )
    username: str = Field(description="User name of the login for Signalbox")
    password: SecretStr = Field(description="Password of that user")
    allow_insecure_http: bool = Field(
        json_schema_extra={"advanced": True},
        default=False,
        description="Allow plain http:// (AdGuard Home's default without HTTPS): the password "
        "is sent unencrypted, use it only on a network you trust",
    )

    @field_validator("url")
    @classmethod
    def _url(cls, value: str) -> str:
        return device_url(value)

    @model_validator(mode="after")
    def _http_needs_opt_in(self) -> AdGuardHomeConfig:
        if self.url.startswith("http://") and not self.allow_insecure_http:
            raise ValueError("plain http:// needs allow_insecure_http (the password is sent clear)")
        return self


def _dict(value: Any, endpoint: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AdapterError(f"unexpected answer from {endpoint}: not an object")
    return value


def _rows(value: Any) -> list[dict[str, Any]]:
    return [r for r in value if isinstance(r, dict)] if isinstance(value, list) else []


def _time(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


class AdGuardHomeAdapter(Adapter):
    manifest = Manifest(
        id="adguardhome",
        name="AdGuard Home",
        version="0.1.0",
        api_version="1.4",
        vendor="AdGuard",
        roles=frozenset({DeviceRole.OTHER}),
        capabilities=frozenset({Capability.DNS, Capability.DHCP, Capability.CLIENTS}),
        config=AdGuardHomeConfig,
        description="Reads an AdGuard Home DNS filter through its REST API: DNS service, "
        "upstream servers, DHCP server and clients. Read only.",
        setup_url=SETUP_URL,
        setup_steps=STEPS,
    )

    def __init__(self, context: AdapterContext) -> None:
        super().__init__(context)
        cfg = context.config
        assert isinstance(cfg, AdGuardHomeConfig)
        self.config = cfg
        self.http = DeviceHttp(
            cfg.url,
            pinned_fingerprint=context.pinned_fingerprint,
            timeout=context.timeout,
            auth=(cfg.username, cfg.password.get_secret_value()),
            allow_insecure_http=cfg.allow_insecure_http,
        )
        self._cache: dict[str, Any] = {}

    async def close(self) -> None:
        await self.http.close()

    async def _get(self, path: str) -> Any:
        if path not in self._cache:
            self._cache[path] = await self.http.get_json(path)
        return self._cache[path]

    async def read_system(self) -> SystemInfo:
        await self.http.reset()
        self._cache.clear()
        status = _dict(await self._get(STATUS), STATUS)
        version = dnsmap.text(status.get("version")).lstrip("v")
        if not version:
            raise AdapterError(f"unexpected answer from {STATUS}: no version")
        return SystemInfo(
            vendor="AdGuard",
            model="AdGuard Home",
            firmware=Firmware(current=version),
            management_address=self.http.host,
            transport_encrypted=self.http.secure,
            vendor_extra={"running": bool(status.get("running", True))},
        )

    # --- DNS ----------------------------------------------------------------------------------

    async def read_dns(self) -> Observation:
        dev = self.context.device_id
        status = _dict(await self._get(STATUS), STATUS)
        info = _dict(await self._get(DNS_INFO), DNS_INFO)
        gaps: list[Gap] = []
        lines = info.get("upstream_dns")
        upstreams: dnsmap.Upstreams | None = dnsmap.parse_upstreams(
            [str(x) for x in lines] if isinstance(lines, list) else []
        )
        if dnsmap.text(info.get("upstream_dns_file")):
            upstreams = None
            gaps.append(
                Gap(
                    message="the upstream servers are read from a file "
                    "(upstream_dns_file), which the API does not show",
                    fix="Enter the upstream servers in AdGuard Home (Settings > DNS settings) "
                    "instead of in a file, so Signalbox can check them for loops.",
                )
            )
        listen: list[IPAddress] = []
        for item in status.get("dns_addresses") or []:
            a = dnsmap.address(item)
            if a is not None and not (a.is_loopback or a.is_unspecified or a.is_link_local):
                listen.append(a)
        port = status.get("dns_port")
        records: list[HostRecord] = []
        try:
            for row in _rows(await self._get(REWRITES)):
                a = dnsmap.address(row.get("answer"))
                name = dnsmap.text(row.get("domain"))
                if a is not None and name and not name.startswith("*"):
                    records.append(HostRecord(name=name, address=a))
        except (Unreachable, AuthFailed):
            raise
        except AdapterError as exc:
            gaps.append(
                Gap(
                    message=f"the DNS rewrites were not read: {exc}",
                    fix="Update AdGuard Home (the API has no rewrite list in this version)."
                    if isinstance(exc, NotFound)
                    else "Check that Signalbox's user may read /control/rewrite/list; without "
                    "it the DNS checks do not know AdGuard Home's host names.",
                )
            )
        protection = status.get("protection_enabled", info.get("protection_enabled"))
        extra: dict[str, Any] = {"filtering_enabled": bool(protection)}
        if isinstance(info.get("upstream_mode"), str):
            extra["upstream_mode"] = info["upstream_mode"]
        bootstrap = [str(x) for x in info.get("bootstrap_dns") or []]
        if bootstrap:
            extra["bootstrap_dns"] = bootstrap
        service = dnsmap.dns_service(
            dev,
            "adguardhome",
            upstreams=upstreams,
            port=port if isinstance(port, int) and 1 <= port <= 65535 else DNS_PORT,
            listen=listen,
            host_records=records,
            enabled=bool(status.get("running", True)),
            extra=extra,
        )
        return Observation(dns_services=[service], incomplete=gaps)

    # --- DHCP ---------------------------------------------------------------------------------

    async def read_dhcp(self) -> Observation:
        data = _dict(await self._get(DHCP_STATUS), DHCP_STATUS)
        if not data.get("enabled"):
            return Observation()
        v4 = data.get("v4")
        v4 = v4 if isinstance(v4, dict) else {}
        reservations: list[Reservation] = []
        leases = []
        for row in _rows(data.get("static_leases")):
            m, a = dnsmap.mac(row.get("mac")), dnsmap.address(row.get("ip"))
            if m is None or a is None:
                continue
            name = dnsmap.text(row.get("hostname")) or None
            reservations.append(Reservation(mac=m, address=a, hostname=name))
            made = dnsmap.lease(a, m, name, None, reserved=True, state=LeaseState.RESERVED)
            if made is not None:
                leases.append(made)
        taken = {(x.mac, x.address) for x in leases}
        for row in _rows(data.get("leases")):
            made = dnsmap.lease(
                row.get("ip"), row.get("mac"), row.get("hostname"), _time(row.get("expires"))
            )
            if made is None or (made.mac, made.address) in taken:
                continue
            reserved = any(r.mac == made.mac and r.address == made.address for r in reservations)
            leases.append(made.model_copy(update={"reserved": reserved}))
        extra: dict[str, Any] = {}
        interface = dnsmap.text(data.get("interface_name"))
        if interface:
            extra["interface"] = interface
        v6 = data.get("v6")
        if isinstance(v6, dict) and dnsmap.text(v6.get("range_start")):
            extra["v6_range_start"] = dnsmap.text(v6.get("range_start"))
        duration = v4.get("lease_duration")
        server, segment = dnsmap.dhcp_server(
            self.context.device_id,
            self.context.site_id,
            "adguardhome",
            start=v4.get("range_start"),
            end=v4.get("range_end"),
            router=v4.get("gateway_ip"),
            lease_time=duration if isinstance(duration, int) and duration > 0 else None,
            reservations=reservations,
            leases=leases,
            dns_servers=await self._dhcp_dns_servers(v4),
            extra=extra,
        )
        return Observation(dhcp_servers=[server], segments=[segment])

    async def _dhcp_dns_servers(self, v4: dict[str, Any]) -> list[IPAddress]:
        """AdGuard Home's DHCP server has no DNS option setting: clients get AdGuard Home
        itself (guess, #21), that is its own IPv4 addresses (``dns_addresses`` of the status)
        in the DHCP network; without a known network all of them."""
        status = _dict(await self._get(STATUS), STATUS)
        own: list[IPAddress] = [
            a
            for item in status.get("dns_addresses") or []
            if (a := dnsmap.address(item)) is not None
            and a.version == 4
            and not (a.is_loopback or a.is_unspecified or a.is_link_local)
        ]
        gateway, mask = dnsmap.address(v4.get("gateway_ip")), dnsmap.address(v4.get("subnet_mask"))
        if gateway is not None and mask is not None and gateway.version == 4 == mask.version:
            try:
                net = ip_network(f"{gateway}/{mask}", strict=False)
            except ValueError:
                return own
            return [a for a in own if a in net]
        return own

    # --- clients ------------------------------------------------------------------------------

    async def read_clients(self) -> Observation:
        """Configured clients that have a MAC address among their identifiers (the model
        keys a client by MAC); clients known by IP address or network only are not listed."""
        data = _dict(await self._get(CLIENTS), CLIENTS)
        dev = self.context.device_id
        out: dict[str, Client] = {}
        for row in _rows(data.get("clients")):
            ids = [str(x) for x in row.get("ids") or []]
            macs = [m for x in ids if (m := dnsmap.mac(x))]
            addresses = [a for x in ids if (a := dnsmap.address(x)) is not None]
            name = dnsmap.text(row.get("name")) or None
            for m in macs:
                out[m] = Client(
                    id=object_id(dev, "client", m), mac=m, addresses=addresses, hostname=name
                )
        return Observation(clients=[out[m] for m in sorted(out)])

    @classmethod
    async def discover(cls, probe: HostProbe) -> Candidate | None:
        """``GET /control/status`` without credentials (a 401 or the status itself)."""
        return await _discovery.discover(probe)
