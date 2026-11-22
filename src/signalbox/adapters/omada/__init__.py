"""TP-Link Omada: one site of an Omada controller through its Open API.

Talks to the controller's Open API v1 with OAuth client credentials (an Open API client with a
viewer role) over HTTPS with a pinned certificate (:mod:`signalbox.adapters.https`). Endpoint
paths and the JSON shapes assumed for them are listed in ``docs/adapters/omada.md``; they are
taken from the Omada Open API documentation and still need confirmation on a real controller
(issue #21).

**One Signalbox device, many Omada devices.** A controller manages a gateway, switches and
access points, but an adapter instance reports one :class:`~signalbox.model.Snapshot`. The
Signalbox device configured with this adapter therefore stands for the controller's *site*: its
``device`` is the controller, and the ports, radios, WLANs, subnets and DHCP servers of the
managed devices are reported under ids prefixed with the configured device id and a slug of the
managed device (``<device>/eap-020000000c01/radio/5g``). Each of these objects carries the
managed device's identity (name, model, MAC, firmware, type) in
``vendor_extra["omada_device"]``. This is a phase-4 limitation of the model; a proper extension
(several devices per snapshot) is issue #46.

Parsing is defensive: missing fields never crash, unknown fields are ignored, and an answer of
the wrong shape raises ``AdapterError("unexpected answer from <endpoint>: ...")``.

Changes (LAN networks, DHCP, switch ports, SSIDs) go through the controller too; see
:mod:`signalbox.adapters.omada.writes`.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from ipaddress import ip_address, ip_interface
from typing import Any
from urllib.parse import urlsplit

from pydantic import Field, JsonValue, SecretStr, field_validator, model_validator

from signalbox.adapters import Adapter as _Adapter
from signalbox.adapters import (
    AdapterConfig,
    AdapterContext,
    AdapterError,
    ApplyResult,
    AuthFailed,
    Backup,
    Capability,
    Manifest,
    Observation,
    SystemInfo,
    VendorCall,
)
from signalbox.adapters.https import DeviceHttp, NotFound
from signalbox.changes import Change, ChangeKind
from signalbox.model import (
    Band,
    Client,
    Device,
    DeviceRole,
    DhcpPool,
    DhcpServer,
    Firmware,
    IPAddress,
    Membership,
    Pmf,
    Port,
    PortMembership,
    PurposeSource,
    Radio,
    Security,
    Segment,
    SegmentPurpose,
    Subnet,
    Wlan,
    normalise_mac,
    object_id,
    passphrase_fingerprint,
    segment_id,
)

INFO = "/api/info"
TOKEN = "/openapi/authorize/token"
#: Rows asked for per page; the controller may return fewer (paging follows ``totalRows``).
PAGE_SIZE = 100
#: Stop paging after this many pages, whatever ``totalRows`` says.
MAX_PAGES = 100

#: Omada error codes of a refused access token (-44112 "The access token has expired", also
#: the answer to a token the controller never issued; -44113 invalid): re-authorise once.
TOKEN_ERRORS = frozenset({-44112, -44113})

#: Radio keys of the radio configuration (``/aps/{mac}/radio-config``), with their band.
RADIO_KEYS: dict[str, Band] = {
    "radioSetting2g": Band.GHZ_2_4,
    "radioSetting5g": Band.GHZ_5,
    "radioSetting5g1": Band.GHZ_5,
    "radioSetting5g2": Band.GHZ_5,
    "radioSetting6g": Band.GHZ_6,
}
#: ``radioId`` of a wireless client → radio keys (0: 2.4 GHz, 1: 5 GHz-1, 2: 5 GHz-2, 3: 6 GHz).
CLIENT_RADIOS = {
    0: ("radioSetting2g",),
    1: ("radioSetting5g", "radioSetting5g1"),
    2: ("radioSetting5g2",),
    3: ("radioSetting6g",),
}
#: Bits of an SSID's ``band`` → radio keys.
BAND_BITS = (
    (1, ("radioSetting2g",)),
    (2, ("radioSetting5g", "radioSetting5g1", "radioSetting5g2")),
    (4, ("radioSetting6g",)),
)
#: ``channelWidth`` code of the radio configuration → MHz (4, 6 and 8 are "auto").
WIDTH_CODES = {2: 20, 3: 40, 5: 80, 7: 160, 10: 320}
#: ``linkSpeed`` code of a switch port → Mbit/s.
LINK_SPEEDS = {1: 10, 2: 100, 3: 1000, 4: 2500, 5: 10000, 6: 5000, 7: 25000, 8: 100000}
#: ``pskSetting.versionPsk`` → security: 1 WPA-PSK, 2 WPA2-PSK, 3 WPA/WPA2-PSK,
#: 4 WPA2-PSK/WPA3-SAE (WPA3-SAE alone on a 6 GHz-only SSID).
PSK_VERSIONS = {
    1: Security.OTHER,
    2: Security.WPA2,
    3: Security.OTHER,
    4: Security.WPA2_WPA3,
}
#: ``pmfMode`` → PMF: 1 mandatory, 2 capable, 3 disabled.
PMF_MODES = {1: Pmf.REQUIRED, 2: Pmf.OPTIONAL, 3: Pmf.DISABLED}
#: ``purpose`` of a LAN network (0 VLAN only, 1 interface: a gateway address); older
#: controllers and the web API spell it as a word.
PURPOSES = {0: "vlan", 1: "interface", "vlan": "vlan", "interface": "interface"}
#: Device ``type`` → prefix of the managed device's slug.
TYPES = {"gateway": "gateway", "router": "gateway", "switch": "switch", "ap": "eap", "eap": "eap"}


class OmadaConfig(AdapterConfig):
    url: str = Field(description="Address of the controller, https://controller:8043")
    omadac_id: str = Field(
        default="",
        description="Controller id (omadacId); empty: read from /api/info",
    )
    site: str = Field(default="Default", description="Name of the Omada site to read")
    client_id: str = Field(
        description="Client ID of an Open API client: viewer role to read, administrator role "
        "to change"
    )
    client_secret: SecretStr = Field(description="Client secret of that Open API client")
    allow_insecure_http: bool = Field(
        default=False,
        description="Allow plain http:// (simulators and tests only: sends the secret unencrypted)",
    )

    @field_validator("url")
    @classmethod
    def _url(cls, value: str) -> str:
        parts = urlsplit(value)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise ValueError("must be https://host[:port]")
        return value.rstrip("/")

    @model_validator(mode="after")
    def _http_needs_opt_in(self) -> OmadaConfig:
        if self.url.startswith("http://") and not self.allow_insecure_http:
            raise ValueError("plain http:// needs allow_insecure_http (simulators only)")
        return self


class OmadaError(AdapterError):
    """The controller answered with a non-zero ``errorCode``."""

    def __init__(self, path: str, code: int, msg: str) -> None:
        self.code = code
        super().__init__(f"{path}: Omada error {code}: {msg or 'no message'}")


class TokenRefused(AuthFailed):
    """The access token was refused (expired or invalid)."""


# --- defensive parsing helpers ---------------------------------------------------------------


def _unexpected(endpoint: str, what: str) -> AdapterError:
    return AdapterError(f"unexpected answer from {endpoint}: {what}")


def _dict(value: Any, endpoint: str, what: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise _unexpected(endpoint, f"{what} is {type(value).__name__}, expected an object")
    return value


def _sub(parent: dict[str, Any], key: str) -> dict[str, Any]:
    value = parent.get(key)
    return value if isinstance(value, dict) else {}


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    text = _text(value)
    return int(text) if text.lstrip("-").isdigit() else None


def _flag(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    return value in (True, 1, "1", "true")


def _addr(value: Any) -> IPAddress | None:
    try:
        return ip_address(_text(value))
    except ValueError:
        return None


def _mac(value: Any) -> str | None:
    try:
        return normalise_mac(_text(value))
    except ValueError:
        return None


def _check(data: Any, path: str) -> Any:
    """The ``result`` of an Omada answer; a non-zero ``errorCode`` raises."""
    body = _dict(data, path, "the answer")
    code = _int(body.get("errorCode"))
    if code is None:
        raise _unexpected(path, "no errorCode")
    if code != 0:
        msg = _text(body.get("msg"))
        if code in TOKEN_ERRORS:
            raise TokenRefused(f"{path}: the controller refused the access token ({msg})")
        raise OmadaError(path, code, msg)
    return body.get("result")


# --- what the controller manages -------------------------------------------------------------


ROLES = {"gateway": DeviceRole.GATEWAY, "switch": DeviceRole.SWITCH, "eap": DeviceRole.AP}


@dataclass(frozen=True)
class _Managed:
    """A device managed by the controller (gateway, switch, EAP)."""

    mac: str  # normalised
    raw_mac: str  # as the controller writes it (used in paths)
    name: str
    kind: str  # gateway / switch / eap / device
    model: str | None
    firmware: str | None
    wlan_id: str | None
    slug: str

    def identity(self) -> dict[str, JsonValue]:
        out: dict[str, JsonValue] = {"name": self.name, "mac": self.mac, "type": self.kind}
        if self.model:
            out["model"] = self.model
        if self.firmware:
            out["firmware"] = self.firmware
        return out

    def extra(self, **more: JsonValue) -> dict[str, JsonValue]:
        return {"omada_device": self.identity(), **{k: v for k, v in more.items() if v}}


@dataclass(frozen=True)
class _Net:
    id: str
    name: str
    vlan: int | None
    segment: str
    raw: dict[str, Any]


@dataclass
class _Wireless:
    radios: list[Radio] = field(default_factory=list)
    wlans: list[Wlan] = field(default_factory=list)
    #: (EAP MAC, radio key, SSID) → WLAN id, for the clients.
    by_ssid: dict[tuple[str, str, str], str] = field(default_factory=dict)


def _security(ssid: dict[str, Any]) -> Security:
    """``security``: 0 none (OWE with ``oweEnable``), 2 WPA-Enterprise, 3 WPA-Personal,
    4 and 5 PPSK (other)."""
    mode = _int(ssid.get("security"))
    psk = _sub(ssid, "pskSetting")
    if mode == 0:
        return Security.OWE if ssid.get("oweEnable") is True else Security.OPEN
    if mode == 2:
        version = _int(_sub(ssid, "entSetting").get("versionEnt"))
        return Security.WPA3_ENTERPRISE if version == 4 else Security.WPA2_ENTERPRISE
    if mode == 3:
        return PSK_VERSIONS.get(_int(psk.get("versionPsk")) or 2, Security.OTHER)
    return Security.OTHER


def _width(value: Any) -> int | None:
    """MHz from a ``channelWidth`` code (a plain MHz number is accepted too)."""
    number = _int(value)
    if number in (20, 40, 80, 160, 320):
        return number
    return WIDTH_CODES.get(number or 0)


def _dhcp_settings(row: dict[str, Any]) -> dict[str, Any]:
    """The DHCP settings of a LAN network: ``dhcpSettingsVO`` in the v1 list, ``dhcpSettings``
    (with ``ipRangePool``) in the detail and the newer lists."""
    return _sub(row, "dhcpSettingsVO") or _sub(row, "dhcpSettings")


def _ranges(dhcp: dict[str, Any]) -> list[tuple[str, str]]:
    pool = dhcp.get("ipRangePool")
    if isinstance(pool, list) and pool:
        return [
            (_text(r.get("ipaddrStart")), _text(r.get("ipaddrEnd")))
            for r in pool
            if isinstance(r, dict)
        ]
    return [(_text(dhcp.get("ipaddrStart")), _text(dhcp.get("ipaddrEnd")))]


class OmadaAdapter(_Adapter):
    manifest = Manifest(
        id="omada",
        name="TP-Link Omada",
        version="0.2.0",
        api_version="1.0",
        vendor="TP-Link",
        roles=frozenset({DeviceRole.OTHER, DeviceRole.AP, DeviceRole.SWITCH, DeviceRole.GATEWAY}),
        capabilities=frozenset(
            {Capability.INTERFACES, Capability.DHCP, Capability.WIRELESS, Capability.CLIENTS}
        ),
        config=OmadaConfig,
        description="Reads one site of an Omada controller through its Open API and changes "
        "its LAN networks, DHCP, switch ports and SSIDs.",
        writes=frozenset({ChangeKind.ROUTER, ChangeKind.DHCP, ChangeKind.PORT, ChangeKind.WLAN}),
    )

    def __init__(self, context: AdapterContext) -> None:
        super().__init__(context)
        cfg = context.config
        assert isinstance(cfg, OmadaConfig)
        self.config = cfg
        self.http = DeviceHttp(
            cfg.url,
            pinned_fingerprint=context.pinned_fingerprint,
            timeout=context.timeout,
            allow_insecure_http=cfg.allow_insecure_http,
        )
        self._omadac_id = ""
        self._site_path = ""
        self._token: str | None = None
        self._cache: dict[str, Any] = {}
        self._wireless_cache: _Wireless | None = None

    async def close(self) -> None:
        await self.http.close()

    # --- writes (signalbox.adapters.omada.writes) ---------------------------------------------

    def _writer(self) -> Any:
        from signalbox.adapters.omada.writes import Writer

        return Writer(self)

    async def plan_changes(
        self, changes: list[Change], secrets: Mapping[str, str]
    ) -> list[VendorCall]:
        calls: list[VendorCall] = await self._writer().plan_changes(changes, secrets)
        return calls

    async def backup(self) -> Backup:
        backup: Backup = await self._writer().backup()
        return backup

    async def apply(
        self, changes: list[Change], secrets: Mapping[str, str], rollback_seconds: int
    ) -> ApplyResult:
        """No rollback timer: the controller has none (``rollback_seconds`` is not used)."""
        result: ApplyResult = await self._writer().apply(changes, secrets)
        return result

    async def confirm(self) -> None:
        """Nothing to confirm (no rollback timer)."""

    async def restore(self, backup: Backup) -> None:
        await self._writer().restore(backup)

    # --- requests -----------------------------------------------------------------------------

    async def _authorise(self) -> None:
        data = await self.http.request_json(
            "POST",
            TOKEN,
            params={"grant_type": "client_credentials"},
            json={
                "omadacId": self._omadac_id,
                "client_id": self.config.client_id,
                "client_secret": self.config.client_secret.get_secret_value(),
            },
        )
        try:
            result = _check(data, TOKEN)
        except OmadaError as exc:
            raise AuthFailed(f"the controller refused the client credentials: {exc}") from exc
        token = _text(_dict(result, TOKEN, "result").get("accessToken"))
        if not token:
            raise _unexpected(TOKEN, "no accessToken")
        self._token = token

    async def _api(self, path: str, params: dict[str, Any] | None = None) -> Any:
        """GET an Open API path; a refused token is renewed once."""
        for attempt in range(2):
            data = await self.http.request_json(
                "GET", path, params=params, headers={"Authorization": f"AccessToken={self._token}"}
            )
            try:
                return _check(data, path)
            except TokenRefused:
                if attempt:
                    raise
                await self._authorise()
        raise AssertionError("unreachable")  # pragma: no cover

    async def _rows(self, path: str) -> list[dict[str, Any]]:
        """All rows of a list endpoint, page by page (a plain list is accepted too); cached."""
        if path in self._cache:
            return list(self._cache[path])
        rows: list[dict[str, Any]] = []
        seen = 0
        for page in range(1, MAX_PAGES + 1):
            result = await self._api(path, {"page": page, "pageSize": PAGE_SIZE})
            if isinstance(result, list):
                rows = [r for r in result if isinstance(r, dict)]
                break
            body = _dict(result, path, "result")
            data = body.get("data")
            if not isinstance(data, list):
                raise _unexpected(path, "no list of data")
            rows += [r for r in data if isinstance(r, dict)]
            seen += len(data)
            total = _int(body.get("totalRows"))
            if not data or total is None or seen >= total:
                break
        self._cache[path] = rows
        return list(rows)

    async def _object(self, path: str) -> dict[str, Any] | None:
        """An endpoint answering one object; None when the controller does not know it."""
        if path not in self._cache:
            try:
                self._cache[path] = _dict(await self._api(path), path, "result")
            except (NotFound, OmadaError):
                self._cache[path] = None
        value: dict[str, Any] | None = self._cache[path]
        return value

    async def _optional_rows(self, path: str) -> list[dict[str, Any]]:
        try:
            return await self._rows(path)
        except (NotFound, OmadaError):
            return []

    # --- system -------------------------------------------------------------------------------

    async def read_system(self) -> SystemInfo:
        # A new observation: probe the certificate again and forget the previous answers.
        await self.http.reset()
        self._cache.clear()
        self._wireless_cache = None
        self._token = None
        info = _dict(_check(await self.http.get_json(INFO), INFO), INFO, "result")
        self._omadac_id = self.config.omadac_id or _text(info.get("omadacId"))
        if not self._omadac_id:
            raise _unexpected(INFO, "no omadacId (set the controller id in the settings)")
        await self._authorise()
        sites = await self._rows(f"/openapi/v1/{self._omadac_id}/sites")
        wanted = self.config.site
        site = next((s for s in sites if _text(s.get("name")) == wanted), None) or next(
            (s for s in sites if _text(s.get("name")).casefold() == wanted.casefold()), None
        )
        site_id = _text(site.get("siteId") or site.get("id")) if site else ""
        if not site_id:
            names = ", ".join(sorted(_text(s.get("name")) for s in sites)) or "none"
            raise AdapterError(f"the controller has no site {wanted!r} (sites: {names})")
        self._site_path = f"/openapi/v1/{self._omadac_id}/sites/{site_id}"
        version = _text(info.get("controllerVer"))
        return SystemInfo(
            vendor="TP-Link",
            model="Omada Controller",
            firmware=Firmware(current=version) if version else None,
            management_address=self.http.host,
        )

    # --- shared views -------------------------------------------------------------------------

    async def _devices(self) -> list[_Managed]:
        out: list[_Managed] = []
        for row in await self._rows(f"{self._site_path}/devices"):
            mac = _mac(row.get("mac"))
            if mac is None:
                continue
            kind = TYPES.get(_text(row.get("type")).lower(), "device")
            out.append(
                _Managed(
                    mac=mac,
                    raw_mac=_text(row.get("mac")),
                    name=_text(row.get("name")) or mac,
                    kind=kind,
                    model=_text(row.get("model")) or None,
                    firmware=_text(row.get("firmwareVersion") or row.get("version")) or None,
                    wlan_id=_text(row.get("wlanId") or row.get("wlanGroupId")) or None,
                    slug=f"{kind}-{mac.replace(':', '')}",
                )
            )
        return out

    async def _networks(self) -> dict[str, _Net]:
        site = self.context.site_id
        nets: dict[str, _Net] = {}
        for row in await self._rows(f"{self._site_path}/lan-networks"):
            net_id = _text(row.get("id") or row.get("networkId"))
            vlan = _int(row.get("vlan"))
            if not net_id or (vlan is not None and not 1 <= vlan <= 4094):
                continue
            nets[net_id] = _Net(
                id=net_id,
                name=_text(row.get("name")) or net_id,
                vlan=vlan,
                segment=segment_id(site, vlan),
                raw=row,
            )
        return nets

    def _prefix(self, managed: _Managed) -> str:
        return f"{self.context.device_id}/{managed.slug}"

    async def _gateway(self) -> _Managed | None:
        return next((d for d in await self._devices() if d.kind == "gateway"), None)

    # --- interfaces ---------------------------------------------------------------------------

    async def read_interfaces(self) -> Observation:
        dev, site = self.context.device_id, self.context.site_id
        nets = await self._networks()
        members: dict[str, dict[str, Membership]] = {n.segment: {} for n in nets.values()}
        segments: dict[str, Segment] = {}
        for n in nets.values():
            if n.segment not in segments:
                segments[n.segment] = Segment(
                    id=n.segment,
                    site_id=site,
                    vlan=None if n.segment == segment_id(site, None) else n.vlan,
                    name=n.name,
                    vendor_extra={"network_id": n.id},
                )
        profiles = {
            _text(p.get("id") or p.get("profileId")): p
            for p in await self._optional_rows(f"{self._site_path}/lan-profiles")
        }

        ports: list[Port] = []
        for sw in (d for d in await self._devices() if d.kind == "switch"):
            for row in await self._ports(sw.raw_mac):
                number = _int(row.get("port"))
                if number is None:
                    continue
                pid = f"{self._prefix(sw)}/port/{number}"
                link = _int(row.get("linkStatus"))
                duplex, speed = _int(row.get("duplex")), _int(row.get("linkSpeed"))
                ports.append(
                    Port(
                        id=pid,
                        device_id=self._prefix(sw),
                        name=f"{sw.name} {_text(row.get('name')) or f'Port{number}'}",
                        up=None if link is None else link == 1,
                        speed_mbps=None if link == 0 else LINK_SPEEDS.get(speed or 0),
                        full_duplex=None if link == 0 else {1: False, 2: True}.get(duplex or 0),
                        poe=row["poe"] if isinstance(row.get("poe"), bool) else None,
                        lag=_text(row.get("lagId")) or None,
                        vendor_extra=sw.extra(
                            port=number,
                            profile=_text(row.get("profileName")) or None,
                            disabled=row.get("disable") is True,
                        ),
                    )
                )
                profile = profiles.get(_text(row.get("profileId")), {})
                native = _text(
                    row["nativeNetworkId"]
                    if "nativeNetworkId" in row
                    else profile.get("nativeNetworkId")
                )
                tagged = (
                    row["tagNetworkIds"] if "tagNetworkIds" in row else profile.get("tagNetworkIds")
                )
                if native in nets:
                    members[nets[native].segment][pid] = Membership.UNTAGGED
                for net_id in tagged if isinstance(tagged, list) else []:
                    net = nets.get(_text(net_id))
                    if net is not None and pid not in members[net.segment]:
                        members[net.segment][pid] = Membership.TAGGED
        segs = [
            s.model_copy(
                update={
                    "members": [
                        PortMembership(port_id=p, mode=m) for p, m in sorted(members[s.id].items())
                    ]
                }
            )
            for s in segments.values()
        ]

        gateway = await self._gateway()
        subnets: list[Subnet] = []
        for n in nets.values():
            try:
                iface = ip_interface(_text(n.raw.get("gatewaySubnet")))
            except ValueError:
                continue
            owner = f"{self._prefix(gateway)}" if gateway else f"{dev}/gateway"
            subnets.append(
                Subnet(
                    id=f"{owner}/subnet/{n.id}",
                    segment_id=n.segment,
                    interface=iface,
                    device_id=self._prefix(gateway) if gateway else dev,
                    gateway=True,
                    vendor_extra=gateway.extra(network=n.name) if gateway else {"network": n.name},
                )
            )
        managed = [
            Device(
                id=self._prefix(d),
                site_id=site,
                name=d.name,
                role=ROLES.get(d.kind, DeviceRole.OTHER),
                vendor="TP-Link",
                model=d.model,
                firmware=Firmware(current=d.firmware) if d.firmware else None,
                adapter=self.manifest.id,
                vendor_extra={"omada_device": d.identity()},
            )
            for d in await self._devices()
        ]
        return Observation(ports=ports, segments=segs, subnets=subnets, devices=managed)

    # --- DHCP ---------------------------------------------------------------------------------

    async def read_dhcp(self) -> Observation:
        dev = self.context.device_id
        gateway = await self._gateway()
        owner = self._prefix(gateway) if gateway else f"{dev}/gateway"
        servers: list[DhcpServer] = []
        for n in (await self._networks()).values():
            dhcp = _dhcp_settings(n.raw)
            if not dhcp:
                continue
            try:
                own: IPAddress | None = ip_interface(_text(n.raw.get("gatewaySubnet"))).ip
            except ValueError:
                own = None
            pools = [
                DhcpPool(start=start, end=end)
                for start, end in ((_addr(a), _addr(b)) for a, b in _ranges(dhcp))
                if start and end
            ]
            if not pools and not _flag(dhcp.get("enable")):
                continue  # what the controller leaves of removed DHCP settings: none
            if _text(dhcp.get("dhcpns")).lower() == "manual":
                dns = [a for a in (_addr(dhcp.get(k)) for k in ("priDns", "sndDns")) if a]
            else:
                dns = [own] if own else []
            lease = _int(dhcp.get("leasetime"))
            servers.append(
                DhcpServer(
                    id=f"{owner}/dhcp/{n.id}",
                    device_id=self._prefix(gateway) if gateway else dev,
                    segment_id=n.segment,
                    enabled=_flag(dhcp.get("enable")),
                    pools=pools,
                    lease_seconds=lease * 60 if lease else None,
                    router=_addr(dhcp.get("gateway")) or own,
                    dns_servers=dns,
                    domain=_text(n.raw.get("domain")) or None,
                    vendor_extra=gateway.extra(network=n.name) if gateway else {"network": n.name},
                )
            )
        return Observation(dhcp_servers=servers)

    # --- wireless -----------------------------------------------------------------------------

    async def _wlan_groups(self) -> tuple[dict[str, str], str | None]:
        """WLAN groups by id (their names) and the primary one."""
        groups = await self._rows(f"{self._site_path}/wireless-network/wlans")
        names = {
            gid: _text(g.get("name")) or gid
            for g in groups
            if (gid := _text(g.get("wlanId") or g.get("id")))
        }
        primary = next(
            (_text(g.get("wlanId") or g.get("id")) for g in groups if _flag(g.get("primary"))),
            next(iter(names), None),
        )
        return names, primary

    async def _ports(self, raw_mac: str) -> list[dict[str, Any]]:
        """A switch's ports: ``portList`` of ``GET …/switches/{mac}`` (there is no port list
        endpoint of its own)."""
        path = f"{self._site_path}/switches/{raw_mac}"
        if path not in self._cache:
            ports = _dict(await self._api(path), path, "result").get("portList")
            if not isinstance(ports, list):
                raise _unexpected(path, "no portList")
            self._cache[path] = [p for p in ports if isinstance(p, dict)]
        return list(self._cache[path])

    async def _ssids(self, group: str) -> list[dict[str, Any]]:
        """The SSIDs of a WLAN group with their details: the list leaves out the security
        settings (``pskSetting``, ``pmfMode``), which only ``…/ssids/{ssidId}`` answers."""
        path = f"{self._site_path}/wireless-network/wlans/{group}/ssids"
        out = []
        for row in await self._rows(path):
            sid = _text(row.get("ssidId") or row.get("id"))
            detail = await self._object(f"{path}/{sid}") if sid else None
            out.append({**row, **(detail or {})})
        return out

    async def _wireless(self) -> _Wireless:
        if self._wireless_cache is not None:
            return self._wireless_cache
        site = self.context.site_id
        out = _Wireless()
        nets = await self._networks()
        vlans = {n.vlan or 1 for n in nets.values()}
        groups, primary = await self._wlan_groups()
        for ap in (d for d in await self._devices() if d.kind == "eap"):
            group = ap.wlan_id if ap.wlan_id in groups else primary
            ssids = await self._ssids(group) if group else []
            settings = await self._object(f"{self._site_path}/aps/{ap.raw_mac}/radio-config")
            radios: dict[str, Radio] = {}
            if settings is None:  # no radio settings: the radios the SSIDs need, details unknown
                needed = {
                    k
                    for s in ssids
                    for bit, ks in BAND_BITS
                    if (_int(s.get("band")) or 0) & bit
                    for k in ks[:1]
                }
                settings = {k: {} for k in RADIO_KEYS if k in needed}
            for key, band in RADIO_KEYS.items():
                cfg = settings.get(key)
                if not isinstance(cfg, dict):
                    continue
                short = key.removeprefix("radioSetting")
                channel = _int(cfg.get("channel"))
                radios[key] = Radio(
                    id=f"{self._prefix(ap)}/radio/{short}",
                    device_id=self._prefix(ap),
                    name=f"{ap.name} {band.value} GHz" + (" (2)" if key.endswith("5g2") else ""),
                    band=band,
                    channel=channel or None,
                    width_mhz=_width(cfg.get("channelWidth")),
                    tx_power_dbm=_int(cfg.get("txPower")),
                    enabled=_flag(cfg.get("radioEnable"), default=True),
                    vendor_extra=ap.extra(),
                )
            out.radios += radios.values()
            for s in ssids:
                name = _text(s.get("name"))
                sid = _text(s.get("ssidId") or s.get("id")) or name
                if not name:
                    continue
                bits = _int(s.get("band")) or 0
                sec = _security(s)
                vlan = _int(s.get("vlanId")) if _flag(s.get("vlanEnable")) else None
                seg = segment_id(site, vlan) if (vlan or 1) in vlans else None
                key_text = _text(_sub(s, "pskSetting").get("securityKey"))
                # "Guest Network": the controller keeps these clients out of the local networks
                guest = _flag(s.get("guestNetEnable"))
                psk = sec in (Security.WPA2, Security.WPA3, Security.WPA2_WPA3) and key_text
                for bit, keys in BAND_BITS:
                    for key in keys:
                        radio = radios.get(key)
                        if not bits & bit or radio is None:
                            continue
                        wid = f"{self._prefix(ap)}/wlan/{sid}-{key.removeprefix('radioSetting')}"
                        out.wlans.append(
                            Wlan(
                                id=wid,
                                device_id=self._prefix(ap),
                                ssid=name,
                                radio_id=radio.id,
                                enabled=radio.enabled
                                and _flag(s.get("ssidEnable", s.get("enable")), default=True),
                                security=sec,
                                pmf=PMF_MODES.get(_int(s.get("pmfMode")) or 0),
                                passphrase_fingerprint=(
                                    passphrase_fingerprint(name, key_text) if psk else None
                                ),
                                segment_id=seg,
                                hidden=not _flag(s.get("broadcast"), default=True),
                                purpose=SegmentPurpose.GUEST if guest else None,
                                purpose_source=PurposeSource.REPORTED if guest else None,
                                vendor_extra=ap.extra(
                                    wlan_group=groups.get(group or ""),
                                    vlan=vlan if seg is None else None,
                                ),
                            )
                        )
                        out.by_ssid[(ap.mac, key, name)] = wid
        self._wireless_cache = out
        return out

    async def read_wireless(self) -> Observation:
        w = await self._wireless()
        return Observation(radios=w.radios, wlans=w.wlans)

    # --- clients ------------------------------------------------------------------------------

    async def read_clients(self) -> Observation:
        dev = self.context.device_id
        managed = await self._devices()
        own = {d.mac for d in managed}
        by_mac = {d.mac: d for d in managed}
        nets = await self._networks()
        by_vlan = {n.vlan or 1: n.segment for n in nets.values()}
        by_name = {n.name: n.segment for n in nets.values()}
        try:
            wireless: _Wireless | None = await self._wireless()
        except AdapterError:
            wireless = None  # clients are still worth reporting, without their WLAN
        clients: dict[str, Client] = {}
        for row in await self._rows(f"{self._site_path}/clients"):
            mac = _mac(row.get("mac"))
            if mac is None or mac in own or mac in clients:
                continue
            addresses = [a for a in [_addr(row.get("ip"))] if a]
            v6 = row.get("ipv6List")
            for text in v6 if isinstance(v6, list) else []:
                a = _addr(text)
                if a is not None and not a.is_link_local and a not in addresses:
                    addresses.append(a)
            vid = _int(row.get("vid"))
            seg = by_vlan.get(vid) if vid else by_name.get(_text(row.get("networkName")))
            seen_on: str | None = None
            if _flag(row.get("wireless")):
                ap = _mac(row.get("apMac"))
                keys = CLIENT_RADIOS.get(_int(row.get("radioId")) or 0, ())
                if wireless and ap:
                    ssid = _text(row.get("ssid"))
                    seen_on = next(
                        (w for k in keys if (w := wireless.by_ssid.get((ap, k, ssid)))), None
                    )
            else:
                sw = by_mac.get(_mac(row.get("switchMac")) or "")
                number = _int(row.get("port"))
                if sw is not None and number is not None:
                    seen_on = f"{self._prefix(sw)}/port/{number}"
            hostname = _text(row.get("hostName")) or _text(row.get("name"))
            last = _int(row.get("lastSeen"))
            clients[mac] = Client(
                id=object_id(dev, "client", mac),
                mac=mac,
                addresses=addresses,
                hostname=hostname if hostname and _mac(hostname) != mac else None,
                segment_id=seg,
                seen_on=seen_on,
                last_seen=datetime.fromtimestamp(last / 1000, UTC) if last else None,
            )
        return Observation(clients=[clients[m] for m in sorted(clients)])


__all__ = ["OmadaAdapter", "OmadaConfig"]
