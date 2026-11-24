"""AVM Fritz!Box: LAN, DHCP, Wi-Fi and hosts over TR-064 (SOAP over HTTPS).

The SOAP side is :mod:`signalbox.adapters.fritzbox.soap`, the HTTPS side (probe, pin, errors)
:class:`signalbox.adapters.https.DeviceHttp`. Authentication is HTTP Digest with a dedicated
Fritz!Box user. Every action and the arguments it is assumed to return are listed in
``docs/adapters/fritzbox.md``; they are checked against AVM's TR-064 service descriptions
(``tests/fixtures/tr064/``) and still need confirmation of their effect on a real device.

Mapping in short: the LAN is the native segment with one bridge port ``lan`` (TR-064 has no
per-port view), its subnet from ``IPRouters``/``SubnetMask``; every ``WLANConfiguration<n>`` is
a WLAN, the non-guest ones also a radio; the guest WLAN gets its own segment
``<site>/segment/guest``. DHCP reservations, DNS and LLDP are not exposed by TR-064.

Writing (:mod:`signalbox.adapters.fritzbox.write`): the LAN DHCP server and the existing Wi-Fi
networks. There is no confirm timer; the backup is the TR-064 values of every setting the
adapter may change, and a restore sets them back.
"""

from __future__ import annotations

import contextlib
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address, IPv4Interface, ip_address, ip_network
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import httpx
from pydantic import Field, JsonValue, SecretStr, field_validator, model_validator

from signalbox.adapters import (
    Adapter,
    AdapterConfig,
    AdapterContext,
    AdapterError,
    ApplyResult,
    AuthFailed,
    Backup,
    Capability,
    Gap,
    Manifest,
    Observation,
    SystemInfo,
    Unreachable,
    VendorCall,
)
from signalbox.adapters.fritzbox import discovery
from signalbox.adapters.fritzbox.soap import UPNP_PORT, SoapFault, Tr064, security_port
from signalbox.adapters.fritzbox.write import (
    BACKUP_FORMAT,
    Call,
    backup_content,
    check_wlan,
    dhcp_wanted,
    lan_calls,
    parse_backup,
    wlan_calls,
    wlan_wanted,
)
from signalbox.adapters.https import DeviceHttp, NotFound, device_url
from signalbox.changes import Change, ChangeKind, WlanValue
from signalbox.discovery import Candidate, HostProbe
from signalbox.model import (
    SERVICE_PORTS,
    AddressSource,
    Band,
    Cipher,
    Client,
    DeviceHealth,
    DeviceRole,
    DeviceTime,
    DhcpLease,
    DhcpPool,
    DhcpRelay,
    DhcpServer,
    Firewall,
    FirewallAction,
    FirewallChain,
    FirewallMatch,
    FirewallProtocol,
    FirewallRule,
    FirewallZone,
    Firmware,
    LeaseState,
    ManagementService,
    Membership,
    NtpClient,
    Port,
    PortForward,
    PortKind,
    PortMembership,
    PortRange,
    PurposeSource,
    Radio,
    Security,
    Segment,
    SegmentPurpose,
    ServiceKind,
    Subnet,
    Uplink,
    UplinkKind,
    Wlan,
    Wps,
    WpsMethod,
    ZonePolicy,
    firewall_id,
    normalise_mac,
    object_id,
    passphrase_digest,
    passphrase_fingerprint,
    port_id,
    segment_id,
)

__all__ = ["FritzboxAdapter", "FritzboxConfig"]

#: TR-064 over HTTPS listens here (plain TR-064 on 49000 is not used: it would need http).
DEFAULT_PORT = 49443
#: The right a Fritz!Box user needs for every action read here.
RIGHT = "FRITZ!Box settings"
#: At most this many WLANConfiguration services (2.4 GHz, 5 GHz, 6 GHz or second 5 GHz, guest).
MAX_WLANS = 4
GUEST = "guest"
#: Port mappings read per connection (a box has a few dozen at most; the loop ends at fault 713).
MAX_PORT_MAPPINGS = 512
#: ``SpecifiedArrayIndexInvalid`` (713) ends the index loop; 714 is its other spelling in UPnP.
END_OF_ARRAY = (713, 714)


class FritzboxConfig(AdapterConfig):
    url: str = Field(
        description="The box's address in your home network, for example fritz.box or "
        "192.0.2.1. Signalbox talks TR-064 over https on port 49443 (https://<box>:49443).",
        examples=["fritz.box"],
    )
    username: str = Field(
        default="",
        description="Fritz!Box user with the right 'FRITZ!Box settings'. Leave empty if the "
        "box asks only for its password (no users set up).",
    )
    password: SecretStr = Field(description="Password of that user")
    allow_insecure_http: bool = Field(
        json_schema_extra={"advanced": True},
        default=False,
        description="Allow plain http:// (simulators and tests only: no encryption at all)",
    )

    @field_validator("url")
    @classmethod
    def _url(cls, value: str) -> str:
        url = device_url(value, port=DEFAULT_PORT)
        parts = urlsplit(url)
        if parts.scheme == "http" and parts.port is None:
            raise ValueError(
                "use https://: the Fritz!Box answers TR-064 on https://<box>:49443; "
                "http:// without a port reaches its web interface"
            )
        return urlunsplit(parts._replace(path=""))

    @model_validator(mode="after")
    def _http_needs_opt_in(self) -> FritzboxConfig:
        if self.url.startswith("http://") and not self.allow_insecure_http:
            raise ValueError("plain http:// needs allow_insecure_http (simulators only)")
        return self


# --- mapping helpers ------------------------------------------------------------------------

#: ``NewBeaconType`` -> security. ``11i`` is WPA2, ``WPAand11i`` WPA/WPA2 mixed, ``WPA`` WPA1.
#: ``Basic`` depends on ``NewBasicEncryptionModes`` (see :func:`security`).
BEACON_TYPES: dict[str, Security] = {
    "none": Security.OPEN,
    "wpa": Security.WPA,
    "11i": Security.WPA2,
    "wpaand11i": Security.WPA_WPA2,
    "wpa3": Security.WPA3,
    "11iandwpa3": Security.WPA2_WPA3,
    "owe": Security.OWE,
    "owetrans": Security.OWE,
}
PERSONAL = {
    Security.WPA,
    Security.WPA_WPA2,
    Security.WPA2,
    Security.WPA3,
    Security.WPA2_WPA3,
    Security.OTHER,
}
BANDS = {"2400": Band.GHZ_2_4, "5000": Band.GHZ_5, "6000": Band.GHZ_6}


def security(beacon_type: str | None, basic_modes: str | None = None) -> Security:
    """``Basic`` is the TR-098 beacon of WEP (``NewBasicEncryptionModes`` ``WEPEncryption``) or
    of an open network (``None``); anything else it names is not known."""
    beacon = (beacon_type or "none").strip().lower()
    if beacon == "basic":
        modes = (basic_modes or "").strip().lower()
        if "wep" in modes:
            return Security.WEP
        return Security.OPEN if modes == "none" else Security.OTHER
    return BEACON_TYPES.get(beacon, Security.OTHER)


def supported_security(possible: str | None) -> list[Security] | None:
    """``NewX_AVM-DE_PossibleBeaconTypes`` (comma separated, spelled as ``NewBeaconType``)
    as security modes; None when the box does not list them."""
    text = (possible or "").strip()
    if not text:
        return None
    modes = [security(t, "WEPEncryption") for t in text.split(",") if t.strip()]
    return list(dict.fromkeys(m for m in modes if m is not Security.OTHER)) or None


def wps_of(mode: str | None, status: str | None) -> Wps | None:
    """``X_AVM-DE_GetWPSInfo``: status ``off`` is WPS disabled; the other statuses (inactive,
    active, success, err_*) mean it is enabled, and mode ``pbc`` is the push button. None:
    neither value."""
    state = (status or "").strip().lower()
    if not state and not (mode or "").strip():
        return None
    if state == "off":
        return Wps(enabled=False)
    pbc = (mode or "").strip().lower() == "pbc"
    return Wps(enabled=True, methods=[WpsMethod.PUSH_BUTTON] if pbc else [])


def _flag(value: str | None) -> bool:
    return (value or "").strip().lower() in ("1", "true", "yes", "up")


def _wlan_on(info: Mapping[str, str]) -> bool:
    """A WLAN is on when enabled and its status is not ``Disabled``."""
    status = info.get("NewStatus", "Up").strip().lower()
    return _flag(info.get("NewEnable")) and status != "disabled"


def _int(value: str | None) -> int | None:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _mac(value: str | None) -> str | None:
    try:
        return normalise_mac(str(value or ""))
    except ValueError:
        return None


def _v4(value: str | None) -> IPv4Address | None:
    try:
        address = ip_address(str(value or "").strip())
    except ValueError:
        return None
    return address if isinstance(address, IPv4Address) and not address.is_unspecified else None


def _v4_list(value: str | None) -> list[IPv4Address]:
    """``"192.0.2.1, 192.0.2.53"`` -> addresses; anything unreadable is dropped."""
    return [a for part in str(value or "").split(",") if (a := _v4(part)) is not None]


#: ``NewWANAccessType`` of WANCommonInterfaceConfig that are a mobile connection
_MOBILE = {"X_AVM-DE_UMTS", "X_AVM-DE_LTE"}
#: Hosts ``NewAddressSource`` (TR-064 Hosts:1: DHCP, Static, AutoIP) per client address (#183).
_ADDRESS_SOURCE = {
    "dhcp": AddressSource.DHCP,
    "static": AddressSource.STATIC,
    "autoip": AddressSource.LINK_LOCAL,
}


def _kbps(value: str | None) -> int | None:
    """A rate in bit/s (``NewLayer1DownstreamMaxBitRate``) in kbit/s; 0 is not known."""
    bits = _int(value)
    return bits // 1000 if bits else None


def wan_uplink(
    device_id: str,
    ppp: dict[str, str] | None,
    ip: dict[str, str] | None,
    link: dict[str, str],
    now: datetime,
) -> Uplink | None:
    """The internet connection from ``WANPPPConnection:1``/``WANIPConnection:1`` ``GetInfo``.

    The enabled one of the two is the connection (PPP first); neither enabled (the box reaches
    the internet over LAN 1 as an IP client, or has no access configured): no uplink.
    """
    info = next((i for i in (ppp, ip) if i and _flag(i.get("NewEnable"))), None)
    if info is None:
        return None
    is_ppp = info is ppp
    access = link.get("NewWANAccessType", "").strip()
    bridged = info.get("NewConnectionType", "").strip() == "IP_Bridged"
    if bridged:
        kind = UplinkKind.BRIDGE
    elif access in _MOBILE:
        kind = UplinkKind.LTE
    else:
        # WANIPConnection does not say whether the address is from DHCP or fixed
        kind = UplinkKind.PPPOE if is_ppp else UplinkKind.OTHER
    up = info.get("NewConnectionStatus", "").strip() == "Connected"
    uptime = _int(info.get("NewUptime"))
    own = None if bridged else _v4(info.get("NewExternalIPAddress"))
    remote = _v4(info.get("NewRemoteIPAddress")) if is_ppp and not bridged else None
    return Uplink(
        id=object_id(device_id, "uplink", "internet"),
        device_id=device_id,
        name=info.get("NewName", "").strip() or None,
        kind=kind,
        up=up,
        since=now - timedelta(seconds=uptime) if up and uptime else None,
        addresses=[IPv4Interface(own)] if own else [],
        upstream_gateway=remote,
        dns_servers=[] if bridged else list(_v4_list(info.get("NewDNSServers"))),
        downstream_kbps=_kbps(link.get("NewLayer1DownstreamMaxBitRate")),
        upstream_kbps=_kbps(link.get("NewLayer1UpstreamMaxBitRate")),
        vendor_extra=_extra(
            info | link, "NewConnectionType", "NewWANAccessType", "NewPhysicalLinkStatus"
        )
        | ({"service": "WANPPPConnection:1" if is_ppp else "WANIPConnection:1"}),
    )


def band(info: dict[str, str], index: int, count: int) -> Band:
    """Band of ``WLANConfiguration<index>``: ``X_AVM-DE_FrequencyBand`` if present, else the
    channel, else AVM's numbering (1 = 2.4 GHz, 2 = 5 GHz)."""
    known = BANDS.get(info.get("NewX_AVM-DE_FrequencyBand", "").strip())
    if known is not None:
        return known
    channel = _int(info.get("NewChannel"))
    if channel:
        return Band.GHZ_5 if channel > 14 else Band.GHZ_2_4
    return Band.GHZ_5 if index == 2 and count > 2 else Band.GHZ_2_4


def local_time(value: str | None) -> datetime | None:
    """``NewCurrentLocalTime``: ``2026-11-22T17:12:00+01:00`` (a time without an offset is
    of no use: the zone is not known for sure)."""
    try:
        when = datetime.fromisoformat((value or "").strip())
    except ValueError:
        return None
    return when if when.tzinfo is not None else None


def time_of(info: Mapping[str, str], start: datetime, end: datetime) -> DeviceTime:
    """``Time:1 GetInfo`` (read between ``start`` and ``end``).

    The clock has whole seconds (its middle is taken, half a second more uncertainty); the
    UTC offset is the one of ``NewCurrentLocalTime``, the zone ``NewLocalTimeZoneName`` (else
    ``NewLocalTimeZone``) as the box reports it. The Fritz!Box always synchronises with
    ``NewNTPServer1``/``2``; whether it is in sync and whether it serves time to the LAN are
    not in TR-064.
    """
    clock = local_time(info.get("NewCurrentLocalTime"))
    half = (end - start) / 2
    offset = clock.utcoffset() if clock is not None else None
    minutes = int(offset.total_seconds() // 60) if offset is not None else None
    servers = [s for k in ("NewNTPServer1", "NewNTPServer2") if (s := (info.get(k) or "").strip())]
    zone = (info.get("NewLocalTimeZoneName") or info.get("NewLocalTimeZone") or "").strip()
    return DeviceTime(
        clock=clock + timedelta(seconds=0.5) if clock else None,
        read_at=start + half if clock else None,
        uncertainty_seconds=half.total_seconds() + 0.5 if clock else None,
        timezone=zone or None,
        utc_offset_minutes=minutes if minutes is not None and abs(minutes) <= 1080 else None,
        ntp_client=NtpClient(enabled=bool(servers), servers=servers),
    )


def _extra(info: dict[str, str], *keys: str) -> dict[str, JsonValue]:
    return {k.removeprefix("New"): info[k] for k in keys if info.get(k)}


def _fixed_policies(guest: bool, wan: bool) -> list[ZonePolicy]:
    """What a Fritz!Box always does between its networks (the box has no filter to read)."""
    accept, drop = FirewallAction.ACCEPT, FirewallAction.DROP
    out = [ZonePolicy(source="lan", destination=None, action=accept)]
    if wan:
        out += [
            ZonePolicy(source="lan", destination="wan", action=accept),
            ZonePolicy(source="wan", destination=None, action=drop),
            ZonePolicy(source="wan", destination="lan", action=drop),
        ]
    if guest:
        out += [
            ZonePolicy(source="guest", destination=None, action=drop),
            ZonePolicy(source="guest", destination="lan", action=drop),
            ZonePolicy(source="lan", destination="guest", action=drop),
        ]
        if wan:
            out += [
                ZonePolicy(source="guest", destination="wan", action=accept),
                ZonePolicy(source="wan", destination="guest", action=drop),
            ]
    return out


def _guest_rules(guest: bool) -> list[FirewallRule]:
    """The guest network may use the box's DNS and DHCP (*guess*: nothing else)."""
    if not guest:
        return []
    return [
        FirewallRule(
            name="guest DNS and DHCP",
            chain=FirewallChain.INPUT,
            protocols=[FirewallProtocol.UDP],
            source=FirewallMatch(zones=["guest"]),
            destination=FirewallMatch(ports=[PortRange(start=53), PortRange(start=67)]),
            action=FirewallAction.ACCEPT,
        )
    ]


def port_forward(row: dict[str, str]) -> PortForward | None:
    """One ``GetGenericPortMappingEntry`` answer; ``None`` without a usable internal client.

    The external port 0 means every port (an exposed host); the description goes to the name
    only. UPnP-created mappings appear in this list too (*guess*)."""
    try:
        target = ip_address(row.get("NewInternalClient", "").strip())
    except ValueError:
        return None
    protocol = {"TCP": FirewallProtocol.TCP, "UDP": FirewallProtocol.UDP}.get(
        row.get("NewProtocol", "").strip().upper()
    )
    external, internal = _int(row.get("NewExternalPort")), _int(row.get("NewInternalPort"))
    remote = row.get("NewRemoteHost", "").strip()
    sources = []
    if remote:
        try:
            sources = [ip_network(remote)]
        except ValueError:
            return None
    return PortForward(
        name=row.get("NewPortMappingDescription", "").strip() or None,
        enabled=_flag(row.get("NewEnabled")),
        protocols=[protocol] if protocol else [],
        zones=["wan"],
        external_ports=[PortRange(start=external)] if external and 0 < external < 65536 else [],
        sources=sources,
        target_address=target,
        target_port=internal if internal and 0 < internal < 65536 else None,
        passes_filter=True,
    )


@dataclass
class WlanService:
    index: int
    info: dict[str, str]
    guest: bool

    @property
    def service(self) -> str:
        return f"WLANConfiguration{self.index}"


# --- the adapter ----------------------------------------------------------------------------


#: Shown in the device form ("Before you add it").
FRITZBOX_STEPS = (
    (
        "On the Fritz!Box: Home Network > Network > Network Settings (Heimnetz > Netzwerk > "
        "Netzwerkeinstellungen), switch on 'Allow access for applications' (Zugriff für "
        "Anwendungen zulassen) and apply. This is TR-064."
    ),
    (
        "System > FRITZ!Box Users (FRITZ!Box-Benutzer): add a user for Signalbox with a long "
        "password and only the right 'FRITZ!Box settings' (FRITZ!Box Einstellungen); leave "
        "access from the internet off."
    ),
    (
        "Below: the box's address (fritz.box or its IP address, no http:// needed), that user "
        "and password. Then Test connection and trust the box's certificate."
    ),
)


class FritzboxAdapter(Adapter):
    manifest = Manifest(
        setup_steps=FRITZBOX_STEPS,
        setup_url="https://github.com/PhilippMundhenk/signalbox/blob/main/docs/adapters/fritzbox.md#setting-up-the-fritzbox",
        id="fritzbox",
        name="AVM Fritz!Box",
        version="0.2.0",
        api_version="1.4",
        vendor="AVM",
        roles=frozenset({DeviceRole.GATEWAY, DeviceRole.AP}),
        capabilities=frozenset(
            {
                Capability.INTERFACES,
                Capability.DHCP,
                Capability.WIRELESS,
                Capability.CLIENTS,
                Capability.HEALTH,
                Capability.TIME,
                Capability.FIREWALL,
            }
        ),
        config=FritzboxConfig,
        description="Reads a Fritz!Box over TR-064 (SOAP over HTTPS) with a dedicated user; "
        "changes its DHCP server and existing Wi-Fi networks. Its fixed firewall behaviour and "
        "port sharing are read as a firewall.",
        writes=frozenset({ChangeKind.DHCP, ChangeKind.WLAN}),
    )

    def __init__(self, context: AdapterContext) -> None:
        super().__init__(context)
        cfg = self.config
        self.http = DeviceHttp(
            cfg.url,
            pinned_fingerprint=context.pinned_fingerprint,
            timeout=context.timeout,
            auth=httpx.DigestAuth(cfg.username, cfg.password.get_secret_value()),
            allow_insecure_http=cfg.allow_insecure_http,
        )
        self.tr064 = Tr064(self.http)
        self._host_cache: list[dict[str, str]] | None = None

    @classmethod
    async def discover(cls, probe: HostProbe) -> Candidate | None:
        """TR-064 description and HTTPS port on port 49000, without credentials."""
        return await discovery.discover(probe)

    @property
    def config(self) -> FritzboxConfig:
        assert isinstance(self.context.config, FritzboxConfig)
        return self.context.config

    async def close(self) -> None:
        await self.http.close()

    @property
    def _native(self) -> str:
        return segment_id(self.context.site_id, None)

    @property
    def _guest(self) -> str:
        return f"{self.context.site_id}/segment/{GUEST}"

    # system ---------------------------------------------------------------------------

    async def read_system(self) -> SystemInfo:
        await self.http.reset()  # a new observation: probe the certificate again
        self._host_cache = None
        try:
            info = await self.tr064.call("DeviceInfo1", "GetInfo")
        except (NotFound, Unreachable) as exc:
            raise await self._no_tr064(exc) from exc
        version = info.get("NewSoftwareVersion")
        return SystemInfo(
            vendor=info.get("NewManufacturerName") or "AVM",
            model=info.get("NewModelName") or None,
            firmware=Firmware(current=version) if version else None,
            management_address=self.http.host,
            transport_encrypted=self.http.secure,
        )

    async def _no_tr064(self, exc: AdapterError) -> AdapterError:
        """TR-064 does not answer at the configured address: ask the box for its port."""
        host, configured = self.http.host, self.http.port
        reported = await security_port(host, self.context.timeout)
        netloc = f"[{host}]" if ":" in host else host
        if reported is not None and reported != configured:
            return type(exc)(
                f"{exc}; this Fritz!Box serves TR-064 on port {reported}, not {configured}",
                fix=f"Change the address in the settings to https://{netloc}:{reported}.",
            )
        return type(exc)(
            str(exc),
            fix_id="fritzbox.enableTr064",
            fix="On the Fritz!Box, Home Network > Network > Network Settings (German: Heimnetz > "
            "Netzwerk > Netzwerkeinstellungen), switch on 'Allow access for applications' "
            "('Zugriff für Anwendungen zulassen') and apply. Use the box's own address in the "
            "home network with the TR-064 port, normally https://<box>:49443; not the web "
            "interface port 443 and not a MyFRITZ address. The box tells its port at "
            f"http://<box>:{UPNP_PORT}/tr64desc.xml if that answers.",
        )

    # health and time ------------------------------------------------------------------

    async def read_health(self) -> Observation:
        """``DeviceInfo:1 GetInfo`` ``NewUpTime``: TR-064 has no CPU, memory or sensors."""
        info = await self.tr064.call("DeviceInfo1", "GetInfo")
        uptime = _int(info.get("NewUpTime"))
        value = DeviceHealth(uptime_seconds=uptime if uptime is not None and uptime >= 0 else None)
        return Observation(health={self.context.device_id: value})

    async def read_time(self) -> Observation:
        start = datetime.now(UTC)
        info = await self.tr064.call("Time1", "GetInfo")
        end = datetime.now(UTC)
        value = time_of(info, start, end)
        return Observation(time={self.context.device_id: value})

    # interfaces -----------------------------------------------------------------------

    async def _lan(self) -> dict[str, str]:
        return await self.tr064.call("LANHostConfigManagement1", "GetInfo")

    def _lan_interface(self, lan: dict[str, str]) -> IPv4Interface | None:
        routers = _v4_list(lan.get("NewIPRouters"))
        mask = _v4(lan.get("NewSubnetMask"))
        if not routers or mask is None:
            return None
        try:
            return IPv4Interface(f"{routers[0]}/{mask}")
        except ValueError:
            return None

    async def _wlans(self) -> list[WlanService]:
        """Every WLANConfiguration service the box has, with its GetInfo answer."""
        found: list[WlanService] = []
        for index in range(1, MAX_WLANS + 1):
            service = f"WLANConfiguration{index}"
            try:
                info = await self.tr064.call(service, "GetInfo")
            except NotFound:
                break
            except SoapFault as exc:
                if exc.code == 401:  # invalid action: no such service on this model
                    break
                raise
            found.append(WlanService(index, info, guest=False))
        guests = []
        for wlan in found:
            try:
                ext = await self.tr064.call(wlan.service, "X_AVM-DE_GetWLANExtInfo")
            except (SoapFault, NotFound):
                continue
            if ext.get("NewX_AVM-DE_APType", "").strip().lower() == GUEST:
                guests.append(wlan)
        if not guests and len(found) >= 3:  # no type reported: AVM numbers the guest WLAN last
            guests = [found[-1]]
        for wlan in guests:
            wlan.guest = True
        return found

    async def read_interfaces(self) -> Observation:
        d = self.context.device_id
        site = self.context.site_id
        eth = await self.tr064.call("LANEthernetInterfaceConfig1", "GetInfo")
        stats: dict[str, str] = {}
        with contextlib.suppress(SoapFault):
            stats = await self.tr064.call("LANEthernetInterfaceConfig1", "GetStatistics")
        lan = await self._lan()
        # The other LANHostConfigManagement getters answer what GetInfo already holds; they
        # are read as a fallback for a FRITZ!OS whose GetInfo leaves the fields empty.
        if not lan.get("NewIPRouters"):
            with contextlib.suppress(SoapFault):
                lan |= await self.tr064.call("LANHostConfigManagement1", "GetIPRoutersList")
        if not lan.get("NewSubnetMask"):
            with contextlib.suppress(SoapFault):
                lan |= await self.tr064.call("LANHostConfigManagement1", "GetSubnetMask")

        # MaxBitRate is the interface's maximum (TR-064: 10, 100, 1000 or Auto), not the rate
        # of a link; TR-064 has no link speed for the LAN side.
        top = eth.get("NewMaxBitRate", "").strip()
        duplex = eth.get("NewDuplexMode", "").strip().lower()
        enabled = eth.get("NewEnable")
        port = Port(
            id=port_id(d, "lan"),
            device_id=d,
            name="lan",
            kind=PortKind.BRIDGE,
            up=eth.get("NewStatus", "").strip().lower() == "up" if eth.get("NewStatus") else None,
            full_duplex={"full": True, "half": False}.get(duplex),
            mac=_mac(eth.get("NewMACAddress")),
            admin_up=_flag(enabled) if enabled is not None else None,
            max_speed_mbps=mbps if (mbps := _int(top)) and mbps > 0 else None,
            autoneg=True if top.lower() == "auto" else None,
            vendor_extra=_extra(
                stats, "NewBytesSent", "NewBytesReceived", "NewPacketsSent", "NewPacketsReceived"
            ),
        )
        segments = [
            Segment(
                id=self._native,
                site_id=site,
                name="LAN",
                members=[PortMembership(port_id=port.id, mode=Membership.UNTAGGED)],
            )
        ]
        with contextlib.suppress(AdapterError):
            if any(w.guest for w in await self._wlans()):
                segments.append(
                    Segment(
                        id=self._guest,
                        site_id=site,
                        name="Guest network",
                        purpose=SegmentPurpose.GUEST,
                        purpose_source=PurposeSource.REPORTED,
                        isolated=True,  # the Fritz!Box keeps guests out of the LAN itself
                        vendor_extra={"fritzbox": "guest network (isolated by the Fritz!Box)"},
                    )
                )
        subnets = []
        interface = self._lan_interface(lan)
        if interface is not None:
            subnets.append(
                Subnet(
                    id=object_id(d, "subnet", "lan"),
                    segment_id=self._native,
                    interface=interface,
                    device_id=d,
                    gateway=self.context.role is DeviceRole.GATEWAY,
                )
            )
        return Observation(
            ports=[port],
            segments=segments,
            subnets=subnets,
            uplinks=await self._uplinks(),
            services=await self._services(),
        )

    async def _try(self, service: str, action: str) -> dict[str, str] | None:
        """An optional read: None when this FRITZ!OS lacks it or the user may not call it."""
        try:
            return await self.tr064.call(service, action)
        except (SoapFault, NotFound):
            return None

    async def _services(self) -> list[ManagementService]:
        """Management services (#173) from TR-064: the box says itself what the internet can
        reach (remote access, MyFRITZ!, FTP from the internet). The web interface in the LAN
        (HTTP 80, HTTPS 443) is not reported by any action: adapter knowledge."""
        d = self.context.device_id

        def service(
            name: str, kind: ServiceKind, port: int | None, enabled: bool, **kw: Any
        ) -> ManagementService:
            return ManagementService(
                id=object_id(d, "service", name),
                device_id=d,
                kind=kind,
                name=name,
                enabled=enabled,
                port=port if port and 0 < port < 65536 else None,
                **kw,
            )

        out = [
            service("http", ServiceKind.HTTP, 80, True),
            service("https", ServiceKind.HTTPS, 443, True),
        ]
        sec = await self._try("DeviceInfo1", "GetSecurityPort") or {}
        if port := _int(sec.get("NewSecurityPort")):
            out.append(service("tr-064", ServiceKind.TR064, port, True, encrypted=True))
        if (upnp := await self._try("X_AVM-DE_UPnP1", "GetInfo")) is not None:
            out.append(service("upnp", ServiceKind.UPNP, None, _flag(upnp.get("NewEnable"))))
        if (remote := await self._try("X_AVM-DE_RemoteAccess1", "GetInfo")) is not None:
            on = _flag(remote.get("NewEnabled"))
            out.append(
                service(
                    "remote-access",
                    ServiceKind.HTTPS,
                    _int(remote.get("NewPort")),
                    on,
                    from_wan=on,
                )
            )
        if (my := await self._try("X_AVM-DE_MyFritz1", "GetInfo")) is not None:
            on = _flag(my.get("NewEnabled"))
            out.append(
                service("myfritz", ServiceKind.HTTPS, _int(my.get("NewPort")), on, from_wan=on)
            )
        if (storage := await self._try("X_AVM-DE_Storage1", "GetInfo")) is not None:
            out.append(
                service(
                    "ftp",
                    ServiceKind.FTP,
                    SERVICE_PORTS[ServiceKind.FTP],
                    _flag(storage.get("NewFTPEnable")),
                    from_wan=False,
                )
            )
            wan = _flag(storage.get("NewFTPWANEnable"))
            out.append(
                service(
                    "ftp-internet",
                    ServiceKind.FTP,
                    _int(storage.get("NewFTPWANPort")),
                    wan,
                    from_wan=wan,
                    encrypted=True if _flag(storage.get("NewFTPWANSSLOnly")) else None,
                )
            )
        return out

    async def _uplinks(self) -> list[Uplink]:
        """The internet connection (#148); a box without these services reports none."""
        if self.context.role is not DeviceRole.GATEWAY:
            return []
        ppp = ip = link = None
        with contextlib.suppress(SoapFault, NotFound):
            ppp = await self.tr064.call("WANPPPConnection1", "GetInfo")
        with contextlib.suppress(SoapFault, NotFound):
            ip = await self.tr064.call("WANIPConnection1", "GetInfo")
        with contextlib.suppress(SoapFault, NotFound):
            link = await self.tr064.call("WANCommonInterfaceConfig1", "GetCommonLinkProperties")
        now = datetime.now(UTC).replace(microsecond=0)
        uplink = wan_uplink(self.context.device_id, ppp, ip, link or {}, now)
        return [uplink] if uplink else []

    # firewall -------------------------------------------------------------------------

    async def read_firewall(self) -> Observation:
        """The box's fixed behaviour and its port sharing (#135). TR-064 has no filter rules:
        the policies are what a Fritz!Box always does (guest network and internet kept out of
        the LAN, the LAN allowed out); port sharing is ``GetGenericPortMappingEntry`` of the
        active internet connection, read until fault 713. IPv6 port sharing (pinholes) is not
        in TR-064, so the port forwards are never complete."""
        if self.context.role is not DeviceRole.GATEWAY:
            return Observation()  # an access point or repeater: no packet filter to report
        d = self.context.device_id
        uplinks = await self._uplinks()
        guest = False
        with contextlib.suppress(AdapterError):
            guest = any(w.guest for w in await self._wlans())
        zones = [FirewallZone(name="lan", segments=[self._native])]
        if guest:
            zones.append(FirewallZone(name="guest", segments=[self._guest]))
        wan = bool(uplinks)
        if wan:
            zones.append(FirewallZone(name="wan", uplinks=[u.id for u in uplinks], masquerade=True))
        policies = _fixed_policies(guest, wan)
        forwards: list[PortForward] = []
        gaps: list[Gap] = []
        if uplinks:
            service = str(uplinks[0].vendor_extra.get("service", "")).split(":")[0] + "1"
            rows, fault = await self._port_mappings(service)
            if fault is not None:
                gaps.append(fault)
            for row in rows:
                if (found := port_forward(row)) is not None:
                    forwards.append(found)
                else:
                    gaps.append(Gap(message="firewall: a port mapping without a usable target"))
        return Observation(
            firewalls=[
                Firewall(
                    id=firewall_id(d),
                    device_id=d,
                    zones=zones,
                    policies=policies,
                    rules=_guest_rules(guest),
                    nat=[],
                    port_forwards=forwards,
                    port_forwards_complete=False,  # IPv6 port sharing is not readable
                )
            ],
            incomplete=gaps,
        )

    async def _port_mappings(self, service: str) -> tuple[list[dict[str, str]], Gap | None]:
        """Every ``GetGenericPortMappingEntry`` of *service* until the box answers 713; a gap
        when it answers otherwise."""
        rows: list[dict[str, str]] = []
        for index in range(MAX_PORT_MAPPINGS):
            try:
                rows.append(
                    await self.tr064.call(
                        service, "GetGenericPortMappingEntry", NewPortMappingIndex=index
                    )
                )
            except SoapFault as exc:
                if exc.code in END_OF_ARRAY:
                    return rows, None
                return rows, Gap(
                    message=f"firewall: port sharing is not read ({exc})",
                    fix=f"Give the user the right {RIGHT!r} (see the setup guide)."
                    if exc.code == 606
                    else None,
                )
            except NotFound:
                return rows, Gap(message=f"firewall: this FRITZ!OS has no {service} port sharing")
        return rows, Gap(message=f"firewall: more than {MAX_PORT_MAPPINGS} port mappings")

    # dhcp -----------------------------------------------------------------------------

    async def _lan_values(self) -> dict[str, str]:
        """LANHostConfigManagement GetInfo, with GetAddressRange when it leaves the range out."""
        lan = await self._lan()
        if not (lan.get("NewMinAddress") and lan.get("NewMaxAddress")):
            with contextlib.suppress(SoapFault):
                lan |= await self.tr064.call("LANHostConfigManagement1", "GetAddressRange")
        return lan

    async def read_dhcp(self) -> Observation:
        d = self.context.device_id
        lan = await self._lan_values()
        enabled = _flag(lan.get("NewDHCPServerEnable"))
        first, last = _v4(lan.get("NewMinAddress")), _v4(lan.get("NewMaxAddress"))
        # The range is kept while the server is off (as on the box), so switching it back on
        # restores the same pool.
        pools = [DhcpPool(start=first, end=last)] if first and last else []
        routers = _v4_list(lan.get("NewIPRouters"))
        now = datetime.now(UTC)
        found: list[DhcpLease] = []
        leases: list[DhcpLease] | None = found
        try:
            hosts = await self._hosts()
        except AdapterError:  # the host list is a client matter: the server is read without
            leases, hosts = None, []
        for host in hosts:  # no lease table: the DHCP hosts of the host list (guess)
            mac, address = _mac(host.get("NewMACAddress")), _v4(host.get("NewIPAddress"))
            if mac is None or address is None:
                continue
            if host.get("NewAddressSource", "").strip().lower() != "dhcp":
                continue
            left = _int(host.get("NewLeaseTimeRemaining"))
            active = _flag(host.get("NewActive"))
            found.append(
                DhcpLease(
                    address=address,
                    mac=mac,
                    hostname=host.get("NewHostName") or None,
                    state=LeaseState.ACTIVE if active else LeaseState.EXPIRED,
                    expires=now + timedelta(seconds=left) if active and left else None,
                )
            )
        server = DhcpServer(
            id=object_id(d, "dhcp", "lan"),
            device_id=d,
            segment_id=self._native,
            enabled=enabled,
            pools=pools,
            router=routers[0] if routers else None,
            dns_servers=list(_v4_list(lan.get("NewDNSServers"))),
            domain=lan.get("NewDomainName") or None,
            leases=leases,
            vendor_extra={"reservations": "not exposed by TR-064"},
        )
        # NewDHCPRelay: the box relays instead of serving; the server address is not exposed
        relays = (
            [
                DhcpRelay(
                    id=object_id(d, "dhcp-relay", "lan"),
                    device_id=d,
                    segment_id=self._native,
                    enabled=True,
                )
            ]
            if _flag(lan.get("NewDHCPRelay"))
            else []
        )
        return Observation(dhcp_servers=[server], dhcp_relays=relays)

    # wireless -------------------------------------------------------------------------

    def _radio_ids(self, wlans: list[WlanService]) -> dict[int, str]:
        """WLAN index -> radio id; the guest WLAN shares the radio of its band."""
        d = self.context.device_id
        count = len(wlans)
        by_band: dict[Band, str] = {}
        for w in wlans:
            if not w.guest:
                by_band.setdefault(
                    band(w.info, w.index, count), object_id(d, "radio", str(w.index))
                )
        out: dict[int, str] = {}
        for w in wlans:
            b = band(w.info, w.index, count)
            if w.guest:
                out[w.index] = by_band.get(b) or next(iter(by_band.values()), "")
            else:
                out[w.index] = object_id(d, "radio", str(w.index))
        return out

    async def _passphrase(self, wlan: WlanService) -> str | None:
        try:
            keys = await self.tr064.call(wlan.service, "GetSecurityKeys")
        except (SoapFault, AuthFailed) as exc:
            raise AdapterError(
                f"{wlan.service} GetSecurityKeys refused ({exc}); give the Fritz!Box user "
                f"the right '{RIGHT}' to compare Wi-Fi passphrases"
            ) from exc
        return keys.get("NewKeyPassphrase") or None

    async def _wps(self, wlan: WlanService) -> Wps | None:
        """``X_AVM-DE_GetWPSInfo``; None when the box has no such action."""
        try:
            answer = await self.tr064.call(wlan.service, "X_AVM-DE_GetWPSInfo")
        except SoapFault as exc:
            if exc.code == 401:
                return None
            raise
        return wps_of(answer.get("NewX_AVM-DE_WPSMode"), answer.get("NewX_AVM-DE_WPSStatus"))

    async def _advertised(self, wlan: WlanService) -> bool | None:
        """Whether the SSID is broadcast; None when the box has no such action."""
        try:
            answer = await self.tr064.call(wlan.service, "GetBeaconAdvertisement")
        except SoapFault as exc:
            if exc.code == 401:
                return None
            raise
        return _flag(answer.get("NewBeaconAdvertisementEnabled", "1"))

    async def read_wireless(self) -> Observation:
        d = self.context.device_id
        wlans = await self._wlans()
        radio_ids = self._radio_ids(wlans)
        radios: list[Radio] = []
        out: list[Wlan] = []
        for w in wlans:
            info = w.info
            on = _flag(info.get("NewEnable"))
            hidden = await self._advertised(w) is False
            if not w.guest:
                radios.append(
                    Radio(
                        id=radio_ids[w.index],
                        device_id=d,
                        name=f"{band(info, w.index, len(wlans)).value} GHz",
                        band=band(info, w.index, len(wlans)),
                        channel=_int(info.get("NewChannel")) or None,
                        enabled=on,
                        supported_security=supported_security(
                            info.get("NewX_AVM-DE_PossibleBeaconTypes")
                        ),
                        vendor_extra=_extra(info, "NewStandard", "NewX_AVM-DE_FrequencyBand"),
                    )
                )
            if not radio_ids[w.index]:
                continue  # a guest WLAN on a box without any other radio: nothing to attach to
            ssid = info.get("NewSSID", "")
            sec = security(info.get("NewBeaconType"), info.get("NewBasicEncryptionModes"))
            fingerprint = digest = None
            wps = None
            if sec in PERSONAL:
                key = await self._passphrase(w)
                fingerprint = passphrase_fingerprint(ssid, key) if key else None
                digest = passphrase_digest(key) if key else None
                wps = await self._wps(w)
            out.append(
                Wlan(
                    id=object_id(d, "wlan", str(w.index)),
                    device_id=d,
                    ssid=ssid,
                    radio_id=radio_ids[w.index],
                    enabled=_wlan_on(info),
                    hidden=hidden,
                    security=sec,
                    passphrase_fingerprint=fingerprint,
                    passphrase_digest=digest,
                    ciphers=[Cipher.WEP] if sec is Security.WEP else None,
                    wps=wps,
                    segment_id=self._guest if w.guest else self._native,
                    purpose=SegmentPurpose.GUEST if w.guest else None,
                    purpose_source=PurposeSource.REPORTED if w.guest else None,
                    vendor_extra=_extra(info, "NewBeaconType", "NewStandard", "NewBSSID")
                    | ({"guest": True} if w.guest else {}),
                )
            )
        return Observation(radios=radios, wlans=out)

    # clients --------------------------------------------------------------------------

    async def _hosts(self) -> list[dict[str, str]]:
        """The host table, read once per observation (DHCP and clients both use it)."""
        if self._host_cache is None:
            self._host_cache = await self._read_hosts()
        return self._host_cache

    async def _read_hosts(self) -> list[dict[str, str]]:
        """The host table: the XML list behind X_AVM-DE_GetHostListPath (one request), else
        GetGenericHostEntry for every index."""
        try:
            answer = await self.tr064.call("Hosts1", "X_AVM-DE_GetHostListPath")
        except SoapFault as exc:
            if exc.code not in (401, 501):
                raise
        else:
            path = answer.get("NewX_AVM-DE_HostListPath", "")
            root = await self.tr064.get_xml(path, "Hosts1 host list")
            return [
                {f"New{child.tag}": (child.text or "").strip() for child in item}
                for item in root
                if item.tag == "Item"
            ]
        count = _int(
            (await self.tr064.call("Hosts1", "GetHostNumberOfEntries")).get(
                "NewHostNumberOfEntries"
            )
        )
        if count is None:
            raise AdapterError("Hosts1 GetHostNumberOfEntries: unexpected answer")
        return [
            await self.tr064.call("Hosts1", "GetGenericHostEntry", NewIndex=i) for i in range(count)
        ]

    async def read_clients(self) -> Observation:
        d = self.context.device_id
        clients: dict[str, dict[str, Any]] = {}
        for w in await self._wlans():
            total = _int(
                (await self.tr064.call(w.service, "GetTotalAssociations")).get(
                    "NewTotalAssociations"
                )
            )
            for i in range(total or 0):
                assoc = await self.tr064.call(
                    w.service, "GetGenericAssociatedDeviceInfo", NewAssociatedDeviceIndex=i
                )
                mac = _mac(assoc.get("NewAssociatedDeviceMACAddress"))
                if mac is None:
                    continue
                entry = clients.setdefault(mac, {"addresses": []})
                entry["seen_on"] = object_id(d, "wlan", str(w.index))
                entry["segment_id"] = self._guest if w.guest else self._native
                if (a := _v4(assoc.get("NewAssociatedDeviceIPAddress"))) is not None:
                    entry["addresses"].append(a)
        for host in await self._hosts():
            mac = _mac(host.get("NewMACAddress"))
            if mac is None or not (_flag(host.get("NewActive")) or mac in clients):
                continue  # the box remembers hosts long gone: only active ones are clients
            entry = clients.setdefault(mac, {"addresses": []})
            if (a := _v4(host.get("NewIPAddress"))) is not None and a not in entry["addresses"]:
                entry["addresses"].append(a)
            if host.get("NewHostName"):
                entry["hostname"] = host["NewHostName"]
            kind = host.get("NewInterfaceType", "").strip()
            if kind.lower() == "ethernet":
                entry.setdefault("seen_on", port_id(d, "lan"))
                entry.setdefault("segment_id", self._native)
            entry.setdefault("vendor_extra", {})
            if kind:
                entry["vendor_extra"]["interface_type"] = kind
            if a is not None and host.get("NewAddressSource"):
                entry.setdefault("address_sources", {})[a] = _ADDRESS_SOURCE.get(
                    str(host["NewAddressSource"]).strip().lower(), AddressSource.UNKNOWN
                )
        return Observation(
            clients=[
                Client(id=object_id(d, "client", m), mac=m, **fields)
                for m, fields in sorted(clients.items())
            ]
        )

    # writing --------------------------------------------------------------------------

    async def _wlan_current(self, wlan: WlanService) -> dict[str, str]:
        """GetInfo of one WLAN with ``NewEnable`` as read and the beacon advertisement."""
        current = dict(wlan.info)
        current["NewEnable"] = "1" if _wlan_on(wlan.info) else "0"
        advertised = await self._advertised(wlan)
        if advertised is not None:
            current["NewBeaconAdvertisementEnabled"] = "1" if advertised else "0"
        return current

    async def _current_passphrase(self, service: str) -> str | None:
        """The passphrase a WLAN has now (to skip an unchanged one); None if not readable."""
        try:
            keys = await self.tr064.call(service, "GetSecurityKeys")
        except SoapFault:
            return None
        return keys.get("NewKeyPassphrase") or None

    async def _calls(self, changes: list[Change], secrets: Mapping[str, str]) -> list[Call]:
        """Read the current values, then the TR-064 calls that make the changes."""
        for c in changes:
            if c.kind not in self.manifest.writes:
                raise AdapterError(
                    f"{c.key}: the Fritz!Box integration cannot change {c.kind.value} "
                    "(not offered by TR-064)"
                )
            if c.kind is ChangeKind.WLAN:
                check_wlan(c)
            elif c.key != self._native:
                raise AdapterError(
                    f"{c.key}: the Fritz!Box has one DHCP server, on its LAN ({self._native})"
                )
        calls: list[Call] = []
        lan: dict[str, str] | None = None
        wlans: dict[int, dict[str, str]] | None = None
        for c in changes:
            if c.kind is ChangeKind.DHCP:
                lan = lan if lan is not None else await self._lan_values()
                wanted = dhcp_wanted(c, lan)
                calls += lan_calls(lan, wanted)
                lan = lan | wanted  # a later change in the same list starts from this
                continue
            if wlans is None:
                wlans = {w.index: await self._wlan_current(w) for w in await self._wlans()}
            assert isinstance(c.old, WlanValue)
            targets = [i for i, cur in wlans.items() if cur.get("NewSSID") == c.old.ssid]
            if not targets:
                raise AdapterError(f"SSID {c.old.ssid}: no Wi-Fi network of the Fritz!Box has it")
            for index in targets:
                service = f"WLANConfiguration{index}"
                current = wlans[index]
                wanted = wlan_wanted(
                    c,
                    current,
                    security(current.get("NewBeaconType"), current.get("NewBasicEncryptionModes")),
                    secrets,
                )
                passphrase = None
                if "NewKeyPassphrase" in wanted:
                    passphrase = await self._current_passphrase(service)
                calls += wlan_calls(service, current, wanted, passphrase)
                wanted.pop("NewKeyPassphrase", None)
                wlans[index] = current | wanted
        return calls

    async def _send(self, calls: list[Call]) -> list[VendorCall]:
        sent = []
        for call in calls:
            try:
                await self.tr064.call(call.service, call.action, **call.args)
            except SoapFault as exc:
                raise AdapterError(f"{call.description}: refused by the Fritz!Box ({exc})") from exc
            sent.append(call.vendor())
        return sent

    async def plan_changes(
        self, changes: list[Change], secrets: Mapping[str, str]
    ) -> list[VendorCall]:
        return [call.vendor() for call in await self._calls(changes, secrets)]

    async def backup(self) -> Backup:
        """The TR-064 values of every setting the adapter may change.

        Passphrases are included (backups are stored encrypted and never leave the server).
        A full configuration export (``DeviceConfig X_AVM-DE_GetConfigFile``) needs an export
        password and can only be restored as a whole, with a reboot, so it is not used.
        """
        lan = await self._lan_values()
        wlans: dict[int, dict[str, str]] = {}
        for w in await self._wlans():
            values = await self._wlan_current(w)
            passphrase = await self._current_passphrase(w.service)
            if passphrase is not None:
                values["NewKeyPassphrase"] = passphrase
            wlans[w.index] = values
        return Backup(
            device_id=self.context.device_id,
            taken_at=datetime.now(UTC),
            format=BACKUP_FORMAT,
            content=backup_content(lan, wlans),
        )

    async def apply(
        self, changes: list[Change], secrets: Mapping[str, str], rollback_seconds: int
    ) -> ApplyResult:
        """Send the calls one after another.

        TR-064 has no transaction and no rollback timer, so ``confirm_deadline`` stays None;
        a failure is undone by the deployer (inverse changes, then :meth:`restore`).
        """
        return ApplyResult(calls=await self._send(await self._calls(changes, secrets)))

    async def confirm(self) -> None:
        """Nothing to confirm: the Fritz!Box applies TR-064 settings at once."""

    async def restore(self, backup: Backup) -> None:
        if backup.format != BACKUP_FORMAT:
            raise AdapterError(f"backup format {backup.format!r} is not {BACKUP_FORMAT!r}")
        lan_wanted, wlans_wanted = parse_backup(backup.content)
        calls = lan_calls(await self._lan_values(), lan_wanted)
        have = {w.index: w for w in await self._wlans()}
        missing = sorted(set(wlans_wanted) - set(have))
        if missing:
            raise AdapterError(
                "the backup holds WLANConfiguration "
                + ", ".join(str(i) for i in missing)
                + ", which this Fritz!Box does not have"
            )
        for index, wanted in sorted(wlans_wanted.items()):
            wlan = have[index]
            passphrase = None
            if "NewKeyPassphrase" in wanted:
                passphrase = await self._current_passphrase(wlan.service)
            calls += wlan_calls(wlan.service, await self._wlan_current(wlan), wanted, passphrase)
        await self._send(calls)
