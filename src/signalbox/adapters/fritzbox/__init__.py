"""AVM Fritz!Box (read): LAN, DHCP, Wi-Fi and hosts over TR-064 (SOAP over HTTPS).

The SOAP side is :mod:`signalbox.adapters.fritzbox.soap`, the HTTPS side (probe, pin, errors)
:class:`signalbox.adapters.https.DeviceHttp`. Authentication is HTTP Digest with a dedicated
Fritz!Box user. Every action and the arguments it is assumed to return are listed in
``docs/adapters/fritzbox.md``; they come from AVM's TR-064 documentation and still need
confirmation on a real device.

Mapping in short: the LAN is the native segment with one bridge port ``lan`` (TR-064 has no
per-port view), its subnet from ``IPRouters``/``SubnetMask``; every ``WLANConfiguration<n>`` is
a WLAN, the non-guest ones also a radio; the guest WLAN gets its own segment
``<site>/segment/guest``. DHCP reservations, DNS and LLDP are not exposed by TR-064.
"""

from __future__ import annotations

import contextlib
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Interface, ip_address
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import httpx
from pydantic import Field, JsonValue, SecretStr, field_validator, model_validator

from signalbox.adapters import (
    Adapter,
    AdapterConfig,
    AdapterContext,
    AdapterError,
    AuthFailed,
    Capability,
    Manifest,
    Observation,
    SystemInfo,
)
from signalbox.adapters.fritzbox.soap import SoapFault, Tr064
from signalbox.adapters.https import DeviceHttp, NotFound
from signalbox.model import (
    Band,
    Client,
    DeviceRole,
    DhcpPool,
    DhcpServer,
    Firmware,
    Membership,
    Port,
    PortKind,
    PortMembership,
    Radio,
    Security,
    Segment,
    Subnet,
    Wlan,
    normalise_mac,
    object_id,
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


class FritzboxConfig(AdapterConfig):
    url: str = Field(
        description="TR-064 over HTTPS, for example https://192.0.2.1:49443 (no port: 49443)"
    )
    username: str = Field(
        default="signalbox", description="Fritz!Box user with the right 'FRITZ!Box settings'"
    )
    password: SecretStr = Field(description="Password of that user")
    allow_insecure_http: bool = Field(
        default=False,
        description="Allow plain http:// (simulators and tests only: no encryption at all)",
    )

    @field_validator("url")
    @classmethod
    def _url(cls, value: str) -> str:
        parts = urlsplit(value.rstrip("/"))
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise ValueError("must be https://host[:port]")
        if parts.port is None and parts.scheme == "https":
            parts = parts._replace(netloc=f"{parts.netloc}:{DEFAULT_PORT}")
        return urlunsplit(parts._replace(path="", query="", fragment=""))

    @model_validator(mode="after")
    def _http_needs_opt_in(self) -> FritzboxConfig:
        if self.url.startswith("http://") and not self.allow_insecure_http:
            raise ValueError("plain http:// needs allow_insecure_http (simulators only)")
        return self


# --- mapping helpers ------------------------------------------------------------------------

#: ``NewBeaconType`` -> security. ``11i`` is WPA2, ``WPAand11i`` WPA+WPA2 (counted as WPA2,
#: like OpenWrt's psk-mixed), ``Basic`` is WEP.
BEACON_TYPES: dict[str, Security] = {
    "none": Security.OPEN,
    "basic": Security.OTHER,
    "wpa": Security.OTHER,
    "11i": Security.WPA2,
    "wpaand11i": Security.WPA2,
    "wpa3": Security.WPA3,
    "11iandwpa3": Security.WPA2_WPA3,
    "owe": Security.OWE,
    "owetrans": Security.OWE,
}
PERSONAL = {Security.WPA2, Security.WPA3, Security.WPA2_WPA3, Security.OTHER}
BANDS = {"2400": Band.GHZ_2_4, "5000": Band.GHZ_5, "6000": Band.GHZ_6}


def security(beacon_type: str | None) -> Security:
    return BEACON_TYPES.get((beacon_type or "none").strip().lower(), Security.OTHER)


def _flag(value: str | None) -> bool:
    return (value or "").strip().lower() in ("1", "true", "yes", "up")


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


def _extra(info: dict[str, str], *keys: str) -> dict[str, JsonValue]:
    return {k.removeprefix("New"): info[k] for k in keys if info.get(k)}


@dataclass
class WlanService:
    index: int
    info: dict[str, str]
    guest: bool

    @property
    def service(self) -> str:
        return f"WLANConfiguration{self.index}"


# --- the adapter ----------------------------------------------------------------------------


class FritzboxAdapter(Adapter):
    manifest = Manifest(
        id="fritzbox",
        name="AVM Fritz!Box",
        version="0.1.0",
        api_version="1.0",
        vendor="AVM",
        roles=frozenset({DeviceRole.GATEWAY, DeviceRole.AP}),
        capabilities=frozenset(
            {Capability.INTERFACES, Capability.DHCP, Capability.WIRELESS, Capability.CLIENTS}
        ),
        config=FritzboxConfig,
        description="Reads a Fritz!Box over TR-064 (SOAP over HTTPS) with a dedicated user.",
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
        info = await self.tr064.call("DeviceInfo1", "GetInfo")
        version = info.get("NewSoftwareVersion")
        return SystemInfo(
            vendor=info.get("NewManufacturerName") or "AVM",
            model=info.get("NewModelName") or None,
            firmware=Firmware(current=version) if version else None,
            management_address=self.http.host,
        )

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

        speed = _int(eth.get("NewMaxBitRate"))
        duplex = eth.get("NewDuplexMode", "").strip().lower()
        port = Port(
            id=port_id(d, "lan"),
            device_id=d,
            name="lan",
            kind=PortKind.BRIDGE,
            up=eth.get("NewStatus", "").strip().lower() == "up" if eth.get("NewStatus") else None,
            speed_mbps=speed,
            full_duplex={"full": True, "half": False}.get(duplex),
            mac=_mac(eth.get("NewMACAddress")),
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
        return Observation(ports=[port], segments=segments, subnets=subnets)

    # dhcp -----------------------------------------------------------------------------

    async def read_dhcp(self) -> Observation:
        d = self.context.device_id
        lan = await self._lan()
        if not (lan.get("NewMinAddress") and lan.get("NewMaxAddress")):
            with contextlib.suppress(SoapFault):
                lan |= await self.tr064.call("LANHostConfigManagement1", "GetAddressRange")
        enabled = _flag(lan.get("NewDHCPServerEnable"))
        first, last = _v4(lan.get("NewMinAddress")), _v4(lan.get("NewMaxAddress"))
        pools = [DhcpPool(start=first, end=last)] if enabled and first and last else []
        routers = _v4_list(lan.get("NewIPRouters"))
        server = DhcpServer(
            id=object_id(d, "dhcp", "lan"),
            device_id=d,
            segment_id=self._native,
            enabled=enabled,
            pools=pools,
            router=routers[0] if routers else None,
            dns_servers=list(_v4_list(lan.get("NewDNSServers"))),
            domain=lan.get("NewDomainName") or None,
            vendor_extra={"reservations": "not exposed by TR-064"},
        )
        return Observation(dhcp_servers=[server])

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

    async def read_wireless(self) -> Observation:
        d = self.context.device_id
        wlans = await self._wlans()
        radio_ids = self._radio_ids(wlans)
        radios: list[Radio] = []
        out: list[Wlan] = []
        for w in wlans:
            info = w.info
            on = _flag(info.get("NewEnable"))
            if not w.guest:
                radios.append(
                    Radio(
                        id=radio_ids[w.index],
                        device_id=d,
                        name=f"{band(info, w.index, len(wlans)).value} GHz",
                        band=band(info, w.index, len(wlans)),
                        channel=_int(info.get("NewChannel")) or None,
                        enabled=on,
                        vendor_extra=_extra(info, "NewStandard", "NewX_AVM-DE_FrequencyBand"),
                    )
                )
            if not radio_ids[w.index]:
                continue  # a guest WLAN on a box without any other radio: nothing to attach to
            ssid = info.get("NewSSID", "")
            sec = security(info.get("NewBeaconType"))
            fingerprint = None
            if sec in PERSONAL:
                key = await self._passphrase(w)
                fingerprint = passphrase_fingerprint(ssid, key) if key else None
            out.append(
                Wlan(
                    id=object_id(d, "wlan", str(w.index)),
                    device_id=d,
                    ssid=ssid,
                    radio_id=radio_ids[w.index],
                    enabled=on and info.get("NewStatus", "Up").strip().lower() != "disabled",
                    security=sec,
                    passphrase_fingerprint=fingerprint,
                    segment_id=self._guest if w.guest else self._native,
                    vendor_extra=_extra(info, "NewBeaconType", "NewStandard", "NewBSSID")
                    | ({"guest": True} if w.guest else {}),
                )
            )
        return Observation(radios=radios, wlans=out)

    # clients --------------------------------------------------------------------------

    async def _hosts(self) -> list[dict[str, str]]:
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
            if host.get("NewAddressSource"):
                entry["vendor_extra"]["address_source"] = host["NewAddressSource"]
        return Observation(
            clients=[
                Client(id=object_id(d, "client", m), mac=m, **fields)
                for m, fields in sorted(clients.items())
            ]
        )
