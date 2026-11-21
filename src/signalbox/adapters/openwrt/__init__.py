"""OpenWrt (read): ubus JSON-RPC through rpcd/uhttpd at ``/ubus``, HTTPS pinned by fingerprint.

The HTTPS side (probe, pin, errors) is :class:`signalbox.adapters.https.DeviceHttp`.

Every call and the JSON it expects is documented in ``docs/adapters/openwrt.md``.
"""

from __future__ import annotations

import contextlib
import re
from dataclasses import dataclass, field
from ipaddress import IPv4Interface, ip_address, ip_interface
from typing import Any
from urllib.parse import urlsplit

from pydantic import Field, JsonValue, SecretStr

from signalbox.adapters import (
    Adapter,
    AdapterConfig,
    AdapterError,
    Capability,
    Manifest,
    Observation,
    SystemInfo,
)
from signalbox.adapters.https import DeviceHttp
from signalbox.adapters.openwrt.ubus import AccessDenied, NotFound, Ubus
from signalbox.model import (
    Band,
    Client,
    DeviceRole,
    DhcpPool,
    DhcpServer,
    Firmware,
    IPAddress,
    IPInterface,
    Membership,
    Neighbour,
    Pmf,
    Port,
    PortKind,
    PortMembership,
    Radio,
    Reservation,
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

__all__ = ["OpenWrtAdapter", "OpenWrtConfig"]


class OpenWrtConfig(AdapterConfig):
    url: str = Field(description="ubus endpoint, for example https://192.0.2.2/ubus")
    username: str = Field(default="signalbox", description="rpcd login with a read-only ACL")
    password: SecretStr
    allow_insecure_http: bool = Field(
        default=False, description="accept an http:// URL (password sent in clear text)"
    )


# --- small helpers ------------------------------------------------------------------------


def _list(value: Any) -> list[str]:
    """UCI options are strings or lists; a space-separated string is a list too."""
    if isinstance(value, list):
        return [str(v) for v in value]
    if isinstance(value, str):
        return value.split()
    return []


def _flag(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    return str(value).lower() in ("1", "true", "yes", "on", "enabled")


def _int(value: Any) -> int | None:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return None


def _mac(value: Any) -> str | None:
    try:
        return normalise_mac(str(value))
    except ValueError:
        return None


def _sections(uci: dict[str, Any], kind: str) -> list[tuple[str, dict[str, Any]]]:
    values = uci.get("values")
    if not isinstance(values, dict):
        raise AdapterError("unexpected answer to uci.get")
    found = [
        (str(s.get(".name", name)), s)
        for name, s in values.items()
        if isinstance(s, dict) and s.get(".type") == kind
    ]
    return sorted(found, key=lambda item: _int(item[1].get(".index")) or 0)


def _extra(section: dict[str, Any], *keys: str) -> dict[str, JsonValue]:
    return {k: section[k] for k in keys if isinstance(section.get(k), str | int | bool)}


def lease_seconds(text: Any) -> int | None:
    """dnsmasq lease time: ``3600``, ``30m``, ``12h``, ``1d``, ``1w``; ``infinite`` is None."""
    match = re.fullmatch(r"(\d+)([smhdw]?)", str(text).strip().lower())
    if not match:
        return None
    unit = {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}[match.group(2)]
    return int(match.group(1)) * unit


ENCRYPTION = {
    "none": Security.OPEN,
    "owe": Security.OWE,
    "psk": Security.OTHER,  # WPA1
    "psk2": Security.WPA2,
    "psk-mixed": Security.WPA2,
    "sae": Security.WPA3,
    "sae-mixed": Security.WPA2_WPA3,
    "wpa": Security.WPA2_ENTERPRISE,
    "wpa2": Security.WPA2_ENTERPRISE,
    "wpa-mixed": Security.WPA2_ENTERPRISE,
    "wpa3": Security.WPA3_ENTERPRISE,
    "wpa3-mixed": Security.WPA3_ENTERPRISE,
    "wpa3-192": Security.WPA3_ENTERPRISE,
}
PERSONAL = {Security.WPA2, Security.WPA3, Security.WPA2_WPA3, Security.OTHER}
PMF = {"0": Pmf.DISABLED, "1": Pmf.OPTIONAL, "2": Pmf.REQUIRED}
#: hostapd.sh default of ieee80211w when the option is not set.
PMF_DEFAULT = {
    Security.WPA3: Pmf.REQUIRED,
    Security.OWE: Pmf.REQUIRED,
    Security.WPA3_ENTERPRISE: Pmf.REQUIRED,
    Security.WPA2_WPA3: Pmf.OPTIONAL,
}
BANDS = {"2g": Band.GHZ_2_4, "5g": Band.GHZ_5, "6g": Band.GHZ_6}


def security(encryption: Any) -> Security:
    base = str(encryption or "none").split("+", 1)[0]
    return ENCRYPTION.get(base, Security.OTHER)


def band(section: dict[str, Any]) -> Band | None:
    if "band" in section:
        return BANDS.get(str(section["band"]))
    hwmode = str(section.get("hwmode", ""))  # before OpenWrt 21.02
    if hwmode == "11a":
        return Band.GHZ_5
    if hwmode in ("11g", "11b", "11n"):
        return Band.GHZ_2_4
    channel = _int(section.get("channel"))
    if channel is not None:
        return Band.GHZ_5 if channel > 14 else Band.GHZ_2_4
    return None


def width(htmode: Any) -> int | None:
    if not htmode:
        return None
    if str(htmode).upper() == "NOHT":
        return 20
    match = re.search(r"(\d+)", str(htmode))
    return int(match.group(1)) if match else None


def bridge_vlans(
    sections: list[tuple[str, dict[str, Any]]],
) -> dict[str, dict[int, list[tuple[str, Membership]]]]:
    """``bridge-vlan`` sections as bridge -> vlan -> [(port, mode)].

    Port suffixes: ``:t`` tagged, ``:u`` untagged, ``*`` primary VLAN (PVID). Without a suffix
    netifd makes a port untagged if it is in only one VLAN of the bridge, tagged otherwise.
    """
    raw: dict[str, dict[int, list[tuple[str, str]]]] = {}
    for _, s in sections:
        vid = _int(s.get("vlan"))
        if vid is None or not s.get("device"):
            continue
        for entry in _list(s.get("ports")):
            name, _, flags = entry.partition(":")
            raw.setdefault(str(s["device"]), {}).setdefault(vid, []).append((name, flags))
    out: dict[str, dict[int, list[tuple[str, Membership]]]] = {}
    for bridge, vlans in raw.items():
        count: dict[str, int] = {}
        for members in vlans.values():
            for name, _ in members:
                count[name] = count.get(name, 0) + 1
        for vid, members in vlans.items():
            resolved: list[tuple[str, Membership]] = []
            for name, flags in members:
                if "t" in flags:
                    mode = Membership.TAGGED
                elif "u" in flags or count[name] == 1:
                    mode = Membership.UNTAGGED
                else:
                    mode = Membership.TAGGED
                resolved.append((name, mode))
            out.setdefault(bridge, {})[vid] = resolved
    return out


_NATIVE: int = 0  # marker for "the untagged network" in the device-to-VLAN map


@dataclass
class NetworkView:
    """The UCI ``network`` config and the running interfaces, as one lookup."""

    bridges: dict[str, list[str]] = field(default_factory=dict)
    vlans: dict[str, dict[int, list[tuple[str, Membership]]]] = field(default_factory=dict)
    #: UCI interface name -> device name
    devices: dict[str, str] = field(default_factory=dict)
    #: running interface (``network.interface dump``) by name
    running: dict[str, dict[str, Any]] = field(default_factory=dict)

    @classmethod
    def build(cls, uci: dict[str, Any], dump: dict[str, Any] | None = None) -> NetworkView:
        view = cls()
        for _, s in _sections(uci, "device"):
            if s.get("type") == "bridge" and s.get("name"):
                view.bridges[str(s["name"])] = _list(s.get("ports"))
        view.vlans = bridge_vlans(_sections(uci, "bridge-vlan"))
        for name, s in _sections(uci, "interface"):
            dev = s.get("device") or s.get("ifname")
            if isinstance(dev, str) and dev:
                view.devices[name] = dev.split()[0]
        if dump is not None:
            entries = dump.get("interface")
            if not isinstance(entries, list):
                raise AdapterError("unexpected answer to network.interface dump")
            for entry in entries:
                if isinstance(entry, dict) and isinstance(entry.get("interface"), str):
                    view.running[entry["interface"]] = entry
                    dev = entry.get("l3_device") or entry.get("device")
                    if isinstance(dev, str) and entry["interface"] not in view.devices:
                        view.devices[entry["interface"]] = dev
        return view

    def vlan_of_device(self, dev: str) -> int | None:
        """VLAN id of a device, ``_NATIVE`` for an unfiltered bridge, None if not a segment."""
        bridge, _, vid = dev.partition(".")
        if bridge in self.vlans:
            number = _int(vid) if vid else None
            return number if number in self.vlans[bridge] else None
        if bridge in self.bridges and not vid:
            return _NATIVE
        return None

    def vlan_of_interface(self, name: str) -> int | None:
        dev = self.devices.get(name)
        return self.vlan_of_device(dev) if dev else None

    def segment_names(self) -> dict[int, str]:
        names: dict[int, str] = {}
        for name in sorted(self.devices):
            vid = self.vlan_of_interface(name)
            if vid is not None:
                names.setdefault(vid, name)
        return names

    def addresses(self, name: str) -> list[IPInterface]:
        entry = self.running.get(name, {})
        out: list[IPInterface] = []
        for key in ("ipv4-address", "ipv6-address"):
            for a in entry.get(key) or []:
                try:
                    out.append(ip_interface(f"{a['address']}/{a['mask']}"))
                except (KeyError, TypeError, ValueError):
                    continue
        return out

    def has_default_route(self, name: str) -> bool:
        routes = self.running.get(name, {}).get("route") or []
        return any(
            isinstance(r, dict) and r.get("mask") == 0 and r.get("target") in ("0.0.0.0", "::")
            for r in routes
        )


def _speed(text: Any) -> tuple[int | None, bool | None]:
    match = re.fullmatch(r"(-?\d+)([FH])", str(text or ""))
    if not match or int(match.group(1)) <= 0:
        return None, None
    return int(match.group(1)), match.group(2) == "F"


def _port_kind(name: str, status: dict[str, Any]) -> PortKind:
    if status.get("type") == "bridge":
        return PortKind.BRIDGE
    if status.get("wireless") or name.startswith(("phy", "wlan")):
        return PortKind.WIRELESS
    return PortKind.ETHERNET


# --- the adapter --------------------------------------------------------------------------


class OpenWrtAdapter(Adapter):
    manifest = Manifest(
        id="openwrt",
        name="OpenWrt",
        version="0.1.0",
        api_version="1.0",
        vendor="OpenWrt",
        roles=frozenset({DeviceRole.AP, DeviceRole.SWITCH, DeviceRole.GATEWAY}),
        capabilities=frozenset(
            {
                Capability.INTERFACES,
                Capability.WIRELESS,
                Capability.DHCP,
                Capability.CLIENTS,
                Capability.NEIGHBOURS,
            }
        ),
        config=OpenWrtConfig,
        description="Reads OpenWrt 21.02+ over ubus JSON-RPC (rpcd) with a read-only ACL.",
    )

    _ubus: Ubus | None = None

    @property
    def config(self) -> OpenWrtConfig:
        assert isinstance(self.context.config, OpenWrtConfig)
        return self.context.config

    @property
    def ubus(self) -> Ubus:
        if self._ubus is None:
            cfg = self.config
            parts = urlsplit(cfg.url)
            http = DeviceHttp(
                f"{parts.scheme}://{parts.netloc}",
                pinned_fingerprint=self.context.pinned_fingerprint,
                timeout=self.context.timeout,
                allow_insecure_http=cfg.allow_insecure_http,
            )
            path = parts.path or "/ubus"
            self._ubus = Ubus(http, path, cfg.username, cfg.password.get_secret_value())
        return self._ubus

    async def close(self) -> None:
        if self._ubus is not None:
            await self._ubus.http.close()

    def _seg(self, vid: int) -> str:
        return segment_id(self.context.site_id, None if vid == _NATIVE else vid)

    async def _network(self, running: bool = True) -> NetworkView:
        uci = await self.ubus.call("uci", "get", {"config": "network"})
        dump = await self.ubus.call("network.interface", "dump") if running else None
        return NetworkView.build(uci, dump)

    # system ---------------------------------------------------------------------------

    async def read_system(self) -> SystemInfo:
        # A new observation: probe the certificate again (the ubus session stays valid).
        await self.ubus.http.reset()
        board = await self.ubus.call("system", "board")
        release = board.get("release") if isinstance(board.get("release"), dict) else {}
        version = release.get("version")
        model = board.get("model")
        return SystemInfo(
            vendor=None,
            model=model if isinstance(model, str) else None,
            firmware=Firmware(current=str(version)) if version else None,
            management_address=self.ubus.http.host,
        )

    # interfaces -----------------------------------------------------------------------

    async def read_interfaces(self) -> Observation:
        d = self.context.device_id
        status = await self.ubus.call("network.device", "status")
        view = await self._network()
        ports: dict[str, Port] = {}
        for name, st in sorted(status.items()):
            if not isinstance(st, dict) or name == "lo" or "." in name:
                continue
            speed, duplex = _speed(st.get("speed"))
            up = st.get("carrier", st.get("up"))
            ports[name] = Port(
                id=port_id(d, name),
                device_id=d,
                name=name,
                kind=_port_kind(name, st),
                up=up if isinstance(up, bool) else None,
                speed_mbps=speed,
                full_duplex=duplex,
                mac=_mac(st.get("macaddr")),
                vendor_extra=_extra(st, "type", "mtu"),
            )

        def ensure(name: str) -> str:
            if name not in ports:
                ports[name] = Port(id=port_id(d, name), device_id=d, name=name)
            return ports[name].id

        names = view.segment_names()
        members: dict[int, dict[str, Membership]] = {}
        for vlans in view.vlans.values():
            for vid, entries in vlans.items():
                for name, mode in entries:
                    members.setdefault(vid, {})[ensure(name)] = mode
        for bridge, bridge_ports in view.bridges.items():
            if bridge not in view.vlans:
                for name in bridge_ports:
                    members.setdefault(_NATIVE, {})[ensure(name)] = Membership.UNTAGGED
        segments = [
            Segment(
                id=self._seg(vid),
                site_id=self.context.site_id,
                vlan=None if vid == _NATIVE else vid,
                name=names.get(vid),
                members=[PortMembership(port_id=p, mode=m) for p, m in sorted(mem.items())],
            )
            for vid, mem in sorted(members.items())
        ]
        router = self.context.role is DeviceRole.GATEWAY
        subnets = [
            Subnet(
                id=object_id(d, "subnet", f"{name}-{n}"),
                segment_id=self._seg(svid),
                interface=addr,
                device_id=d,
                gateway=router and not view.has_default_route(name),
            )
            for name in sorted(view.running)
            if (svid := view.vlan_of_interface(name)) is not None
            for n, addr in enumerate(view.addresses(name))
        ]
        return Observation(ports=list(ports.values()), segments=segments, subnets=subnets)

    # wireless -------------------------------------------------------------------------

    async def _radios_up(self) -> dict[str, dict[str, Any]]:
        status = await self.ubus.call("network.wireless", "status")
        return {k: v for k, v in status.items() if isinstance(v, dict)}

    async def read_wireless(self) -> Observation:
        d = self.context.device_id
        uci = await self.ubus.call("uci", "get", {"config": "wireless"})
        up = await self._radios_up()
        view = await self._network(running=False)
        radios: dict[str, Radio] = {}
        for name, s in _sections(uci, "wifi-device"):
            b = band(s)
            if b is None:
                continue
            radios[name] = Radio(
                id=object_id(d, "radio", name),
                device_id=d,
                name=name,
                band=b,
                channel=_int(s.get("channel")),
                width_mhz=width(s.get("htmode")),
                tx_power_dbm=_int(s.get("txpower")),
                country=str(s["country"]) if s.get("country") else None,
                enabled=not _flag(s.get("disabled")) and bool(up.get(name, {}).get("up")),
                vendor_extra=_extra(s, "htmode", "type", "cell_density"),
            )
        wlans: list[Wlan] = []
        for name, s in _sections(uci, "wifi-iface"):
            radio = radios.get(str(s.get("device")))
            if radio is None or s.get("mode", "ap") != "ap":
                continue
            sec = security(s.get("encryption"))
            ssid = str(s.get("ssid", ""))
            key = s.get("key")
            networks = _list(s.get("network"))
            vid = view.vlan_of_interface(networks[0]) if networks else None
            pmf = PMF.get(str(s["ieee80211w"])) if "ieee80211w" in s else PMF_DEFAULT.get(sec)
            wlans.append(
                Wlan(
                    id=object_id(d, "wlan", name),
                    device_id=d,
                    ssid=ssid,
                    radio_id=radio.id,
                    enabled=radio.enabled and not _flag(s.get("disabled")),
                    security=sec,
                    pmf=pmf,
                    passphrase_fingerprint=(
                        passphrase_fingerprint(ssid, str(key)) if key and sec in PERSONAL else None
                    ),
                    segment_id=self._seg(vid) if vid is not None else None,
                    hidden=_flag(s.get("hidden")),
                    roaming_80211r=_flag(s.get("ieee80211r")),
                    roaming_80211k=_flag(s.get("ieee80211k")),
                    roaming_80211v=_flag(s.get("bss_transition", s.get("ieee80211v"))),
                    vendor_extra=_extra(s, "encryption", "network"),
                )
            )
        return Observation(radios=list(radios.values()), wlans=wlans)

    # dhcp -----------------------------------------------------------------------------

    async def read_dhcp(self) -> Observation:
        d = self.context.device_id
        uci = await self.ubus.call("uci", "get", {"config": "dhcp"})
        view = await self._network()
        hosts: list[tuple[str, IPAddress, str | None]] = []
        for _, s in _sections(uci, "host"):
            try:
                addr = ip_address(str(s.get("ip")))
            except ValueError:
                continue
            for mac in _list(s.get("mac")):
                if (m := _mac(mac)) is not None:
                    hosts.append((m, addr, str(s["name"]) if s.get("name") else None))
        servers: list[DhcpServer] = []
        for name, s in _sections(uci, "dhcp"):
            iface = str(s.get("interface", name))
            vid = view.vlan_of_interface(iface)
            v4 = [a for a in view.addresses(iface) if isinstance(a, IPv4Interface)]
            if vid is None or not v4:
                continue
            net = v4[0].network
            enabled = not _flag(s.get("ignore"))
            options = dict(opt.split(",", 1) for opt in _list(s.get("dhcp_option")) if "," in opt)
            pools: list[DhcpPool] = []
            start, limit = _int(s.get("start", 100)), _int(s.get("limit", 150))
            if enabled and start is not None and limit is not None and limit > 0:
                first = net.network_address + start
                last = min(first + limit - 1, net.broadcast_address - 1)
                pools.append(DhcpPool(start=first, end=last))
            router = options.get("3") or str(v4[0].ip)
            servers.append(
                DhcpServer(
                    id=object_id(d, "dhcp", name),
                    device_id=d,
                    segment_id=self._seg(vid),
                    enabled=enabled,
                    pools=pools,
                    lease_seconds=lease_seconds(s.get("leasetime", "12h")),
                    router=ip_address(router.split(",")[0]) if router else None,
                    dns_servers=[ip_address(x) for x in options.get("6", "").split(",") if x],
                    reservations=[
                        Reservation(mac=m, address=a, hostname=h) for m, a, h in hosts if a in net
                    ],
                    vendor_extra=_extra(s, "dhcpv6", "ra", "ra_management"),
                )
            )
        return Observation(dhcp_servers=servers)

    # clients --------------------------------------------------------------------------

    async def _leases(self) -> list[tuple[str, str, str | None]]:
        """(mac, address, hostname) from luci-rpc, else /tmp/dhcp.leases, else nothing."""
        try:
            data = await self.ubus.call("luci-rpc", "getDHCPLeases")
        except (NotFound, AccessDenied):
            pass
        else:
            return [
                (str(x.get("macaddr")), str(x.get("ipaddr")), x.get("hostname") or None)
                for x in data.get("dhcp_leases") or []
                if isinstance(x, dict)
            ]
        try:
            data = await self.ubus.call("file", "read", {"path": "/tmp/dhcp.leases"})
        except (NotFound, AccessDenied):
            return []
        out = []
        for line in str(data.get("data", "")).splitlines():
            parts = line.split()
            if len(parts) >= 4:
                out.append((parts[1], parts[2], None if parts[3] == "*" else parts[3]))
        return out

    async def read_clients(self) -> Observation:
        d = self.context.device_id
        uci = await self.ubus.call("uci", "get", {"config": "wireless"})
        up = await self._radios_up()
        view = await self._network(running=False)
        networks = {name: _list(s.get("network")) for name, s in _sections(uci, "wifi-iface")}
        clients: dict[str, dict[str, Any]] = {}
        for radio in up.values():
            for iface in radio.get("interfaces") or []:
                section, ifname = iface.get("section"), iface.get("ifname")
                if not section or not ifname:
                    continue
                try:
                    data = await self.ubus.call(f"hostapd.{ifname}", "get_clients")
                except NotFound:  # interface not up (yet)
                    continue
                nets = networks.get(section) or []
                vid = view.vlan_of_interface(nets[0]) if nets else None
                for mac in data.get("clients") or {}:
                    if (m := _mac(mac)) is not None:
                        clients[m] = {
                            "seen_on": object_id(d, "wlan", section),
                            "segment_id": self._seg(vid) if vid is not None else None,
                            "addresses": [],
                        }
        for mac, addr, hostname in await self._leases():
            m = _mac(mac)
            if m is None:
                continue
            entry = clients.setdefault(m, {"addresses": []})
            with contextlib.suppress(ValueError):
                entry["addresses"].append(ip_address(addr))
            if hostname:
                entry["hostname"] = hostname
        return Observation(
            clients=[
                Client(id=object_id(d, "client", m), mac=m, **fields)
                for m, fields in sorted(clients.items())
            ]
        )

    # neighbours -----------------------------------------------------------------------

    async def read_neighbours(self) -> Observation:
        d = self.context.device_id
        try:
            data = await self.ubus.call("lldpd", "show_neighbours")
        except NotFound:
            raise AdapterError("lldpd not installed (no ubus object lldpd)") from None
        neighbours: list[Neighbour] = []
        for lldp in data.get("lldp") or []:
            for iface in lldp.get("interface") or []:
                name = iface.get("name")
                chassis = (iface.get("chassis") or [{}])[0]
                port = (iface.get("port") or [{}])[0]
                cid = _first(chassis.get("id"))
                if not name or not cid:
                    continue
                neighbours.append(
                    Neighbour(
                        id=object_id(d, "neighbour", f"{name}-{cid}"),
                        local_port_id=port_id(d, str(name)),
                        chassis_id=_mac(cid) or cid,
                        remote_port=_first(port.get("id")),
                        system_name=_first(chassis.get("name")),
                        management_address=_first(chassis.get("mgmt-ip")),
                    )
                )
        return Observation(neighbours=neighbours)


def _first(values: Any) -> str | None:
    """lldpcli ``-f json0`` wraps every value as ``[{"value": ...}]``."""
    if isinstance(values, list) and values and isinstance(values[0], dict):
        value = values[0].get("value")
        return str(value) if value is not None else None
    return None
