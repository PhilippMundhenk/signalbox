"""OpenWrt: ubus JSON-RPC through rpcd/uhttpd at ``/ubus``, HTTPS pinned by fingerprint.

The HTTPS side (probe, pin, errors) is :class:`signalbox.adapters.https.DeviceHttp`. Writing
(UCI staging, ``uci apply`` with rollback, ``uci confirm``) translates changes with
:mod:`signalbox.adapters.openwrt.write`.

Every call and the JSON it expects is documented in ``docs/adapters/openwrt.md``.
"""

from __future__ import annotations

import contextlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Interface, IPv6Network, ip_address, ip_interface, ip_network
from typing import Any
from urllib.parse import urlsplit

from pydantic import Field, JsonValue, SecretStr, field_validator

from signalbox.adapters import (
    Adapter,
    AdapterConfig,
    AdapterError,
    AdminLogin,
    ApplyResult,
    Backup,
    Capability,
    Gap,
    Manifest,
    Observation,
    PreviewStep,
    RemedyRequest,
    SetupExtra,
    SetupPlan,
    SetupRequest,
    SetupResult,
    SystemInfo,
    VendorCall,
)
from signalbox.adapters.https import DeviceHttp, device_url
from signalbox.adapters.openwrt import discovery as _discovery
from signalbox.adapters.openwrt import firewall, provision, setup, vitals, wireguard
from signalbox.adapters.openwrt.structure import structure
from signalbox.adapters.openwrt.ubus import (
    AccessDenied,
    CallFailed,
    InvalidArgument,
    NoData,
    NotFound,
    Ubus,
)
from signalbox.changes import Change, ChangeKind
from signalbox.discovery import Candidate, HostProbe
from signalbox.model import (
    DNS_PORT,
    SERVICE_PORTS,
    AddressSource,
    Band,
    Cipher,
    Client,
    DeviceRole,
    DhcpBoot,
    DhcpLease,
    DhcpOption,
    DhcpPool,
    DhcpRelay,
    DhcpRoute,
    DhcpServer,
    DnsForwarder,
    DnsService,
    Firmware,
    HostRecord,
    IPAddress,
    IPInterface,
    LeaseState,
    ManagementService,
    Membership,
    Neighbour,
    Pmf,
    Port,
    PortKind,
    PortMembership,
    Radio,
    Reservation,
    SaePwe,
    SaeSettings,
    Security,
    Segment,
    ServiceKind,
    Subnet,
    TemperatureSensor,
    Uplink,
    UplinkKind,
    Wlan,
    Wps,
    WpsMethod,
    normalise_mac,
    object_id,
    passphrase_digest,
    passphrase_fingerprint,
    port_id,
    segment_id,
)

__all__ = ["OpenWrtAdapter", "OpenWrtConfig"]


class OpenWrtConfig(AdapterConfig):
    url: str = Field(
        description="The router's address, for example 192.0.2.2 or openwrt.lan. Signalbox "
        "uses https://<router>/ubus (the router's web server with uhttpd-mod-ubus).",
        examples=["192.0.2.2"],
    )

    @field_validator("url")
    @classmethod
    def _url(cls, value: str) -> str:
        return device_url(value, path="/ubus")

    username: str = Field(
        default="signalbox",
        description="Login on the router. Best a user of its own with Signalbox's read-only "
        "permissions (see the setup guide); root works too once the permission file is installed",
    )
    password: SecretStr
    allow_insecure_http: bool = Field(
        json_schema_extra={"advanced": True},
        default=False,
        description="accept an http:// URL (password sent in clear text)",
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


def _listen(text: str) -> tuple[IPAddress | None, int] | None:
    """``uhttpd`` ``listen_http``: ``0.0.0.0:80``, ``[::]:443``, ``192.0.2.1:80``."""
    host, _, port = text.rpartition(":")
    try:
        number = int(port)
    except ValueError:
        return None
    try:
        return ip_address(host.strip("[]")), number
    except ValueError:
        return None, number


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


def _addresses(text: str) -> list[IPAddress]:
    out: list[IPAddress] = []
    for part in text.split(","):
        try:
            out.append(ip_address(part.strip()))
        except ValueError:
            continue
    return out


def _extra(section: dict[str, Any], *keys: str) -> dict[str, JsonValue]:
    return {k: section[k] for k in keys if isinstance(section.get(k), str | int | bool)}


_OPTION_NAMES = {
    "router": 3,
    "dns-server": 6,
    "time-server": 4,
    "domain-name": 15,
    "domain": 15,
    "ntp-server": 42,
    "tftp-server": 66,
    "bootfile-name": 67,
    "domain-search": 119,
    "classless-static-route": 121,
    "wpad": 252,
}
_TYPED = frozenset({3, 6, 15, 42, 51, 66, 67, 119, 121})


def dhcp_options(raw: list[str]) -> dict[int, tuple[str | None, str]]:
    """``dhcp_option`` entries (``6,192.0.2.1``, ``option:ntp-server,192.0.2.1``, ``121,...``)
    as code -> (name, value); the first entry of a code wins, ``tag:`` and ``vendor:`` ones and
    unknown names are left out."""
    out: dict[int, tuple[str | None, str]] = {}
    for entry in raw:
        key, _, value = entry.partition(",")
        key = key.removeprefix("option:")
        if not value or ":" in key:
            continue
        code = _int(key) if key.isdigit() else _OPTION_NAMES.get(key)
        if code is not None and 1 <= code <= 254:
            out.setdefault(code, (None if key.isdigit() else key, value))
    return out


def _routes(text: str) -> list[DhcpRoute]:
    """``203.0.113.0/24,198.51.100.254,192.0.2.0/24,198.51.100.253``: destination, gateway pairs."""
    parts = [p for p in text.split(",") if p]
    out = []
    for dest, gateway in zip(parts[::2], parts[1::2], strict=False):
        with contextlib.suppress(ValueError):
            out.append(
                DhcpRoute(destination=ip_network(dest, strict=False), gateway=ip_address(gateway))
            )
    return out


def _boot(dnsmasq: dict[str, Any]) -> tuple[str, str, str] | None:
    """``dhcp_boot`` of the dnsmasq section: ``file[,servername[,server address]]``."""
    raw = dnsmasq.get("dhcp_boot")
    first = raw[0] if isinstance(raw, list) and raw else raw
    if not isinstance(first, str) or not first:
        return None
    file, name, address = [*first.split(","), "", ""][:3]
    return file, name, address


def _boot_with(
    boot: tuple[str, str, str] | None, coded: dict[int, tuple[str | None, str]]
) -> DhcpBoot | None:
    file, name, address = boot or ("", "", "")
    name = name or coded.get(66, (None, ""))[1]
    file = file or coded.get(67, (None, ""))[1]
    try:
        server = ip_address(address) if address else None
    except ValueError:
        server = None
    if not (file or name or server):
        return None
    return DhcpBoot(next_server=server, server_name=name or None, filename=file or None)


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
    "wep": Security.WEP,
    "wep-open": Security.WEP,
    "wep-shared": Security.WEP,
    "psk": Security.WPA,
    "psk-mixed": Security.WPA_WPA2,
    "psk2": Security.WPA2,
    "sae": Security.WPA3,
    "sae-mixed": Security.WPA2_WPA3,
    "wpa": Security.WPA_ENTERPRISE,
    "wpa-mixed": Security.WPA_ENTERPRISE,
    "wpa2": Security.WPA2_ENTERPRISE,
    "wpa3": Security.WPA3_ENTERPRISE,
    "wpa3-mixed": Security.WPA3_ENTERPRISE,
    "wpa3-192": Security.WPA3_ENTERPRISE_192,
}
PERSONAL = {
    Security.WPA,
    Security.WPA_WPA2,
    Security.WPA2,
    Security.WPA3,
    Security.WPA2_WPA3,
    Security.OTHER,
}
SAE_MODES = {Security.WPA3, Security.WPA2_WPA3}
#: ``encryption`` suffix words (``psk2+tkip+ccmp``); ``aes`` is hostapd.sh's word for CCMP.
CIPHER_WORDS = {
    "ccmp": Cipher.CCMP,
    "aes": Cipher.CCMP,
    "ccmp256": Cipher.CCMP_256,
    "ccmp-256": Cipher.CCMP_256,
    "gcmp": Cipher.GCMP,
    "gcmp256": Cipher.GCMP_256,
    "gcmp-256": Cipher.GCMP_256,
    "tkip": Cipher.TKIP,
}
#: Weakest first: a network with several pairwise ciphers uses the weakest as group cipher,
#: so that every station can decrypt group traffic.
CIPHER_STRENGTH = [
    Cipher.WEP,
    Cipher.TKIP,
    Cipher.CCMP,
    Cipher.CCMP_256,
    Cipher.GCMP,
    Cipher.GCMP_256,
]
SAE_PWE = {
    "0": SaePwe.HUNTING_AND_PECKING,
    "1": SaePwe.HASH_TO_ELEMENT,
    "2": SaePwe.BOTH,
}
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


def ciphers(encryption: Any, sec: Security) -> list[Cipher] | None:
    """Pairwise ciphers of an ``encryption`` value: the ``+ccmp``/``+tkip`` suffix, else
    hostapd.sh's default (``tkip+ccmp`` for ``psk`` and ``psk-mixed``, ``gcmp-256`` for
    ``wpa3-192``, otherwise ``ccmp``). None: open, or a word this does not know."""
    if sec is Security.OPEN:
        return None
    if sec is Security.WEP:
        return [Cipher.WEP]
    words = str(encryption or "").split("+")[1:]
    if words:
        found = [CIPHER_WORDS[w] for w in words if w in CIPHER_WORDS]
        return list(dict.fromkeys(found)) if len(found) == len(words) else None
    if sec is Security.OTHER:
        return None
    if sec is Security.WPA3_ENTERPRISE_192:
        return [Cipher.GCMP_256]
    if sec in (Security.WPA, Security.WPA_WPA2):
        return [Cipher.TKIP, Cipher.CCMP]
    return [Cipher.CCMP]


def group_cipher(pairwise: list[Cipher] | None) -> Cipher | None:
    """The group cipher is not a UCI option: hostapd uses the weakest pairwise cipher."""
    if not pairwise:
        return None
    return min(pairwise, key=CIPHER_STRENGTH.index)


def wps(s: dict[str, Any]) -> Wps:
    """``wps_pushbutton`` and ``wps_label`` (PIN); neither set: WPS is off."""
    methods = []
    if _flag(s.get("wps_pushbutton")):
        methods.append(WpsMethod.PUSH_BUTTON)
    if _flag(s.get("wps_label")):
        methods.append(WpsMethod.PIN)
    return Wps(enabled=bool(methods), methods=methods)


def supported_from_features(features: dict[str, Any]) -> list[Security]:
    """Security modes from the ``hostapd`` flags of ``luci getFeatures`` (as LuCI reads them)."""
    hostapd = features.get("hostapd")
    flags = hostapd if isinstance(hostapd, dict) else {}
    modes = [Security.OPEN, Security.WPA, Security.WPA_WPA2, Security.WPA2]
    if flags.get("owe"):
        modes.append(Security.OWE)
    if flags.get("sae"):
        modes += [Security.WPA3, Security.WPA2_WPA3]
    if flags.get("eap"):
        modes += [Security.WPA_ENTERPRISE, Security.WPA2_ENTERPRISE]
        if flags.get("sae"):
            modes.append(Security.WPA3_ENTERPRISE)
    if flags.get("suiteb192"):
        modes.append(Security.WPA3_ENTERPRISE_192)
    return modes


def supported_from_packages(packages: dict[str, Any]) -> list[Security] | None:
    """Security modes from the installed ``wpad-*`` package: ``-basic`` builds have no SAE, OWE
    or EAP, the full ones (mbedtls, openssl, wolfssl, mesh) have all. None: no wpad listed."""
    wpad = sorted(n for n in packages if str(n).startswith("wpad"))
    if not wpad:
        return None
    if "-basic" in wpad[0]:
        return supported_from_features({})
    return supported_from_features({"hostapd": {"owe": 1, "sae": 1, "eap": 1, "suiteb192": 1}})


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
    #: bridge port -> its primary VLAN (``*`` in a ``bridge-vlan`` port list)
    pvids: dict[str, int] = field(default_factory=dict)
    #: devices a ``device`` section switches off (``enabled 0``)
    disabled: set[str] = field(default_factory=set)
    #: the UCI ``network`` config as read (swconfig sections for the port structure)
    uci: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def build(cls, uci: dict[str, Any], dump: dict[str, Any] | None = None) -> NetworkView:
        view = cls(uci=uci)
        for _, s in _sections(uci, "device"):
            if s.get("type") == "bridge" and s.get("name"):
                view.bridges[str(s["name"])] = _list(s.get("ports"))
            if s.get("name") and not _flag(s.get("enabled"), default=True):
                view.disabled.add(str(s["name"]))
        view.vlans = bridge_vlans(_sections(uci, "bridge-vlan"))
        for _, s in _sections(uci, "bridge-vlan"):
            vid = _int(s.get("vlan"))
            for entry in _list(s.get("ports")):
                name, _, flags = entry.partition(":")
                if vid is not None and 1 <= vid <= 4094 and "*" in flags:
                    view.pvids.setdefault(name, vid)
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


#: netifd protocol -> uplink kind (``qmi``, ``mbim``, ``ncm``, ``3g``, ``modemmanager``: mobile)
_PROTO_KINDS = {
    "dhcp": UplinkKind.DHCP,
    "static": UplinkKind.STATIC,
    "pppoe": UplinkKind.PPPOE,
    "pppoa": UplinkKind.PPPOE,
    "dslite": UplinkKind.DSLITE,
    "map": UplinkKind.MAP_E,
    "qmi": UplinkKind.LTE,
    "mbim": UplinkKind.LTE,
    "ncm": UplinkKind.LTE,
    "3g": UplinkKind.LTE,
    "modemmanager": UplinkKind.LTE,
}
#: protocols that only ever connect a router to its provider
_WAN_PROTOS = frozenset(_PROTO_KINDS) - {"dhcp", "static"} | {"dhcpv6", "464xlat"}


def _is_wan(name: str, entry: dict[str, Any]) -> bool:
    """A netifd interface of the uplink: named ``wan``/``wan6``/``wan2``..., or a WAN protocol."""
    named = re.fullmatch(r"wan\d*(_\w+)?", name) is not None
    return named or entry.get("proto") in _WAN_PROTOS


def _default_nexthop(entry: dict[str, Any]) -> IPAddress | None:
    for r in entry.get("route") or []:
        if isinstance(r, dict) and r.get("mask") == 0 and r.get("target") in ("0.0.0.0", "::"):
            with contextlib.suppress(ValueError):
                return ip_address(str(r.get("nexthop")))
    return None


def _delegated(entry: dict[str, Any]) -> list[IPv6Network]:
    out: list[IPv6Network] = []
    for p in entry.get("ipv6-prefix") or []:
        try:
            net = ip_network(f"{p['address']}/{p['mask']}", strict=False)
        except (KeyError, TypeError, ValueError):
            continue
        if isinstance(net, IPv6Network) and net not in out:
            out.append(net)
    return out


def _speed(text: Any) -> tuple[int | None, bool | None]:
    match = re.fullmatch(r"(-?\d+)([FH])", str(text or ""))
    if not match or int(match.group(1)) <= 0:
        return None, None
    return int(match.group(1)), match.group(2) == "F"


def link_speeds(modes: Any) -> list[int]:
    """netifd's ``link-supported``/``link-advertising``: ``["100baseT-F", "1000baseT-F"]``."""
    if not isinstance(modes, list):
        return []
    found = (re.match(r"(\d+)base", m) for m in modes if isinstance(m, str))
    return sorted({int(m.group(1)) for m in found if m and int(m.group(1)) > 0})


def _mtu(value: Any) -> int | None:
    return value if isinstance(value, int) and 68 <= value <= 65535 else None


def _port_kind(name: str, status: dict[str, Any]) -> PortKind:
    if status.get("type") == "bridge":
        return PortKind.BRIDGE
    if status.get("wireless") or name.startswith(("phy", "wlan")):
        return PortKind.WIRELESS
    return PortKind.ETHERNET


# --- the adapter --------------------------------------------------------------------------


#: Shown in the device form ("Before you add it").
OPENWRT_STEPS = (
    ("Log in to the router: ssh root@<router>."),
    (
        "Paste the commands below (replace CHOOSE-A-PASSWORD first). They install the packages "
        "Signalbox reads through, its read-only permissions and a login 'signalbox'."
    ),
    (
        "Below: the router's address, user signalbox and the password you chose. Then Test "
        "connection and trust the router's certificate."
    ),
)


class OpenWrtAdapter(Adapter):
    manifest = Manifest(
        setup_steps=OPENWRT_STEPS,
        setup_commands=setup.commands(),
        setup_url="https://github.com/PhilippMundhenk/signalbox/blob/main/docs/adapters/openwrt.md#read-only-user-on-the-device",
        id="openwrt",
        name="OpenWrt",
        version="0.1.0",
        api_version="1.4",
        vendor="OpenWrt",
        roles=frozenset({DeviceRole.AP, DeviceRole.SWITCH, DeviceRole.GATEWAY}),
        capabilities=frozenset(
            {
                Capability.INTERFACES,
                Capability.WIRELESS,
                Capability.DHCP,
                Capability.DNS,
                Capability.CLIENTS,
                Capability.NEIGHBOURS,
                Capability.HEALTH,
                Capability.TIME,
                Capability.VPN,
                Capability.FIREWALL,
            }
        ),
        config=OpenWrtConfig,
        description=(
            "Reads OpenWrt 21.02+ over ubus JSON-RPC (rpcd); writes bridge VLANs, SSIDs, "
            "dnsmasq DHCP and firewall policies, rules and port forwards through UCI with "
            "rpcd's confirm-or-revert apply."
        ),
        writes=frozenset(
            {
                ChangeKind.PORT,
                ChangeKind.WLAN,
                ChangeKind.DHCP,
                ChangeKind.RESERVATION,
                ChangeKind.ZONE_POLICY,
                ChangeKind.FIREWALL_RULE,
                ChangeKind.PORT_FORWARD,
            }
        ),
        admin_login=AdminLogin(
            transport="SSH as root",
            user_default="root",
            secret_label="root password",
            port_default=22,
            note="The router's SSH server (dropbear) must allow a password login for root, as "
            "OpenWrt does by default. The router needs internet access if packages are missing.",
            preview=[
                PreviewStep(id="packages", title="Install the packages Signalbox reads through"),
                PreviewStep(id="acl", title="Write Signalbox's permission file"),
                PreviewStep(id="login", title="Create the rpcd login with a generated password"),
                PreviewStep(id="restart", title="Restart rpcd"),
                PreviewStep(id="certificate", title="Trust the web server's certificate"),
                PreviewStep(
                    id="lldp-packages", title="Install lldpd and luci-app-lldpd", extra="lldp"
                ),
                PreviewStep(id="lldpd", title="Enable and start lldpd", extra="lldp"),
                PreviewStep(id="login", title="Delete the rpcd login", remove=True),
                PreviewStep(id="acl", title="Delete Signalbox's permission file", remove=True),
                PreviewStep(id="restart", title="Restart rpcd", remove=True),
                PreviewStep(id="packages", title="Keep the installed packages", remove=True),
                PreviewStep(
                    id="lldp-remove",
                    title="Remove lldpd and its package",
                    remove=True,
                    extra="lldp",
                ),
            ],
            extras=[
                SetupExtra(
                    id="lldp",
                    label="Also install LLDP (lldpd and luci-app-lldpd)",
                    note="Optional: shows which device is plugged into which port. Installs the "
                    "packages, enables and starts lldpd; the router then sends and receives LLDP.",
                    remove_label="Also remove LLDP (stop lldpd, remove lldpd and luci-app-lldpd)",
                )
            ],
        ),
        remedies=provision.REMEDIES,
    )

    @classmethod
    async def discover(cls, probe: HostProbe) -> Candidate | None:
        """ubus JSON-RPC (null session) or the LuCI page, without credentials."""
        return await _discovery.discover(probe)

    @classmethod
    async def plan_setup(cls, request: SetupRequest) -> SetupPlan:
        """Packages, ACL file and rpcd login over SSH as root (docs: Automatic setup)."""
        return await provision.OpenWrtSetup(request).plan()

    @classmethod
    async def apply_setup(cls, request: SetupRequest) -> SetupResult:
        return await provision.OpenWrtSetup(request).apply()

    @classmethod
    async def plan_remedy(cls, request: RemedyRequest) -> SetupPlan:
        """*Fix it* (#215): packages and permissions over SSH as root (docs: Fix it)."""
        return await provision.OpenWrtFix(request).plan()

    @classmethod
    async def apply_remedy(cls, request: RemedyRequest) -> SetupResult:
        return await provision.OpenWrtFix(request).apply()

    _ubus: Ubus | None = None
    #: ``uci apply`` with rollback was called and not yet confirmed or rolled back
    _pending: bool = False

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

    async def _uci(self, config: str) -> dict[str, Any]:
        """A UCI config for reading. A router without Wi-Fi has no ``wireless`` config, one
        without DHCP server no ``dhcp``: that is read as empty, not as an error."""
        try:
            data: dict[str, Any] = await self.ubus.call("uci", "get", {"config": config})
        except NotFound:
            if config != "network":
                return {"values": {}}
            raise AdapterError(
                "the router has no readable network configuration (/etc/config/network)",
                fix="Signalbox reads standard OpenWrt. Check that the address points to an "
                "OpenWrt router (not a firmware built on it with its own configuration) and "
                "that /etc/config/network exists there.",
            ) from None
        if config == "network":  # WireGuard keys: dropped on arrival (#152)
            wireguard.scrub(data)
        return data

    async def _network(self, running: bool = True) -> NetworkView:
        uci = await self._uci("network")
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
            transport_encrypted=self.ubus.http.secure,
        )

    # interfaces -----------------------------------------------------------------------

    async def read_interfaces(self) -> Observation:
        d = self.context.device_id
        status = await self.ubus.call("network.device", "status")
        view = await self._network()
        ports: dict[str, Port] = {}
        devices, gap = await self._network_devices()
        for name, st in sorted(status.items()):
            if not isinstance(st, dict) or name == "lo":
                continue
            speed, duplex = _speed(st.get("speed"))
            up = st.get("carrier", st.get("up"))
            disabled = name in view.disabled
            supported = link_speeds(st.get("link-supported"))
            autoneg = st.get("autoneg")
            ports[name] = Port(
                id=port_id(d, name),
                device_id=d,
                name=name,
                kind=_port_kind(name, st),
                up=False if disabled else up if isinstance(up, bool) else None,
                speed_mbps=None if disabled else speed,
                full_duplex=None if disabled else duplex,
                mac=_mac(st.get("macaddr")),
                # a device netifd has up is enabled; a down one may just be unused
                admin_up=False if disabled else (True if st.get("up") is True else None),
                mtu=_mtu(st.get("mtu")),
                max_speed_mbps=supported[-1] if supported else None,
                advertised_speeds_mbps=link_speeds(st.get("link-advertising")),
                autoneg=autoneg if isinstance(autoneg, bool) else None,
                vendor_extra=_extra(st, "type"),
            )

        wifi = frozenset(n for n, p in ports.items() if p.kind is PortKind.WIRELESS)
        tree = structure(sorted(ports), status, devices, view.uci, wifi)
        for name, (role, lower, kind) in tree.items():
            update: dict[str, Any] = {"role": role, "lower": [port_id(d, x) for x in lower]}
            if kind is not None:
                update["kind"] = kind
            ports[name] = ports[name].model_copy(update=update)

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
        for name, vid in view.pvids.items():
            if name in ports:
                ports[name] = ports[name].model_copy(update={"pvid": vid})
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
        uplinks = self._uplinks(view, ports) if router else []
        gaps: list[Gap] = [gap] if gap else []
        try:
            services = await self._services(view, ports, {s.id for s in segments})
        except AccessDenied as exc:  # set up with an older ACL: the rest is read
            services = []
            gaps.append(Gap(message=f"management services: {exc}", fix=exc.fix, remedy=exc.remedy))
        return Observation(
            ports=list(ports.values()),
            segments=segments,
            subnets=subnets,
            uplinks=uplinks,
            services=services,
            incomplete=gaps,
        )

    async def _network_devices(self) -> tuple[dict[str, Any] | None, Gap | None]:
        """``luci-rpc getNetworkDevices`` for the port structure (#252): None without
        rpcd-mod-luci (roles stay unknown where netifd does not tell), a gap with an older ACL."""
        try:
            data = await self.ubus.call("luci-rpc", "getNetworkDevices")
        except NotFound:
            return None, None
        except AccessDenied:
            return None, Gap(
                message="port structure (CPU port, switch ports): luci-rpc getNetworkDevices "
                "is not allowed",
                fix="Update Signalbox's permission file on the router (see the device form): "
                "it now allows luci-rpc getNetworkDevices. Then run service rpcd restart.",
                remedy="access",
            )
        return (data if isinstance(data, dict) else None), None

    async def _services(
        self, view: NetworkView, ports: dict[str, Port], segment_ids: set[str]
    ) -> list[ManagementService]:
        """SSH (dropbear) and the web UI (uhttpd) from their UCI configs (#173). A router set
        up with an older ACL refuses ``uci get`` of both (AccessDenied): the caller reports that
        as a gap with the fix, the rest of the observation is unaffected."""
        d = self.context.device_id
        dropbear = _sections(await self._uci("dropbear"), "dropbear")
        uhttpd = _sections(await self._uci("uhttpd"), "uhttpd")
        out: list[ManagementService] = []
        taken: set[str] = set()

        def key(name: str) -> str:
            unique = name
            while unique in taken:
                unique += "-2"
            taken.add(unique)
            return unique

        for _, s in dropbear:
            port = _int(s.get("Port")) or 22
            name = key("dropbear" if not taken else f"dropbear-{port}")
            segments = [
                seg
                for n in _list(s.get("Interface"))
                if (vid := view.vlan_of_interface(n)) is not None
                and (seg := self._seg(vid)) in segment_ids
            ]
            out.append(
                ManagementService(
                    id=object_id(d, "service", name),
                    device_id=d,
                    kind=ServiceKind.SSH,
                    name=name,
                    enabled=_flag(s.get("enable"), default=True),
                    port=port,
                    segments=segments,
                    interfaces=[
                        port_id(d, n) for n in _list(s.get("DirectInterface")) if n in ports
                    ],
                    password_login=_flag(s.get("PasswordAuth"), default=True),
                    root_login=_flag(s.get("RootLogin"), default=True),
                    root_password_login=_flag(s.get("RootPasswordAuth"), default=True),
                )
            )
        for _, s in uhttpd[:1]:  # ``main``: the instance LuCI runs on
            for kind, option, name in (
                (ServiceKind.HTTP, "listen_http", "uhttpd"),
                (ServiceKind.HTTPS, "listen_https", "uhttpd-ssl"),
            ):
                listens = [x for x in map(_listen, _list(s.get(option))) if x is not None]
                out.append(
                    ManagementService(
                        id=object_id(d, "service", key(name)),
                        device_id=d,
                        kind=kind,
                        name=name,
                        enabled=bool(listens),
                        port=listens[0][1] if listens else SERVICE_PORTS[kind],
                        listen=[a for a, _ in listens if a is not None],
                        redirects_to_https=_flag(s.get("redirect_https"))
                        if kind is ServiceKind.HTTP
                        else None,
                    )
                )
        return out

    def _uplinks(self, view: NetworkView, ports: dict[str, Port]) -> list[Uplink]:
        """The WAN interfaces of ``network.interface dump``; ``wan6`` joins ``wan`` (#148).

        A WAN interface is named ``wan``/``wan6``/``wan2``..., has a protocol only uplinks use,
        or carries a default route without being a network of the site.
        """
        d = self.context.device_id
        wans = {
            n: e
            for n, e in sorted(view.running.items())
            if _is_wan(n, e) or (view.has_default_route(n) and view.vlan_of_interface(n) is None)
        }
        groups: dict[str, list[str]] = {}
        for name in wans:
            base = name[:-1] if name.endswith("6") and name[:-1] in wans else name
            groups.setdefault(base, []).append(name)
        now = datetime.now(UTC).replace(microsecond=0)
        out: list[Uplink] = []
        for base, names in groups.items():
            entries = [wans[n] for n in names]
            main = entries[0]
            addresses: list[IPInterface] = []
            dns: list[IPAddress] = []
            prefixes: list[IPv6Network] = []
            gateways: list[IPAddress] = []
            for n, e in zip(names, entries, strict=True):
                addresses += [a for a in view.addresses(n) if a not in addresses]
                for text in e.get("dns-server") or []:
                    with contextlib.suppress(ValueError):
                        a = ip_address(str(text))
                        if a not in dns:
                            dns.append(a)
                prefixes += [p for p in _delegated(e) if p not in prefixes]
                hop = _default_nexthop(e)
                if hop is not None:
                    gateways.append(hop)
            up = main.get("up")
            uptime = _int(main.get("uptime"))
            dev = next((x for x in (main.get("device"), main.get("l3_device")) if x in ports), None)
            out.append(
                Uplink(
                    id=object_id(d, "uplink", base),
                    device_id=d,
                    port_id=port_id(d, dev) if dev else None,
                    name=base,
                    kind=_PROTO_KINDS.get(str(main.get("proto")), UplinkKind.OTHER),
                    up=up if isinstance(up, bool) else None,
                    since=now - timedelta(seconds=uptime)
                    if up is True and uptime is not None
                    else None,
                    addresses=addresses,
                    delegated_prefixes=prefixes,
                    upstream_gateway=gateways[0] if gateways else None,
                    dns_servers=dns,
                    vendor_extra={
                        "proto": [str(e.get("proto")) for e in entries],
                        "interfaces": list(names),
                    },
                )
            )
        return out

    # wireless -------------------------------------------------------------------------

    async def _radios_up(self) -> dict[str, dict[str, Any]]:
        """``network.wireless status``; on OpenWrt 25.12 through ``luci-rpc``.

        netifd's wireless object is written in ucode since 25.12 and answers "invalid
        argument" to calls through rpcd (which adds ``ubus_rpc_session``). LuCI reads it through
        ``luci-rpc getWirelessDevices`` (rpcd-mod-luci), which calls it on the device and
        answers the same shape with ``iwinfo`` added.
        """
        try:
            status = await self.ubus.call("network.wireless", "status")
        except NotFound:  # no Wi-Fi at all (a switch, or wireless packages removed): no radios
            return {}
        except InvalidArgument:
            try:
                status = await self.ubus.call("luci-rpc", "getWirelessDevices")
            except (NotFound, AccessDenied):
                raise AdapterError(
                    "network.wireless status refuses calls over HTTP (OpenWrt 25.12 and later): "
                    "install rpcd-mod-luci and allow luci-rpc getWirelessDevices in the ACL",
                    fix="Install the package rpcd-mod-luci on the router (LuCI: System, "
                    "Software) and use Signalbox's permission file, which allows luci-rpc "
                    "getWirelessDevices; then run service rpcd restart and test again.",
                    remedy="access",
                ) from None
        return {k: v for k, v in status.items() if isinstance(v, dict)}

    async def _supported_security(self) -> list[Security] | None:
        """Modes the installed hostapd can offer: ``luci getFeatures`` (rpcd-mod-luci), else the
        ``wpad-*`` package from ``rpc-sys packagelist``; None when neither is readable (an
        older ACL, packages missing)."""
        missing = (NotFound, AccessDenied, InvalidArgument, NoData)
        try:
            features = await self.ubus.call("luci", "getFeatures")
        except missing:
            pass
        else:
            return supported_from_features(features)
        try:
            listed = await self.ubus.call("rpc-sys", "packagelist")
        except missing:
            return None
        packages = listed.get("packages")
        return supported_from_packages(packages) if isinstance(packages, dict) else None

    async def read_wireless(self) -> Observation:
        d = self.context.device_id
        uci = await self._uci("wireless")
        up = await self._radios_up()
        view = await self._network(running=False)
        supported = await self._supported_security()
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
                supported_security=supported,
                vendor_extra=_extra(s, "htmode", "type", "cell_density"),
            )
        # wifi-iface section -> its running interface (``phy0-ap0``), for Wlan.port_id (#252)
        ifnames = {
            str(i["section"]): str(i["ifname"])
            for radio in up.values()
            for i in radio.get("interfaces") or []
            if isinstance(i, dict) and i.get("section") and i.get("ifname")
        }
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
            pairwise = ciphers(s.get("encryption"), sec)
            personal = bool(key) and sec in PERSONAL
            rekey = _int(s.get("wpa_group_rekey")) if sec is not Security.OPEN else None
            wlans.append(
                Wlan(
                    id=object_id(d, "wlan", name),
                    device_id=d,
                    ssid=ssid,
                    radio_id=radio.id,
                    enabled=radio.enabled and not _flag(s.get("disabled")),
                    security=sec,
                    pmf=pmf,
                    passphrase_fingerprint=passphrase_fingerprint(ssid, str(key))
                    if personal
                    else None,
                    passphrase_digest=passphrase_digest(str(key)) if personal else None,
                    ciphers=pairwise,
                    group_cipher=group_cipher(pairwise),
                    sae=SaeSettings(pwe=SAE_PWE.get(str(s.get("sae_pwe"))))
                    if sec in SAE_MODES
                    else None,
                    wps=wps(s) if sec in PERSONAL and sec is not Security.OTHER else None,
                    key_rotation_seconds=rekey,
                    beacon_protection=_flag(s["beacon_prot"]) if "beacon_prot" in s else None,
                    segment_id=self._seg(vid) if vid is not None else None,
                    hidden=_flag(s.get("hidden")),
                    roaming_80211r=_flag(s.get("ieee80211r")),
                    roaming_80211k=_flag(s.get("ieee80211k")),
                    roaming_80211v=_flag(s.get("bss_transition", s.get("ieee80211v"))),
                    client_isolation=_flag(s.get("isolate")),
                    port_id=port_id(d, ifnames[name]) if name in ifnames else None,
                    vendor_extra=_extra(s, "encryption", "network"),
                )
            )
        return Observation(radios=list(radios.values()), wlans=wlans)

    # dhcp -----------------------------------------------------------------------------

    async def read_dhcp(self) -> Observation:
        d = self.context.device_id
        uci = await self._uci("dhcp")
        view = await self._network()
        hosts: list[tuple[str, IPAddress, str | None]] = []
        reserved: set[tuple[str | None, IPAddress]] = set()
        for _, s in _sections(uci, "host"):
            try:
                addr = ip_address(str(s.get("ip")))
            except ValueError:
                continue
            for mac in _list(s.get("mac")):
                if (m := _mac(mac)) is not None:
                    hosts.append((m, addr, str(s["name"]) if s.get("name") else None))
                    reserved.add((m, addr))
        table = await self._lease_table()
        dnsmasq = next((x for _, x in _sections(uci, "dnsmasq")), None)
        authoritative = _flag(dnsmasq.get("authoritative"), True) if dnsmasq is not None else None
        boot = _boot(dnsmasq or {})
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
            coded = dhcp_options(_list(s.get("dhcp_option")) + _list(s.get("dhcp_option_force")))
            nets = [a.network for a in view.addresses(iface)]
            leases = None
            if table is not None:
                leases = [
                    lease.model_copy(update={"reserved": (lease.mac, lease.address) in reserved})
                    for lease in table
                    if any(lease.address in n for n in nets if n.version == lease.address.version)
                ]
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
                    ntp_servers=_addresses(
                        options.get("42") or options.get("option:ntp-server") or ""
                    ),
                    reservations=[
                        Reservation(mac=m, address=a, hostname=h) for m, a, h in hosts if a in net
                    ],
                    leases=leases,
                    search_domains=[d for d in coded.get(119, (None, ""))[1].split(",") if d],
                    static_routes=_routes(coded.get(121, (None, ""))[1]),
                    boot=_boot_with(boot, coded),
                    options=[
                        DhcpOption(code=c, name=n, value=v)
                        for c, (n, v) in sorted(coded.items())
                        if c not in _TYPED
                    ],
                    authoritative=authoritative,
                    vendor_extra=_extra(s, "dhcpv6", "ra", "ra_management"),
                )
            )
        return Observation(dhcp_servers=servers, dhcp_relays=self._relays(uci, view))

    def _relays(self, uci: dict[str, Any], view: NetworkView) -> list[DhcpRelay]:
        """dnsmasq ``config relay`` sections (``interface``, ``server_addr``)."""
        d = self.context.device_id
        relays: list[DhcpRelay] = []
        for _, s in _sections(uci, "relay"):
            vid = view.vlan_of_interface(str(s.get("interface", "")))
            try:
                server = ip_address(str(s.get("server_addr")))
            except ValueError:
                continue
            key = "lan" if vid == _NATIVE else str(vid)
            if vid is None or any(r.id.endswith(f"/{key}") for r in relays):
                continue
            relays.append(
                DhcpRelay(
                    id=object_id(d, "dhcp-relay", key),
                    device_id=d,
                    segment_id=self._seg(vid),
                    servers=[server],
                    enabled=not _flag(s.get("disabled")),
                )
            )
        return relays

    async def read_dns(self) -> Observation:
        """dnsmasq's DNS, one service per ``dnsmasq`` section of ``/etc/config/dhcp`` (#241).

        ``port`` 0 turns DNS off. ``server`` entries are forwarders (``192.0.2.53``,
        ``192.0.2.53#5353``, an ``@interface`` suffix is dropped); domain-specific ones
        (``/corp.example/192.0.2.53``) are not counted. Without ``noresolv`` dnsmasq also
        forwards to the servers of ``resolvfile`` (the WAN's), which are not read. ``domain``
        sections are host records.
        """
        d = self.context.device_id
        uci = await self._uci("dhcp")
        view = await self._network()
        records = []
        for _, sec in _sections(uci, "domain"):
            try:
                address = ip_address(str(sec.get("ip")))
            except ValueError:
                continue
            if sec.get("name"):
                records.append(HostRecord(name=str(sec["name"]), address=address))
        services = []
        instances = _sections(uci, "dnsmasq")
        for name, sec in instances:
            port = _int(sec.get("port", DNS_PORT))
            forwarders: list[DnsForwarder] = []
            for text in _list(sec.get("server")):
                if text.startswith("/"):
                    continue  # domain-specific
                try:
                    fwd = DnsForwarder.model_validate(text.split("@")[0])
                except ValueError:
                    continue
                if fwd not in forwarders:
                    forwarders.append(fwd)
            listen: list[IPAddress] = []
            for text in _list(sec.get("listen_address")):
                with contextlib.suppress(ValueError):
                    listen.append(ip_address(text))
            if not listen:
                for iface in _list(sec.get("interface")):
                    listen += [a.ip for a in view.addresses(iface) if a.ip not in listen]
            extra: dict[str, Any] = {}
            if not _flag(sec.get("noresolv")):
                extra["upstream"] = "also the servers of resolvfile (not read)"
            services.append(
                DnsService(
                    id=object_id(d, "dns", "dnsmasq" if len(instances) == 1 else name),
                    device_id=d,
                    name="dnsmasq",
                    enabled=port != 0,
                    listen=listen,
                    port=port if port and 0 < port <= 65535 else DNS_PORT,
                    forwarders=forwarders,
                    host_records=records if len(instances) == 1 else [],
                    vendor_extra=extra,
                )
            )
        return Observation(dns_services=services)

    # health and time --------------------------------------------------------------------

    async def _temperatures(self) -> list[TemperatureSensor]:
        """Thermal zones through ``file read`` (rpcd-mod-file and the ACL paths of the docs);
        the first zone that is missing, refused or unreadable ends the list."""
        found = []
        for zone in range(vitals.THERMAL_ZONES):
            base = f"/sys/class/thermal/thermal_zone{zone}"
            try:
                temp = await self.ubus.call("file", "read", {"path": f"{base}/temp"})
            except AdapterError:  # not found, not allowed, not installed
                break
            try:
                kind = await self.ubus.call("file", "read", {"path": f"{base}/type"})
            except AdapterError:
                kind = {}
            sensor = vitals.thermal(zone, temp.get("data"), kind.get("data"))
            if sensor is not None:
                found.append(sensor)
        return found

    async def read_health(self) -> Observation:
        info = await self.ubus.call("system", "info")
        value = vitals.health_of(info, await self._temperatures())
        return Observation(health={self.context.device_id: value})

    async def read_time(self) -> Observation:
        start = datetime.now(UTC)
        info = await self.ubus.call("system", "info")
        end = datetime.now(UTC)
        uci = await self.ubus.call("uci", "get", {"config": "system"})
        view = await self._network(running=False)
        segments = {}
        for name in view.devices:
            vid = view.vlan_of_interface(name)
            if vid is not None:
                segments[name] = self._seg(vid)
        value = vitals.time_of(info, uci, start, end, segments)
        return Observation(time={self.context.device_id: value})

    # clients --------------------------------------------------------------------------

    async def _lease_rows(self) -> list[dict[str, Any]] | None:
        """Lease entries from luci-rpc, else /tmp/dhcp.leases, else None (neither readable):
        ``mac``, ``address``, ``hostname``, ``expires`` (UTC, None: never or unknown),
        ``client_id``."""
        now = datetime.now(UTC)
        out: list[dict[str, Any]] = []
        try:
            data = await self.ubus.call("luci-rpc", "getDHCPLeases")
        except (NotFound, AccessDenied):
            pass
        else:
            for x in data.get("dhcp_leases") or []:
                if isinstance(x, dict):
                    out.append(self._row(x.get("macaddr"), x.get("ipaddr"), x, now))
            for x in data.get("dhcp6_leases") or []:  # odhcpd; DUID, no MAC
                if not isinstance(x, dict):
                    continue
                for text in _list(x.get("ip6addrs") or x.get("ip6addr")):
                    row = self._row(None, text.split("/")[0], x, now)
                    row["client_id"] = str(x["duid"]) if x.get("duid") else None
                    out.append(row)
            return out
        try:
            data = await self.ubus.call("file", "read", {"path": "/tmp/dhcp.leases"})
        except (NotFound, AccessDenied):
            return None
        for line in str(data.get("data", "")).splitlines():
            parts = line.split()
            if len(parts) >= 4:
                epoch = _int(parts[0])
                out.append(
                    {
                        "mac": parts[1],
                        "address": parts[2],
                        "hostname": None if parts[3] == "*" else parts[3],
                        "expires": datetime.fromtimestamp(epoch, UTC) if epoch else None,
                        "client_id": parts[4] if len(parts) > 4 and parts[4] != "*" else None,
                    }
                )
        return out

    @staticmethod
    def _row(mac: Any, address: Any, x: dict[str, Any], now: datetime) -> dict[str, Any]:
        """``expires`` is the seconds left (LuCI), ``false`` for a lease that never ends."""
        left = x.get("expires")
        seconds = left if isinstance(left, int) and not isinstance(left, bool) else None
        return {
            "mac": str(mac) if mac else None,
            "address": str(address),
            "hostname": x.get("hostname") or None,
            "expires": now + timedelta(seconds=seconds) if seconds is not None else None,
            "client_id": None,
        }

    async def _leases(self) -> list[tuple[str, str, str | None]]:
        """(mac, address, hostname) for the clients."""
        return [
            (str(r["mac"]), r["address"], r["hostname"])
            for r in await self._lease_rows() or []
            if r["mac"]
        ]

    async def _lease_table(self) -> list[DhcpLease] | None:
        """The leases as model objects; None when neither source can be read (not ``[]``)."""
        rows = await self._lease_rows()
        if rows is None:
            return None
        out = []
        for r in rows:
            mac = _mac(r["mac"]) if r["mac"] else None
            try:
                address = ip_address(r["address"])
            except ValueError:
                continue
            if mac is None and not r["client_id"]:
                continue
            out.append(
                DhcpLease(
                    address=address,
                    mac=mac,
                    client_id=r["client_id"],
                    hostname=r["hostname"],
                    state=LeaseState.ACTIVE,  # dnsmasq and odhcpd list leases in use only
                    expires=r["expires"],
                )
            )
        return out

    async def read_clients(self) -> Observation:
        d = self.context.device_id
        uci = await self._uci("wireless")
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
                a = ip_address(addr)
                entry["addresses"].append(a)
                if a.version == 4:  # dnsmasq leases: IPv4 only
                    entry.setdefault("address_sources", {})[a] = AddressSource.DHCP
            if hostname:
                entry["hostname"] = hostname
        return Observation(
            clients=[
                Client(id=object_id(d, "client", m), mac=m, **fields)
                for m, fields in sorted(clients.items())
            ]
        )

    # writing --------------------------------------------------------------------------

    async def _configs(self) -> dict[str, Any]:
        """``uci get`` of the written configs; ``firewall`` is left out where the login may
        not read it (an ACL from before #135): changes to it are refused then, the others
        work as before, and the backup does not hold it (a restore leaves it alone)."""
        out = {}
        for c in write.CONFIGS:
            try:
                out[c] = await self.ubus.call("uci", "get", {"config": c})
            except AccessDenied:
                if c != "firewall":
                    raise
        return out

    async def _translate(self, changes: list[Change], secrets: Mapping[str, str]) -> write.Configs:
        data = await self._configs()
        dump = await self.ubus.call("network.interface", "dump")
        return write.translate(changes, data, dump, self.context.site_id, secrets)

    async def plan_changes(
        self, changes: list[Change], secrets: Mapping[str, str]
    ) -> list[VendorCall]:
        return [op.call() for op in (await self._translate(changes, secrets)).ops]

    async def backup(self) -> Backup:
        data = {c: answer.get("values") for c, answer in (await self._configs()).items()}
        if not all(isinstance(v, dict) for v in data.values()):
            raise AdapterError("unexpected answer to uci.get")
        return Backup(
            device_id=self.context.device_id,
            taken_at=datetime.now(UTC),
            format=write.BACKUP_FORMAT,
            content=json.dumps(data),
        )

    async def _revert(self, ops: list[write.UciOp]) -> None:
        """Drop what this session staged (best effort: the session may be gone already)."""
        for config in sorted({op.config for op in ops}):
            with contextlib.suppress(AdapterError, OSError):
                await self.ubus.call("uci", "revert", {"config": config}, keep_session=True)

    async def _staged(self) -> set[str]:
        """The written configs with changes staged in this session (``uci changes``)."""
        data = await self.ubus.call("uci", "changes", {}, keep_session=True)
        changes = data.get("changes")
        return {c for c in write.CONFIGS if isinstance(changes, dict) and changes.get(c)}

    async def _clear_staging(self) -> None:
        """Drop changes left staged in this session before reading the configs to change.

        rpcd puts the staged changes of an apply back into its session when it rolls back (the
        timer ran out, or ``uci rollback``), as LuCI shows them as unsaved changes again. Left
        there, the next ``uci get`` would see them and the next ``uci apply`` would commit
        them. Best effort: a login without the write ACL fails later with a clear error.

        While an apply waits for its confirmation, rpcd refuses ``uci revert``, and a new login
        of the same user gets the session of that apply ("reclaims" it, rpcd session.c), with
        whatever another client staged there. Then nothing can be changed safely: refused.
        """
        try:
            stale = await self._staged()
        except (AdapterError, OSError):
            return
        for config in sorted(stale):
            with contextlib.suppress(AdapterError, OSError):
                await self.ubus.call("uci", "revert", {"config": config}, keep_session=True)
        if stale and await self._staged():
            raise AdapterError(
                "another change waits for its confirmation on the device (rpcd accepts no "
                "other change until it is confirmed or rolled back); try again later"
            )

    async def _transaction(self, ops: list[write.UciOp], apply: dict[str, Any]) -> None:
        """Stage ``ops`` in this session, then ``uci apply``; revert the staging on any error."""
        try:
            for op in ops:
                await self.ubus.call("uci", op.method, op.args, keep_session=True)
            await self.ubus.call("uci", "apply", apply, keep_session=True)
        except BaseException:
            await self._revert(ops)
            raise

    async def _twice(self, attempt: Any) -> Any:
        """Run a transaction; once more in a new session if access was denied.

        An expired session answers "access denied" and takes its staged changes with it, so the
        whole transaction starts over. Denied twice: the ACL really forbids it.
        """
        try:
            return await attempt()
        except AccessDenied:
            self.ubus.session = None
        try:
            return await attempt()
        except AccessDenied as exc:
            raise AccessDenied(
                f"{exc} (uci.apply is also refused while another change waits for its "
                "confirmation)",
                fix=exc.fix,
                remedy=exc.remedy,
            ) from None

    async def apply(
        self, changes: list[Change], secrets: Mapping[str, str], rollback_seconds: int
    ) -> ApplyResult:
        async def attempt() -> ApplyResult:
            await self._clear_staging()
            ops = (await self._translate(changes, secrets)).ops
            if not ops:
                return ApplyResult()
            self._pending = True  # also if the answer to apply is lost
            try:
                await self._transaction(ops, {"rollback": True, "timeout": rollback_seconds})
            except BaseException:
                self._pending = False
                raise
            return ApplyResult(
                confirm_deadline=datetime.now(UTC) + timedelta(seconds=rollback_seconds),
                calls=[op.call() for op in ops],
            )

        result: ApplyResult = await self._twice(attempt)
        return result

    async def confirm(self) -> None:
        try:
            await self.ubus.call("uci", "confirm", {}, keep_session=True)
        except NoData:
            self._pending = False
            raise AdapterError(
                "uci confirm: nothing waits for confirmation; the deadline passed and the device "
                "rolled the change back"
            ) from None
        except AccessDenied:
            raise AdapterError(
                "uci confirm refused (session expired, or not allowed by the rpcd ACL); the "
                "device rolls the change back at the deadline"
            ) from None
        self._pending = False

    async def restore(self, backup: Backup) -> None:
        if backup.format != write.BACKUP_FORMAT:
            raise AdapterError(f"not an OpenWrt backup (format {backup.format})")
        try:
            saved = json.loads(backup.content)
        except ValueError:
            raise AdapterError("the backup is not valid JSON") from None
        if not isinstance(saved, dict) or not all(
            c in write.CONFIGS and isinstance(v, dict) for c, v in saved.items()
        ):
            raise AdapterError("the backup does not hold UCI configs")
        if self._pending:
            # our own change still waits for confirmation: let rpcd undo it at once
            with contextlib.suppress(AdapterError, OSError):
                await self.ubus.call("uci", "rollback", {}, keep_session=True)
            self._pending = False

        async def attempt() -> None:
            await self._clear_staging()
            current = {
                c: (await self.ubus.call("uci", "get", {"config": c})).get("values") for c in saved
            }
            ops = write.restore_ops(saved, current)
            if not ops:
                return
            await self._transaction(ops, {"rollback": False})
            # rpcd answers OK to an apply without rollback while another change waits for its
            # confirmation, but applies nothing: the changes are still staged.
            if await self._staged():
                raise AdapterError(
                    "the backup was not applied: another change waits for its confirmation on "
                    "the device (rpcd applies nothing until it is confirmed or rolled back)"
                )

        await self._twice(attempt)

    # vpn ------------------------------------------------------------------------------

    async def read_vpn(self) -> Observation:
        """WireGuard interfaces (``proto wireguard``) and their ``wireguard_<if>`` peers from
        UCI (keys already dropped by :meth:`_uci`), with handshakes and transfer from
        ``luci.wireguard getWgInstances`` (luci-proto-wireguard) where that is installed (#152)."""
        uci = await self._uci("network")
        if not wireguard.interfaces(uci):
            return Observation(tunnels=[])
        runtime: dict[str, dict[str, Any]] = {}
        with contextlib.suppress(NotFound):  # no luci-proto-wireguard: configuration only
            runtime = wireguard.instances(await self.ubus.call("luci.wireguard", "getWgInstances"))
        dump = await self.ubus.call("network.interface", "dump")
        entries = dump.get("interface") if isinstance(dump, dict) else None
        running = {
            str(e["interface"]): e
            for e in entries or []
            if isinstance(e, dict) and isinstance(e.get("interface"), str)
        }
        up = {n: bool(e.get("up")) for n, e in running.items()}
        status = await self.ubus.call("network.device", "status")
        ports = set(status) if isinstance(status, dict) else set()  # as read_interfaces names them
        tunnels = wireguard.tunnels(uci, runtime, self.context.device_id, up, ports)
        return Observation(tunnels=tunnels)

    # firewall -------------------------------------------------------------------------

    async def read_firewall(self) -> Observation:
        """The UCI ``firewall`` config (#135): zones mapped to segments, uplinks and tunnels,
        forwardings and rules, redirects and NAT. A router set up with an older ACL refuses
        ``uci get firewall``: that is a gap with the fix, not an error."""
        try:
            uci = await self._uci("firewall")
        except AccessDenied as exc:
            return Observation(
                incomplete=[
                    Gap(message=f"firewall: {exc}", fix=exc.fix, remedy=exc.remedy),
                ]
            )
        d = self.context.device_id
        view = await self._network()
        router = (
            self.context.role is DeviceRole.GATEWAY
        )  # as read_interfaces: only a router has uplinks
        uplinks = {
            n: u.id
            for u in (self._uplinks(view, {}) if router else [])
            for n in (u.vendor_extra.get("interfaces") or [])  # type: ignore[union-attr]
        }
        tunnels = {n for n, _ in wireguard.interfaces(view.uci)}
        segment_ids = self._segment_ids(view)

        def mapper(name: str) -> tuple[list[str], list[str], list[str]] | None:
            if name in uplinks:
                return [], [uplinks[name]], []
            if name in tunnels:
                return [], [], [object_id(d, "tunnel", name)]
            vid = view.vlan_of_interface(name)
            if vid is not None and self._seg(vid) in segment_ids:
                return [self._seg(vid)], [], []
            return None

        return Observation(firewalls=[firewall.build(uci, d, mapper)])

    def _segment_ids(self, view: NetworkView) -> set[str]:
        """The segments :meth:`read_interfaces` reports: bridge VLANs with members, and the
        native segment of a bridge with ports."""
        vids = {vid for vlans in view.vlans.values() for vid in vlans}
        if any(ports for b, ports in view.bridges.items() if b not in view.vlans):
            vids.add(_NATIVE)
        return {self._seg(v) for v in vids}

    # neighbours -----------------------------------------------------------------------

    async def read_neighbours(self) -> Observation:
        d = self.context.device_id
        try:
            status = await self.ubus.call("luci.lldpd", "getStatus")
        except NotFound:
            return self._lldp_gap(
                "LLDP is not installed on the router (no ubus object luci.lldpd)",
                "Optional: without LLDP Signalbox cannot see which device is plugged into "
                "which port; everything else works. To add it, install the packages lldpd and "
                "luci-app-lldpd (LuCI: System, Software), run service rpcd restart and test again.",
            )
        except CallFailed:
            # luci.lldpd's script fails while lldpd is stopped (seen on OpenWrt 24.10/25.12)
            return self._lldp_gap(
                "lldpd is installed but not running (luci.lldpd getStatus failed)",
                "Optional: start it on the router with service lldpd enable && service lldpd "
                "start (LuCI: System, Startup), then test again.",
            )
        data = status.get("neighbors")
        if not isinstance(data, dict):
            return self._lldp_gap(
                "lldpd is installed but not running (luci.lldpd getStatus has no neighbours)",
                "Optional: start it on the router with service lldpd enable && service lldpd "
                "start (LuCI: System, Startup), then test again.",
            )
        neighbours: list[Neighbour] = []
        for lldp in data.get("lldp") or []:
            if not isinstance(lldp, dict):
                continue
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

    @staticmethod
    def _lldp_gap(message: str, fix: str) -> Observation:
        return Observation(incomplete=[Gap(message=message, fix=fix, remedy="lldp", optional=True)])


def _first(values: Any) -> str | None:
    """lldpcli ``-f json0`` wraps every value as ``[{"value": ...}]``."""
    if isinstance(values, list) and values and isinstance(values[0], dict):
        value = values[0].get("value")
        return str(value) if value is not None else None
    return None


from signalbox.adapters.openwrt import write  # noqa: E402 - uses the helpers above
