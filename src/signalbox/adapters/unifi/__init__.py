"""Ubiquiti UniFi: one site of the UniFi Network application, read only.

Talks to the Network application's web API over HTTPS with a pinned certificate
(:mod:`signalbox.adapters.https`). Two kinds of installation are told apart automatically:

- a **UniFi OS console** (UDM, UDR, Cloud Gateway, Cloud Key Gen2+): login at
  ``/api/auth/login``, the application's API below ``/proxy/network``;
- a **self-hosted controller** (Linux package, Docker): login at ``/api/login``, the API at the
  root.

Two logins: a **local account** (a read-only role is enough; session cookie) or an **API key**
(``X-API-KEY``, Network 9.0.108 and later). The classic API (``/api/s/<site>/stat/device``,
``rest/networkconf``, ``rest/portconf``, ``rest/wlanconf``, ``stat/sta``) has everything this
adapter reads but is unofficial and changes between versions. The official Integration API
(``/integration/v1``) is stable but small (devices, networks, clients): it is used only when an
API key is refused by the classic API, and the read is then reported as incomplete.

Versions: the Network application 10, 9 and 8 (:data:`TESTED_MAJORS`). Where a field changed
spelling between them (``wlan_band`` / ``wlan_bands``, ``tagged_networkconf_ids`` / excluded
lists, LLDP per port or per device) both spellings are read. Other versions are read the same
way and reported with an optional gap. What is a guess without a real device (issue #21) is
marked *(guess)* and listed in ``docs/adapters/unifi.md``.

**One Signalbox device, many UniFi devices.** As with Omada (ADR 0004), the Signalbox device
stands for the site: its ``device`` is the application; the gateway, switches and access points
are reported as devices of their own with ids ``<device>/<type>-<mac>``.

Parsing is defensive: a missing field is left empty, an unknown one ignored, an answer of the
wrong shape raises ``AdapterError("unexpected answer from <endpoint>: ...")``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from email.utils import parsedate_to_datetime
from ipaddress import ip_address, ip_interface
from typing import Any, Literal

from pydantic import Field, JsonValue, SecretStr, field_validator, model_validator

from signalbox.adapters import Adapter as _Adapter
from signalbox.adapters import (
    AdapterConfig,
    AdapterContext,
    AdapterError,
    AuthFailed,
    Capability,
    Gap,
    Manifest,
    Observation,
    SystemInfo,
    unexpected_answer,
)
from signalbox.adapters.https import DeviceHttp, NotFound, device_url
from signalbox.adapters.portcounters import counters_of
from signalbox.adapters.unifi import multiwan
from signalbox.model import (
    Band,
    BandSteering,
    Cipher,
    Client,
    Device,
    DeviceHealth,
    DeviceRole,
    DeviceTime,
    DhcpPool,
    DhcpServer,
    DynamicDns,
    FdbEntry,
    FdbKind,
    Firmware,
    GatewayGroup,
    IPAddress,
    Link,
    LinkKind,
    LinkOrigin,
    Membership,
    MeshLinkKind,
    MeshMembership,
    MeshRole,
    MeshUplink,
    Neighbour,
    NeighbourProtocol,
    Pmf,
    PoeMode,
    PoeStatus,
    PoeSupply,
    Port,
    PortKind,
    PortMembership,
    PortPoe,
    PortRole,
    PurposeSource,
    Radio,
    Security,
    Segment,
    SegmentPurpose,
    StorageUsage,
    Subnet,
    TemperatureSensor,
    Uplink,
    UplinkKind,
    WifiStandard,
    WirelessAssociation,
    WirelessLinkInfo,
    Wlan,
    fdb_id,
    normalise_capabilities,
    normalise_mac,
    object_id,
    passphrase_digest,
    passphrase_fingerprint,
    segment_id,
)

#: The Network application major versions this adapter is written and tested for: the
#: current one and the two before it (#389, #403). Others are read the same way, with a gap.
TESTED_MAJORS = (8, 9, 10)

LOGIN = "/api/login"
LOGIN_OS = "/api/auth/login"
#: Path prefix of the Network application on a UniFi OS console.
OS_PREFIX = "/proxy/network"
SITES = "/api/self/sites"
INTEGRATION = "/integration/v1"
#: Rows asked per page of the Integration API (it caps at 200).
PAGE_SIZE = 200
MAX_PAGES = 50
#: Statuses :meth:`DeviceHttp.request` hands back instead of raising (the login's refusals and
#: the style probe's redirect).
_ANY = range(100, 600)

#: ``radio`` of a radio and of a virtual AP → band.
BANDS = {"ng": Band.GHZ_2_4, "na": Band.GHZ_5, "6e": Band.GHZ_6, "6g": Band.GHZ_6}
#: ``wlan_band`` / ``wlan_bands`` entries → radio codes.
WLAN_BANDS = {"2g": ("ng",), "5g": ("na",), "6g": ("6e", "6g"), "both": ("ng", "na")}
#: ``wpa_mode`` of a personal network (older spellings included).
WPA_MODES = {"wpa1": Security.WPA, "wpa": Security.WPA, "wpa2": Security.WPA2}
PMF = {"disabled": Pmf.DISABLED, "optional": Pmf.OPTIONAL, "required": Pmf.REQUIRED}
#: Purposes of ``rest/networkconf`` that are networks of the site (the rest: WAN, VPN).
LAN_PURPOSES = {"corporate", "guest", "vlan-only", ""}
#: ``wan_type`` of a WAN network → uplink kind.
WAN_KINDS = {
    "dhcp": UplinkKind.DHCP,
    "static": UplinkKind.STATIC,
    "pppoe": UplinkKind.PPPOE,
    "disabled": UplinkKind.OTHER,
}
#: Device ``type`` prefixes → the kind of managed device.
GATEWAY_TYPES = ("ugw", "usg", "udm", "uxg", "ucg", "udr")
AP_TYPES = ("uap", "ubb", "uwb")
ROLES = {"gateway": DeviceRole.GATEWAY, "switch": DeviceRole.SWITCH, "uap": DeviceRole.AP}


#: ``stat/device`` ``port_table`` rows (the controller's own names, the same in every
#: application version since 5.x; ``rx_crc_errors`` only where the firmware reports it).
_COUNTER_KEYS = {
    "rx_bytes": "rx_bytes",
    "tx_bytes": "tx_bytes",
    "rx_packets": "rx_packets",
    "tx_packets": "tx_packets",
    "rx_errors": "rx_errors",
    "tx_errors": "tx_errors",
    "rx_crc_errors": ("rx_crc_errors", "crc_errors"),
    "rx_drops": ("rx_dropped", "rx_drops"),
    "tx_drops": ("tx_dropped", "tx_drops"),
    "link_downs": "link_down_count",
}


class UnifiConfig(AdapterConfig):
    url: str = Field(
        description="Address of the Network application with its port, for example "
        "https://192.0.2.1 (UniFi OS console) or https://192.0.2.10:8443 (self-hosted)",
        examples=["https://192.0.2.1"],
    )
    site: str = Field(
        default="default",
        description="Site to read: its internal name (default) or the name shown in the UI",
    )
    api_key: SecretStr | None = Field(
        default=None,
        description="API key of the Network application (Settings > Control Plane > "
        "Integrations; Network 9.0.108 and later). Use this or a local account.",
    )
    username: str = Field(
        default="",
        description="Local account with a read-only role (instead of an API key); not a "
        "Ubiquiti cloud account",
    )
    password: SecretStr | None = Field(default=None, description="Password of that local account")
    kind: Literal["auto", "unifi_os", "controller"] = Field(
        default="auto",
        json_schema_extra={"advanced": True},
        description="UniFi OS console or self-hosted controller; auto: detected",
    )
    allow_insecure_http: bool = Field(
        json_schema_extra={"advanced": True},
        default=False,
        description="Allow plain http:// (simulators and tests only: sends the login unencrypted)",
    )

    @field_validator("url")
    @classmethod
    def _url(cls, value: str) -> str:
        return device_url(value)

    @field_validator("api_key", "password")
    @classmethod
    def _blank(cls, value: SecretStr | None) -> SecretStr | None:
        return None if value is None or not value.get_secret_value().strip() else value

    @model_validator(mode="after")
    def _login(self) -> UnifiConfig:
        if self.url.startswith("http://") and not self.allow_insecure_http:
            raise ValueError("plain http:// needs allow_insecure_http (simulators only)")
        if self.api_key is None and not (self.username.strip() and self.password is not None):
            raise ValueError("give an API key, or the user name and password of a local account")
        return self


class UnifiError(AdapterError):
    """The application answered with ``meta.rc`` ``error``."""

    def __init__(self, path: str, msg: str) -> None:
        detail = msg or "no message"
        super().__init__(
            f"{path}: UniFi error {detail}",
            message_id="unifi.error",
            params={"path": path, "detail": detail},
        )


class SessionExpired(AuthFailed):
    """The session cookie is no longer accepted."""


# --- defensive parsing helpers ---------------------------------------------------------------


def _dict(value: Any, endpoint: str, what: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise unexpected_answer(endpoint, f"{what} is {type(value).__name__}, expected an object")
    return value


def _sub(parent: dict[str, Any], key: str) -> dict[str, Any]:
    value = parent.get(key)
    return value if isinstance(value, dict) else {}


def _list(parent: dict[str, Any], key: str) -> list[dict[str, Any]]:
    value = parent.get(key)
    return [r for r in value if isinstance(r, dict)] if isinstance(value, list) else []


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    text = _text(value)
    return int(text) if text.lstrip("-").isdigit() else None


def _num(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, int | float | str):
        return None
    try:
        return float(value)
    except ValueError:
        return None


_POE_MODES = {
    "pasv24": PoeMode.PASSIVE_24V,
    "passthrough": None,
    "auto": None,
}


def _port_poe(row: dict[str, Any]) -> PortPoe:
    """PoE of a switch port from ``port_table``: ``poe_enable``, ``poe_mode`` (``auto``,
    ``pasv24``, ``passthrough``, ``off``; ``auto`` negotiates 802.3af/at/bt, so no mode), the
    delivered ``poe_power`` (watts as text), ``poe_good`` (a device is powered) and
    ``poe_class`` (``Class 4``). Network versions that lack a field leave it out."""
    enabled = _flag(row.get("poe_enable"), None)
    mode_text = _text(row.get("poe_mode")).lower()
    if mode_text == "off":
        enabled = False
    power = _num(row.get("poe_power"))
    good = _flag(row.get("poe_good"), None)
    status = None
    if enabled is False:
        status = PoeStatus.DISABLED
    elif good is True or (power is not None and power > 0):
        status = PoeStatus.DELIVERING
    elif enabled is True:
        status = PoeStatus.SEARCHING
    class_text = _text(row.get("poe_class")).lower().removeprefix("class").strip()
    return PortPoe(
        enabled=enabled,
        status=status,
        mode=_POE_MODES.get(mode_text),
        power_class=int(class_text) if class_text.isdigit() and int(class_text) <= 8 else None,
        power_w=power if power is not None and power >= 0 else None,
        voltage_v=_num(row.get("poe_voltage")),
        current_ma=_num(row.get("poe_current")),
    )


def _poe_supply(row: dict[str, Any]) -> PoeSupply | None:
    """The PoE budget of a switch: ``total_max_power`` (watts) and the sum of its ports'
    ``poe_power``. ``None`` for a device without a budget."""
    budget = _num(row.get("total_max_power"))
    if budget is None or budget <= 0:
        return None
    drawn = [_num(p.get("poe_power")) for p in _list(row, "port_table")]
    return PoeSupply(budget_w=budget, used_w=sum(w for w in drawn if w is not None))


def _flag(value: Any, default: bool | None = None) -> bool | None:
    if isinstance(value, bool):
        return value
    if value in (1, "1", "true"):
        return True
    if value in (0, "0", "false"):
        return False
    return default


def _mac(value: Any) -> str | None:
    try:
        return normalise_mac(_text(value))
    except ValueError:
        return None


def _addr(value: Any) -> IPAddress | None:
    try:
        return ip_address(_text(value))
    except ValueError:
        return None


def _when(value: Any) -> datetime | None:
    """A time in seconds since the epoch (milliseconds from 1e11 on)."""
    number = _num(value)
    if number is None or number <= 0:
        return None
    try:
        return datetime.fromtimestamp(number / 1000 if number > 1e11 else number, UTC)
    except (OverflowError, OSError, ValueError):
        return None


def major_of(version: str) -> int | None:
    """``10.0.26`` → 10; None for text without a number."""
    head = version.strip().split(".")[0]
    return int(head) if head.isdigit() else None


def security_of(wlan: dict[str, Any]) -> Security:
    """Security of a ``rest/wlanconf`` row. ``security`` is ``open``, ``wpapsk``, ``wpaeap`` or
    ``wep``; WPA3 is ``wpa3_support`` with ``wpa3_transition`` for the mixed mode (8 and later;
    6 GHz forces WPA3 on the controller side); ``wpa_mode`` names WPA or WPA2."""
    kind = _text(wlan.get("security")).lower()
    wpa3 = _flag(wlan.get("wpa3_support"), False)
    transition = _flag(wlan.get("wpa3_transition"), False)
    if kind == "open":
        return Security.OWE if _flag(wlan.get("owe_enabled"), False) else Security.OPEN
    if kind == "wep":
        return Security.WEP
    if kind == "wpaeap":
        if wpa3:
            return Security.WPA3_ENTERPRISE
        return (
            Security.WPA_ENTERPRISE
            if _text(wlan.get("wpa_mode")) == "wpa1"
            else (Security.WPA2_ENTERPRISE)
        )
    if kind == "wpapsk":
        if wpa3:
            return Security.WPA2_WPA3 if transition else Security.WPA3
        return WPA_MODES.get(_text(wlan.get("wpa_mode")).lower(), Security.WPA2)
    return Security.OTHER


PERSONAL = {Security.WPA, Security.WPA_WPA2, Security.WPA2, Security.WPA3, Security.WPA2_WPA3}


def ciphers_of(wlan: dict[str, Any], security: Security) -> list[Cipher] | None:
    """Pairwise ciphers of a personal or enterprise network: ``wpa_enc`` ``ccmp`` / ``tkip`` /
    ``auto`` *(guess: ``auto`` is TKIP and CCMP)*."""
    if security in (Security.OPEN, Security.OWE, Security.OTHER, Security.WEP):
        return None
    enc = _text(wlan.get("wpa_enc")).lower()
    if enc == "tkip":
        return [Cipher.TKIP]
    if enc == "auto":
        return [Cipher.TKIP, Cipher.CCMP]
    return [Cipher.CCMP]


def wlan_bands(wlan: dict[str, Any]) -> tuple[str, ...]:
    """Radio codes a network is on: ``wlan_bands`` (a list, 9 and later) or ``wlan_band``
    (``both``, ``2g``, ``5g``, 8 and earlier); neither: 2.4 and 5 GHz."""
    names = wlan.get("wlan_bands")
    found: list[str] = []
    if isinstance(names, list) and names:
        for name in names:
            found += WLAN_BANDS.get(_text(name).lower(), ())
    else:
        found += WLAN_BANDS.get(_text(wlan.get("wlan_band")).lower(), WLAN_BANDS["both"])
    return tuple(dict.fromkeys(found))


# --- what the application manages ------------------------------------------------------------


@dataclass(frozen=True)
class _Managed:
    """An adopted UniFi device (gateway, switch, access point)."""

    mac: str
    name: str
    kind: str  # gateway / switch / uap / device
    model: str | None
    firmware: str | None
    slug: str
    row: dict[str, Any] = field(compare=False, hash=False, repr=False)
    #: ``upgradable`` / ``upgrade_to_firmware`` of the classic device list (#181); the
    #: Integration API has neither.
    upgradable: bool | None = None
    upgrade_to: str | None = None

    def identity(self) -> dict[str, JsonValue]:
        out: dict[str, JsonValue] = {"name": self.name, "mac": self.mac, "type": self.kind}
        if self.model:
            out["model"] = self.model
        if self.firmware:
            out["firmware"] = self.firmware
        return out

    def extra(self, **more: JsonValue) -> dict[str, JsonValue]:
        return {"unifi_device": self.identity(), **{k: v for k, v in more.items() if v}}


def kind_of(row: dict[str, Any]) -> str:
    """gateway / switch / uap / device by the device ``type`` (``usw``, ``uap``, ``ugw``,
    ``udm``, ``uxg``, ``ucg``...)."""
    kind = _text(row.get("type")).lower()
    if kind.startswith("usw"):
        return "switch"
    if kind.startswith(AP_TYPES):
        return "uap"
    if kind.startswith(GATEWAY_TYPES):
        return "gateway"
    return "device"


@dataclass(frozen=True)
class _Net:
    id: str
    name: str
    vlan: int | None
    segment: str
    raw: dict[str, Any] = field(compare=False, hash=False, repr=False)


@dataclass
class _Wireless:
    radios: list[Radio] = field(default_factory=list)
    wlans: list[Wlan] = field(default_factory=list)
    #: (AP MAC, radio code, SSID) → WLAN id, for the clients.
    by_ssid: dict[tuple[str, str, str], str] = field(default_factory=dict)


@dataclass(frozen=True)
class _Link:
    """What a device says about its uplink: the device it hangs on and how."""

    parent: str  # MAC
    local_idx: int | None  # its own port
    remote_idx: int | None  # the parent's port
    speed: int | None
    mesh: bool
    #: the ``uplink`` object itself (radio details of a wireless uplink)
    info: dict[str, Any] = field(default_factory=dict, compare=False, hash=False)


def mesh_info(link: _Link) -> WirelessLinkInfo:
    """Radio details of a wireless uplink (#459) from the ``uplink`` object of the device:
    ``radio`` (``ng``/``na``/``6e``), ``channel``, ``signal`` (dBm) and ``tx_rate``/``rx_rate``
    (kbit/s, as the station rows; below 1000 read as Mbit/s), else ``speed`` (Mbit/s) for both
    directions. Field names are *guesses* from the controller's JSON (#21); a value that is
    missing or out of range stays ``None``."""
    info = link.info
    signal = _int(info.get("signal"))
    channel = _int(info.get("channel"))

    def rate(key: str) -> float | None:
        value = info.get(key)
        if isinstance(value, bool) or not isinstance(value, int | float) or value <= 0:
            return None
        return round(value / 1000, 1) if value >= 1000 else float(value)

    tx, rx = rate("tx_rate"), rate("rx_rate")
    if tx is None and rx is None and link.speed:
        tx = rx = float(link.speed)
    return WirelessLinkInfo(
        band=_STATION_BANDS.get(_text(info.get("radio")).lower()),
        channel=channel if channel and channel > 0 else None,
        signal_dbm=signal if signal is not None and -120 <= signal <= 0 else None,
        tx_rate_mbps=tx,
        rx_rate_mbps=rx,
        kind=MeshLinkKind.MESH,
    )


def uplink_of(row: dict[str, Any]) -> _Link | None:
    """The ``uplink`` object of a device: ``type`` ``wire`` or ``wireless``, ``uplink_mac`` the
    parent, ``uplink_remote_port`` its port (6 and later) *(guess: ``port_idx`` is the device's
    own port)*; the older ``last_uplink`` is read when the device is offline."""
    info = _sub(row, "uplink") or _sub(row, "last_uplink")
    parent = _mac(info.get("uplink_mac"))
    if parent is None or parent == _mac(row.get("mac")):
        return None
    return _Link(
        parent=parent,
        local_idx=_int(info.get("port_idx")),
        remote_idx=_int(info.get("uplink_remote_port")),
        speed=_int(info.get("speed")),
        mesh=_text(info.get("type")).lower() == "wireless",
        info=info,
    )


#: ``radio_proto`` / ``radio`` of a station (``ng``, ``na``, ``ac``, ``ax``, ``6e``, ``be``).
_STATION_STANDARDS = {
    "b": WifiStandard.B,
    "a": WifiStandard.A,
    "g": WifiStandard.G,
    "ng": WifiStandard.N,
    "na": WifiStandard.N,
    "n": WifiStandard.N,
    "ac": WifiStandard.AC,
    "ax": WifiStandard.AX,
    "6e": WifiStandard.AX,
    "be": WifiStandard.BE,
}
_STATION_BANDS = {"ng": Band.GHZ_2_4, "na": Band.GHZ_5, "6e": Band.GHZ_6}


def _roaming(conf: dict[str, Any]) -> dict[str, Any]:
    """Roaming fields (#168) of a ``rest/wlanconf`` entry: ``fast_roaming_enabled`` (802.11r),
    ``bss_transition`` (802.11v), ``mcastenhance_enabled``, ``dtim_mode``/``dtim_na``/
    ``dtim_ng``, ``band_steering_mode`` *(guess: value spelling)*. Left out when absent."""
    out: dict[str, Any] = {}
    for key, name in (
        ("fast_roaming_enabled", "roaming_80211r"),
        ("bss_transition", "roaming_80211v"),
        ("mcastenhance_enabled", "multicast_to_unicast"),
    ):
        value = _flag(conf.get(key), None)
        if value is not None:
            out[name] = value
    if _text(conf.get("dtim_mode")) == "custom":
        dtim = _int(conf.get("dtim_na")) or _int(conf.get("dtim_ng"))
        if dtim is not None and 1 <= dtim <= 255:
            out["dtim_period"] = dtim
    steering = _text(conf.get("band_steering_mode")).lower()
    mode = {
        "off": BandSteering.OFF,
        "prefer_5g": BandSteering.PREFER_5GHZ,
        "equal": BandSteering.BALANCE,
        "balanced": BandSteering.BALANCE,
    }.get(steering)
    if mode is not None:
        out["band_steering"] = mode
    return out


def _association(row: dict[str, Any], wlan_id: str | None) -> WirelessAssociation:
    """Wi-Fi details of a ``stat/sta`` row (#170): ``signal`` (dBm), ``noise``, ``tx_rate`` and
    ``rx_rate`` (kbit/s), ``radio_proto``, ``channel_width`` *(guess)*, ``uptime`` and
    ``idle_time`` (s), ``tx_retries`` and ``tx_packets``, ``powersave_enabled``."""
    signal = _int(row.get("signal"))
    noise = _int(row.get("noise"))
    tx, rx = _num(row.get("tx_rate")), _num(row.get("rx_rate"))
    proto = _text(row.get("radio_proto") or row.get("radio")).lower()
    up, idle = _int(row.get("uptime")), _int(row.get("idle_time"))
    packets, retries = _int(row.get("tx_packets")), _int(row.get("tx_retries"))
    width = _int(row.get("channel_width"))
    return WirelessAssociation(
        wlan_id=wlan_id,
        bssid=_mac(row.get("bssid")),
        band=_STATION_BANDS.get(_text(row.get("radio")).lower()),
        signal_dbm=signal if signal is not None and -120 <= signal < 0 else None,
        noise_dbm=noise if noise is not None and -120 <= noise < 0 else None,
        snr_db=signal - noise
        if signal is not None and noise is not None and -120 <= noise < signal < 0
        else None,
        tx_rate_mbps=round(tx / 1000, 1) if tx is not None and tx >= 0 else None,
        rx_rate_mbps=round(rx / 1000, 1) if rx is not None and rx >= 0 else None,
        standard=_STATION_STANDARDS.get(proto),
        width_mhz=width if width is not None and width > 0 else None,
        connected_seconds=up if up is not None and up >= 0 else None,
        inactive_seconds=idle if idle is not None and idle >= 0 else None,
        retries_pct=round(100 * retries / packets, 1)
        if packets and retries is not None and 0 <= retries <= packets
        else None,
        power_save=_flag(row.get("powersave_enabled"), None),
    )


class UnifiAdapter(_Adapter):
    manifest = Manifest(
        setup_steps=(
            "In the UniFi Network application: Settings > Admins & Users, add a local user "
            "with a read-only role (Network: View Only) and no cloud access. Or, with Network "
            "9.0.108 or later: Settings > Control Plane > Integrations > create an API key.",
            "Below: the address of the console or controller (port 443 on a UniFi OS console, "
            "8443 on a self-hosted controller), the site, and the API key or the user name and "
            "password. Then Test connection and trust the certificate.",
        ),
        setup_url="https://github.com/PhilippMundhenk/signalbox/blob/main/docs/adapters/unifi.md#setup",
        id="unifi",
        name="Ubiquiti UniFi",
        version="0.1.0",
        api_version="1.4",
        vendor="Ubiquiti",
        roles=frozenset({DeviceRole.OTHER, DeviceRole.AP, DeviceRole.SWITCH, DeviceRole.GATEWAY}),
        capabilities=frozenset(
            {
                Capability.INTERFACES,
                Capability.DHCP,
                Capability.WIRELESS,
                Capability.CLIENTS,
                Capability.NEIGHBOURS,
                Capability.HEALTH,
                Capability.TIME,
            }
        ),
        config=UnifiConfig,
        description="Reads one site of the UniFi Network application (UniFi OS console or "
        "self-hosted controller): gateway, switches and access points with their ports, VLANs, "
        "radios and Wi-Fi networks, clients and uplinks. Read only.",
    )

    def __init__(self, context: AdapterContext) -> None:
        super().__init__(context)
        cfg = context.config
        assert isinstance(cfg, UnifiConfig)
        self.config = cfg
        key = cfg.api_key.get_secret_value() if cfg.api_key is not None else ""
        self.http = DeviceHttp(
            cfg.url,
            pinned_fingerprint=context.pinned_fingerprint,
            timeout=context.timeout,
            allow_insecure_http=cfg.allow_insecure_http,
            headers={"X-API-KEY": key} if key else None,
        )
        self._os = cfg.kind == "unifi_os"
        self._mode: Literal["classic", "integration"] = "classic"
        self._site = cfg.site
        self._site_uuid = ""  # the Integration API's id of the site
        self._version = ""
        self._timezone: str | None = None
        self._cache: dict[str, Any] = {}
        self._gaps: list[Gap] = []
        self._reported = 0
        self._wireless_cache: _Wireless | None = None

    async def close(self) -> None:
        await self.http.close()

    # --- requests -----------------------------------------------------------------------------

    @property
    def _base(self) -> str:
        return OS_PREFIX if self._os else ""

    async def _guess_style(self) -> None:
        """UniFi OS answers its start page (200); a self-hosted controller redirects (302)."""
        if self.config.kind != "auto":
            self._os = self.config.kind == "unifi_os"
            return
        answer = await self.http.request("GET", "/", accept=_ANY)
        self._os = answer.status_code == 200

    async def _login(self) -> None:
        cfg = self.config
        assert cfg.password is not None
        body: dict[str, Any] = {
            "username": cfg.username,
            "password": cfg.password.get_secret_value(),
        }
        body["rememberMe" if self._os else "remember"] = False
        path = LOGIN_OS if self._os else LOGIN
        answer = await self.http.request("POST", path, json=body, accept=_ANY)
        detail = ""
        if answer.status_code in (404, 405):
            raise NotFound(
                f"{path}: not found (HTTP 404); is the API enabled?",
                message_id="transport.http404",
                params={"path": path},
            )
        try:
            data = answer.json()
        except ValueError:
            data = None
        if isinstance(data, dict):
            detail = _text(_sub(data, "meta").get("msg")) or _text(data.get("message"))
            detail = detail or _text(data.get("code"))
        refused = answer.status_code != 200 or (
            isinstance(data, dict) and _text(_sub(data, "meta").get("rc")) == "error"
        )
        if refused:
            detail = detail or f"HTTP {answer.status_code}"
            raise AuthFailed(
                f"the Network application refused the login: {detail}",
                fix="Check the user name and password of the local account (a Ubiquiti cloud "
                "account or one with two-factor login cannot be used), or use an API key.",
                fix_id="unifi.loginRefused.fix",
                message_id="unifi.loginRefused",
                params={"detail": detail},
            )

    async def _json(self, path: str) -> Any:
        """GET a path; a session that has expired is renewed once (a login, not a key)."""
        for attempt in range(2):
            try:
                return await self.http.get_json(path)
            except AuthFailed as exc:
                if (
                    attempt
                    or self.config.api_key is not None
                    or exc.message_id != "transport.http401"
                ):
                    raise
                await self._login()
        raise AssertionError("unreachable")  # pragma: no cover

    async def _rows(self, rest: str) -> list[dict[str, Any]]:
        """``data`` of a classic API path below the site (``stat/device``); cached."""
        path = f"{self._base}/api/s/{self._site}/{rest}"
        if path in self._cache:
            return list(self._cache[path])
        body = _dict(await self._json(path), path, "the answer")
        meta = _sub(body, "meta")
        if _text(meta.get("rc")) not in ("", "ok"):
            msg = _text(meta.get("msg"))
            if msg == "api.err.LoginRequired":
                raise SessionExpired(
                    f"{path}: the session was refused",
                    message_id="transport.http401",
                    params={"path": path},
                )
            raise UnifiError(path, msg)
        data = body.get("data")
        if not isinstance(data, list):
            raise unexpected_answer(path, "no list of data")
        rows = [r for r in data if isinstance(r, dict)]
        self._cache[path] = rows
        return list(rows)

    async def _optional(self, rest: str, what: str) -> list[dict[str, Any]]:
        """Rows of an endpoint a role or a version may not have: a gap, not a failed read."""
        try:
            return await self._rows(rest)
        except (NotFound, UnifiError, AuthFailed, AdapterError) as exc:
            self._gaps.append(self._optional_gap(what, exc))
            return []

    @staticmethod
    def _optional_gap(what: str, exc: Exception) -> Gap:
        return Gap(
            message=f"{what}: not read ({exc})",
            optional=True,
            message_id="unifi.optional",
            params={"what": what, "cause": str(exc)},
        )

    async def _integration_rows(self, rest: str) -> list[dict[str, Any]]:
        """All rows of an Integration API list, page by page."""
        path = f"{self._base}{INTEGRATION}/{rest}"
        key = f"integration:{path}"
        if key in self._cache:
            return list(self._cache[key])
        rows: list[dict[str, Any]] = []
        for page in range(MAX_PAGES):
            body = _dict(
                await self.http.get_json(path, {"limit": PAGE_SIZE, "offset": page * PAGE_SIZE}),
                path,
                "the answer",
            )
            data = body.get("data")
            if not isinstance(data, list):
                raise unexpected_answer(path, "no list of data")
            rows += [r for r in data if isinstance(r, dict)]
            total = _int(body.get("totalCount"))
            if not data or total is None or len(rows) >= total:
                break
        self._cache[key] = rows
        return list(rows)

    # --- system -------------------------------------------------------------------------------

    async def read_system(self) -> SystemInfo:
        await self.http.reset()
        self._cache.clear()
        self._gaps = []
        self._reported = 0
        self._wireless_cache = None
        self._mode = "classic"
        await self._guess_style()
        try:
            await self._start()
        except NotFound:
            if self.config.kind != "auto":
                raise
            self._os = not self._os  # the other kind of installation
            await self._start()
        version = self._version
        major = major_of(version)
        if major is not None and major not in TESTED_MAJORS:
            tested = ", ".join(str(m) for m in TESTED_MAJORS)
            self._gaps.append(
                Gap(
                    message=f"the Network application is version {version}; Signalbox is "
                    f"written for versions {tested}: it reads on, but a field may be missing",
                    optional=True,
                    message_id="unifi.version",
                    params={"version": version, "tested": tested},
                )
            )
        return SystemInfo(
            vendor="Ubiquiti",
            model="UniFi Network Application",
            firmware=Firmware(current=version) if version else None,
            management_address=self.http.host,
            transport_encrypted=self.http.secure,
        )

    async def _start(self) -> None:
        """Log in (or try the key), find the site and the version."""
        if self.config.api_key is None:
            await self._login()
        sites = await self._sites()
        wanted = self.config.site
        site = next(
            (s for s in sites if wanted in (_text(s.get("name")), _text(s.get("desc")))), None
        )
        site = site or next(
            (
                s
                for s in sites
                if wanted.casefold()
                in {_text(s.get("name")).casefold(), _text(s.get("desc")).casefold()}
            ),
            None,
        )
        if sites and site is None:
            names = ", ".join(sorted(_text(s.get("desc") or s.get("name")) for s in sites))
            raise AdapterError(
                f"the Network application has no site {wanted!r} (sites: {names or 'none'})",
                message_id="unifi.noSite",
                params={"site": repr(wanted), "sites": names or "none"},
            )
        if site is not None:
            self._site = _text(site.get("name")) or wanted
            self._site_uuid = _text(site.get("_uuid"))
        await self._read_version()

    async def _sites(self) -> list[dict[str, Any]]:
        """The sites of the account. With an API key the classic API may refuse: the Integration
        API's sites are then used and the read goes through it (:attr:`_mode`)."""
        path = f"{self._base}{SITES}"
        try:
            body = _dict(await self.http.get_json(path), path, "the answer")
            rows = [r for r in body.get("data", []) if isinstance(r, dict)]
            if _text(_sub(body, "meta").get("rc")) not in ("", "ok"):
                raise UnifiError(path, _text(_sub(body, "meta").get("msg")))
            return rows
        except NotFound:
            if self.config.api_key is None:
                return []  # a role that cannot list sites: the configured one is used
            raise
        except (AuthFailed, UnifiError) as exc:
            if self.config.api_key is None:
                return []
            try:
                sites = await self._integration_rows("sites")
            except AdapterError:
                raise exc from None
            self._mode = "integration"
            self._gaps.append(
                Gap(
                    message="the Network application accepts this API key for the Integration "
                    "API only: devices, networks and clients are read, ports, radios, Wi-Fi "
                    "networks and uplinks are not",
                    fix="Use a local account with a read-only role for the full read.",
                    optional=True,
                    message_id="unifi.integrationOnly",
                    fix_id="unifi.integrationOnly.fix",
                )
            )
            return [
                {
                    "name": _text(s.get("internalReference")) or _text(s.get("name")),
                    "desc": _text(s.get("name")),
                    "_uuid": _text(s.get("id")),
                }
                for s in sites
            ]

    async def _read_version(self) -> None:
        if self._mode == "integration":
            path = f"{self._base}{INTEGRATION}/info"
            info = _dict(await self.http.get_json(path), path, "the answer")
            self._version = _text(info.get("applicationVersion"))
            return
        rows = await self._optional_quiet("stat/sysinfo")
        first = rows[0] if rows else {}
        self._version = _text(first.get("version"))
        zone = _text(first.get("timezone"))
        self._timezone = zone or None

    def _take_gaps(self) -> list[Gap]:
        """The gaps found since the last read reported them."""
        new = self._gaps[self._reported :]
        self._reported = len(self._gaps)
        return new

    async def _optional_quiet(self, rest: str) -> list[dict[str, Any]]:
        try:
            return await self._rows(rest)
        except (NotFound, UnifiError, AuthFailed):
            return []

    # --- shared views -------------------------------------------------------------------------

    def _prefix(self, managed: _Managed) -> str:
        return f"{self.context.device_id}/{managed.slug}"

    async def _devices(self) -> list[_Managed]:
        if self._mode == "integration":
            return await self._integration_devices()
        out: list[_Managed] = []
        for row in await self._rows("stat/device"):
            mac = _mac(row.get("mac"))
            if mac is None or _flag(row.get("adopted"), True) is False:
                continue
            kind = kind_of(row)
            out.append(
                _Managed(
                    mac=mac,
                    name=_text(row.get("name")) or mac,
                    kind=kind,
                    model=_text(row.get("model")) or None,
                    firmware=_text(row.get("version")) or None,
                    slug=f"{kind}-{mac.replace(':', '')}",
                    row=row,
                    upgradable=row["upgradable"]
                    if isinstance(row.get("upgradable"), bool)
                    else None,
                    upgrade_to=_text(row.get("upgrade_to_firmware")) or None,
                )
            )
        return out

    async def _integration_devices(self) -> list[_Managed]:
        out: list[_Managed] = []
        for row in await self._integration_rows(f"sites/{self._site_uuid}/devices"):
            mac = _mac(row.get("macAddress"))
            if mac is None:
                continue
            features = {_text(f).lower() for f in row.get("features", []) if isinstance(f, str)}
            kind = (
                "uap"
                if "accesspoint" in features
                else "switch"
                if "switching" in features
                else "gateway"
                if "gateway" in features or "routing" in features
                else "device"
            )
            out.append(
                _Managed(
                    mac=mac,
                    name=_text(row.get("name")) or mac,
                    kind=kind,
                    model=_text(row.get("model")) or None,
                    firmware=_text(row.get("firmwareVersion")) or None,
                    slug=f"{kind}-{mac.replace(':', '')}",
                    row={"_id": _text(row.get("id"))},
                )
            )
        return out

    async def _networks(self) -> dict[str, _Net]:
        site = self.context.site_id
        nets: dict[str, _Net] = {}
        if self._mode == "integration":
            rows = await self._integration_rows(f"sites/{self._site_uuid}/networks")
            for row in rows:
                net_id = _text(row.get("id"))
                vlan = _int(row.get("vlanId"))
                if net_id and _flag(row.get("enabled"), True):
                    nets[net_id] = _Net(
                        net_id,
                        _text(row.get("name")) or net_id,
                        vlan,
                        segment_id(site, vlan),
                        row,
                    )
            return nets
        for row in await self._rows("rest/networkconf"):
            net_id = _text(row.get("_id"))
            purpose = _text(row.get("purpose")).lower()
            if (
                not net_id
                or purpose not in LAN_PURPOSES
                or _flag(row.get("enabled"), True) is False
            ):
                continue
            vlan = _int(row.get("vlan")) if _flag(row.get("vlan_enabled"), False) else None
            if vlan is not None and not 1 <= vlan <= 4094:
                continue
            nets[net_id] = _Net(
                net_id,
                _text(row.get("name")) or net_id,
                vlan,
                segment_id(site, vlan),
                row,
            )
        return nets

    async def _profiles(self) -> dict[str, dict[str, Any]]:
        rows = await self._optional("rest/portconf", "port profiles")
        return {_text(r.get("_id")): r for r in rows if _text(r.get("_id"))}

    # --- interfaces ---------------------------------------------------------------------------

    @staticmethod
    def _port_number(row: dict[str, Any]) -> int | None:
        number = _int(row.get("port_idx"))
        return number if number is not None and number > 0 else None

    @staticmethod
    def _is_wan(row: dict[str, Any]) -> bool:
        return _text(row.get("network_name")).lower().startswith("wan") or _text(
            row.get("name")
        ).upper().startswith("WAN")

    @staticmethod
    def _vlan_ids(
        profile: dict[str, Any], row: dict[str, Any], nets: dict[str, _Net], default: str
    ) -> tuple[str, set[str]] | None:
        """(native network, tagged networks) of a port by its profile; None: the port carries
        no network (``forward`` ``disabled``). ``all`` tags every network, ``native`` none,
        ``customize`` the listed ones (``tagged_networkconf_ids``, 8 and later) or every one
        but the excluded (``excluded_networkconf_ids``, earlier)."""
        native = (
            _text(row.get("native_networkconf_id"))
            or _text(profile.get("native_networkconf_id"))
            or default
        )
        forward = _text(profile.get("forward")).lower()
        mode = _text(profile.get("tagged_vlan_mgmt")).lower()
        if forward == "disabled":
            return None
        everything = set(nets)
        if forward == "native" or mode == "block_all":
            tagged: set[str] = set()
        elif "tagged_networkconf_ids" in profile and (forward == "customize" or mode == "custom"):
            tagged = {_text(i) for i in profile.get("tagged_networkconf_ids") or []}
        else:
            tagged = everything - {_text(i) for i in profile.get("excluded_networkconf_ids") or []}
        return native, tagged - {native}

    async def read_interfaces(self) -> Observation:
        dev = self.context.device_id
        devices = await self._devices()
        nets = await self._networks()
        auto = await self._auto_upgrade()
        managed = [self._device(d, auto) for d in devices]
        if self._mode == "integration":
            segs = self._segments(nets, {})
            return Observation(segments=segs, devices=managed, incomplete=self._take_gaps())
        profiles = await self._profiles()
        default = next((n.id for n in nets.values() if n.vlan is None), "")
        members: dict[str, dict[str, Membership]] = {n.segment: {} for n in nets.values()}
        ports: list[Port] = []
        for d in devices:
            if d.kind == "device":
                continue
            ports.extend(self._device_ports(d, profiles, nets, default, members))
        ap_ports, _ = await self._ap_view(ports)
        ports.extend(ap_ports)
        mesh_links, mesh_members = self._cache["ap-mesh"]
        segs = self._segments(nets, members)
        gateway = next((d for d in devices if d.kind == "gateway"), None)
        owner = self._prefix(gateway) if gateway else f"{dev}/gateway"
        subnets = []
        for n in nets.values():
            try:
                iface = ip_interface(_text(n.raw.get("ip_subnet")))
            except ValueError:
                continue
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
        uplinks: list[Uplink] = []
        wan_groups: list[GatewayGroup] = []
        wan_ddns: list[DynamicDns] = []
        if gateway is not None:
            uplinks, wan_groups, wan_ddns = await self._wan(gateway)
        return Observation(
            ports=ports,
            segments=segs,
            subnets=subnets,
            devices=managed,
            wireless_links=mesh_links,
            mesh=mesh_members,
            uplinks=uplinks,
            gateway_groups=wan_groups,
            ddns=wan_ddns,
            incomplete=self._take_gaps(),
        )

    async def _auto_upgrade(self) -> bool | None:
        """Whether the site installs device firmware by itself (#181): the ``auto_upgrade`` flag
        of the site settings (``rest/setting``, the ``super_mgmt`` section on the controller
        versions known; any section that carries the flag otherwise). ``None``: not said, and
        always in integration mode, which has no settings endpoint."""
        if self._mode == "integration":
            return None
        sections = await self._optional_quiet("rest/setting")
        ordered = sorted(sections, key=lambda r: _text(r.get("key")) != "super_mgmt")
        for row in ordered:
            if isinstance(row.get("auto_upgrade"), bool):
                return bool(row["auto_upgrade"])
        return None

    def _device(self, d: _Managed, auto_update: bool | None = None) -> Device:
        return Device(
            id=self._prefix(d),
            site_id=self.context.site_id,
            name=d.name,
            role=ROLES.get(d.kind, DeviceRole.OTHER),
            vendor="Ubiquiti",
            model=d.model,
            firmware=Firmware(
                current=d.firmware,
                available=d.upgrade_to if d.upgrade_to and d.upgrade_to != d.firmware else None,
                upgradable=d.upgradable,
                auto_update=auto_update,
            )
            if d.firmware
            else None,
            mac=d.mac,
            management_address=_text(d.row.get("ip")) or None,
            adapter=self.manifest.id,
            poe=_poe_supply(d.row),
            vendor_extra={"unifi_device": d.identity()},
        )

    def _segments(
        self, nets: dict[str, _Net], members: dict[str, dict[str, Membership]]
    ) -> list[Segment]:
        site = self.context.site_id
        out: dict[str, Segment] = {}
        for n in nets.values():
            if n.segment in out:
                continue
            guest = _text(n.raw.get("purpose")).lower() == "guest"
            out[n.segment] = Segment(
                id=n.segment,
                site_id=site,
                vlan=None if n.segment == segment_id(site, None) else n.vlan,
                name=n.name,
                purpose=SegmentPurpose.GUEST if guest else None,
                purpose_source=PurposeSource.REPORTED if guest else None,
                members=[
                    PortMembership(port_id=p, mode=m)
                    for p, m in sorted(members.get(n.segment, {}).items())
                ],
                vendor_extra={"network_id": n.id},
            )
        return list(out.values())

    def _device_ports(
        self,
        d: _Managed,
        profiles: dict[str, dict[str, Any]],
        nets: dict[str, _Net],
        default: str,
        members: dict[str, dict[str, Membership]],
    ) -> list[Port]:
        rows = _list(d.row, "port_table")
        out: list[Port] = []
        by_lag: dict[int, list[str]] = {}
        for row in rows:
            number = self._port_number(row)
            if number is None:
                continue
            pid = f"{self._prefix(d)}/port/{number}"
            profile = profiles.get(_text(row.get("portconf_id")), {})
            wan = self._is_wan(row)
            enabled = _flag(row.get("enable"), None)
            up = _flag(row.get("up"), None)
            speed = _int(row.get("speed"))
            lag = _int(row.get("aggregated_by"))
            if lag:
                by_lag.setdefault(lag, []).append(pid)
            if _text(row.get("op_mode")).lower() == "aggregate":
                by_lag.setdefault(number, [])
                if pid not in by_lag[number]:
                    by_lag[number].append(pid)
            vlans = None if wan else self._vlan_ids(profile, row, nets, default)
            native = nets.get(vlans[0]) if vlans else None
            capable = _flag(row.get("port_poe"), False)
            out.append(
                Port(
                    id=pid,
                    device_id=self._prefix(d),
                    name=f"{d.name} {_text(row.get('name')) or f'Port {number}'}",
                    up=False if enabled is False else up,
                    speed_mbps=speed if up and speed else None,
                    full_duplex=_flag(row.get("full_duplex"), None) if up else None,
                    poe=_port_poe(row) if capable else None,
                    lag=str(lag) if lag else None,
                    role=PortRole.JACK,
                    admin_up=enabled,
                    autoneg=_flag(row.get("autoneg"), None),
                    jumbo=_flag(row.get("jumbo"), None),
                    counters=counters_of(row, _COUNTER_KEYS),
                    profile=None if wan else _text(profile.get("name")) or None,
                    pvid=native.vlan if native and native.vlan else (1 if native else None),
                    vendor_extra=d.extra(
                        port=number,
                        poe_mode=_text(row.get("poe_mode")) or None,
                        poe_power=_text(row.get("poe_power")) or None,
                        media=_text(row.get("media")) or None,
                    ),
                )
            )
            if vlans is not None:
                native_id, tagged = vlans
                if native_id in nets:
                    members[nets[native_id].segment][pid] = Membership.UNTAGGED
                for net_id in sorted(tagged):
                    net = nets.get(net_id)
                    if net is not None and pid not in members[net.segment]:
                        members[net.segment][pid] = Membership.TAGGED
        for master, lower in sorted(by_lag.items()):
            if len(lower) < 2:
                continue
            out.append(
                Port(
                    id=f"{self._prefix(d)}/port/lag{master}",
                    device_id=self._prefix(d),
                    name=f"{d.name} LAG{master}",
                    kind=PortKind.LAG,
                    role=PortRole.LAG,
                    lower=lower,
                    lag_mode=None,
                    vendor_extra=d.extra(lag=master),
                )
            )
        # members that are not in a group of two or more are no LAG members
        grouped = {p for lower in by_lag.values() if len(lower) >= 2 for p in lower}
        return [
            p.model_copy(update={"lag": None}) if p.lag and p.id not in grouped else p for p in out
        ]

    async def _wan(
        self, gateway: _Managed
    ) -> tuple[list[Uplink], list[GatewayGroup], list[DynamicDns]]:
        """The WAN connections with their failover priority, the group they form (#150) and the
        dynamic DNS entries of the site (#154; quiet where the controller has no such list)."""
        uplinks, groups = await self._uplinks(gateway)
        prefix = self._prefix(gateway)
        rows = await self._optional_quiet("rest/dynamicdns")
        return uplinks, groups, multiwan.ddns_clients(prefix, rows)

    async def _uplinks(self, gateway: _Managed) -> tuple[list[Uplink], list[GatewayGroup]]:
        """The gateway's WAN connections: ``wan1``, ``wan2`` of the device (address, gateway,
        DNS, state) with the WAN network's ``wan_type`` (DHCP, static, PPPoE)."""
        wans = {
            _text(n.get("wan_networkgroup")).lower(): n
            for n in await self._optional("rest/networkconf", "networks")
            if _text(n.get("purpose")).lower() == "wan"
        }
        out: list[Uplink] = []
        confs: dict[str, dict[str, Any]] = {}
        infos: dict[str, dict[str, Any]] = {}
        for key in ("wan1", "wan2", "wan3"):
            info = _sub(gateway.row, key)
            if not info:
                continue
            conf = wans.get("wan" if key == "wan1" else key, {})
            dns = [a for a in (_addr(x) for x in info.get("dns") or []) if a is not None]
            addresses = []
            ip = _addr(info.get("ip"))
            if ip is not None and not ip.is_unspecified:
                try:
                    addresses.append(ip_interface(f"{ip}/{_text(info.get('netmask')) or 32}"))
                except ValueError:
                    addresses.append(ip_interface(ip))
            up = _flag(info.get("up"), None)
            confs[key], infos[key] = conf, info
            priority, weight = multiwan.priority_weight(conf)
            out.append(
                Uplink(
                    id=f"{self._prefix(gateway)}/uplink/{key}",
                    device_id=self._prefix(gateway),
                    name=_text(info.get("name")) or key.upper(),
                    kind=WAN_KINDS.get(_text(conf.get("wan_type")).lower(), UplinkKind.OTHER),
                    up=up,
                    addresses=addresses,
                    upstream_gateway=_addr(info.get("gateway")),
                    dns_servers=dns,
                    priority=priority,
                    weight=weight,
                    health=multiwan.health(info, up),
                    vendor_extra=gateway.extra(),
                )
            )
        groups = multiwan.group(self._prefix(gateway), out, confs, infos)
        return out, groups

    # --- access points and uplinks (#336 pattern) ---------------------------------------------

    async def _ap_view(
        self, known_ports: list[Port] | None = None
    ) -> tuple[list[Port], list[Neighbour]]:
        """The wired port of every access point without a port table (``ETH0``), a mesh port for
        those in a wireless mesh, and the neighbours: what every device says about its uplink
        and the LLDP tables of switches and gateways."""
        cached = self._cache.get("ap-view")
        if cached is not None:
            return cached  # type: ignore[no-any-return]
        dev = self.context.device_id
        devices = await self._devices()
        by_mac = {d.mac: d for d in devices}
        ports: list[Port] = []
        existing = {p.id: p for p in (known_ports or [])}
        links = {d.mac: link for d in devices if (link := uplink_of(d.row)) is not None}
        meshed = {
            m
            for m, link in links.items()
            if link.mesh and (p := by_mac.get(link.parent)) is not None and p.kind == "uap"
        }
        meshed |= {links[m].parent for m in list(meshed)}
        for d in devices:
            if d.kind != "uap":
                continue
            link = links.get(d.mac)
            if not _list(d.row, "port_table"):
                wired = link is not None and not link.mesh
                ports.append(
                    Port(
                        id=f"{self._prefix(d)}/port/1",
                        device_id=self._prefix(d),
                        name=f"{d.name} ETH0",
                        up=True if wired else None,
                        speed_mbps=link.speed if link is not None and wired else None,
                        role=PortRole.JACK,
                        vendor_extra=d.extra(port=1),
                    )
                )
            if d.mac in meshed:
                ports.append(
                    Port(
                        id=f"{self._prefix(d)}/port/mesh",
                        device_id=self._prefix(d),
                        name=f"{d.name} Mesh",
                        kind=PortKind.WIRELESS,
                        role=PortRole.WIRELESS,
                        vendor_extra=d.extra(),
                    )
                )
        every = {**existing, **{p.id: p for p in ports}}
        neighbours: dict[str, Neighbour] = {}

        def add(local: str, chassis: str, **kw: Any) -> None:
            if local in every:
                nid = object_id(dev, "neighbour", f"{local}-{chassis}")
                seen = neighbours.get(nid)
                if seen is None:
                    neighbours[nid] = Neighbour(
                        id=nid, local_port_id=local, chassis_id=chassis, **kw
                    )
                else:  # uplink and LLDP table name one neighbour: fill what is missing
                    fill = {
                        k: v
                        for k, v in kw.items()
                        if k != "vendor_extra" and v not in (None, [], "") and not getattr(seen, k)
                    }
                    neighbours[nid] = seen.model_copy(update=fill)

        for d in devices:
            link = links.get(d.mac)
            if link is None:
                continue
            parent = by_mac.get(link.parent)
            if link.mesh:
                if d.mac not in meshed or parent is None or parent.kind != "uap":
                    continue
                add(
                    f"{self._prefix(d)}/port/mesh",
                    link.parent,
                    remote_port=f"{parent.name} Mesh",
                    system_name=parent.name,
                    wireless=True,
                    vendor_extra=d.extra(uplink="mesh"),
                )
                continue
            local = f"{self._prefix(d)}/port/{link.local_idx or 1}"
            if local not in every:
                local = f"{self._prefix(d)}/port/1"
            remote = f"Port {link.remote_idx}" if link.remote_idx else None
            if parent is not None and link.remote_idx:
                row = next(
                    (
                        r
                        for r in _list(parent.row, "port_table")
                        if _int(r.get("port_idx")) == link.remote_idx
                    ),
                    {},
                )
                remote = f"{parent.name} {_text(row.get('name')) or f'Port {link.remote_idx}'}"
            add(
                local,
                link.parent,
                remote_port=remote,
                system_name=parent.name if parent else None,
                vendor_extra=d.extra(uplink="wired"),
            )
        for d in devices:
            for entry in _lldp(d.row):
                chassis = _mac(entry.get("chassis_id")) or _text(entry.get("chassis_id"))
                idx = _int(entry.get("local_port_idx"))
                if not chassis or idx is None:
                    continue
                name = _text(entry.get("chassis_name") or entry.get("system_name"))
                descr = _text(entry.get("chassis_descr") or entry.get("system_descr"))
                port_text = _text(entry.get("port_id"))
                port_descr = _text(entry.get("port_descr") or entry.get("port_description"))
                add(
                    f"{self._prefix(d)}/port/{idx}",
                    chassis,
                    remote_port=port_text or port_descr or None,
                    port_description=port_descr or None,
                    system_name=name or None,
                    description=descr or None,
                    protocol=NeighbourProtocol.LLDP,
                    chassis_id_kind="mac" if _mac(entry.get("chassis_id")) else None,
                    capabilities=_lldp_capabilities(entry),
                    vendor_extra=d.extra(uplink="lldp"),
                )
        self._cache["ap-mesh"] = self._mesh_of(devices, links, meshed)
        result = (ports, list(neighbours.values()))
        self._cache["ap-view"] = result
        return result

    def _mesh_of(
        self, devices: list[_Managed], links: dict[str, _Link], meshed: set[str]
    ) -> tuple[list[Link], dict[str, MeshMembership]]:
        """Backhaul links and mesh membership of the access points in a wireless mesh (#459):
        the hop count is the length of the chain of wireless uplinks to an access point that is
        wired."""
        by_mac = {d.mac: d for d in devices}
        out: list[Link] = []
        member: dict[str, MeshMembership] = {}
        for d in devices:
            if d.mac not in meshed:
                continue
            hops, cur, seen = 0, d.mac, {d.mac}
            while (up := links.get(cur)) is not None and up.mesh and up.parent in by_mac:
                if up.parent in seen:
                    break
                cur = up.parent
                seen.add(cur)
                hops += 1
            link = links.get(d.mac)
            wireless = link is not None and link.mesh
            member[self._prefix(d)] = MeshMembership(
                role=MeshRole.AGENT,
                controller_id=self.context.device_id,
                hop=hops,
                uplink=MeshUplink.WIRELESS if wireless else MeshUplink.WIRED,
            )
            if link is None or not link.mesh or link.parent not in by_mac:
                continue
            a = f"{self._prefix(by_mac[link.parent])}/port/mesh"
            b = f"{self._prefix(d)}/port/mesh"
            out.append(
                Link(
                    id=f"mesh:{min(a, b)}~{max(a, b)}",
                    a=a,
                    b=b,
                    kind=LinkKind.WIRELESS,
                    origin=LinkOrigin.MESH,
                    wireless=mesh_info(link),
                )
            )
        return out, member

    async def read_neighbours(self) -> Observation:
        if self._mode == "integration":
            return Observation()
        devices = await self._devices()
        ports = [p for d in devices if d.kind != "device" for p in self._port_stubs(d)]
        _, neighbours = await self._ap_view(ports)
        return Observation(neighbours=list(neighbours))

    def _port_stubs(self, d: _Managed) -> list[Port]:
        """Just enough of the ports for neighbours to find their local port (the
        ``interfaces`` read has the real ones)."""
        out = []
        for row in _list(d.row, "port_table"):
            number = self._port_number(row)
            if number is not None:
                out.append(
                    Port(id=f"{self._prefix(d)}/port/{number}", device_id=self._prefix(d), name="-")
                )
        return out

    # --- DHCP ---------------------------------------------------------------------------------

    async def read_dhcp(self) -> Observation:
        if self._mode == "integration":
            return Observation()
        dev = self.context.device_id
        gateway = next((d for d in await self._devices() if d.kind == "gateway"), None)
        owner = self._prefix(gateway) if gateway else f"{dev}/gateway"
        servers: list[DhcpServer] = []
        for n in (await self._networks()).values():
            raw = n.raw
            if "dhcpd_enabled" not in raw:
                continue
            start, stop = _addr(raw.get("dhcpd_start")), _addr(raw.get("dhcpd_stop"))
            try:
                own: IPAddress | None = ip_interface(_text(raw.get("ip_subnet"))).ip
            except ValueError:
                own = None
            enabled = bool(_flag(raw.get("dhcpd_enabled"), False))
            if not enabled and not (start and stop):
                continue
            dns = [a for k in (1, 2, 3, 4) if (a := _addr(raw.get(f"dhcpd_dns_{k}"))) is not None]
            if not _flag(raw.get("dhcpd_dns_enabled"), False):
                dns = [own] if own else []
            lease = _int(raw.get("dhcpd_leasetime"))
            router = (
                _addr(raw.get("dhcpd_gateway"))
                if _flag(raw.get("dhcpd_gateway_enabled"), False)
                else own
            )
            servers.append(
                DhcpServer(
                    id=f"{owner}/dhcp/{n.id}",
                    device_id=self._prefix(gateway) if gateway else dev,
                    segment_id=n.segment,
                    enabled=enabled,
                    pools=[DhcpPool(start=start, end=stop)] if start and stop else [],
                    lease_seconds=lease if lease and lease > 0 else None,
                    router=router,
                    dns_servers=dns,
                    domain=_text(raw.get("domain_name")) or None,
                    vendor_extra=gateway.extra(network=n.name) if gateway else {"network": n.name},
                )
            )
        return Observation(dhcp_servers=servers)

    # --- wireless -----------------------------------------------------------------------------

    async def _wireless(self) -> _Wireless:
        if self._wireless_cache is not None:
            return self._wireless_cache
        out = _Wireless()
        self._wireless_cache = out
        if self._mode == "integration":
            return out
        site = self.context.site_id
        nets = await self._networks()
        vlans = {n.vlan or 1 for n in nets.values()}
        wlans = {
            _text(w.get("_id")): w for w in await self._optional("rest/wlanconf", "Wi-Fi networks")
        }
        groups = {
            _text(g.get("_id")): {m for m in (_mac(x) for x in g.get("device_macs") or []) if m}
            for g in await self._optional_quiet("rest/apgroups")
        }
        for ap in (d for d in await self._devices() if _list(d.row, "radio_table")):
            stats = {_text(s.get("name")): s for s in _list(ap.row, "radio_table_stats")}
            radios: dict[str, Radio] = {}
            for cfg in _list(ap.row, "radio_table"):
                name, code = _text(cfg.get("name")), _text(cfg.get("radio")).lower()
                band = BANDS.get(code)
                if not name or band is None:
                    continue
                state = stats.get(name, {})
                channel = _int(cfg.get("channel"))
                auto = _text(cfg.get("channel")).lower() == "auto" or channel == 0
                busy = _num(state.get("cu_total"))
                own = (_num(state.get("cu_self_rx")) or 0) + (_num(state.get("cu_self_tx")) or 0)
                radios[name] = Radio(
                    id=f"{self._prefix(ap)}/radio/{name}",
                    device_id=self._prefix(ap),
                    name=f"{ap.name} {band.value} GHz",
                    band=band,
                    channel=_int(state.get("channel")) or (None if auto else channel),
                    width_mhz=_int(cfg.get("ht")),
                    tx_power_dbm=_int(
                        state.get("tx_power")
                        if state.get("tx_power") is not None
                        else cfg.get("tx_power")
                    ),
                    enabled=_flag(cfg.get("disabled"), False) is not True,
                    channel_auto=auto if cfg.get("channel") is not None else None,
                    dfs_capable=_flag(cfg.get("has_dfs"), None) if band is Band.GHZ_5 else None,
                    channel_utilisation_pct=busy if busy is not None and 0 <= busy <= 100 else None,
                    interference_pct=(
                        max(0.0, busy - own) if busy is not None and 0 <= busy <= 100 else None
                    ),
                    client_count=_int(state.get("num_sta")),
                    vendor_extra=ap.extra(),
                )
            out.radios += radios.values()
            vaps = _list(ap.row, "vap_table")
            planned: list[tuple[dict[str, Any], str, dict[str, Any]]] = []
            if vaps:
                for vap in vaps:
                    conf = wlans.get(_text(vap.get("id")), {})
                    planned.append((conf, _text(vap.get("radio_name")), vap))
            else:  # an offline AP broadcasts nothing now: the networks it is configured for
                for conf in wlans.values():
                    ids = [_text(i) for i in conf.get("ap_group_ids") or []]
                    if ids and not any(ap.mac in groups.get(i, set()) for i in ids):
                        continue
                    for name in radios:
                        code = radio_code(ap.row, name)
                        if code in wlan_bands(conf):
                            planned.append((conf, name, {}))
            for conf, rname, vap in planned:
                radio = radios.get(rname)
                ssid = _text(conf.get("name")) or _text(vap.get("essid"))
                if radio is None or not ssid:
                    continue
                sec = security_of(conf) if conf else Security.OTHER
                key_text = _text(conf.get("x_passphrase"))
                psk = sec in PERSONAL and bool(key_text)
                net = nets.get(_text(conf.get("networkconf_id")))
                vlan = (
                    net.vlan
                    if net
                    else (
                        _int(conf.get("vlan")) if _flag(conf.get("vlan_enabled"), False) else None
                    )
                )
                seg = (
                    net.segment
                    if net
                    else (segment_id(site, vlan) if (vlan or 1) in vlans else None)
                )
                guest = bool(
                    _flag(conf.get("is_guest"), False) or _flag(vap.get("is_guest"), False)
                )
                rekey = _int(conf.get("group_rekey"))
                wid = f"{self._prefix(ap)}/wlan/{_text(conf.get('_id')) or ssid}-{rname}"
                if any(w.id == wid for w in out.wlans):
                    continue
                out.wlans.append(
                    Wlan(
                        id=wid,
                        device_id=self._prefix(ap),
                        ssid=ssid,
                        radio_id=radio.id,
                        enabled=radio.enabled and bool(_flag(conf.get("enabled"), True)),
                        security=sec,
                        pmf=PMF.get(_text(conf.get("pmf_mode")).lower()),
                        ciphers=ciphers_of(conf, sec) if conf else None,
                        passphrase_fingerprint=passphrase_fingerprint(ssid, key_text)
                        if psk
                        else None,
                        passphrase_digest=passphrase_digest(key_text) if psk else None,
                        key_rotation_seconds=rekey
                        if psk and rekey is not None and rekey >= 0
                        else None,
                        segment_id=seg,
                        hidden=bool(_flag(conf.get("hide_ssid"), False)),
                        client_isolation=_flag(conf.get("l2_isolation"), None),
                        **_roaming(conf),
                        purpose=SegmentPurpose.GUEST if guest else None,
                        purpose_source=PurposeSource.REPORTED if guest else None,
                        bssid=_mac(vap.get("bssid")),
                        vendor_extra=ap.extra(vlan=vlan if seg is None else None),
                    )
                )
                code = _text(radio_code(ap.row, rname))
                out.by_ssid[(ap.mac, code, ssid)] = wid
        return out

    async def read_wireless(self) -> Observation:
        w = await self._wireless()
        return Observation(radios=w.radios, wlans=w.wlans, incomplete=self._take_gaps())

    # --- clients ------------------------------------------------------------------------------

    async def read_clients(self) -> Observation:
        dev = self.context.device_id
        managed = await self._devices()
        own = {d.mac for d in managed}
        by_mac = {d.mac: d for d in managed}
        nets = await self._networks()
        by_vlan = {n.vlan or 1: n.segment for n in nets.values()}
        clients: dict[str, Client] = {}
        fdb: dict[str, FdbEntry] = {}
        if self._mode == "integration":
            for row in await self._integration_rows(f"sites/{self._site_uuid}/clients"):
                mac = _mac(row.get("macAddress"))
                addr = _addr(row.get("ipAddress"))
                if mac is None or mac in own or mac in clients:
                    continue
                clients[mac] = Client(
                    id=object_id(dev, "client", mac),
                    mac=mac,
                    addresses=[addr] if addr else [],
                    hostname=_text(row.get("name")) if _mac(row.get("name")) != mac else None,
                    last_seen=_when(row.get("connectedAt")),
                )
            return Observation(clients=[clients[m] for m in sorted(clients)])
        try:
            wireless: _Wireless | None = await self._wireless()
        except AdapterError:
            wireless = None
        for row in await self._rows("stat/sta"):
            mac = _mac(row.get("mac"))
            if mac is None or mac in own or mac in clients:
                continue
            addr = _addr(row.get("ip")) or _addr(row.get("last_ip"))
            vlan = _int(row.get("vlan"))
            net = nets.get(_text(row.get("network_id") or row.get("last_connection_network_id")))
            seg = net.segment if net else by_vlan.get(vlan or 1) if vlan else None
            seen_on: str | None = None
            if _flag(row.get("is_wired"), False):
                sw = by_mac.get(_mac(row.get("sw_mac")) or "")
                number = _int(row.get("sw_port"))
                if sw is not None and number is not None:
                    seen_on = f"{self._prefix(sw)}/port/{number}"
                    vid = vlan if vlan and 1 <= vlan <= 4094 else None
                    fid = fdb_id(self._prefix(sw), str(number), mac, vid)
                    fdb[fid] = FdbEntry(
                        id=fid,
                        device_id=self._prefix(sw),
                        port_id=seen_on,
                        mac=mac,
                        vlan=vid,
                        segment_id=seg,
                    )
            elif wireless is not None:
                ap = _mac(row.get("ap_mac"))
                seen_on = wireless.by_ssid.get(
                    (ap or "", _text(row.get("radio")).lower(), _text(row.get("essid")))
                )
            hostname = _text(row.get("hostname")) or _text(row.get("name"))
            clients[mac] = Client(
                wireless=None if _flag(row.get("is_wired"), False) else _association(row, seen_on),
                id=object_id(dev, "client", mac),
                mac=mac,
                addresses=[addr] if addr else [],
                hostname=hostname if hostname and _mac(hostname) != mac else None,
                segment_id=seg,
                seen_on=seen_on,
                last_seen=_when(row.get("last_seen")),
            )
        for sw in (d for d in managed if d.kind in ("switch", "gateway")):
            for row in _list(sw.row, "port_table"):
                number = self._port_number(row)
                for entry in _list(row, "mac_table"):
                    mac = _mac(entry.get("mac"))
                    if mac is None or number is None or int(mac[:2], 16) & 1 or mac in own:
                        continue
                    vlan = _int(entry.get("vlan"))
                    vid = vlan if vlan and 1 <= vlan <= 4094 else None
                    fid = fdb_id(self._prefix(sw), str(number), mac, vid)
                    static = bool(_flag(entry.get("static"), False))
                    fdb.setdefault(
                        fid,
                        FdbEntry(
                            id=fid,
                            device_id=self._prefix(sw),
                            port_id=f"{self._prefix(sw)}/port/{number}",
                            mac=mac,
                            vlan=vid,
                            segment_id=by_vlan.get(vid or 1) if vid or by_vlan else None,
                            kind=FdbKind.STATIC if static else FdbKind.DYNAMIC,
                            age_seconds=_int(entry.get("age")),
                        ),
                    )
        return Observation(
            clients=[clients[m] for m in sorted(clients)], fdb=[fdb[k] for k in sorted(fdb)]
        )

    # --- health and time ----------------------------------------------------------------------

    async def read_health(self) -> Observation:
        values = {self.context.device_id: DeviceHealth()}
        if self._mode == "integration":
            for d in await self._devices():
                stats = _dict(
                    await self.http.get_json(
                        f"{self._base}{INTEGRATION}/sites/{self._site_uuid}/devices/"
                        f"{d.row.get('_id')}/statistics/latest"
                    ),
                    "statistics",
                    "the answer",
                )
                values[self._prefix(d)] = DeviceHealth(
                    uptime_seconds=_nonneg(stats.get("uptimeSec")),
                    cpu_load_pct=_pct(stats.get("cpuUtilizationPct")),
                )
            return Observation(health=values)
        for d in await self._devices():
            values[self._prefix(d)] = health_of(d.row)
        return Observation(health=values)

    async def read_time(self) -> Observation:
        """The application's clock (``Date`` of an answer) and the site's time zone."""
        path = (
            f"{self._base}{INTEGRATION}/info"
            if self._mode == "integration"
            else f"{self._base}/api/s/{self._site}/stat/sysinfo"
        )
        start = datetime.now(UTC)
        response = await self.http.request("GET", path)
        end = datetime.now(UTC)
        return Observation(
            time={
                self.context.device_id: time_of(
                    response.headers.get("date"), self._timezone, start, end
                )
            }
        )


def radio_code(row: dict[str, Any], name: str) -> str:
    """``ng`` / ``na`` / ``6e`` of the radio called ``name`` in a device's radio table."""
    for cfg in _list(row, "radio_table"):
        if _text(cfg.get("name")) == name:
            return _text(cfg.get("radio")).lower()
    return ""


def _lldp(row: dict[str, Any]) -> list[dict[str, Any]]:
    """LLDP neighbours of a device: its ``lldp_table`` (``local_port_idx`` names the port) and
    those of its ports (older versions) *(guess: which versions have which)*."""
    out = list(_list(row, "lldp_table"))
    for port in _list(row, "port_table"):
        for entry in _list(port, "lldp_table"):
            out.append({"local_port_idx": port.get("port_idx"), **entry})
    return out


def _lldp_capabilities(entry: dict[str, Any]) -> list[str]:
    """System capabilities of an ``lldp_table`` entry, when the controller lists them: a list or
    a comma separated text under ``chassis_capabilities`` / ``capabilities`` *(guess: the field
    name, #21)*; none otherwise."""
    value = entry.get("chassis_capabilities", entry.get("capabilities"))
    if isinstance(value, str):
        value = value.split(",")
    if not isinstance(value, list):
        return []
    return normalise_capabilities(str(v) for v in value if isinstance(v, str | int) and str(v))


def _nonneg(value: Any) -> int | None:
    number = _num(value)
    return int(number) if number is not None and number >= 0 else None


def _pct(value: Any) -> float | None:
    number = _num(value)
    return number if number is not None and 0 <= number <= 100 else None


def health_of(row: dict[str, Any]) -> DeviceHealth:
    """Vital signs of a device row: ``uptime`` (s), ``system-stats`` (``cpu``, ``mem`` in
    percent), ``sys_stats`` (load averages, ``mem_total`` / ``mem_used`` in bytes), the
    temperature (``general_temperature``, or ``temperatures`` on consoles) and ``storage``."""
    stats, sys_stats = _sub(row, "system-stats"), _sub(row, "sys_stats")
    loads = [_num(sys_stats.get(f"loadavg_{n}")) for n in (1, 5, 15)]
    total, used = _nonneg(sys_stats.get("mem_total")), _nonneg(sys_stats.get("mem_used"))
    if total is not None and used is not None and used > total:
        used = None
    temps = [
        TemperatureSensor(name=_text(t.get("name")) or "device", value_c=v)
        for t in _list(row, "temperatures")
        if (v := _num(t.get("value"))) is not None
    ]
    general = _num(row.get("general_temperature"))
    if not temps and general is not None:
        temps = [TemperatureSensor(name="device", value_c=general)]
    storage = []
    for s in _list(row, "storage"):
        size, free_used = _nonneg(s.get("size")), _nonneg(s.get("used"))
        name = _text(s.get("mount_point")) or _text(s.get("name"))
        if name and size is not None and (free_used is None or free_used <= size):
            storage.append(StorageUsage(name=name, total_bytes=size, used_bytes=free_used))
    return DeviceHealth(
        uptime_seconds=_nonneg(
            row.get("uptime") if row.get("uptime") is not None else stats.get("uptime")
        ),
        cpu_load_pct=_pct(stats.get("cpu")),
        load_average=(loads[0], loads[1], loads[2]) if all(x is not None for x in loads) else None,
        memory_total_bytes=total,
        memory_used_bytes=used,
        temperatures=temps,
        storage=storage,
    )


def time_of(date_header: str | None, zone: Any, start: datetime, end: datetime) -> DeviceTime:
    """The application's clock from the ``Date`` header (whole seconds, read between ``start``
    and ``end``) and the site's time zone."""
    clock = None
    if date_header:
        try:
            clock = parsedate_to_datetime(date_header)
        except (TypeError, ValueError, IndexError):
            clock = None
    if clock is not None and clock.tzinfo is None:
        clock = None
    half = (end - start) / 2
    name = zone.strip() if isinstance(zone, str) and zone.strip() else None
    return DeviceTime(
        clock=clock.astimezone(UTC) + timedelta(seconds=0.5) if clock else None,
        read_at=start + half if clock else None,
        uncertainty_seconds=half.total_seconds() + 0.5 if clock else None,
        timezone=name,
    )


__all__ = ["UnifiAdapter", "UnifiConfig"]
