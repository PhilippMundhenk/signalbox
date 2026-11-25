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

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from ipaddress import IPv4Address, IPv4Interface, ip_address, ip_interface
from typing import Any

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
    Gap,
    Manifest,
    Observation,
    SystemInfo,
    VendorCall,
    unexpected_answer,
)
from signalbox.adapters.https import DeviceHttp, NotFound, device_url
from signalbox.adapters.omada import discovery as _discovery
from signalbox.adapters.omada import firewall, multiwan, vitals
from signalbox.adapters.portcounters import counters_of
from signalbox.changes import Change, ChangeKind
from signalbox.discovery import Candidate, HostProbe
from signalbox.factory_defaults import is_factory_default
from signalbox.model import (
    SERVICE_PORTS,
    STANDARD_RANK,
    AccountPrivilege,
    Band,
    Cipher,
    Client,
    Device,
    DeviceAccount,
    DeviceHealth,
    DeviceRole,
    DhcpPool,
    DhcpServer,
    FdbEntry,
    Firewall,
    FirewallAction,
    FirewallRule,
    Firmware,
    GatewayGroup,
    IPAddress,
    IPInterface,
    LagMode,
    Link,
    LinkKind,
    LinkOrigin,
    LogKind,
    LogTarget,
    LogTransport,
    ManagementService,
    Membership,
    MeshLinkKind,
    MeshMembership,
    MeshRole,
    MeshUplink,
    Neighbour,
    Pmf,
    PoeStatus,
    PoeSupply,
    Port,
    PortCounters,
    PortForward,
    PortKind,
    PortMembership,
    PortPoe,
    PortRole,
    PurposeSource,
    Radio,
    ScanSource,
    Security,
    Segment,
    SegmentPurpose,
    ServiceKind,
    SnmpSettings,
    SnmpVersion,
    Subnet,
    Uplink,
    UplinkHealth,
    UplinkKind,
    UplinkState,
    WifiScanResult,
    WifiStandard,
    WirelessAssociation,
    WirelessLinkInfo,
    Wlan,
    fdb_id,
    firewall_id,
    normalise_mac,
    object_id,
    passphrase_digest,
    passphrase_fingerprint,
    scan_id,
    segment_id,
)

INFO = "/api/info"
TOKEN = "/openapi/authorize/token"
#: Omada Cloud access, a controller setting (#327). GUESS: neither the path nor the field
#: is confirmed; the integration job dumps the controller's API description (``cloud``
#: paths) so it can be corrected (#21).
CLOUD_ACCESS = "/openapi/v1/{omadac}/cloud-access"
CLOUD_FIELD = "enable"
#: The site's remote syslog server (#327). GUESS, same as above: sits next to the SNMP
#: setting under ``setting/service``; fields ``enable``, ``serverIp``, ``serverPort``.
SITE_LOGGING = "/setting/service/logging"
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
#: Band of a wireless client's ``radioId``.
CLIENT_BANDS = {0: Band.GHZ_2_4, 1: Band.GHZ_5, 2: Band.GHZ_5, 3: Band.GHZ_6}
#: ``wifiMode`` of a wireless client: 0 11a, 1 11b, 2 11g, 3 11na, 4 11ng, 5 11ac, 6 11axa,
#: 7 11axg, 8 11bea, 9 11beg, 10 11beg6 *(guess for 8 and up)*.
CLIENT_STANDARDS = {
    0: WifiStandard.A,
    1: WifiStandard.B,
    2: WifiStandard.G,
    3: WifiStandard.N,
    4: WifiStandard.N,
    5: WifiStandard.AC,
    6: WifiStandard.AX,
    7: WifiStandard.AX,
    8: WifiStandard.BE,
    9: WifiStandard.BE,
    10: WifiStandard.BE,
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
    1: Security.WPA,
    2: Security.WPA2,
    3: Security.WPA_WPA2,
    4: Security.WPA2_WPA3,
}
#: ``pskSetting.encryptionPsk`` → pairwise ciphers: 1 auto (TKIP and AES), 2 TKIP, 3 AES.
PSK_CIPHERS = {
    1: [Cipher.TKIP, Cipher.CCMP],
    2: [Cipher.TKIP],
    3: [Cipher.CCMP],
}
#: ``entSetting.versionEnt`` → security (guess: 1 WPA, 3 WPA/WPA2 are not in the description).
ENT_VERSIONS = {
    1: Security.WPA_ENTERPRISE,
    2: Security.WPA2_ENTERPRISE,
    3: Security.WPA_ENTERPRISE,
    4: Security.WPA3_ENTERPRISE,
}
#: Modes with a pre-shared passphrase.
PERSONAL = {Security.WPA, Security.WPA_WPA2, Security.WPA2, Security.WPA3, Security.WPA2_WPA3}
#: ``pmfMode`` → PMF: 1 mandatory, 2 capable, 3 disabled.
PMF_MODES = {1: Pmf.REQUIRED, 2: Pmf.OPTIONAL, 3: Pmf.DISABLED}
#: ``purpose`` of a LAN network (0 VLAN only, 1 interface: a gateway address); older
#: controllers and the web API spell it as a word.
PURPOSES = {0: "vlan", 1: "interface", "vlan": "vlan", "interface": "interface"}
#: Device ``type`` → prefix of the managed device's slug.
TYPES = {"gateway": "gateway", "router": "gateway", "switch": "switch", "ap": "eap", "eap": "eap"}


#: Port statistics of a switch's ``portList`` row (also under ``portStatus``): bytes and
#: packets as ``rx``/``tx`` and ``rxPkt``/``txPkt``, the error and drop counters under the
#: spellings of the controller generations. A guess for the exact names, not seen on a
#: device (#21): the readers take the first present.
_COUNTER_KEYS = {
    "rx_bytes": ("rx", "rxBytes"),
    "tx_bytes": ("tx", "txBytes"),
    "rx_packets": ("rxPkt", "rxPackets"),
    "tx_packets": ("txPkt", "txPackets"),
    "rx_errors": ("rxErr", "rxErrors", "rxErrorPkt"),
    "tx_errors": ("txErr", "txErrors", "txErrorPkt"),
    "rx_crc_errors": ("rxCrcErr", "crcErrors", "fcsErrors"),
    "rx_drops": ("rxDrop", "rxDropped"),
    "tx_drops": ("txDrop", "txDropped"),
}


def _counters(row: dict[str, Any]) -> PortCounters | None:
    status = row.get("portStatus")
    return counters_of({**row, **(status if isinstance(status, dict) else {})}, _COUNTER_KEYS)


class OmadaConfig(AdapterConfig):
    url: str = Field(
        description="Address of the controller with its port, for example "
        "https://192.0.2.5:8043 (software controller) or https://192.0.2.5 (OC200/OC300)",
        examples=["https://192.0.2.5:8043"],
    )
    omadac_id: str = Field(
        default="",
        json_schema_extra={"advanced": True},
        description="Controller id (omadacId); empty: read from /api/info",
    )
    site: str = Field(default="Default", description="Name of the Omada site to read")
    client_id: str = Field(
        description="Client ID of an Open API client: viewer role to read, administrator role "
        "to change"
    )
    client_secret: SecretStr = Field(description="Client secret of that Open API client")
    allow_insecure_http: bool = Field(
        json_schema_extra={"advanced": True},
        default=False,
        description="Allow plain http:// (simulators and tests only: sends the secret unencrypted)",
    )

    @field_validator("url")
    @classmethod
    def _url(cls, value: str) -> str:
        return device_url(value)

    @model_validator(mode="after")
    def _http_needs_opt_in(self) -> OmadaConfig:
        if self.url.startswith("http://") and not self.allow_insecure_http:
            raise ValueError("plain http:// needs allow_insecure_http (simulators only)")
        return self


_AUTH_CODE_ONLY = -44118  # "only supports the authorization code mode" (controller 6.3, #354)


def _client_mode_gap() -> Gap:
    """The controller's users (``/users``, ``/all-users``, ``/roles/available``) are only
    offered in authorization-code mode; Signalbox logs in with client credentials (#354)."""
    return Gap(
        message="accounts: the controller's users are only available with authorization-code "
        "mode; Signalbox uses client mode",
        fix="Nothing to fix in Signalbox: Omada offers its user list only to "
        "authorization-code logins. The device account of the site is still read.",
        optional=True,
        message_id="omada.accounts.client_mode",
        fix_id="omada.accounts.client_mode.fix",
    )


_VERSION = re.compile(r"(\d+)\.(\d+)")

#: The Open API (``/openapi/v1``, client credentials) needs controller 5.9 or later (guess, #21:
#: TP-Link's page names 6.4 for the current description and does not date its start).
OPEN_API_FROM = (5, 9)


def controller_release(version: str | None) -> tuple[int, int] | None:
    """(major, minor) of ``controllerVer`` (``5.15.20.18`` is (5, 15)); None if not in that form."""
    found = _VERSION.match((version or "").strip())
    return (int(found.group(1)), int(found.group(2))) if found else None


def _old_gap(what: str, release: tuple[int, int]) -> Gap:
    """An optional gap for a read that a controller older than 6 may not offer (#415)."""
    text = f"{release[0]}.{release[1]}"
    return Gap(
        message=f"{what}: controller {text} does not offer it through the Open API "
        "(controller 6 does)",
        optional=True,
        message_id="omada.oldController",
        params={"what": what, "release": text},
    )


class OmadaError(AdapterError):
    """The controller answered with a non-zero ``errorCode``."""

    def __init__(self, path: str, code: int, msg: str) -> None:
        self.code = code
        detail = msg or "no message"
        super().__init__(
            f"{path}: Omada error {code}: {detail}",
            message_id="omada.error",
            params={"path": path, "code": code, "detail": detail},
        )


class TokenRefused(AuthFailed):
    """The access token was refused (expired or invalid)."""


# --- defensive parsing helpers ---------------------------------------------------------------


def _unexpected(endpoint: str, what: str) -> AdapterError:
    return unexpected_answer(endpoint, what)


def _dict(value: Any, endpoint: str, what: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise _unexpected(endpoint, f"{what} is {type(value).__name__}, expected an object")
    return value


def _sub(parent: dict[str, Any], key: str) -> dict[str, Any]:
    value = parent.get(key)
    return value if isinstance(value, dict) else {}


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _pct(value: Any) -> float | None:
    """A percentage (0-100) as a number or text; anything else: None."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int | float):
        number = float(value)
    else:
        try:
            number = float(_text(value).rstrip("%"))
        except ValueError:
            return None
    return number if 0 <= number <= 100 else None


_STANDARDS = {x.value: x for x in WifiStandard}


def radio_state(detail: dict[str, Any], short: str) -> dict[str, Any]:
    """Current state of one radio from the EAP's detail (#172): ``wp<band>`` (``rdMode``
    ``802.11a/n/ac/ax``, ``txUtil``, ``rxUtil``, ``interUtil``, ``channelUtil``) and
    ``clientNum<band>`` *(guess: field names, from the controller's web UI)*."""
    out: dict[str, Any] = {}
    wp = detail.get(f"wp{short}")
    if isinstance(wp, dict):
        mode = _text(wp.get("rdMode")).lower().removeprefix("802.11")
        found = [_STANDARDS[w] for w in mode.replace(" ", "/").split("/") if w in _STANDARDS]
        if found:
            out["standard"] = max(found, key=lambda x: STANDARD_RANK[x])
        parts = [_pct(wp.get(k)) for k in ("txUtil", "rxUtil", "interUtil")]
        busy = _pct(wp.get("channelUtil"))
        if busy is None and all(x is not None for x in parts):
            busy = min(100.0, sum(x for x in parts if x is not None))
        if busy is not None:
            out["channel_utilisation_pct"] = busy
        if parts[2] is not None:
            out["interference_pct"] = parts[2]
    count = _int(detail.get(f"clientNum{short}"))
    if count is not None and count >= 0:
        out["client_count"] = count
    return out


#: ``lagType`` of a switch port (#157): numbers and names as the controller's web API may use
#: them. A guess from the Omada web UI (Static / LACP Active / LACP Passive), not checked
#: against a controller with a LAG (#21).
_LAG_TYPES: dict[Any, LagMode] = {
    0: LagMode.STATIC,
    1: LagMode.LACP_ACTIVE,
    2: LagMode.LACP_PASSIVE,
    "static": LagMode.STATIC,
    "lacpactive": LagMode.LACP_ACTIVE,
    "lacp_active": LagMode.LACP_ACTIVE,
    "active": LagMode.LACP_ACTIVE,
    "lacppassive": LagMode.LACP_PASSIVE,
    "lacp_passive": LagMode.LACP_PASSIVE,
    "passive": LagMode.LACP_PASSIVE,
}


def _lag_mode(value: Any) -> LagMode | None:
    if isinstance(value, bool) or value is None:
        return None
    key = value.lower() if isinstance(value, str) else value
    return _LAG_TYPES.get(key, LagMode.OTHER)


def _lag_type(row: dict[str, Any]) -> Any:
    """``lagType`` of a port row, or of its ``lagSetting``."""
    if "lagType" in row:
        return row["lagType"]
    setting = row.get("lagSetting")
    return setting.get("lagType") if isinstance(setting, dict) else None


#: ``band`` of a rogue AP row *(guess)*: the radio ids of the client list.
_ROGUE_BANDS = {0: Band.GHZ_2_4, 1: Band.GHZ_5, 2: Band.GHZ_5, 3: Band.GHZ_6}


def _rogue_security(value: Any) -> Security | None:
    """Security of a rogue AP as the controller writes it (``WPA2-PSK``, ``WPA2/WPA3-SAE``,
    ``None``/``Open``) *(guess)*."""
    text = _text(value).lower().replace(" ", "")
    if not text:
        return None
    if text in ("none", "open"):
        return Security.OPEN
    if "owe" in text:
        return Security.OWE
    if "wep" in text:
        return Security.WEP
    enterprise = "enterprise" in text or "eap" in text or "802.1x" in text
    if "wpa3" in text:
        if enterprise:
            return Security.WPA3_ENTERPRISE
        return Security.WPA2_WPA3 if "wpa2" in text else Security.WPA3
    if "wpa2" in text:
        if enterprise:
            return Security.WPA2_ENTERPRISE
        return Security.WPA_WPA2 if "wpa/" in text or "wpa-wpa2" in text else Security.WPA2
    if "wpa" in text:
        return Security.WPA_ENTERPRISE if enterprise else Security.WPA
    return Security.OTHER


def _lag_id(value: Any) -> str | None:
    """Id of the link aggregation group of a port: text or number; 0 and empty: none."""
    if isinstance(value, int) and not isinstance(value, bool):
        return str(value) if value > 0 else None
    return _text(value) or None


def _int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    text = _text(value)
    return int(text) if text.lstrip("-").isdigit() else None


def _watts(value: Any) -> float | None:
    """A number of watts (a number or numeric text); ``None`` for anything else."""
    if isinstance(value, bool):
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if number >= 0 else None


def _port_poe(row: dict[str, Any]) -> PortPoe | None:
    """PoE of a switch port: ``poe`` (on or off) and ``poePower`` (watts delivered now). Both
    names are a guess for the Omada versions without a documented field (#21); a controller
    that reports neither gives ``None``."""
    on = row.get("poe") if isinstance(row.get("poe"), bool) else None
    power = _watts(row.get("poePower"))
    if on is None and power is None:
        return None
    status = None
    if on is False:
        status = PoeStatus.DISABLED
    elif power is not None:
        status = PoeStatus.DELIVERING if power > 0 else PoeStatus.SEARCHING
    return PortPoe(enabled=on, status=status, power_w=power)


def _poe_supply(switch: dict[str, Any]) -> PoeSupply | None:
    """The budget of a PoE switch: ``totalPower`` (older controllers ``poePower``) in watts and
    ``poeRemain`` (watts left); used power is the difference. ``None``: not reported."""
    total = _watts(switch.get("totalPower"))
    if total is None:
        total = _watts(switch.get("poePower"))
    remain = _watts(switch.get("poeRemain"))
    if total is None:
        return None
    used = max(total - remain, 0.0) if remain is not None else None
    return PoeSupply(budget_w=total, used_w=used)


def _flag(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    return value in (True, 1, "1", "true")


def omada_role(row: dict[str, Any]) -> AccountPrivilege | None:
    """The privilege of a controller user by its role name (*guess*, #21): the master
    administrator and administrators are admin, viewers read, other roles other."""
    role = _text(row.get("roleName") or row.get("role")).lower()
    if not role:
        return None
    if "admin" in role:
        return AccountPrivilege.ADMIN
    if "viewer" in role or "read" in role:
        return AccountPrivilege.READ
    return AccountPrivilege.OTHER


def _on(row: dict[str, Any]) -> bool:
    """A controller user is enabled unless it says otherwise (``disable``, ``enable``)."""
    if "disable" in row:
        return not _flag(row.get("disable"))
    return _flag(row.get("enable"), default=True)


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


#: ``proto`` of a WAN port ("Static IP, DHCP, PPPoE, L2TP, PPTP, DS-Lite, and MAP-E" in the
#: API description), compared without case, spaces and dashes
_PROTOS = {
    "staticip": UplinkKind.STATIC,
    "static": UplinkKind.STATIC,
    "dhcp": UplinkKind.DHCP,
    "pppoe": UplinkKind.PPPOE,
    "dslite": UplinkKind.DSLITE,
    "mape": UplinkKind.MAP_E,
}


def _config(row: dict[str, Any], key: str) -> dict[str, Any]:
    value = row.get(key)
    return value if isinstance(value, dict) else {}


def _wan_addresses(row: dict[str, Any]) -> list[IPInterface]:
    v4, v6 = _config(row, "wanPortIpv4Config"), _config(row, "wanPortIpv6Config")
    out: list[IPInterface] = []
    ip = _addr(v4.get("ip")) or _addr(row.get("ip"))
    if isinstance(ip, IPv4Address) and not ip.is_unspecified:
        try:
            out.append(IPv4Interface(f"{ip}/{_text(v4.get('netmask')) or 32}"))
        except ValueError:
            out.append(IPv4Interface(ip))
    if _flag(v6.get("enable"), default=True):
        try:
            addr = ip_interface(_text(v6.get("addr")))
        except ValueError:
            addr = None
        if addr is not None and addr.version == 6 and not addr.ip.is_unspecified:
            out.append(addr)
    return out


def _float(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if number >= 0 else None


def _wan_health(row: dict[str, Any], up: bool | None) -> UplinkHealth | None:
    """What the controller's WAN monitor sees of a port (#150): ``latency`` in ms and ``loss`` in
    percent of ``wan-status`` (*guess*: the unit of both; a port that is down reports 0 and
    keeps no figures). The state is online or down; the degraded threshold is the rule's."""
    if up is None:
        return None
    if not up:
        return UplinkHealth(state=UplinkState.DOWN)
    latency, loss = _float(row.get("latency")), _float(row.get("loss"))
    return UplinkHealth(
        state=UplinkState.ONLINE,
        latency_ms=latency if latency else None,
        loss_pct=min(loss, 100.0) if loss is not None else None,
    )


def wan_uplink(row: dict[str, Any], device_id: str, extra: dict[str, JsonValue]) -> Uplink | None:
    """One entry of ``…/gateways/{mac}/wan-status``; a port in LAN mode is no uplink."""
    port = _int(row.get("port"))
    mode, kind_of_port = _int(row.get("mode")), _int(row.get("type"))
    if port is None or mode == 1 or (mode is None and kind_of_port == 2):
        return None
    v4, v6 = _config(row, "wanPortIpv4Config"), _config(row, "wanPortIpv6Config")
    proto = _text(row.get("proto"))
    kind = _PROTOS.get(proto.lower().replace(" ", "").replace("-", ""), UplinkKind.OTHER)
    status, internet = _int(row.get("status")), _int(row.get("internetState"))
    up = False if status == 0 else {0: False, 1: True}.get(internet if internet is not None else -1)
    gateways = [a for a in (_addr(v4.get("gateway")), _addr(v6.get("gateway"))) if a]
    dns: list[IPAddress] = []
    for config in (v4, v6):
        for key in ("priDns", "sndDns"):
            a = _addr(config.get(key))
            if a is not None and not a.is_unspecified and a not in dns:
                dns.append(a)
    return Uplink(
        id=f"{device_id}/uplink/port{port}",
        device_id=device_id,
        health=_wan_health(row, up),
        name=_text(row.get("name")) or f"WAN{port}",
        kind=kind,
        up=up,
        addresses=_wan_addresses(row),
        upstream_gateway=next((g for g in gateways if not g.is_unspecified), None),
        dns_servers=dns,
        vendor_extra={
            **extra,
            **{k: _text(row[k]) for k in ("proto", "portDesc") if _text(row.get(k))},
            **({"port": port}),
        },
    )


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
    #: Identity (#177): ``sn`` / ``hwVersion`` of the device list (``serialNumber`` is a guess).
    serial: str | None = None
    hardware: str | None = None
    #: ``needUpgrade`` of the device list (#181): the controller has a newer firmware for it.
    upgradable: bool | None = None

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
class _ApLink:
    """What the controller says about an access point's uplink (#336)."""

    parent: str  # normalised MAC of the device it hangs on
    port: str | None  # that device's port as the controller writes it (wired uplink)
    speed: int | None  # Mbit/s of the wired link
    mesh: bool  # a wireless uplink to another access point
    #: the ``wireless uplink info`` object (channel, rssi, rates, partner radio), mesh only
    info: dict[str, Any] | None = None


#: Names the controller gives the wireless uplink of an access point in its answer: the 6.3
#: description of ``GET …/aps/{apMac}`` spells it ``wireless uplink info``; the camel-case
#: spellings are *guesses* for what a real answer carries.
MESH_KEYS = ("wirelessUpLinkInfo", "wirelessUplinkInfo", "wireless uplink info")
#: Fields of a wired uplink in the device list or the AP detail: *guesses* (the 6.3 description
#: of the AP detail has none; the controller's own UI API names its uplink so), see #21.
WIRED_MAC_KEYS = ("uplinkDeviceMac", "uplinkMac")
WIRED_PORT_KEYS = ("uplinkDevicePort", "uplinkPortName", "uplinkPort")


def _first(rows: tuple[dict[str, Any], ...], keys: tuple[str, ...]) -> Any:
    for row in rows:
        for key in keys:
            if row.get(key) not in (None, ""):
                return row[key]
    return None


#: ``radioId`` of the controller's radios: 0 is 2.4 GHz, 1 is 5 GHz, 2 the third radio (6 GHz
#: on a tri-band access point; *guess*, #21).
_RADIO_BANDS = {0: Band.GHZ_2_4, 1: Band.GHZ_5, 2: Band.GHZ_6}


def mesh_info(info: dict[str, Any]) -> WirelessLinkInfo:
    """Radio details of a mesh uplink from ``wireless uplink info`` (#171): ``channel``,
    ``rssi`` (dBm), ``txRateInt`` and ``rxRateInt`` (Mbit/s) are the controller's own field names
    (6.3 description); the partner link's ``radioId`` names the radio, else the channel decides
    (up to 14: 2.4 GHz)."""
    partners = [p for p in info.get("partnerLinks") or [] if isinstance(p, dict)]
    channel = _int(info.get("channel")) or _int(partners[0].get("channel") if partners else None)
    rssi = _int(info.get("rssi")) if info.get("rssi") is not None else None
    band = _RADIO_BANDS.get(_int(partners[0].get("radioId")) if partners else None)  # type: ignore[arg-type]
    if band is None and channel:
        band = Band.GHZ_2_4 if channel <= 14 else Band.GHZ_5
    tx, rx = _int(info.get("txRateInt")), _int(info.get("rxRateInt"))
    return WirelessLinkInfo(
        band=band,
        channel=channel or None,
        signal_dbm=rssi if rssi is not None and -120 <= rssi <= 0 else None,
        tx_rate_mbps=float(tx) if tx else None,
        rx_rate_mbps=float(rx) if rx else None,
        kind=MeshLinkKind.MESH,
    )


def ap_link(row: dict[str, Any], detail: dict[str, Any]) -> _ApLink | None:
    """The uplink of an access point from its device-list row and its detail answer: a mesh
    uplink (``wirelessLinked`` with the uplink AP's MAC) or a wired one (switch MAC, port and
    link speed). None: the controller says nothing (an AP without an uplink, a field this
    controller version does not have)."""
    info = _first((detail,), MESH_KEYS)
    if isinstance(info, dict) and detail.get("wirelessLinked") is not False:
        parent = _mac(info.get("uplinkMac"))
        if parent is not None:
            return _ApLink(parent=parent, port=None, speed=None, mesh=True, info=info)
    both = (detail, row)
    parent = _mac(_first(both, WIRED_MAC_KEYS))
    if parent is None:
        return None
    port = _first(both, WIRED_PORT_KEYS)
    speed = LINK_SPEEDS.get(_int(_first(both, ("linkSpeed",))) or 0)
    return _ApLink(parent=parent, port=_text(port) or None, speed=speed, mesh=False)


#: Frame size of a switch without jumbo frames (Omada's default ``jumbo`` setting).
STANDARD_FRAME = 1518


def _port_name(sw: _Managed, name: Any, number: int) -> str:
    return f"{sw.name} {_text(name) or f'Port{number}'}"


def jumbo_of(switch: dict[str, Any] | None) -> bool | None:
    """Jumbo frames of a switch: ``jumbo`` is its largest frame (1518 to 9216) *(guess)*."""
    value = (switch or {}).get("jumbo")
    if isinstance(value, bool):
        return value
    size = _int(value)
    return None if size is None else size > STANDARD_FRAME


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
        return ENT_VERSIONS.get(version or 0, Security.WPA2_ENTERPRISE)
    if mode == 3:
        return PSK_VERSIONS.get(_int(psk.get("versionPsk")) or 2, Security.OTHER)
    return Security.OTHER


def _psk_details(ssid: dict[str, Any], sec: Security) -> dict[str, Any]:
    """Ciphers and group rekey of a personal SSID (``pskSetting``): ``encryptionPsk`` and
    ``gikRekeyPskEnable`` (off: 0, never rotated; on: the interval field, if the controller
    has one: ``rekeyPskInterval`` is a guess, else None). Nothing for other modes."""
    if sec not in PERSONAL:
        return {}
    psk = _sub(ssid, "pskSetting")
    out: dict[str, Any] = {"ciphers": PSK_CIPHERS.get(_int(psk.get("encryptionPsk")) or 0)}
    enabled = psk.get("gikRekeyPskEnable")
    if enabled is False:
        out["key_rotation_seconds"] = 0
    elif enabled is True:
        interval = _int(psk.get("rekeyPskInterval"))
        out["key_rotation_seconds"] = interval if interval and interval > 0 else None
    return out


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


#: Shown in the device form ("Before you add it").
OMADA_STEPS = (
    (
        "In the controller: Global View > Settings > Platform Integration > Open API, add an "
        "application in Client mode with the Viewer role and access to the site."
    ),
    (
        "Below: the controller's address with its port, the site name, Client ID and Client "
        "Secret. Then Test connection and trust the certificate."
    ),
)


class OmadaAdapter(_Adapter):
    manifest = Manifest(
        setup_steps=OMADA_STEPS,
        setup_url="https://github.com/PhilippMundhenk/signalbox/blob/main/docs/adapters/omada.md#setup",
        id="omada",
        name="TP-Link Omada",
        version="0.2.0",
        api_version="1.4",
        vendor="TP-Link",
        roles=frozenset({DeviceRole.OTHER, DeviceRole.AP, DeviceRole.SWITCH, DeviceRole.GATEWAY}),
        capabilities=frozenset(
            {
                Capability.INTERFACES,
                Capability.DHCP,
                Capability.WIRELESS,
                Capability.CLIENTS,
                Capability.HEALTH,
                Capability.TIME,
                Capability.FIREWALL,
                Capability.NEIGHBOURS,
            }
        ),
        config=OmadaConfig,
        description="Reads one site of an Omada controller through its Open API and changes "
        "its LAN networks, DHCP, switch ports and SSIDs; reads its gateway ACLs and port forwards.",
        writes=frozenset({ChangeKind.ROUTER, ChangeKind.DHCP, ChangeKind.PORT, ChangeKind.WLAN}),
    )

    @classmethod
    async def discover(cls, probe: HostProbe) -> Candidate | None:
        """``/api/info`` on port 8043 or 443, which the controller answers without login."""
        return await _discovery.discover(probe)

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
        self._users_need_auth_code = False  # -44118 seen: do not ask again (#354)
        self._site_zone: Any = None
        self._token: str | None = None
        #: controller release as (major, minor) once read, for notes on what an older one lacks
        self._release: tuple[int, int] | None = None
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

    def _no_open_api(self) -> AdapterError:
        """The controller is too old for the Open API (no classic-API fallback, see the docs)."""
        text = f"{self._release[0]}.{self._release[1]}" if self._release else "of this version"
        need = f"{OPEN_API_FROM[0]}.{OPEN_API_FROM[1]}"
        return AdapterError(
            f"this controller ({text}) has no Open API: Signalbox needs Omada controller "
            f"{need} or later",
            fix="Update the controller (Omada Software Controller, OC200/OC300) to a release "
            "with the Open API, or leave this controller out of Signalbox. The classic web "
            "API of older controllers is not supported.",
            message_id="omada.noOpenApi",
            fix_id="omada.noOpenApi.fix",
            params={"release": text, "need": need},
        )

    async def _authorise(self) -> None:
        try:
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
        except NotFound as exc:  # Tomcat's 404: controller 5.8 or older has no Open API
            raise self._no_open_api() from exc
        try:
            result = _check(data, TOKEN)
        except OmadaError as exc:
            raise AuthFailed(
                f"the controller refused the client credentials: {exc}",
                message_id="omada.clientRefused",
                params={"detail": str(exc)},
            ) from exc
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
        self._release = controller_release(_text(info.get("controllerVer")))
        if self._release is not None and self._release[0] < 5:
            raise self._no_open_api()  # 4.x: classic web API only
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
            raise AdapterError(
                f"the controller has no site {wanted!r} (sites: {names})",
                message_id="omada.noSite",
                params={"site": repr(wanted), "sites": names},
            )
        self._site_path = f"/openapi/v1/{self._omadac_id}/sites/{site_id}"
        self._site_zone = site.get("timeZone") if site else None
        version = _text(info.get("controllerVer"))
        return SystemInfo(
            vendor="TP-Link",
            model="Omada Controller",
            firmware=Firmware(current=version) if version else None,
            management_address=self.http.host,
            transport_encrypted=self.http.secure,
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
                    serial=_text(row.get("sn") or row.get("serialNumber")) or None,
                    hardware=_text(row.get("hwVersion") or row.get("hardwareVersion")) or None,
                    upgradable=row["needUpgrade"]
                    if isinstance(row.get("needUpgrade"), bool)
                    else None,
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
        poe_supply: dict[str, PoeSupply] = {}
        for sw in (d for d in await self._devices() if d.kind == "switch"):
            first = len(ports)
            lag_types: dict[str, Any] = {}
            switch_row = await self._switch(sw.raw_mac)
            jumbo = jumbo_of(switch_row)
            supply = _poe_supply(switch_row)
            if supply is not None:
                poe_supply[self._prefix(sw)] = supply
            for row in await self._ports(sw.raw_mac):
                number = _int(row.get("port"))
                if number is None:
                    continue
                pid = f"{self._prefix(sw)}/port/{number}"
                lag_types[pid] = _lag_type(row)
                profile = profiles.get(_text(row.get("profileId")), {})
                native = _text(
                    row["nativeNetworkId"]
                    if "nativeNetworkId" in row
                    else profile.get("nativeNetworkId")
                )
                tagged = (
                    row["tagNetworkIds"] if "tagNetworkIds" in row else profile.get("tagNetworkIds")
                )
                link = _int(row.get("linkStatus"))
                duplex, speed = _int(row.get("duplex")), _int(row.get("linkSpeed"))
                disable = row.get("disable")
                ports.append(
                    Port(
                        id=pid,
                        device_id=self._prefix(sw),
                        name=_port_name(sw, row.get("name"), number),
                        up=False if disable is True else None if link is None else link == 1,
                        speed_mbps=None if link == 0 else LINK_SPEEDS.get(speed or 0),
                        full_duplex=None if link == 0 else {1: False, 2: True}.get(duplex or 0),
                        poe=_port_poe(row),
                        lag=_lag_id(row.get("lagId")),
                        role=PortRole.JACK,
                        admin_up=not disable if isinstance(disable, bool) else None,
                        profile=_text(row.get("profileName")) or None,
                        pvid=nets[native].vlan if native in nets else None,
                        max_speed_mbps=LINK_SPEEDS.get(_int(row.get("maxSpeed")) or 0),
                        jumbo=jumbo,
                        counters=_counters(row),
                        vendor_extra=sw.extra(port=number),
                    )
                )
                if native in nets:
                    members[nets[native].segment][pid] = Membership.UNTAGGED
                for net_id in tagged if isinstance(tagged, list) else []:
                    net = nets.get(_text(net_id))
                    if net is not None and pid not in members[net.segment]:
                        members[net.segment][pid] = Membership.TAGGED
            ports.extend(self._lags(sw, ports[first:], lag_types))
        ports.extend((await self._ap_view())[0])
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
        mesh_links, mesh_members = await self._mesh()
        managed = [
            Device(
                id=self._prefix(d),
                site_id=site,
                name=d.name,
                role=ROLES.get(d.kind, DeviceRole.OTHER),
                vendor="TP-Link",
                model=d.model,
                firmware=Firmware(current=d.firmware, upgradable=d.upgradable)
                if d.firmware
                else None,
                mac=d.mac,
                serial=d.serial,
                hardware_revision=d.hardware,
                hostname=d.name if d.name != d.mac else None,
                adapter=self.manifest.id,
                vendor_extra={"omada_device": d.identity()},
            )
            for d in await self._devices()
        ]
        uplinks = await self._uplinks(gateway) if gateway is not None else []
        groups, group_gaps = (
            await self._wan_groups(gateway, uplinks) if gateway is not None else ([], [])
        )
        return Observation(
            ports=ports,
            poe=poe_supply,
            segments=segs,
            subnets=subnets,
            devices=managed,
            wireless_links=mesh_links,
            mesh=mesh_members,
            uplinks=uplinks,
            gateway_groups=groups,
            incomplete=group_gaps,
            services=await self._services([m.id for m in managed]),
            **await self._accounts([m.id for m in managed]),
            log_targets=await self._log_targets([m.id for m in managed]),
        )

    # --- access points and their uplinks (#336) -------------------------------------------------

    async def _ap_view(self) -> tuple[list[Port], list[Neighbour]]:
        """The wired port of every access point (``ETH1``; the controller lists none), a wireless
        mesh port for those in a mesh, and the uplinks the controller reports as neighbours:
        the switch (and its port) the AP hangs on, or the AP its mesh uplink goes to."""
        cached = self._cache.get("ap-view")
        if cached is not None:
            return cached  # type: ignore[no-any-return]
        dev = self.context.device_id
        devices = await self._devices()
        by_mac = {d.mac: d for d in devices}
        aps = [d for d in devices if d.kind == "eap"]
        rows = {_mac(r.get("mac")): r for r in await self._rows(f"{self._site_path}/devices")}
        links: dict[str, _ApLink] = {}
        for ap in aps:
            detail = await self._object(f"{self._site_path}/aps/{ap.raw_mac}") or {}
            link = ap_link(rows.get(ap.mac, {}), detail)
            if link is not None and link.parent != ap.mac:
                links[ap.mac] = link
        meshed: set[str] = set()
        for mac, link in links.items():
            parent = by_mac.get(link.parent)
            if link.mesh and parent is not None and parent.kind == "eap":
                meshed |= {mac, link.parent}
        ports: list[Port] = []
        for ap in aps:
            link = links.get(ap.mac)
            wired = link is not None and not link.mesh
            ports.append(
                Port(
                    id=f"{self._prefix(ap)}/port/1",
                    device_id=self._prefix(ap),
                    name=f"{ap.name} ETH1",
                    up=True if wired else None,
                    speed_mbps=link.speed if link is not None and wired else None,
                    role=PortRole.JACK,
                    vendor_extra=ap.extra(port=1),
                )
            )
            if ap.mac in meshed:
                ports.append(
                    Port(
                        id=f"{self._prefix(ap)}/port/mesh",
                        device_id=self._prefix(ap),
                        name=f"{ap.name} Mesh",
                        kind=PortKind.WIRELESS,
                        role=PortRole.WIRELESS,
                        vendor_extra=ap.extra(),
                    )
                )
        neighbours: list[Neighbour] = []
        for ap in aps:
            link = links.get(ap.mac)
            if link is None:
                continue
            parent = by_mac.get(link.parent)
            remote: str | None
            if link.mesh:
                if link.parent not in meshed or parent is None or parent.kind != "eap":
                    continue
                local = f"{self._prefix(ap)}/port/mesh"
                remote = f"{parent.name} Mesh"
            else:
                local = f"{self._prefix(ap)}/port/1"
                remote = link.port
                if parent is not None and parent.kind == "switch" and link.port:
                    remote = await self._switch_port_name(parent, link.port)
            nid = object_id(dev, "neighbour", f"{local}-{link.parent}")
            neighbours.append(
                Neighbour(
                    id=nid,
                    local_port_id=local,
                    chassis_id=link.parent,
                    remote_port=remote,
                    system_name=parent.name if parent else None,
                    wireless=link.mesh,
                    vendor_extra=ap.extra(uplink="mesh" if link.mesh else "wired"),
                )
            )
        self._cache["ap-view"] = (ports, neighbours)
        self._cache["ap-mesh"] = self._mesh_of(aps, links, meshed)
        return ports, neighbours

    def _mesh_of(
        self, aps: list[_Managed], links: dict[str, _ApLink], meshed: set[str]
    ) -> tuple[list[Link], dict[str, MeshMembership]]:
        """Backhaul links and mesh membership of the access points (#171). The controller
        manages the mesh: the access points are its agents; a root AP has a wired uplink, the
        others a wireless one, and their hop count is the length of the chain to a root AP."""
        by_mac = {ap.mac: ap for ap in aps}
        out: list[Link] = []
        member: dict[str, MeshMembership] = {}
        for ap in aps:
            if ap.mac not in meshed:
                continue
            hops, cur, seen = 0, ap.mac, {ap.mac}
            while (up := links.get(cur)) is not None and up.mesh and up.parent in by_mac:
                if up.parent in seen:
                    break
                cur = up.parent
                seen.add(cur)
                hops += 1
            link = links.get(ap.mac)
            wireless = link is not None and link.mesh
            member[self._prefix(ap)] = MeshMembership(
                role=MeshRole.AGENT,
                controller_id=self.context.device_id,
                hop=hops,
                uplink=MeshUplink.WIRELESS if wireless else MeshUplink.WIRED,
            )
            if link is None or not link.mesh or link.info is None or link.parent not in by_mac:
                continue
            a = f"{self._prefix(by_mac[link.parent])}/port/mesh"
            b = f"{self._prefix(ap)}/port/mesh"
            out.append(
                Link(
                    id=f"mesh:{min(a, b)}~{max(a, b)}",
                    a=a,
                    b=b,
                    kind=LinkKind.WIRELESS,
                    origin=LinkOrigin.MESH,
                    wireless=mesh_info(link.info),
                )
            )
        return out, member

    async def _mesh(self) -> tuple[list[Link], dict[str, MeshMembership]]:
        await self._ap_view()
        return self._cache["ap-mesh"]  # type: ignore[no-any-return]

    async def _switch_port_name(self, sw: _Managed, text: str) -> str:
        """The name of the switch port an AP's uplink field names (a number or ``Port5``)."""
        digits = "".join(c if c.isdigit() else " " for c in text).split()
        number = int(digits[-1]) if digits else None
        for row in await self._ports(sw.raw_mac):
            if _int(row.get("port")) == number and number is not None:
                return _port_name(sw, row.get("name"), number)
        return text

    async def read_neighbours(self) -> Observation:
        return Observation(neighbours=list((await self._ap_view())[1]))

    async def _accounts(self, managed: list[str]) -> dict[str, Any]:
        """Accounts (#175): the controller's administrators (``/users``, *guess*) on the
        controller, and the site's device account (*guess*), the login every adopted device
        gets for SSH and its own web page, on each managed device. Its password is compared
        with the Omada factory default in memory and dropped; only the boolean is kept. An
        endpoint the controller does not offer (or the client may not read) gives nothing."""
        dev = self.context.device_id
        out: dict[str, Any] = {"accounts": {}, "default_credentials": {}}
        users: list[dict[str, Any]] = []
        if self._users_need_auth_code:
            out["incomplete"] = [_client_mode_gap()]
        else:
            try:
                users = await self._rows(f"/openapi/v1/{self._omadac_id}/users")
            except NotFound:  # this controller has no such endpoint
                if self._release is not None and self._release[0] < 6:
                    out["incomplete"] = [_old_gap("accounts", self._release)]
            except OmadaError as exc:  # refused for this client (#349): not "no accounts"
                if exc.code == _AUTH_CODE_ONLY:  # 6.3: a limit of client mode (#354)
                    self._users_need_auth_code = True
                    out["incomplete"] = [_client_mode_gap()]
                else:
                    out["incomplete"] = [
                        Gap(
                            message=f"accounts: the controller's users are not read ({exc})",
                            fix="Optional: use an Open API client with a role that may read "
                            "the controller's users (for example Administrator).",
                            optional=True,
                            message_id="omada.accounts",
                            fix_id="omada.accounts.fix",
                            params={"cause": str(exc)},
                        )
                    ]
        if users:
            out["accounts"][dev] = [
                DeviceAccount(name=name, privilege=omada_role(row), enabled=_on(row))
                for row in users
                if (name := _text(row.get("name") or row.get("userName")))
            ]
        account = await self._object(f"{self._site_path}/device-account")
        username = _text((account or {}).get("username"))
        password = (account or {}).get("password")
        if not managed or not username:
            return out
        default = (
            is_factory_default("omada-device", password, username)
            if isinstance(password, str) and password and set(password) != {"*"}
            else None
        )
        for device in managed:
            out["accounts"][device] = [
                DeviceAccount(
                    name=username,
                    privilege=AccountPrivilege.ADMIN,
                    password_set=bool(password) if isinstance(password, str) else None,
                )
            ]
            if default is not None:
                out["default_credentials"][device] = default
        return out

    # --- firewall -----------------------------------------------------------------------------

    async def read_firewall(self) -> Observation:
        """The gateway's ACLs and port forwarding (#135), mapped from the Open API description
        *(guess until a site with a gateway is read, #21)*. A site without a gateway has no
        firewall to report; an ACL or forwarding list the viewer role cannot read is a gap."""
        gateway = await self._gateway()
        if gateway is None:
            return Observation()
        owner = self._prefix(gateway)
        nets = await self._networks()
        names = firewall.zone_names({n.id: n.name for n in nets.values()})
        segments = {names[n.id]: n.segment for n in nets.values()}
        wan = [u.id for u in await self._uplinks(gateway)]
        zones, policies = firewall.zones_and_policies(segments, wan)
        gaps: list[Gap] = []
        rules: list[FirewallRule] = []
        rules_complete = port_forwards_complete = True
        try:
            mode = await self._object(f"{self._site_path}/acls/osg-config-mode")
            if mode is not None and mode.get("mode") == 1:  # custom ACLs instead of profiles
                custom = await self._rows(f"{self._site_path}/acls/osg-custom-acls")
                rules = firewall.custom_acl_rules(custom, names)
            else:
                rows = await self._rows(f"{self._site_path}/acls/osg-acls")
                rules = firewall.acl_rules(rows, names)
        except (NotFound, OmadaError) as exc:
            rules_complete = False
            if isinstance(exc, NotFound) and self._release and self._release[0] < 6:
                gaps.append(_old_gap("firewall ACLs", self._release))
            else:
                gaps.append(
                    Gap(
                        message=f"firewall: the gateway ACLs are not read ({exc})",
                        message_id="omada.aclsNotRead",
                        params={"cause": str(exc)},
                    )
                )
        forwards: list[PortForward] = []
        try:
            rows = await self._rows(f"{self._site_path}/nat/port-forwardings")
            forwards = firewall.port_forwards(rows)
        except (NotFound, OmadaError) as exc:
            port_forwards_complete = False
            if isinstance(exc, NotFound) and self._release and self._release[0] < 6:
                gaps.append(_old_gap("port forwarding", self._release))
            else:
                gaps.append(
                    Gap(
                        message=f"firewall: the port forwarding is not read ({exc})",
                        message_id="omada.forwardsNotRead",
                        params={"cause": str(exc)},
                    )
                )
        return Observation(
            firewalls=[
                Firewall(
                    id=firewall_id(owner),
                    device_id=owner,
                    zones=zones,
                    policies=policies,
                    forward_policy=FirewallAction.ACCEPT,  # LAN to LAN is routed by default
                    rules=rules,
                    rules_complete=rules_complete,
                    port_forwards=forwards,
                    port_forwards_complete=port_forwards_complete,
                )
            ],
            incomplete=gaps,
        )

    async def _uplinks(self, gateway: _Managed) -> list[Uplink]:
        """The gateway's WAN ports in WAN mode (``wan-status``)."""
        path = f"{self._site_path}/gateways/{gateway.raw_mac}/wan-status"
        found = (
            wan_uplink(row, self._prefix(gateway), gateway.extra())
            for row in await self._optional_rows(path)
        )
        return [u for u in found if u is not None]

    async def _wan_groups(
        self, gateway: _Managed, uplinks: list[Uplink]
    ) -> tuple[list[GatewayGroup], list[Gap]]:
        """The WAN mode of the gateway (load balancing or link backup, #150) as one gateway
        group. The setting's path is a guess: a controller that does not answer it leaves the
        group out, with an optional gap where the gateway has two or more WAN ports."""
        if len(uplinks) < 2:
            return [], []
        setting = await self._object(f"{self._site_path}/{multiwan.SETTING}")
        group = (
            multiwan.wan_group(self._prefix(gateway), setting, uplinks)
            if setting is not None
            else None
        )
        if group is not None:
            return [group], []
        return [], [
            Gap(
                message="multi-WAN: the controller does not report the WAN mode (load "
                "balancing or link backup) of the gateway, so failover is not checked",
                fix="Optional: nothing to grant. The WAN mode is read from the controller's "
                "Open API where it offers it.",
                optional=True,
                message_id="omada.wanModeUnread",
                fix_id="omada.wanModeUnread.fix",
            )
        ]

    async def _services(self, device_ids: list[str]) -> list[ManagementService]:
        """SSH and SNMP of the site (#173). The controller applies both to every device it
        manages, so each managed device gets the same two services; the controller's own web
        interface is not read (the Open API has no call for it). Cloud access is a controller
        setting (#327, guessed path, see ``CLOUD_ACCESS``). A setting the controller refuses
        or does not have is left out."""
        ssh = await self._object(f"{self._site_path}/ssh")
        snmp = await self._object(f"{self._site_path}/setting/service/snmp")
        out: list[ManagementService] = []
        cloud = await self._object(CLOUD_ACCESS.format(omadac=self._omadac_id))
        if cloud is not None and isinstance(cloud.get(CLOUD_FIELD), bool):
            controller = self.context.device_id
            out.append(
                ManagementService(
                    id=object_id(controller, "service", "omada-cloud"),
                    device_id=controller,
                    kind=ServiceKind.CLOUD,
                    name="omada-cloud",
                    enabled=cloud[CLOUD_FIELD],
                )
            )
        for device in device_ids:
            if ssh is not None and isinstance(ssh.get("sshEnable"), bool):
                out.append(
                    ManagementService(
                        id=object_id(device, "service", "ssh"),
                        device_id=device,
                        kind=ServiceKind.SSH,
                        name="ssh",
                        enabled=ssh["sshEnable"],
                        port=_int(ssh.get("sshServerPort")) or SERVICE_PORTS[ServiceKind.SSH],
                    )
                )
            if snmp is not None:
                v12 = snmp.get("snmpV1V2CEnable") is True
                v3 = snmp.get("snmpV3Enable") is True
                community = _text(snmp.get("communityString"))
                level = _int(snmp.get("securityLevel"))
                out.append(
                    ManagementService(
                        id=object_id(device, "service", "snmp"),
                        device_id=device,
                        kind=ServiceKind.SNMP,
                        name="snmp",
                        enabled=v12 or v3,
                        port=SERVICE_PORTS[ServiceKind.SNMP],
                        snmp=SnmpSettings(
                            versions=[
                                *([SnmpVersion.V2C] if v12 else []),
                                *([SnmpVersion.V3] if v3 else []),
                            ],
                            default_community=community.lower() in ("public", "private")
                            if v12 and community
                            else None,
                            v3_privacy=level == 2 if v3 and level is not None else None,
                        ),
                    )
                )
        return out

    async def _log_targets(self, device_ids: list[str]) -> dict[str, list[LogTarget]]:
        """The site's remote syslog server (#327), which the controller applies to every device
        it manages. GUESS (``SITE_LOGGING``): path and field names are not confirmed; a
        controller that does not have the setting leaves the targets unread (``None``). Syslog
        from Omada devices is UDP."""
        conf = await self._object(f"{self._site_path}{SITE_LOGGING}")
        if conf is None or not isinstance(conf.get("enable"), bool):
            return {}
        target = _text(conf.get("serverIp"))
        targets = (
            [
                LogTarget(
                    kind=LogKind.SYSLOG,
                    address=target,
                    port=_int(conf.get("serverPort")) or None,
                    transport=LogTransport.UDP,
                    enabled=conf["enable"],
                    name="site",
                )
            ]
            if target
            else []
        )
        return {d: [t.model_copy() for t in targets] for d in device_ids}

    # --- health and time ----------------------------------------------------------------------

    async def read_health(self) -> Observation:
        """Per managed device from the device list; the controller itself reports nothing (the
        Open API does not describe its host), so its health is empty."""
        rows = {
            mac: row
            for row in await self._rows(f"{self._site_path}/devices")
            if (mac := _mac(row.get("mac"))) is not None
        }
        values = {self.context.device_id: DeviceHealth()}
        for d in await self._devices():
            values[self._prefix(d)] = vitals.health_of(rows.get(d.mac, {}))
        return Observation(health=values)

    async def read_time(self) -> Observation:
        """The controller's clock (``Date`` of ``/api/info``) and the site's time zone."""
        start = datetime.now(UTC)
        response = await self.http.request("GET", INFO)
        end = datetime.now(UTC)
        value = vitals.time_of(response.headers.get("date"), self._site_zone, start, end)
        return Observation(time={self.context.device_id: value})

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

    async def _switch(self, raw_mac: str) -> dict[str, Any]:
        """``GET …/switches/{mac}``: the switch's settings with its ``portList``; cached."""
        path = f"{self._site_path}/switches/{raw_mac}"
        if path not in self._cache:
            self._cache[path] = _dict(await self._api(path), path, "result")
        return dict(self._cache[path])

    def _lags(
        self, sw: _Managed, switch_ports: list[Port], types: dict[str, Any] | None = None
    ) -> list[Port]:
        """A port of role ``lag`` for every link aggregation group of the switch (#252): its
        members are the ports that name the group in ``lagId``. The mode (#157) is the
        ``lagType`` its members agree on (port id -> raw value in ``types``)."""
        groups: dict[str, list[Port]] = {}
        for p in switch_ports:
            if p.lag and p.lag != "0":
                groups.setdefault(p.lag, []).append(p)
        out = []
        for lag, members in sorted(groups.items()):
            modes = {_lag_mode((types or {}).get(m.id)) for m in members}
            out.append(
                Port(
                    id=f"{self._prefix(sw)}/port/lag{lag}",
                    device_id=self._prefix(sw),
                    name=f"{sw.name} LAG{lag}",
                    kind=PortKind.LAG,
                    role=PortRole.LAG,
                    lower=[m.id for m in members],
                    lag_mode=modes.pop() if len(modes) == 1 else None,
                    vendor_extra=sw.extra(lag=lag),
                )
            )
        return out

    async def _ports(self, raw_mac: str) -> list[dict[str, Any]]:
        """A switch's ports: ``portList`` of ``GET …/switches/{mac}`` (there is no port list
        endpoint of its own)."""
        ports = (await self._switch(raw_mac)).get("portList")
        if not isinstance(ports, list):
            raise _unexpected(f"{self._site_path}/switches/{raw_mac}", "no portList")
        return [p for p in ports if isinstance(p, dict)]

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
            detail = await self._object(f"{self._site_path}/aps/{ap.raw_mac}") or {}
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
                    channel_auto=channel == 0 if channel is not None else None,
                    vendor_extra=ap.extra(),
                    **radio_state(detail, short),
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
                psk = sec in PERSONAL and key_text
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
                                passphrase_digest=passphrase_digest(key_text) if psk else None,
                                **_psk_details(s, sec),
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
        return Observation(radios=w.radios, wlans=w.wlans, wifi_scan=await self._rogue_aps(w))

    async def _rogue_aps(self, wireless: _Wireless) -> list[WifiScanResult]:
        """The controller's rogue AP list (#169; ``GET …/insight/rogue-aps`` *(guess: path
        and field names, from the controller's Insight page)*): foreign access points its EAPs
        heard, read passively; empty while rogue AP detection is off. The controller leaves
        out the access points it manages. Attached to the EAP that heard it (``apMac``) and its
        radio of that band, else to the controller."""
        rows = await self._optional_rows(f"{self._site_path}/insight/rogue-aps")
        if not rows:
            return []
        eaps = {d.mac: d for d in await self._devices() if d.kind == "eap"}
        radios = {(r.device_id, r.band): r.id for r in wireless.radios}
        out = []
        for row in rows:
            bssid = _mac(row.get("bssid") or row.get("mac"))
            if bssid is None:
                continue
            channel = _int(row.get("channel"))
            code = _int(row.get("band"))
            band = _ROGUE_BANDS.get(code) if code is not None else None
            if band is None and channel:
                band = Band.GHZ_2_4 if channel <= 14 else Band.GHZ_5
            ap = eaps.get(_mac(row.get("apMac") or row.get("deviceMac")) or "")
            device = self._prefix(ap) if ap else self.context.device_id
            radio = radios.get((device, band)) if band else None
            signal = _int(row.get("rssi", row.get("signal")))
            last = _int(row.get("lastSeen"))
            out.append(
                WifiScanResult(
                    id=scan_id(radio or device, bssid),
                    device_id=device,
                    radio_id=radio,
                    bssid=bssid,
                    ssid=_text(row.get("ssid")) or None,
                    band=band,
                    channel=channel or None,
                    width_mhz=_width(row.get("channelWidth")),
                    signal_dbm=signal if signal is not None and -120 <= signal < 0 else None,
                    security=_rogue_security(row.get("security")),
                    last_seen=datetime.fromtimestamp(last / 1000, UTC) if last else None,
                    kind=ScanSource.ROGUE_DETECTION,
                )
            )
        return out

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
        fdb: dict[str, FdbEntry] = {}
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
                    # the controller's client list is the switch's table for this MAC (#160)
                    vlan = vid if vid and 1 <= vid <= 4094 else None
                    fid = fdb_id(self._prefix(sw), str(number), mac, vlan)
                    fdb[fid] = FdbEntry(
                        id=fid,
                        device_id=self._prefix(sw),
                        port_id=seen_on,
                        mac=mac,
                        vlan=vlan,
                        segment_id=seg,
                    )
            association = _association(row, seen_on) if _flag(row.get("wireless")) else None
            hostname = _text(row.get("hostName")) or _text(row.get("name"))
            last = _int(row.get("lastSeen"))
            clients[mac] = Client(
                id=object_id(dev, "client", mac),
                mac=mac,
                addresses=addresses,
                hostname=hostname if hostname and _mac(hostname) != mac else None,
                segment_id=seg,
                seen_on=seen_on,
                wireless=association,
                last_seen=datetime.fromtimestamp(last / 1000, UTC) if last else None,
            )
        return Observation(
            clients=[clients[m] for m in sorted(clients)], fdb=[fdb[k] for k in sorted(fdb)]
        )


def _association(row: dict[str, Any], wlan_id: str | None) -> WirelessAssociation:
    """Wi-Fi details of a controller client row (#170): ``rssi`` (dBm), ``snr``, ``rxRate`` and
    ``txRate`` (kbit/s), ``wifiMode``, ``uptime`` (s), ``powerSave`` *(guess: field names from
    the controller's client list, not checked against a device)*."""
    signal = _int(row.get("rssi"))
    snr = _int(row.get("snr"))
    rx, tx = _int(row.get("rxRate")), _int(row.get("txRate"))
    radio = _int(row.get("radioId"))
    mode = _int(row.get("wifiMode"))
    up = _int(row.get("uptime"))
    return WirelessAssociation(
        wlan_id=wlan_id,
        band=CLIENT_BANDS.get(radio) if radio is not None else None,
        signal_dbm=signal if signal is not None and -120 <= signal < 0 else None,
        snr_db=snr if snr is not None and 0 <= snr <= 120 else None,
        rx_rate_mbps=round(rx / 1000, 1) if rx is not None and rx >= 0 else None,
        tx_rate_mbps=round(tx / 1000, 1) if tx is not None and tx >= 0 else None,
        standard=CLIENT_STANDARDS.get(mode) if mode is not None else None,
        connected_seconds=up if up is not None and up >= 0 else None,
        power_save=_flag(row.get("powerSave")) if row.get("powerSave") is not None else None,
    )


__all__ = ["OmadaAdapter", "OmadaConfig"]
