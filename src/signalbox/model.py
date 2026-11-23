"""The vendor-neutral network model.

Adapters return a :class:`Snapshot` per device. :func:`signalbox.merge.merge` joins the snapshots
of a site into one :class:`Network` that rules, topology and UI work on.

Identifiers are strings that are unique across the whole installation. Objects of a device are
prefixed with the device id (``<device>/port/<name>``); segments are per site
(``<site>/segment/<vlan>``) so that the same VLAN seen on several devices is one segment.
Adapters report the untagged LAN as ``<site>/segment/native``; the merge gives the separate
LANs of further routers their own ids (:func:`native_segment_id`, #205).
Use the helper functions below to build them.
"""

from __future__ import annotations

import hashlib
import re
from datetime import UTC, datetime
from enum import StrEnum
from ipaddress import (
    IPv4Address,
    IPv4Interface,
    IPv4Network,
    IPv6Address,
    IPv6Interface,
    IPv6Network,
    ip_address,
)
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, JsonValue, field_validator, model_validator

IPAddress = IPv4Address | IPv6Address
IPInterface = IPv4Interface | IPv6Interface
IPNetwork = IPv4Network | IPv6Network

#: Segment key of the untagged network of a device without VLANs.
NATIVE = "native"


def port_id(device_id: str, name: str) -> str:
    return f"{device_id}/port/{name}"


#: The default VLAN of almost every device. A device that reports its plain LAN as VLAN 1
#: (OpenWrt with DSA, most managed switches) and one that reports it as untagged without an id
#: (most routers) describe the same network, so both map to the native segment.
DEFAULT_VLAN = 1


def segment_id(site_id: str, vlan: int | None) -> str:
    """Segment of a site; ``vlan=None`` and VLAN 1 are the untagged (native) network."""
    return f"{site_id}/segment/{NATIVE if vlan in (None, DEFAULT_VLAN) else vlan}"


def native_segment_id(site_id: str, gateway_id: str | None = None) -> str:
    """Id of an untagged (native) network of a site (#205).

    ``<site>/segment/native`` is the site's main untagged network, the only one at a site with
    one router. A site with several routers whose untagged networks are really separate (an ISP
    router with a firewall behind it) gets one more native segment per further router:
    ``<site>/segment/native-<gateway device id>``, where the device id is the lowest id of the
    router(s) of that network, with characters other than letters, digits, ``.``, ``_`` and
    ``-`` replaced by ``-``.
    """
    if gateway_id is None:
        return segment_id(site_id, None)
    slug = re.sub(r"[^A-Za-z0-9._-]", "-", gateway_id)
    return f"{site_id}/segment/{NATIVE}-{slug}"


def is_native_segment(segment_id: str) -> bool:
    """True for every untagged network of a site (the main one and those of further routers)."""
    key = segment_id.rsplit("/segment/", 1)[-1]
    return key == NATIVE or key.startswith(f"{NATIVE}-")


def object_id(device_id: str, kind: str, name: str) -> str:
    return f"{device_id}/{kind}/{name}"


def normalise_mac(mac: str) -> str:
    """Lower-case, colon-separated MAC address; raises ValueError for anything else."""
    digits = "".join(c for c in mac.lower() if c in "0123456789abcdef")
    if len(digits) != 12 or len(mac) > 17:
        raise ValueError(f"not a MAC address: {mac!r}")
    return ":".join(digits[i : i + 2] for i in range(0, 12, 2))


def passphrase_fingerprint(ssid: str, passphrase: str) -> str:
    """Comparable fingerprint of a WPA passphrase without revealing it.

    Derived from the WPA pairwise master key (PBKDF2 over the SSID), then hashed again and
    shortened, so two access points can be compared. Never shown in the UI or exported.
    """
    pmk = hashlib.pbkdf2_hmac("sha1", passphrase.encode(), ssid.encode(), 4096, 32)
    return hashlib.sha256(b"signalbox-psk" + pmk).hexdigest()[:16]


#: Per-installation key of :func:`passphrase_digest`, set by the service from the vault key
#: (:meth:`signalbox.secrets.Vault.derive_key`). None: no digests (library use, tests, recordings).
_digest_key: bytes | None = None


def set_passphrase_digest_key(key: bytes | None) -> bytes | None:
    """Install (or, with None, remove) the per-installation key of :func:`passphrase_digest`;
    returns the key it replaces.

    The service calls it once at start with a key derived from the vault key, so the digest
    shares the vault key's storage and rotation: a new vault key changes every digest with the
    next observation. Tests use :func:`signalbox.testing.passphrase_digest_key`.
    """
    global _digest_key
    if key is not None and len(key) < 32:
        raise ValueError("the passphrase digest key needs at least 32 bytes")
    old, _digest_key = _digest_key, key
    return old


def passphrase_digest(passphrase: str) -> str | None:
    """SSID-independent, keyed digest of a WPA passphrase (#167), None without a key.

    :func:`passphrase_fingerprint` is salted with the SSID, so it only compares the same SSID
    on several access points. This digest compares passphrases across SSIDs (a guest network
    with the main network's passphrase, #101). It is PBKDF2 with the installation's secret key
    as salt: without that key, which never leaves the vault, nobody can test a guessed
    passphrase against a digest, so a leaked digest does not help an offline dictionary attack
    the way an unkeyed hash of a short passphrase would. Never shown, never exported.
    """
    if _digest_key is None:
        return None
    raw = hashlib.pbkdf2_hmac("sha256", passphrase.encode(), _digest_key, 4096, 32)
    return raw.hex()[:16]


Mac = Annotated[str, Field(pattern=r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")]


class Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Source(Model):
    """Where an observed object came from."""

    adapter: str
    device_id: str


class Observed(Model):
    id: str
    source: Source | None = None
    observed_at: datetime | None = None
    #: Vendor fields the model does not cover. Shown on the device's advanced tab only;
    #: core logic and rules never read it.
    vendor_extra: dict[str, JsonValue] = Field(default_factory=dict)


class Site(Model):
    id: str
    name: str


class DeviceRole(StrEnum):
    GATEWAY = "gateway"
    SWITCH = "switch"
    AP = "ap"
    OTHER = "other"


class Firmware(Model):
    current: str | None = None
    available: str | None = None
    end_of_life: bool | None = None


Percent = Annotated[float, Field(ge=0, le=100)]
Bytes = Annotated[int, Field(ge=0)]


class RebootReason(StrEnum):
    POWER = "power"
    WATCHDOG = "watchdog"
    USER = "user"
    UPGRADE = "upgrade"
    CRASH = "crash"
    OTHER = "other"


class StorageKind(StrEnum):
    #: Where the configuration and firmware live (root, overlay, flash): full means settings
    #: and updates fail.
    SYSTEM = "system"
    DATA = "data"  # disks for logs, packages, user data
    #: RAM-backed (tmpfs): counted as memory, not as storage that fills up permanently.
    TEMPORARY = "temporary"
    OTHER = "other"


class StorageUsage(Model):
    #: Mount point or the device's own name for the store (``/overlay``, ``flash``).
    name: str
    kind: StorageKind = StorageKind.OTHER
    total_bytes: Bytes | None = None
    used_bytes: Bytes | None = None
    #: Wear of SSD/eMMC/flash as reported by the device (100: end of its rated life).
    wear_pct: Percent | None = None

    def used_pct(self) -> float | None:
        if not self.total_bytes or self.used_bytes is None:
            return None
        return 100 * self.used_bytes / self.total_bytes


class TemperatureSensor(Model):
    name: str
    value_c: float
    #: The device's own warning limit, where it reports one.
    limit_c: float | None = None


class Fan(Model):
    name: str
    rpm: Annotated[int, Field(ge=0)] | None = None
    #: The device's verdict (``None``: it reports no state).
    ok: bool | None = None


class PowerSupply(Model):
    name: str
    ok: bool | None = None
    watts: Annotated[float, Field(ge=0)] | None = None
    input_voltage: float | None = None


class UpsStatus(Model):
    """A UPS monitored by the device (NUT on OPNsense, ``/system/ups`` on MikroTik)."""

    name: str
    on_battery: bool | None = None
    charge_pct: Percent | None = None
    runtime_seconds: Annotated[int, Field(ge=0)] | None = None
    load_pct: Percent | None = None
    #: When the UPS last ran a self-test.
    last_test: datetime | None = None


class DeviceHealth(Model):
    """Vital signs of a device at observation time (capability ``health``).

    Every value is optional: devices report very different subsets. Values change on every
    observation; rules compare them with thresholds and the history, never as drift.
    """

    uptime_seconds: Annotated[int, Field(ge=0)] | None = None
    #: Derived from the uptime by ``Adapter.observe()`` when the device reports only one of them.
    boot_time: datetime | None = None
    last_reboot_reason: RebootReason | None = None
    #: CPU use over all cores, as the device reports it (usually the last few seconds).
    cpu_load_pct: Percent | None = None
    #: 1, 5 and 15 minute load averages (Unix-like devices).
    load_average: tuple[float, float, float] | None = None
    cpu_count: Annotated[int, Field(ge=1)] | None = None
    memory_total_bytes: Bytes | None = None
    #: Memory in use by programs: page cache and buffers do not count (total minus available).
    memory_used_bytes: Bytes | None = None
    storage: list[StorageUsage] = Field(default_factory=list)
    temperatures: list[TemperatureSensor] = Field(default_factory=list)
    fans: list[Fan] = Field(default_factory=list)
    power_supplies: list[PowerSupply] = Field(default_factory=list)
    ups: list[UpsStatus] = Field(default_factory=list)

    def memory_used_pct(self) -> float | None:
        if not self.memory_total_bytes or self.memory_used_bytes is None:
            return None
        return 100 * self.memory_used_bytes / self.memory_total_bytes

    def max_temperature_c(self) -> float | None:
        return max((t.value_c for t in self.temperatures), default=None)


class NtpClient(Model):
    enabled: bool
    #: Configured servers, names or addresses, in the device's order.
    servers: list[str] = Field(default_factory=list)
    synchronised: bool | None = None
    last_sync: datetime | None = None
    stratum: Annotated[int, Field(ge=0, le=16)] | None = None
    #: The server the device currently synchronises with, where it says.
    current_server: str | None = None


class NtpServer(Model):
    enabled: bool
    #: Segments where the device serves time (empty while enabled: all of its networks).
    segments: list[str] = Field(default_factory=list)


class DeviceTime(Model):
    """Clock, time zone and NTP of a device (capability ``time``).

    ``clock`` is the device's time when it was read and ``read_at`` Signalbox's own time at that
    moment, so :meth:`offset_seconds` is the device's clock error, give or take
    ``uncertainty_seconds`` (half the request's round trip).
    """

    clock: datetime | None = None
    read_at: datetime | None = None
    uncertainty_seconds: Annotated[float, Field(ge=0)] | None = None
    #: IANA name (``Europe/Berlin``) where the device has one, else its POSIX TZ string.
    timezone: str | None = None
    utc_offset_minutes: Annotated[int, Field(ge=-1080, le=1080)] | None = None
    ntp_client: NtpClient | None = None
    ntp_server: NtpServer | None = None

    def offset_seconds(self) -> float | None:
        """Device clock minus Signalbox's clock (positive: the device is ahead)."""
        if self.clock is None or self.read_at is None:
            return None
        return (self.clock - self.read_at).total_seconds()


class Device(Observed):
    site_id: str
    name: str
    role: DeviceRole
    vendor: str | None = None
    model: str | None = None
    firmware: Firmware | None = None
    management_address: str | None = None
    adapter: str
    capabilities: list[str] = Field(default_factory=list)
    #: Set for a device reported through a controller (the configured device that observed it).
    managed_by: str | None = None
    #: Uptime, CPU, memory, storage, sensors (API 1.2, capability ``health``).
    health: DeviceHealth | None = None
    #: Clock, time zone, NTP (API 1.2, capability ``time``).
    time: DeviceTime | None = None
    #: How Signalbox itself reads the device (#173): ``False`` for a protocol without
    #: encryption (NETGEAR NSDP, TP-Link Easy Smart UDP) or plain HTTP (``allow_insecure_http``),
    #: so the password it sends can be captured in that network. Set by the adapter
    #: (``SystemInfo.transport_encrypted``); ``None``: the adapter does not say.
    transport_encrypted: bool | None = None


class PortKind(StrEnum):
    ETHERNET = "ethernet"
    WIRELESS = "wireless"
    BRIDGE = "bridge"
    LAG = "lag"
    VIRTUAL = "virtual"


class PortRole(StrEnum):
    """Where a port sits in the device's internal structure (#252, ADR 0008).

    ``Port.kind`` says what a port is made of (Ethernet, Wi-Fi, bridge); the role says where
    it sits: a jack on the case, the internal port between the CPU and a switch chip, or an
    interface built on top of other ports (``Port.lower``).
    """

    #: A connector on the case (RJ45 jack, SFP cage): a cable can be plugged in. A DSA user
    #: port (``lan1``) is one; so is the NIC of a PC or a VM.
    JACK = "jack"
    #: The internal link between the CPU and a built-in switch chip (DSA conduit ``eth0``,
    #: the swconfig CPU port). Never cabled; it carries every VLAN of the switch tagged.
    CPU = "cpu"
    #: A port of a built-in switch chip that the device does not say more about (usually a
    #: jack; which one is not known).
    SWITCH_PORT = "switch-port"
    BRIDGE = "bridge"
    #: An 802.1Q interface on top of one port (``eth0.2``, ``br-lan.10``, MikroTik ``vlan20``).
    VLAN = "vlan"
    #: A Wi-Fi interface (``phy0-ap0``, ``wlan1``); its radio is the ``Wlan.radio_id`` of the
    #: SSIDs it carries (``Wlan.port_id``).
    WIRELESS = "wireless"
    #: A link aggregation over its member jacks (cabled through them).
    LAG = "lag"
    #: A tunnel (WireGuard, GRE, PPPoE session): no layer-2 port of its own.
    TUNNEL = "tunnel"
    #: Any other software interface (loopback, dummy, veth, macvlan).
    VIRTUAL = "virtual"


#: Roles of ports that a cable can be plugged into (a LAG through its members).
CABLED_ROLES = frozenset({PortRole.JACK, PortRole.LAG})
#: Roles of ports that are never the end of a cable.
INTERNAL_ROLES = frozenset(set(PortRole) - CABLED_ROLES - {PortRole.SWITCH_PORT})


class FrameTypes(StrEnum):
    """Which frames a port accepts on ingress (802.1Q acceptable frame types)."""

    ALL = "all"
    TAGGED_ONLY = "tagged-only"  # a trunk: untagged frames are dropped, the PVID is unused
    UNTAGGED_ONLY = "untagged-only"  # an access port: tagged frames are dropped


class PortMedia(StrEnum):
    """Physical medium of a wired port (wireless ports are ``PortKind.WIRELESS``)."""

    COPPER = "copper"  # RJ45
    SFP = "sfp"  # 1 Gbit/s cage
    SFP_PLUS = "sfp+"  # 10 Gbit/s (and faster) cage
    OTHER = "other"


#: Largest frame payload of standard Ethernet; a larger MTU means jumbo frames.
STANDARD_MTU = 1500

Vlan = Annotated[int, Field(ge=1, le=4094)]
Mtu = Annotated[int, Field(ge=68, le=65535)]
Mbps = Annotated[int, Field(ge=1)]


class Port(Observed):
    """A port of a device.

    ``up`` is the link state. The configuration details below (from ``description`` on) are
    filled only where the device reports them, as part of the ``interfaces`` capability;
    ``None`` (or an empty list) means "not reported", never "off".
    """

    device_id: str
    name: str
    kind: PortKind = PortKind.ETHERNET
    up: bool | None = None
    speed_mbps: int | None = None
    full_duplex: bool | None = None
    poe: bool | None = None
    lag: str | None = None
    mac: Mac | None = None
    #: The user's own label of the port (alias, comment: "office desk"). User text: may
    #: contain names, so it is shown but never put into exports or reports by default.
    description: str | None = None
    #: Administratively enabled. A disabled port has ``admin_up=False`` and ``up=False``.
    admin_up: bool | None = None
    #: VLAN that untagged frames arriving on the port are put into (1: the native network).
    #: Ingress only: what the port *sends* untagged is its untagged ``Segment.members``
    #: entry; on switches that keep both settings apart (ProSAFE, Easy Smart) they can differ.
    pvid: Vlan | None = None
    frame_types: FrameTypes | None = None
    #: Frames of VLANs the port is not a member of are dropped on ingress.
    ingress_filter: bool | None = None
    #: Layer-3 MTU (IP packet size; 1500 standard).
    mtu: Mtu | None = None
    #: Largest layer-2 frame without the Ethernet header, where the device has its own setting
    #: (MikroTik ``l2mtu``).
    l2_mtu: Mtu | None = None
    #: Jumbo frames on, for switches that only have a switch-wide or per-port flag.
    jumbo: bool | None = None
    #: Fastest speed the port supports (hardware), for "1G link on 2.5G ports".
    max_speed_mbps: Mbps | None = None
    #: Speeds the port offers in auto-negotiation, ascending (empty: not reported).
    advertised_speeds_mbps: list[Mbps] = Field(default_factory=list)
    #: Auto-negotiation on; ``False``: speed and duplex are forced.
    autoneg: bool | None = None
    media: PortMedia | None = None
    #: Name of the port profile a controller applies (Omada).
    profile: str | None = None
    flow_control: bool | None = None
    #: Energy-efficient Ethernet (802.3az).
    eee: bool | None = None
    # internal structure (#252, ADR 0008); None / empty: not reported -----------------------
    #: Where the port sits in the device (jack, CPU port, bridge, VLAN interface, ...).
    role: PortRole | None = None
    #: Ids of the ports of the same device this one runs on: a bridge's members, a VLAN
    #: interface's parent, a DSA user port's CPU port (conduit), a LAG's members. Bottom-up:
    #: the jack does not list the bridge, the bridge lists the jack.
    lower: list[str] = Field(default_factory=list)

    @field_validator("advertised_speeds_mbps")
    @classmethod
    def _sorted_speeds(cls, value: list[int]) -> list[int]:
        return sorted(set(value))

    @field_validator("description", "profile")
    @classmethod
    def _no_blank(cls, value: str | None) -> str | None:
        return (value.strip() or None) if value is not None else None

    def label(self) -> str:
        """Name for findings and the UI: ``5 (office desk)`` when the port has a description."""
        if self.description and self.description != self.name:
            return f"{self.name} ({self.description})"
        return self.name

    def jumbo_frames(self) -> bool | None:
        """Jumbo frames on, from the flag or the MTU (comparable across both kinds of device)."""
        if self.jumbo is not None:
            return self.jumbo
        return None if self.mtu is None else self.mtu > STANDARD_MTU

    @property
    def external(self) -> bool | None:
        """A cable can end here (a jack, or a LAG through its jacks); ``False`` for internal
        ports (CPU port, bridge, VLAN interface, Wi-Fi interface, tunnel); ``None``: not known
        (no role, or a switch port the device says nothing more about)."""
        if self.role is None or self.role is PortRole.SWITCH_PORT:
            return None
        return self.role in CABLED_ROLES


class Membership(StrEnum):
    UNTAGGED = "untagged"
    TAGGED = "tagged"


class PortMembership(Model):
    port_id: str
    mode: Membership


class SegmentPurpose(StrEnum):
    """What a network is for: the vocabulary users think in ("my IoT network")."""

    MAIN = "main"
    GUEST = "guest"
    IOT = "iot"
    MANAGEMENT = "management"
    SERVERS = "servers"
    LAB = "lab"
    VOICE = "voice"
    CAMERAS = "cameras"
    TRANSIT = "transit"
    OTHER = "other"


#: Purposes of networks whose devices are not trusted (rules about exposure use these).
UNTRUSTED_PURPOSES = frozenset({SegmentPurpose.GUEST, SegmentPurpose.IOT, SegmentPurpose.CAMERAS})


class PurposeSource(StrEnum):
    """Where a purpose came from. Declared beats reported beats heuristic."""

    #: The device knows it (Fritz!Box guest network, Omada guest SSID).
    REPORTED = "reported"
    #: The user set it in the desired state.
    DECLARED = "declared"
    #: Guessed from the name ("guest", "gast", "visitor", "iot"); shown as a guess.
    HEURISTIC = "heuristic"


class Segment(Observed):
    """A layer-2 network (VLAN) of a site."""

    site_id: str
    vlan: int | None = Field(default=None, ge=1, le=4094)
    name: str | None = None
    members: list[PortMembership] = Field(default_factory=list)
    purpose: SegmentPurpose | None = None
    purpose_source: PurposeSource | None = None
    #: What the device reported when a declared purpose overrides a different one.
    reported_purpose: SegmentPurpose | None = None
    #: True when the device isolates this network by itself, independent of firewall rules
    #: (a router's built-in guest network, a private VLAN). None: not known.
    isolated: bool | None = None


class Subnet(Observed):
    segment_id: str
    #: Address of the device on this subnet, with prefix length (e.g. 192.0.2.1/24).
    interface: IPInterface
    device_id: str
    #: True when this device is the subnet's gateway (router).
    gateway: bool = False


class UplinkKind(StrEnum):
    """How a gateway reaches its provider (or the router in front of it)."""

    DHCP = "dhcp"
    STATIC = "static"
    PPPOE = "pppoe"
    #: DS-Lite (RFC 6333): native IPv6, IPv4 tunnelled to the provider's carrier-grade NAT.
    DSLITE = "dslite"
    MAP_E = "map-e"
    LTE = "lte"  # mobile (LTE, 5G)
    #: The device only bridges the line (a modem in front of the real router): no address.
    BRIDGE = "bridge"
    OTHER = "other"


class NatClass(StrEnum):
    """Where an uplink's IPv4 address lies; derived by :meth:`Uplink.nat_class`, not reported."""

    #: A routable address: inbound connections and port forwards can work.
    PUBLIC = "public"
    #: Provider NAT (100.64.0.0/10, RFC 6598): nothing from the internet reaches the site.
    CGNAT = "cgnat"
    #: RFC 1918 space: another router (NAT) is in front of this one.
    PRIVATE = "private"
    #: No IPv4 address of its own (IPv6 only, DS-Lite, MAP-E): no inbound IPv4.
    NONE = "none"


_CGNAT = IPv4Network("100.64.0.0/10")
_RFC1918 = (IPv4Network("10.0.0.0/8"), IPv4Network("172.16.0.0/12"), IPv4Network("192.168.0.0/16"))
#: Not an internet address of the device: link-local, the DS-Lite B4/AFTR range (RFC 6333),
#: loopback, unspecified.
_NO_ADDRESS = (
    IPv4Network("169.254.0.0/16"),
    IPv4Network("192.0.0.0/29"),
    IPv4Network("127.0.0.0/8"),
    IPv4Network("0.0.0.0/32"),
)


def address_nat_class(address: IPv4Address) -> NatClass:
    """NAT class of one IPv4 address.

    Deliberately not :attr:`IPv4Address.is_global`: documentation prefixes (192.0.2.0/24 and
    friends) count as public, so that simulators and tests can stand in for real addresses.
    """
    if address in _CGNAT:
        return NatClass.CGNAT
    if any(address in net for net in _RFC1918):
        return NatClass.PRIVATE
    if any(address in net for net in _NO_ADDRESS):
        return NatClass.NONE
    return NatClass.PUBLIC


class Uplink(Observed):
    """A gateway's connection to its provider (WAN), ``object_id(device, "uplink", <name>)``.

    Read with the ``interfaces`` capability. WAN addresses are not :class:`Subnet` objects: the
    uplink is not a network of the site. The public address and the delegated IPv6 prefix
    identify the household: shown in the UI behind a click, never exported (MQTT, reports).
    """

    device_id: str
    #: The port the uplink uses (``<device>/port/<name>``), where the device says.
    port_id: str | None = None
    #: The device's own name of the connection (``wan``, ``pppoe-out1``, ``Internet``).
    name: str | None = None
    kind: UplinkKind = UplinkKind.OTHER
    #: Connected (has its address, PPP session up), not only link on the port.
    up: bool | None = None
    #: When the current connection came up.
    since: datetime | None = None
    #: The device's own address(es) on the uplink, IPv4 and IPv6, with prefix length.
    addresses: list[IPInterface] = Field(default_factory=list)
    #: IPv6 prefixes delegated by the provider (DHCPv6-PD), for the site's networks.
    delegated_prefixes: list[IPv6Network] = Field(default_factory=list)
    #: The next hop upstream (default route), IPv4 or IPv6.
    upstream_gateway: IPAddress | None = None
    #: Resolvers the provider handed out (not the ones the device forwards to).
    dns_servers: list[IPAddress] = Field(default_factory=list)
    #: The address the internet sees, only where the device itself knows it apart from its own
    #: addresses (MikroTik ``/ip/cloud``); Signalbox never looks it up on the internet. An
    #: address the device has itself (Fritz!Box ``GetExternalIPAddress``) goes into
    #: ``addresses``.
    public_ipv4: IPv4Address | None = None
    #: Line rate where the modem knows it (DSL sync, LTE), in kbit/s.
    downstream_kbps: Annotated[int, Field(ge=0)] | None = None
    upstream_kbps: Annotated[int, Field(ge=0)] | None = None

    def ipv4(self) -> list[IPv4Interface]:
        return [a for a in self.addresses if isinstance(a, IPv4Interface)]

    def ipv6(self) -> list[IPv6Interface]:
        """Global IPv6 addresses (link-local ones left out)."""
        return [a for a in self.addresses if isinstance(a, IPv6Interface) and not a.is_link_local]

    def nat_class(self) -> NatClass | None:
        """Where the uplink's IPv4 lies (``None``: not known).

        The device's own IPv4 addresses decide (the best one: public before CGNAT before
        private); ``public_ipv4`` is used only when the device reports no address of its own.
        DS-Lite and MAP-E have no IPv4 of their own (``none``), nor has an uplink with IPv6
        addresses only. A bridge or an uplink without any address is not known.
        """
        if self.kind in (UplinkKind.DSLITE, UplinkKind.MAP_E):
            return NatClass.NONE
        v4 = [a.ip for a in self.ipv4()] or ([self.public_ipv4] if self.public_ipv4 else [])
        found = {address_nat_class(a) for a in v4}
        for best in (NatClass.PUBLIC, NatClass.CGNAT, NatClass.PRIVATE):
            if best in found:
                return best
        if found or self.ipv6():
            return NatClass.NONE
        return None


# VPN tunnels (#239) -------------------------------------------------------------------------
#
# A tunnel is a VPN interface of one device (a WireGuard interface, ``wg0``) with the peers it
# talks to. Two tunnels whose peers name each other's public keys are the two ends of one site
# link (:meth:`Network.tunnel_end`, a ``vpn`` link from :func:`signalbox.topology.tunnel_links`).
# Private and pre-shared keys are never part of the model: there is no field for them, and the
# contract checks refuse anything shaped like a key that is not a public key of the snapshot.

#: A WireGuard key: 32 bytes in base64, 43 characters and ``=``; the last character carries
#: four bits only.
WIREGUARD_KEY = r"^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$"
WireGuardKey = Annotated[str, Field(pattern=WIREGUARD_KEY)]


class TunnelKind(StrEnum):
    WIREGUARD = "wireguard"


class TunnelPeer(Model):
    """One peer of a tunnel: the other end as this device knows it (#239).

    Never the pre-shared key; ``preshared_key`` only says whether one is set. The endpoint
    is the other site's public address: shown behind a click like an uplink's, never exported.
    """

    public_key: WireGuardKey
    #: The device's name for the peer (OPNsense peer name, OpenWrt section, MikroTik comment).
    name: str | None = None
    #: Where packets for the peer go: the configured endpoint or, after a handshake, the address
    #: the peer was last seen at; a host name or an address. None: the peer connects to us.
    endpoint_host: str | None = None
    endpoint_port: Annotated[int, Field(ge=1, le=65535)] | None = None
    #: Networks routed to this peer and accepted from it (WireGuard ``AllowedIPs``).
    allowed_ips: list[IPNetwork] = Field(default_factory=list)
    #: Time of the last completed handshake. None: none since the interface came up, or not read.
    latest_handshake: datetime | None = None
    rx_bytes: Annotated[int, Field(ge=0)] | None = None
    tx_bytes: Annotated[int, Field(ge=0)] | None = None
    #: Persistent keepalive in seconds; 0: off. None: not known.
    keepalive_seconds: Annotated[int, Field(ge=0, le=65535)] | None = None
    #: A pre-shared key is set (the key itself is never read). None: not known.
    preshared_key: bool | None = None
    enabled: bool = True

    @field_validator("latest_handshake")
    @classmethod
    def _aware(cls, value: datetime | None) -> datetime | None:
        return _utc(value)

    def handshake_age(self, at: datetime) -> float | None:
        """Seconds since the last handshake at *at*; None without one."""
        if self.latest_handshake is None:
            return None
        return (_utc(at) - self.latest_handshake).total_seconds()  # type: ignore[operator]


class Tunnel(Observed):
    """A VPN interface of a device (#239), ``object_id(device, "tunnel", <interface name>)``.

    Read with the ``vpn`` capability (adapter API 1.3). ``peers`` lists every peer the device
    has on this interface, site-to-site and road-warrior ones alike.
    """

    device_id: str
    kind: TunnelKind = TunnelKind.WIREGUARD
    #: The interface name (``wg0``, ``wg_s2s``).
    name: str = Field(min_length=1)
    #: The device's own name of the tunnel (OPNsense instance name, a comment).
    description: str | None = None
    #: The port of the interface (``<device>/port/wg0``), where the device lists it as a port.
    port_id: str | None = None
    #: The interface is up (WireGuard has no connection state: see the peers' handshakes).
    up: bool | None = None
    enabled: bool = True
    listen_port: Annotated[int, Field(ge=1, le=65535)] | None = None
    public_key: WireGuardKey | None = None
    #: The device's own addresses on the tunnel, with prefix length.
    addresses: list[IPInterface] = Field(default_factory=list)
    mtu: Annotated[int, Field(ge=68, le=65535)] | None = None
    peers: list[TunnelPeer] = Field(default_factory=list)

    def peer(self, public_key: str) -> TunnelPeer | None:
        return next((p for p in self.peers if p.public_key == public_key), None)

    def remote_networks(self, peer: TunnelPeer) -> list[IPNetwork]:
        """The networks a peer's allowed IPs route through the tunnel: every allowed network
        that is neither a single address (``/32``, ``/128``: the peer's own tunnel address, or
        one host) nor inside one of the tunnel's own address networks (transit). A device may
        report its tunnel address as a host address (FreeBSD shows ``/128``), so the single
        address rule is what keeps the transit out. ``0.0.0.0/0`` and ``::/0`` stay: the peer
        is the way to everything (a full tunnel)."""
        own = [a.network for a in self.addresses]
        return [
            n
            for n in peer.allowed_ips
            if n.num_addresses > 1
            and not any(n.version == o.version and n.subnet_of(o) for o in own)  # type: ignore[arg-type]
        ]

    def site_peers(self) -> list[TunnelPeer]:
        """Peers that route networks of their own (a site behind them), not only their own
        tunnel address (a phone or laptop)."""
        return [p for p in self.peers if self.remote_networks(p)]


class ServiceKind(StrEnum):
    """A way to manage (log in to, configure, query) a device (#173)."""

    SSH = "ssh"
    TELNET = "telnet"
    HTTP = "http"  # web UI without TLS
    HTTPS = "https"  # web UI with TLS (also a vendor's internet remote access)
    #: A plain-text configuration API (RouterOS API on 8728).
    API = "api"
    #: The same API over TLS (RouterOS ``api-ssl`` on 8729).
    API_SSL = "api-ssl"
    SNMP = "snmp"
    FTP = "ftp"
    TFTP = "tftp"
    WINBOX = "winbox"  # MikroTik Winbox over IP (TCP 8291)
    #: MikroTik MAC server: telnet and Winbox over layer 2, reachable without an IP address.
    MAC_TELNET = "mac-telnet"
    MAC_WINBOX = "mac-winbox"
    ROMON = "romon"  # MikroTik RoMON: layer-2 relay to other routers
    TR064 = "tr-064"  # Fritz!Box configuration API (SOAP)
    UPNP = "upnp"  # UPnP IGD control (port forwards opened by any client)
    #: The vendor's own configuration protocol (NETGEAR NSDP, TP-Link Easy Smart UDP).
    VENDOR = "vendor"
    OTHER = "other"


class ServiceTransport(StrEnum):
    TCP = "tcp"
    UDP = "udp"
    #: Ethernet frames, not routed: reachable only in a layer-2 network of the device.
    LAYER2 = "layer2"


#: Whether a kind of service encrypts by itself (``None``: depends on the device or version).
SERVICE_ENCRYPTED: dict[ServiceKind, bool | None] = {
    ServiceKind.SSH: True,
    ServiceKind.TELNET: False,
    ServiceKind.HTTP: False,
    ServiceKind.HTTPS: True,
    ServiceKind.API: False,
    ServiceKind.API_SSL: True,
    ServiceKind.SNMP: False,  # v1/v2c; v3 with privacy: see ManagementService
    ServiceKind.FTP: False,
    ServiceKind.TFTP: False,
    ServiceKind.WINBOX: True,  # encrypted since RouterOS 6.43
    ServiceKind.MAC_TELNET: False,
    ServiceKind.MAC_WINBOX: True,
    ServiceKind.ROMON: None,  # a relay: as encrypted as what runs through it
    ServiceKind.TR064: None,  # HTTP on 49000 and HTTPS on 49443
    ServiceKind.UPNP: False,
    ServiceKind.VENDOR: False,
    ServiceKind.OTHER: None,
}

#: Transport of a kind of service (absent: not fixed by the kind).
SERVICE_TRANSPORT: dict[ServiceKind, ServiceTransport] = {
    ServiceKind.SNMP: ServiceTransport.UDP,
    ServiceKind.TFTP: ServiceTransport.UDP,
    ServiceKind.VENDOR: ServiceTransport.UDP,
    ServiceKind.MAC_TELNET: ServiceTransport.LAYER2,
    ServiceKind.MAC_WINBOX: ServiceTransport.LAYER2,
    ServiceKind.ROMON: ServiceTransport.LAYER2,
    **dict.fromkeys(
        (
            ServiceKind.SSH,
            ServiceKind.TELNET,
            ServiceKind.HTTP,
            ServiceKind.HTTPS,
            ServiceKind.API,
            ServiceKind.API_SSL,
            ServiceKind.FTP,
            ServiceKind.WINBOX,
            ServiceKind.TR064,
        ),
        ServiceTransport.TCP,
    ),
}

#: Usual port of a kind of service, for adapters that know a service is on but not its port.
SERVICE_PORTS: dict[ServiceKind, int] = {
    ServiceKind.SSH: 22,
    ServiceKind.TELNET: 23,
    ServiceKind.HTTP: 80,
    ServiceKind.HTTPS: 443,
    ServiceKind.API: 8728,
    ServiceKind.API_SSL: 8729,
    ServiceKind.SNMP: 161,
    ServiceKind.FTP: 21,
    ServiceKind.TFTP: 69,
    ServiceKind.WINBOX: 8291,
    ServiceKind.TR064: 49000,
}


#: Names for findings and the UI.
SERVICE_LABELS: dict[ServiceKind, str] = {
    ServiceKind.SSH: "SSH",
    ServiceKind.TELNET: "Telnet",
    ServiceKind.HTTP: "HTTP",
    ServiceKind.HTTPS: "HTTPS",
    ServiceKind.API: "API",
    ServiceKind.API_SSL: "API (TLS)",
    ServiceKind.SNMP: "SNMP",
    ServiceKind.FTP: "FTP",
    ServiceKind.TFTP: "TFTP",
    ServiceKind.WINBOX: "Winbox",
    ServiceKind.MAC_TELNET: "MAC telnet",
    ServiceKind.MAC_WINBOX: "MAC Winbox",
    ServiceKind.ROMON: "RoMON",
    ServiceKind.TR064: "TR-064",
    ServiceKind.UPNP: "UPnP",
    ServiceKind.VENDOR: "configuration protocol",
    ServiceKind.OTHER: "service",
}


class SnmpVersion(StrEnum):
    V1 = "1"
    V2C = "2c"
    V3 = "3"


class SnmpSettings(Model):
    """SNMP details of a :class:`ManagementService` of kind ``snmp``.

    Community strings and SNMPv3 passwords are secrets and never enter the model; only whether
    a factory default is in use.
    """

    #: Versions the agent answers (empty: not reported).
    versions: list[SnmpVersion] = Field(default_factory=list)
    #: A community named ``public`` or ``private`` (the factory defaults) is configured.
    default_community: bool | None = None
    #: SNMPv3 requires privacy (``authPriv``): the traffic is encrypted.
    v3_privacy: bool | None = None
    #: Some community or user may write (``set``), not only read.
    write_access: bool | None = None

    @field_validator("versions")
    @classmethod
    def _sorted_versions(cls, value: list[SnmpVersion]) -> list[SnmpVersion]:
        order = list(SnmpVersion)
        return sorted(set(value), key=order.index)


_UNSPECIFIED = (IPv4Address("0.0.0.0"), IPv6Address("::"))
#: Address space that is never reached from the internet: RFC 1918, CGNAT, link-local,
#: loopback, IPv6 unique local and link-local. Documentation prefixes count as public, as in
#: :func:`address_nat_class`.
_NOT_FROM_INTERNET: tuple[IPNetwork, ...] = (
    *_RFC1918,
    _CGNAT,
    IPv4Network("169.254.0.0/16"),
    IPv4Network("127.0.0.0/8"),
    IPv6Network("fc00::/7"),
    IPv6Network("fe80::/10"),
    IPv6Network("::1/128"),
)


def internet_reachable_network(net: IPNetwork) -> bool:
    """True when *net* holds addresses the internet can come from (not private space only)."""
    return not any(net.version == p.version and net.subnet_of(p) for p in _NOT_FROM_INTERNET)  # type: ignore[arg-type]


class ManagementService(Observed):
    """A management service a device offers (#173), ``object_id(device, "service", <key>)``.

    One object per service the device has, enabled or not: an integration that reads services
    reports every one it knows, so an empty list means "not read", never "none". Read with the
    ``interfaces`` capability (no API version needed).

    Where it listens: ``listen`` (addresses), ``interfaces`` (ports) and ``segments``
    (networks) are restrictions the device itself applies; all empty means every address on
    every interface. ``allowed_from`` is the service's own address filter (MikroTik
    ``address``), not the firewall: Signalbox cannot see firewall rules yet (#135), so
    :meth:`Network.service_segments` and :meth:`Network.service_from_wan` answer from these
    fields only.
    """

    device_id: str
    kind: ServiceKind
    #: The device's own name of the service (``www-ssl``, ``dropbear``, ``remote-access``).
    name: str | None = None
    enabled: bool
    port: Annotated[int, Field(ge=1, le=65535)] | None = None
    #: Filled from ``kind`` when not reported (:data:`SERVICE_TRANSPORT`).
    transport: ServiceTransport | None = None
    #: Traffic is encrypted. Filled from ``kind`` when not reported (:data:`SERVICE_ENCRYPTED`;
    #: SNMP that answers only v3 with privacy counts as encrypted).
    encrypted: bool | None = None
    #: Addresses it listens on (empty: all; ``0.0.0.0`` or ``::``: all of that family).
    listen: list[IPAddress] = Field(default_factory=list)
    #: Ports it is bound to (``<device>/port/<name>``; empty: all). MikroTik MAC server
    #: interface lists, OpenWrt ``DirectInterface``.
    interfaces: list[str] = Field(default_factory=list)
    #: Networks the device offers it in (``<site>/segment/<vlan>``; empty: all). OpenWrt
    #: ``Interface``, OPNsense listen interfaces, mapped to their segments by the adapter.
    segments: list[str] = Field(default_factory=list)
    #: Source networks the service itself accepts (empty: any).
    allowed_from: list[IPNetwork] = Field(default_factory=list)
    #: The device itself says the service is reachable from the internet (Fritz!Box remote
    #: access, FTP from the internet) or is not. ``None``: it does not say; see
    #: :meth:`Network.service_from_wan`.
    from_wan: bool | None = None
    #: Password logins accepted (SSH ``PasswordAuth``; ``False``: keys only).
    password_login: bool | None = None
    #: Root (or ``admin``) may log in at all.
    root_login: bool | None = None
    #: Root may log in with a password (OpenWrt ``RootPasswordAuth``, OPNsense
    #: ``permitrootlogin`` with ``passwordauth``).
    root_password_login: bool | None = None
    #: Plain HTTP only redirects to HTTPS (OpenWrt ``redirect_https``, OPNsense without
    #: ``disablehttpredirect``).
    redirects_to_https: bool | None = None
    snmp: SnmpSettings | None = None

    @model_validator(mode="before")
    @classmethod
    def _defaults_from_kind(cls, data: Any) -> Any:
        if not isinstance(data, dict) or "kind" not in data:
            return data
        try:
            kind = ServiceKind(data["kind"])
        except ValueError:
            return data  # field validation reports it
        out = dict(data)
        if out.get("transport") is None and kind in SERVICE_TRANSPORT:
            out["transport"] = SERVICE_TRANSPORT[kind]
        if out.get("encrypted") is None:
            encrypted = SERVICE_ENCRYPTED[kind]
            snmp = out.get("snmp")
            if isinstance(snmp, dict):
                snmp = SnmpSettings.model_validate(snmp)
            if (
                kind is ServiceKind.SNMP
                and isinstance(snmp, SnmpSettings)
                and snmp.versions == [SnmpVersion.V3]
                and snmp.v3_privacy
            ):
                encrypted = True
            out["encrypted"] = encrypted
        return out

    def label(self) -> str:
        """``SSH``, ``HTTPS (remote-access)``: for findings and the UI."""
        text = SERVICE_LABELS[self.kind]
        if self.name and self.name.lower() not in (self.kind.value, text.lower()):
            return f"{text} ({self.name})"
        return text

    def unrestricted(self) -> bool:
        """Listens everywhere and accepts any source (as far as the device itself says)."""
        return not (self.listen_restricted() or self.allowed_from)

    def listen_restricted(self) -> bool:
        specific = [a for a in self.listen if a not in _UNSPECIFIED]
        return bool(specific or self.interfaces or self.segments)

    def accepts_from(self, address: IPAddress) -> bool:
        """The service's own filter lets *address* in (no ``allowed_from``: everyone)."""
        return not self.allowed_from or any(
            address.version == n.version and address in n for n in self.allowed_from
        )

    def plaintext(self) -> bool:
        """Enabled and unencrypted; plain HTTP that only redirects to HTTPS does not count."""
        if not self.enabled or self.encrypted is not False:
            return False
        return not (self.kind is ServiceKind.HTTP and self.redirects_to_https)

    def allows_root_password(self) -> bool | None:
        """Root may log in with a password (``None``: not known)."""
        if self.root_login is False or self.password_login is False:
            return False
        if self.root_password_login is not None:
            return self.root_password_login
        if self.root_login and self.password_login:
            return True
        return None


class DhcpPool(Model):
    start: IPAddress
    end: IPAddress

    def contains(self, address: IPAddress) -> bool:
        """The address lies in the range (both ends included; another family never does)."""
        if address.version != self.start.version or address.version != self.end.version:
            return False
        return self.start <= address <= self.end  # type: ignore[operator]


class Reservation(Model):
    mac: Mac
    address: IPAddress
    hostname: str | None = None


class AddressSource(StrEnum):
    """How a client got one of its addresses (#183)."""

    #: A dynamic lease from a DHCP server.
    DHCP = "dhcp"
    #: A lease for a reservation (static lease, host entry): the server always hands out this one.
    DHCP_RESERVED = "dhcp-reserved"
    #: Configured on the client itself.
    STATIC = "static"
    #: IPv6 stateless autoconfiguration from the MAC address or a stable secret.
    SLAAC = "slaac"
    #: SLAAC temporary (privacy) address, RFC 8981.
    SLAAC_PRIVACY = "slaac-privacy"
    DHCPV6 = "dhcpv6"
    #: 169.254.0.0/16 (Auto-IP after DHCP failed) or fe80::/10.
    LINK_LOCAL = "link-local"
    #: The device lists the address without saying where it came from.
    UNKNOWN = "unknown"


#: Address sources that mean "a DHCP server handed it out".
LEASED_SOURCES = frozenset({AddressSource.DHCP, AddressSource.DHCP_RESERVED, AddressSource.DHCPV6})
#: Address sources that only exist for one address family.
_V4_ONLY_SOURCES = frozenset({AddressSource.DHCP, AddressSource.DHCP_RESERVED})
_V6_ONLY_SOURCES = frozenset(
    {AddressSource.SLAAC, AddressSource.SLAAC_PRIVACY, AddressSource.DHCPV6}
)


def source_fits(address: IPAddress, source: AddressSource) -> bool:
    """False when the source cannot apply to an address of this family (SLAAC for IPv4)."""
    if address.version == 4:
        return source not in _V6_ONLY_SOURCES
    return source not in _V4_ONLY_SOURCES


class LeaseState(StrEnum):
    ACTIVE = "active"
    EXPIRED = "expired"
    #: The client said the address is in use by someone else (DHCPDECLINE): an address conflict.
    DECLINED = "declined"
    #: Offered, not yet acknowledged.
    OFFERED = "offered"
    #: A reservation the client does not use right now (MikroTik ``waiting`` static lease).
    RESERVED = "reserved"


class DhcpLease(Model):
    """One entry of a DHCP server's lease table (#183).

    Lease host names, client ids and vendor classes identify devices and people: they are client
    data like :attr:`Client.hostname` (kept in the store, shown to signed-in users, neutralised
    in recordings).
    """

    address: IPAddress
    #: Hardware address; DHCPv6 leases may have a DUID only (``client_id``).
    mac: Mac | None = None
    #: DHCP option 61 (client identifier) or the DHCPv6 DUID, as the server shows it.
    client_id: str | None = None
    hostname: str | None = None
    state: LeaseState = LeaseState.ACTIVE
    #: The lease is for a reservation (static lease, host entry). None: not known.
    reserved: bool | None = None
    starts: datetime | None = None
    #: When the lease ends; None for leases that never expire or when not known.
    expires: datetime | None = None
    #: DHCP option 60 (``android-dhcp-14``, ``MSFT 5.0``, ``udhcp 1.36.1``): a device-type hint.
    vendor_class: str | None = None

    @field_validator("starts", "expires")
    @classmethod
    def _aware(cls, value: datetime | None) -> datetime | None:
        return _utc(value)

    def active(self, at: datetime | None = None) -> bool:
        """In use: state active and, when *at* and the expiry are known, not expired at *at*."""
        if self.state is not LeaseState.ACTIVE:
            return False
        return at is None or self.expires is None or self.expires > _utc(at)  # type: ignore[operator]

    def source(self) -> AddressSource:
        """The address source this lease gives its address."""
        if self.address.version == 6:
            return AddressSource.DHCPV6
        return AddressSource.DHCP_RESERVED if self.reserved else AddressSource.DHCP


class DhcpOption(Model):
    """A DHCP option the server hands out that has no typed field (#183)."""

    code: Annotated[int, Field(ge=1, le=254)]
    #: The device's name for it (``wpad``, ``tftp-server``).
    name: str | None = None
    #: The value as the device shows it (text, address list or hex).
    value: str


#: Option codes with a typed field on :class:`DhcpServer` (router 3, DNS 6, domain 15, NTP 42,
#: lease time 51, TFTP server and boot file 66/67, search list 119, classless routes 121);
#: :attr:`DhcpServer.options` never repeats them.
TYPED_OPTION_CODES = frozenset({3, 6, 15, 42, 51, 66, 67, 119, 121})


class DhcpBoot(Model):
    """Network boot (PXE): ``next-server`` / ``siaddr``, option 66 and 67."""

    next_server: IPAddress | None = None
    #: Option 66 (TFTP server name), when it is a name rather than ``next_server``.
    server_name: str | None = None
    filename: str | None = None


class DhcpRoute(Model):
    """A classless static route (option 121, RFC 3442)."""

    destination: IPv4Network
    gateway: IPv4Address


class DhcpServer(Observed):
    device_id: str
    segment_id: str
    enabled: bool
    pools: list[DhcpPool] = Field(default_factory=list)
    lease_seconds: int | None = None
    router: IPAddress | None = None
    dns_servers: list[IPAddress] = Field(default_factory=list)
    domain: str | None = None
    reservations: list[Reservation] = Field(default_factory=list)
    #: NTP servers handed out (DHCP option 42; API 1.2).
    ntp_servers: list[IPAddress] = Field(default_factory=list)
    #: The lease table (#183). ``None``: not read; ``[]``: read, and no leases. Every state the
    #: server reports (expired and declined too); an adapter may cap a very long table.
    leases: list[DhcpLease] | None = None
    #: Domain search list (option 119).
    search_domains: list[str] = Field(default_factory=list)
    #: Classless static routes (option 121). When set, clients ignore ``router`` (option 3).
    static_routes: list[DhcpRoute] = Field(default_factory=list)
    boot: DhcpBoot | None = None
    #: Further options (NTP, WPAD, vendor options): never the ones in :data:`TYPED_OPTION_CODES`.
    options: list[DhcpOption] = Field(default_factory=list)
    #: Answers clients with addresses it does not know with a NAK (ISC/Kea ``authoritative``,
    #: dnsmasq ``dhcp-authoritative``, MikroTik ``authoritative``). None: not known.
    authoritative: bool | None = None
    #: Name or address of the failover / HA peer (ISC failover, Kea HA). None: none or not known.
    failover_peer: str | None = None

    def in_pool(self, address: IPAddress) -> bool:
        """The address lies in one of the dynamic pools."""
        return any(p.contains(address) for p in self.pools)

    def leases_of(self, mac: str) -> list[DhcpLease]:
        """Leases (any state) of one MAC address; empty when the table was not read."""
        return [lease for lease in self.leases or [] if lease.mac == mac]

    def lease_for(self, address: IPAddress, at: datetime | None = None) -> DhcpLease | None:
        """The active lease of an address, if the server has one (see :meth:`DhcpLease.active`)."""
        return next((x for x in self.leases or [] if x.address == address and x.active(at)), None)

    def active_leases(self, at: datetime | None = None) -> list[DhcpLease]:
        return [x for x in self.leases or [] if x.active(at)]


class DhcpRelay(Observed):
    """A DHCP relay on a segment (#183), ``object_id(device, "dhcp-relay", <segment key>)``.

    Read with the ``dhcp`` capability: a segment with a relay needs no DHCP server of its own.
    """

    device_id: str
    segment_id: str
    #: Where requests are forwarded to.
    servers: list[IPAddress] = Field(default_factory=list)
    enabled: bool = True


class HostRecord(Model):
    name: str
    address: IPAddress


DNS_PORT = 53


def _split_host_port(text: str) -> tuple[str, int | None]:
    """``192.0.2.1``, ``192.0.2.1:5353``, ``192.0.2.1#5353`` (dnsmasq), ``[2001:db8::1]:5353``,
    ``2001:db8::1#5353``, ``2001:db8::1`` -> (address, port or None)."""
    text = text.strip()
    if text.startswith("["):
        host, sep, rest = text[1:].partition("]")
        if not sep or (rest and not rest.startswith(":")):
            raise ValueError(f"not an address with port: {text!r}")
        return host, int(rest[1:]) if rest else None
    if "#" in text:
        host, _, port = text.partition("#")
        return host, int(port)
    if text.count(":") == 1:
        host, _, port = text.partition(":")
        return host, int(port)
    return text, None


class DnsForwarder(Model):
    """Where a DNS service forwards lookups to: an address and a port (#241).

    Accepts a bare address (port 53), ``address:port``, ``[IPv6]:port`` or dnsmasq's
    ``address#port``; older snapshots stored bare addresses.
    """

    address: IPAddress
    port: Annotated[int, Field(ge=1, le=65535)] = DNS_PORT

    @model_validator(mode="before")
    @classmethod
    def _from_text(cls, data: Any) -> Any:
        if isinstance(data, IPv4Address | IPv6Address):
            return {"address": data}
        if isinstance(data, str):
            host, port = _split_host_port(data)
            return {"address": host} if port is None else {"address": host, "port": port}
        return data

    def __str__(self) -> str:
        if self.port == DNS_PORT:
            return str(self.address)
        if self.address.version == 6:
            return f"[{self.address}]:{self.port}"
        return f"{self.address}:{self.port}"


class DnsService(Observed):
    """A DNS server on a device, ``object_id(device, "dns", <name>)``.

    A device may run several (#241): Unbound on another port next to AdGuard Home, dnsmasq next
    to Unbound. Each has its own id and port.
    """

    device_id: str
    #: The software or the device's name for it (``unbound``, ``dnsmasq``); None: not known.
    name: str | None = None
    enabled: bool = True
    #: Addresses it listens on (empty: every address of the device).
    listen: list[IPAddress] = Field(default_factory=list)
    #: Port it listens on (#241).
    port: Annotated[int, Field(ge=1, le=65535)] = DNS_PORT
    forwarders: list[DnsForwarder] = Field(default_factory=list)
    host_records: list[HostRecord] = Field(default_factory=list)
    #: False: the service is only known to exist (something answers on the port, its own API
    #: needs its own login, like AdGuard Home on OPNsense); its forwarders and host records
    #: were not read, so empty lists mean "unknown", not "none".
    config_read: bool = True


class Band(StrEnum):
    GHZ_2_4 = "2.4"
    GHZ_5 = "5"
    GHZ_6 = "6"


class Security(StrEnum):
    OPEN = "open"
    OWE = "owe"
    WEP = "wep"
    #: WPA (version 1) Personal; TKIP in practice.
    WPA = "wpa-psk"
    #: WPA/WPA2 Personal mixed mode: WPA1 stations are allowed, TKIP stays on.
    WPA_WPA2 = "wpa-wpa2-psk"
    WPA2 = "wpa2-psk"
    WPA3 = "wpa3-sae"
    WPA2_WPA3 = "wpa2-wpa3"
    #: WPA (version 1) Enterprise, also WPA/WPA2 Enterprise mixed mode.
    WPA_ENTERPRISE = "wpa-enterprise"
    WPA2_ENTERPRISE = "wpa2-enterprise"
    WPA3_ENTERPRISE = "wpa3-enterprise"
    #: WPA3-Enterprise 192-bit mode (Suite B: GCMP-256, BIP-GMAC-256).
    WPA3_ENTERPRISE_192 = "wpa3-enterprise-192"
    OTHER = "other"


class Radio(Observed):
    device_id: str
    name: str
    band: Band
    channel: int | None = None
    width_mhz: int | None = None
    tx_power_dbm: int | None = None
    country: str | None = None
    enabled: bool = True
    #: Security modes this radio's hardware and firmware can offer (#167), for example no
    #: ``wpa3-sae`` on an OpenWrt build with ``wpad-basic``. None: not reported.
    supported_security: list[Security] | None = None


class Cipher(StrEnum):
    """Pairwise or group data cipher of a WLAN."""

    CCMP = "ccmp"  # AES-CCMP-128, what "AES" means in most UIs
    CCMP_256 = "ccmp-256"
    GCMP = "gcmp"
    GCMP_256 = "gcmp-256"
    TKIP = "tkip"
    WEP = "wep"


class SaePwe(StrEnum):
    """How SAE derives the password element (``sae_pwe`` in hostapd)."""

    HUNTING_AND_PECKING = "hunting-and-pecking"
    #: Hash-to-element (H2E), required on 6 GHz.
    HASH_TO_ELEMENT = "hash-to-element"
    BOTH = "both"


class SaeSettings(Model):
    """WPA3-SAE details of a WLAN (#167); every value None where the device does not say."""

    pwe: SaePwe | None = None
    #: SAE public key (SAE-PK) in use.
    sae_pk: bool | None = None
    #: Open SAE commits before anti-clogging tokens are required.
    anti_clogging_threshold: int | None = Field(default=None, ge=0)


class WpsMethod(StrEnum):
    PUSH_BUTTON = "push-button"
    PIN = "pin"
    NFC = "nfc"


class Wps(Model):
    """Wi-Fi Protected Setup of a WLAN (#167)."""

    enabled: bool
    #: Methods offered while enabled; empty: enabled, method not known.
    methods: list[WpsMethod] = Field(default_factory=list)
    #: The AP PIN is locked after failed attempts (or permanently). None: not known.
    ap_pin_locked: bool | None = None


class Pmf(StrEnum):
    DISABLED = "disabled"
    OPTIONAL = "optional"
    REQUIRED = "required"


class Wlan(Observed):
    device_id: str
    ssid: str
    radio_id: str
    enabled: bool = True
    security: Security
    pmf: Pmf | None = None
    passphrase_fingerprint: str | None = None
    segment_id: str | None = None
    hidden: bool = False
    roaming_80211r: bool | None = None
    roaming_80211k: bool | None = None
    roaming_80211v: bool | None = None
    #: Some devices know a guest SSID without a VLAN of its own (Omada guest network).
    purpose: SegmentPurpose | None = None
    purpose_source: PurposeSource | None = None
    #: What the device reported when a declared purpose overrides a different one.
    reported_purpose: SegmentPurpose | None = None
    #: Stations of this SSID cannot talk to each other (OpenWrt ``isolate``). None: not known.
    client_isolation: bool | None = None
    # security details (#167); None everywhere: not reported -------------------------------
    #: Pairwise ciphers offered (``ccmp`` alone normally; ``tkip`` as well in mixed modes).
    ciphers: list[Cipher] | None = None
    group_cipher: Cipher | None = None
    sae: SaeSettings | None = None
    wps: Wps | None = None
    #: :func:`passphrase_digest`: compares passphrases across SSIDs. Like the fingerprint it
    #: stays in the observation database and never leaves the server (removed from the API).
    passphrase_digest: str | None = Field(default=None, pattern=r"^[0-9a-f]{16}$")
    #: Group key rotation interval; 0: never rotated.
    key_rotation_seconds: int | None = Field(default=None, ge=0)
    #: Beacon protection (802.11 BIGTK) on.
    beacon_protection: bool | None = None
    #: The Wi-Fi interface (port) that carries this SSID (``phy0-ap0``; #252). None: not
    #: reported.
    port_id: str | None = None


class Client(Observed):
    mac: Mac
    addresses: list[IPAddress] = Field(default_factory=list)
    hostname: str | None = None
    segment_id: str | None = None
    #: Port or WLAN where the client was seen.
    seen_on: str | None = None
    last_seen: datetime | None = None
    #: Where each address came from (#183), for the addresses in ``addresses`` the device can
    #: say it of; an address left out: not known (see :meth:`Network.address_source`).
    address_sources: dict[IPAddress, AddressSource] = Field(default_factory=dict)


class Neighbour(Observed):
    """A device seen on a port by LLDP (or a similar protocol)."""

    local_port_id: str
    chassis_id: str
    remote_port: str | None = None
    system_name: str | None = None
    management_address: str | None = None


class LinkOrigin(StrEnum):
    LLDP = "lldp"
    MAC = "mac"
    MANUAL = "manual"
    #: Two tunnels whose peers name each other's public keys (#239).
    TUNNEL = "tunnel"


class LinkKind(StrEnum):
    CABLE = "cable"
    WIRELESS = "wireless"
    #: A VPN tunnel between two devices, often of two sites (#239): ``a`` and ``b`` are tunnel
    #: ids (``<device>/tunnel/<name>``), not ports.
    VPN = "vpn"


class Link(Model):
    id: str
    #: Port ids; tunnel ids for a ``vpn`` link.
    a: str
    b: str
    kind: LinkKind = LinkKind.CABLE
    origin: LinkOrigin


class ReadError(Model):
    """A capability that was declared but could not be read: becomes an "incomplete" finding."""

    device_id: str
    capability: str
    message: str
    #: What the user can do about it, in plain words, where the adapter knows.
    fix: str | None = None


# annotations (#186) -------------------------------------------------------------------------
#
# User data, not observed: a friendly name, what an object is for, who looks after it, notes,
# typed expectations, and acknowledged findings. Declared in the desired state (YAML) or set in
# the UI (database); the runner puts them on every Network it builds
# (``signalbox.annotate.apply``). They never cause writes to devices. Labels, owners and
# notes are personal data: shown in the UI, never exported to MQTT.


class AnnotationSource(StrEnum):
    """Where an annotation or acknowledgement comes from."""

    #: The desired-state YAML (reviewable, in git); read-only in the UI.
    DECLARED = "declared"
    #: Set in the web interface or the API; kept in the database.
    STORED = "stored"
    #: Seeded from a name or comment on a device (not used yet).
    IMPORTED = "imported"


class TargetKind(StrEnum):
    """What an annotation target names (see :func:`target_kind`)."""

    DEVICE = "device"
    PORT = "port"
    SEGMENT = "segment"
    SUBNET = "subnet"
    #: A MAC address: a client, a station, a foreign access point (BSSID), an LLDP neighbour.
    CLIENT = "client"
    #: Any other object of a device: ``<device>/<uplink|wlan|radio|dhcp|dns|...>/<name>``.
    OTHER = "other"


class ClientCategory(StrEnum):
    """What kind of thing a client is, in the words people use."""

    COMPUTER = "computer"
    PHONE = "phone"
    TABLET = "tablet"
    IOT = "iot"
    CAMERA = "camera"
    PRINTER = "printer"
    MEDIA = "media"
    SERVER = "server"
    NETWORK = "network"
    OTHER = "other"


CLIENT_TARGET = "client/"
_OBJECT_KIND = re.compile(
    r"^.+/(port|segment|subnet|uplink|dhcp|dns|radio|wlan|neighbour|client|gateway)/.+$"
)
_PLAIN_MAC = re.compile(r"^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$")


def client_target(mac: str) -> str:
    """The annotation target of a MAC address: ``client/<mac>`` (the merged client's id)."""
    return f"{CLIENT_TARGET}{normalise_mac(mac)}"


def annotation_target(text: str) -> str:
    """The canonical form of a target.

    A bare MAC address (``02:00:...``) or ``client/<MAC>`` becomes ``client/<lower-case mac>``;
    every other id is a model id and stays as it is. Raises ValueError for an empty target or a
    ``client/`` target that is not a MAC address.
    """
    text = text.strip()
    if not text:
        raise ValueError("the target is empty")
    if _PLAIN_MAC.match(text):
        return client_target(text)
    if text.startswith(CLIENT_TARGET):
        return client_target(text[len(CLIENT_TARGET) :])
    return text


def target_kind(target: str) -> TargetKind:
    """The kind of object a canonical target names, from the id alone.

    ``client/<mac>``: client; ``<device>/port/<name>``: port; ``<site>/segment/<key>``: segment;
    ``<device>/subnet/<name>``: subnet; ``<device>/<kind>/<name>`` of another kind: other;
    anything else is a device id (also ``<controller>/<device>`` of a managed device).
    """
    if target.startswith(CLIENT_TARGET):
        return TargetKind.CLIENT
    m = _OBJECT_KIND.match(target)
    if m is None:
        return TargetKind.DEVICE
    kinds = {"port": TargetKind.PORT, "segment": TargetKind.SEGMENT, "subnet": TargetKind.SUBNET}
    return kinds.get(m.group(1), TargetKind.OTHER)


class Expected(Model):
    """Typed expectations about one object; each field applies to the kinds named.

    Checks read them to stay silent (or be more precise) where the user has said what is
    intended. None: nothing said.
    """

    #: client: the network (segment id) it belongs in.
    segment: str | None = Field(None, max_length=200)
    #: client: uses a fixed address on purpose (no lease, perhaps inside the pool).
    static_address: bool | None = None
    #: client: what it is (IoT, camera, printer, ...).
    category: ClientCategory | None = None
    #: port: the neighbour expected behind it (device id, LLDP system name or MAC address).
    neighbour: str | None = Field(None, max_length=200)
    #: port: an uplink towards the router.
    uplink: bool | None = None
    #: device: the role it is meant to have.
    role: DeviceRole | None = None
    #: device or client: may be off or unreachable for long (a laptop, a seasonal camera).
    may_be_unreachable: bool | None = None
    #: client (MAC): a known foreign device (a neighbour's access point, a device left out of
    #: Signalbox on purpose): not ours, not a problem.
    known_neighbour: bool | None = None


#: Which target kinds each expectation applies to.
EXPECTED_KINDS: dict[str, frozenset[TargetKind]] = {
    "segment": frozenset({TargetKind.CLIENT}),
    "static_address": frozenset({TargetKind.CLIENT}),
    "category": frozenset({TargetKind.CLIENT}),
    "neighbour": frozenset({TargetKind.PORT}),
    "uplink": frozenset({TargetKind.PORT}),
    "role": frozenset({TargetKind.DEVICE}),
    "may_be_unreachable": frozenset({TargetKind.DEVICE, TargetKind.CLIENT}),
    "known_neighbour": frozenset({TargetKind.CLIENT}),
}


def check_expected(target: str, expected: Expected) -> None:
    """Raise ValueError when an expectation does not apply to the kind of the target."""
    kind = target_kind(target)
    wrong = sorted(
        k
        for k, kinds in EXPECTED_KINDS.items()
        if getattr(expected, k) is not None and kind not in kinds
    )
    if wrong:
        raise ValueError(f"{', '.join(wrong)} does not apply to a {kind.value} ({target})")


def _utc(value: datetime | None) -> datetime | None:
    """Times without a zone are UTC (YAML and date inputs often have none)."""
    if value is not None and value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value


class Annotation(Model):
    """What the user knows about one object (#186): label, purpose, owner, notes, expectations.

    ``target`` is a model id (:func:`target_kind`): a device id, ``<device>/port/<name>``,
    ``<site>/segment/<key>``, ``<device>/subnet/<name>`` or ``client/<mac>``. A network's
    purpose stays in the desired state's ``segments[].purpose``; ``purpose`` here is free text.
    """

    target: str = Field(min_length=1, max_length=300)
    #: Friendly name ("office printer").
    label: str | None = Field(None, max_length=100)
    purpose: str | None = Field(None, max_length=200)
    owner: str | None = Field(None, max_length=100)
    notes: str | None = Field(None, max_length=2000)
    tags: list[Annotated[str, Field(min_length=1, max_length=40)]] = Field(
        default_factory=list, max_length=20
    )
    expected: Expected = Field(default_factory=Expected)
    source: AnnotationSource = AnnotationSource.STORED
    updated_at: datetime | None = None

    @field_validator("target")
    @classmethod
    def _target(cls, value: str) -> str:
        return annotation_target(value)

    @field_validator("label", "purpose", "owner", "notes")
    @classmethod
    def _blank(cls, value: str | None) -> str | None:
        return (value.strip() or None) if value is not None else None

    @model_validator(mode="after")
    def _fits(self) -> Annotation:
        check_expected(self.target, self.expected)
        return self

    def kind(self) -> TargetKind:
        return target_kind(self.target)


def finding_fingerprint(message: str) -> str:
    """Fingerprint of a finding's details.

    An acknowledgement that carries it lapses when the message changes (another address, a new
    error count).
    """
    return hashlib.sha256(message.encode()).hexdigest()[:16]


class Acknowledgement(Model):
    """A finding the user has accepted (#186): shown apart, not counted as a problem.

    Matches either one finding (``finding_id``, stable across runs) or every finding of
    ``rule_id`` that names ``target`` among its objects. ``until``: expires then (the finding
    comes back and ``ack.expired`` says so). ``fingerprint``: lapses when the finding's message
    changes (:func:`finding_fingerprint`).
    """

    id: str = Field(min_length=1, max_length=64)
    rule_id: str = Field(min_length=1, max_length=100)
    finding_id: str | None = Field(None, max_length=64)
    target: str | None = Field(None, max_length=300)
    reason: str | None = Field(None, max_length=500)
    by: str | None = Field(None, max_length=100)
    at: datetime | None = None
    until: datetime | None = None
    fingerprint: str | None = Field(None, max_length=64)
    source: AnnotationSource = AnnotationSource.STORED

    @field_validator("target")
    @classmethod
    def _target(cls, value: str | None) -> str | None:
        return annotation_target(value) if value is not None else None

    @field_validator("at", "until")
    @classmethod
    def _zone(cls, value: datetime | None) -> datetime | None:
        return _utc(value)

    @model_validator(mode="after")
    def _scope(self) -> Acknowledgement:
        if self.finding_id is None and self.target is None:
            raise ValueError("an acknowledgement names a finding or a target object")
        return self

    def active(self, now: datetime) -> bool:
        return self.until is None or self.until > now

    def matches(self, rule_id: str, finding_id: str, objects: list[str], message: str) -> bool:
        """True when this acknowledgement covers the finding (expiry aside)."""
        if rule_id != self.rule_id:
            return False
        if self.finding_id is not None and self.finding_id != finding_id:
            return False
        if self.target is not None and self.target not in objects:
            return False
        return self.fingerprint is None or self.fingerprint == finding_fingerprint(message)


class DeviceStatus(StrEnum):
    OK = "ok"
    PARTIAL = "partial"
    UNREACHABLE = "unreachable"
    AUTH_FAILED = "auth-failed"
    UNTRUSTED = "untrusted-certificate"


class Snapshot(Model):
    """Everything one adapter observed on one device at one time."""

    device: Device
    observed_at: datetime
    status: DeviceStatus = DeviceStatus.OK
    ports: list[Port] = Field(default_factory=list)
    segments: list[Segment] = Field(default_factory=list)
    subnets: list[Subnet] = Field(default_factory=list)
    #: WAN connections of a gateway (#148; part of ``interfaces``).
    uplinks: list[Uplink] = Field(default_factory=list)
    #: Management services of the devices (#173; part of ``interfaces``).
    services: list[ManagementService] = Field(default_factory=list)
    dhcp_servers: list[DhcpServer] = Field(default_factory=list)
    #: DHCP relays (#183; part of ``dhcp``).
    dhcp_relays: list[DhcpRelay] = Field(default_factory=list)
    dns_services: list[DnsService] = Field(default_factory=list)
    radios: list[Radio] = Field(default_factory=list)
    wlans: list[Wlan] = Field(default_factory=list)
    clients: list[Client] = Field(default_factory=list)
    neighbours: list[Neighbour] = Field(default_factory=list)
    #: VPN tunnels with their peers (#239; ``vpn``, adapter API 1.3).
    tunnels: list[Tunnel] = Field(default_factory=list)
    errors: list[ReadError] = Field(default_factory=list)
    #: Devices reported through this one (a controller's managed devices). Their ids start with
    #: ``<device id>/`` and their ``managed_by`` is the observed device.
    extra_devices: list[Device] = Field(default_factory=list)
    #: Status per extra device, when the controller knows it (default: the snapshot's status).
    extra_status: dict[str, DeviceStatus] = Field(default_factory=dict)


class PortNode(Model):
    """One entry of :meth:`Network.port_tree`: a port (or a radio) and what runs on it."""

    #: Port id, or radio id for ``radio`` nodes.
    id: str
    node: Literal["port", "radio"] = "port"
    #: Ports that run on this one alone (a DSA user port under its CPU port, a VLAN interface
    #: under its parent; under a radio: its Wi-Fi interfaces).
    children: list[PortNode] = Field(default_factory=list)
    #: For a port over several others (bridge, LAG): their ids; each is shown at its own place.
    members: list[str] = Field(default_factory=list)
    #: SSIDs (``Wlan`` ids) carried here: by a Wi-Fi interface, or by a radio for the SSIDs
    #: whose interface is not reported.
    wlans: list[str] = Field(default_factory=list)


_ROLE_ORDER = {
    role: i
    for i, role in enumerate(
        (
            PortRole.CPU,
            PortRole.JACK,
            PortRole.SWITCH_PORT,
            None,
            PortRole.LAG,
            PortRole.BRIDGE,
            PortRole.VLAN,
            PortRole.WIRELESS,
            PortRole.TUNNEL,
            PortRole.VIRTUAL,
        )
    )
}


def natural_key(text: str) -> list[tuple[int, int | str]]:
    """Sort key that puts ``lan2`` before ``lan10``."""
    return [(0, int(t)) if t.isdigit() else (1, t) for t in re.split(r"(\d+)", text) if t]


class Network(Model):
    """The merged view of all sites: what rules, topology and UI work on."""

    sites: list[Site] = Field(default_factory=list)
    devices: list[Device] = Field(default_factory=list)
    statuses: dict[str, DeviceStatus] = Field(default_factory=dict)
    ports: list[Port] = Field(default_factory=list)
    segments: list[Segment] = Field(default_factory=list)
    subnets: list[Subnet] = Field(default_factory=list)
    #: WAN connections of a gateway (#148; part of ``interfaces``).
    uplinks: list[Uplink] = Field(default_factory=list)
    #: Management services of the devices (#173; part of ``interfaces``).
    services: list[ManagementService] = Field(default_factory=list)
    dhcp_servers: list[DhcpServer] = Field(default_factory=list)
    #: DHCP relays (#183; part of ``dhcp``).
    dhcp_relays: list[DhcpRelay] = Field(default_factory=list)
    dns_services: list[DnsService] = Field(default_factory=list)
    radios: list[Radio] = Field(default_factory=list)
    wlans: list[Wlan] = Field(default_factory=list)
    clients: list[Client] = Field(default_factory=list)
    neighbours: list[Neighbour] = Field(default_factory=list)
    #: VPN tunnels with their peers (#239; ``vpn``, adapter API 1.3).
    tunnels: list[Tunnel] = Field(default_factory=list)
    links: list[Link] = Field(default_factory=list)
    errors: list[ReadError] = Field(default_factory=list)
    #: User annotations, one per target (#186), set by the runner; read-only for rules.
    annotations: list[Annotation] = Field(default_factory=list)
    #: Acknowledged findings (#186); :func:`signalbox.rules.evaluate` applies them.
    acknowledgements: list[Acknowledgement] = Field(default_factory=list)

    def annotation(self, target: str) -> Annotation | None:
        """The annotation of a target (a model id or a MAC address), if the user made one."""
        try:
            key = annotation_target(target)
        except ValueError:
            return None
        return next((a for a in self.annotations if a.target == key), None)

    def expected(self, target: str) -> Expected:
        """The user's expectations about a target; empty (all None) when nothing is said."""
        a = self.annotation(target)
        return a.expected if a else Expected()

    def label(self, target: str) -> str | None:
        """The user's friendly name of a target, if any."""
        a = self.annotation(target)
        return a.label if a else None

    def knows(self, object_id: str) -> bool:
        """True when an object with this id is in the network: a device, a site, any observed
        object, a merged client (``client/<mac>``) or a link."""
        groups: list[list[Any]] = [
            self.devices,
            self.sites,
            self.ports,
            self.segments,
            self.subnets,
            self.uplinks,
            self.dhcp_servers,
            self.dhcp_relays,
            self.dns_services,
            self.radios,
            self.wlans,
            self.clients,
            self.neighbours,
            self.tunnels,
            self.links,
        ]
        return any(o.id == object_id for objs in groups for o in objs)

    def device(self, device_id: str) -> Device | None:
        return next((d for d in self.devices if d.id == device_id), None)

    def port(self, port_id: str) -> Port | None:
        return next((p for p in self.ports if p.id == port_id), None)

    def segment(self, segment_id: str) -> Segment | None:
        return next((s for s in self.segments if s.id == segment_id), None)

    def pvid_segment(self, port_id: str) -> str | None:
        """Segment that untagged frames arriving on the port land in (from ``Port.pvid``).

        ``None`` when the port or its PVID is unknown, or the port accepts tagged frames only.
        """
        port = self.port(port_id)
        if port is None or port.pvid is None or port.frame_types is FrameTypes.TAGGED_ONLY:
            return None
        device = self.device(port.device_id)
        if device is None:
            return None
        if port.pvid == DEFAULT_VLAN:
            return self.native_segment(device.id)
        return segment_id(device.site_id, port.pvid)

    def native_segment(self, device_id: str) -> str | None:
        """The untagged network a device belongs to (#205; ``None``: unknown device).

        At a site with one untagged network that is ``<site>/segment/native``. With several (see
        :func:`native_segment_id`): the one the device's own ports are untagged members of,
        else the one of its own subnet, else the one whose subnet holds its management
        address, else the main one.
        """
        device = self.device(device_id)
        if device is None:
            return None
        main = segment_id(device.site_id, None)
        natives = [
            s for s in self.segments if s.site_id == device.site_id and is_native_segment(s.id)
        ]
        if len(natives) < 2:
            return main
        own = f"{device_id}/port/"
        for seg in natives:
            if any(m.port_id.startswith(own) for m in seg.members):
                return seg.id
        ids = {s.id for s in natives}
        for sub in self.subnets:
            if sub.device_id == device_id and sub.segment_id in ids:
                return sub.segment_id
        try:
            addr = ip_address((device.management_address or "").strip("[]"))
        except ValueError:
            return main
        for sub in sorted(self.subnets, key=lambda x: x.id):
            if sub.segment_id in ids and addr in sub.interface.network:
                return sub.segment_id
        return main

    def dhcp_servers_on(self, segment_id: str) -> list[DhcpServer]:
        return [s for s in self.dhcp_servers if s.segment_id == segment_id]

    def dhcp_relays_on(self, segment_id: str) -> list[DhcpRelay]:
        """Enabled DHCP relays on a segment (#183): it needs no DHCP server of its own."""
        return [r for r in self.dhcp_relays if r.segment_id == segment_id and r.enabled]

    def leases_read(self, segment_id: str) -> bool:
        """The segment has an enabled DHCP server, and every one of them reported its leases.

        Only then does "no lease" mean something (#67): a server whose table was not read may
        have leased any address.
        """
        servers = [s for s in self.dhcp_servers_on(segment_id) if s.enabled]
        return bool(servers) and all(s.leases is not None for s in servers)

    def lease_of(
        self, mac: str, address: IPAddress, at: datetime | None = None
    ) -> tuple[DhcpServer, DhcpLease] | None:
        """The active lease of this MAC address and address on any known DHCP server."""
        for server in sorted(self.dhcp_servers, key=lambda s: s.id):
            lease = server.lease_for(address, at)
            if lease is not None and lease.mac == mac:
                return server, lease
        return None

    def address_source(
        self, client: Client, address: IPAddress, at: datetime | None = None
    ) -> AddressSource | None:
        """Where one of a client's addresses came from (#183); ``None``: not known.

        The client's own answer (:attr:`Client.address_sources`) wins unless it is
        ``unknown``. Otherwise an active lease of that MAC and address on a known DHCP server
        gives ``dhcp``, ``dhcp-reserved`` or ``dhcpv6``, and a link-local address is
        ``link-local``. Never ``static`` by elimination: whether a missing lease means a fixed
        address needs :meth:`leases_read` and a grace period, which the checks decide.
        """
        own = client.address_sources.get(address)
        if own is not None and own is not AddressSource.UNKNOWN:
            return own
        found = self.lease_of(client.mac, address, at)
        if found is not None:
            return found[1].source()
        if address.is_link_local:
            return AddressSource.LINK_LOCAL
        return own

    def tunnels_of(self, device_id: str) -> list[Tunnel]:
        return [t for t in self.tunnels if t.device_id == device_id]

    def tunnel(self, tunnel_id: str) -> Tunnel | None:
        return next((t for t in self.tunnels if t.id == tunnel_id), None)

    def tunnel_end(self, tunnel: Tunnel, peer: TunnelPeer) -> Tunnel | None:
        """The other end of a peer (#239): the read tunnel whose public key is the peer's and
        which itself has a peer with this tunnel's public key. None when that tunnel is not
        read, or when it does not name this one (the two ends disagree)."""
        if tunnel.public_key is None:
            return None
        for other in sorted(self.tunnels, key=lambda t: t.id):
            if (
                other.id != tunnel.id
                and other.public_key == peer.public_key
                and other.peer(tunnel.public_key) is not None
            ):
                return other
        return None

    def tunnel_with_key(self, public_key: str) -> Tunnel | None:
        """A read tunnel with this public key, whatever its peers say."""
        return next(
            (t for t in sorted(self.tunnels, key=lambda t: t.id) if t.public_key == public_key),
            None,
        )

    def remote_sites(self) -> list[tuple[Tunnel, TunnelPeer]]:
        """Site peers whose other end is not read (#239): an unmanaged site behind a tunnel,
        known only by the networks the peer's allowed IPs route to it."""
        return [
            (t, p)
            for t in sorted(self.tunnels, key=lambda t: t.id)
            for p in t.site_peers()
            if self.tunnel_end(t, p) is None
        ]

    def uplinks_of(self, device_id: str) -> list[Uplink]:
        return [u for u in self.uplinks if u.device_id == device_id]

    def upstream_router(self, uplink: Uplink) -> Subnet | None:
        """Gateway subnet of *another* known device that holds an IPv4 address of the uplink.

        Found: this gateway sits behind that one (double NAT, "Internet via 192.0.2.1").
        """
        for sub in self.subnets:
            if not sub.gateway or sub.device_id == uplink.device_id:
                continue
            if any(a.ip in sub.interface.network for a in uplink.addresses):
                return sub
        return None

    def services_of(self, device_id: str) -> list[ManagementService]:
        return [s for s in self.services if s.device_id == device_id]

    def service_segments(self, service: ManagementService) -> list[str]:
        """Segments whose devices can reach the service, as far as the device itself says (#173).

        Without firewall data (#135) this is an upper bound: a firewall rule may still block a
        segment listed here, but a segment left out cannot reach the service through any of
        the device's addresses. Candidates are the segments of the device's own subnets and
        the one holding its management address (for a layer-2 service: the segments its ports
        are members of). The device's restrictions narrow them: ``segments`` as reported,
        ``listen`` to the segments whose subnet holds a listen address, ``interfaces`` to the
        segments of those ports; then ``allowed_from`` drops segments none of whose known
        subnets overlaps an allowed network (a segment without a known subnet is kept).
        A disabled service has none.
        """
        if not service.enabled:
            return []
        dev = service.device_id
        member_of = {
            s.id: {m.port_id for m in s.members}
            for s in self.segments
            if any(m.port_id.startswith(f"{dev}/port/") for m in s.members)
        }
        nets: dict[str, list[IPNetwork]] = {}
        for sub in self.subnets:
            nets.setdefault(sub.segment_id, []).append(sub.interface.network)
        if service.transport is ServiceTransport.LAYER2:
            found = set(member_of)
        else:
            found = {s.segment_id for s in self.subnets if s.device_id == dev}
            device = self.device(dev)
            try:
                mgmt = ip_address((device.management_address or "").strip("[]")) if device else None
            except ValueError:
                mgmt = None
            if mgmt is not None:
                found |= {sid for sid, ns in nets.items() if any(mgmt in n for n in ns)}
        if service.segments:
            found = set(service.segments)
        specific = [a for a in service.listen if a not in _UNSPECIFIED]
        if specific:
            found &= {
                sid
                for sid, ns in nets.items()
                if any(a.version == n.version and a in n for a in specific for n in ns)
            }
        if service.interfaces:
            wanted = set(service.interfaces)
            found &= {sid for sid, ports in member_of.items() if ports & wanted}
        if service.allowed_from and service.transport is not ServiceTransport.LAYER2:
            found = {
                sid
                for sid in found
                if sid not in nets
                or any(
                    n.version == a.version and n.overlaps(a)
                    for n in nets[sid]
                    for a in service.allowed_from
                )
            }
        return sorted(found)

    def service_from_wan(self, service: ManagementService) -> bool | None:
        """Whether the service can be reached from the internet (#173, #123).

        The device's own answer (``from_wan``) wins. Otherwise: ``False`` when it is disabled,
        when the device has no uplink (port forwards to it are #135), when it is bound to
        addresses, ports or segments that are not the uplink's, when it is a layer-2 service
        bound to other ports (where the uplink's port is known), or when ``allowed_from``
        holds private address space only.
        ``None`` in every other case: it listens on the uplink and only the firewall, which
        Signalbox does not read yet (#135), decides.
        """
        if not service.enabled:
            return False
        if service.from_wan is not None:
            return service.from_wan
        uplinks = self.uplinks_of(service.device_id)
        if not uplinks:
            return False
        if service.allowed_from and not any(
            internet_reachable_network(n) for n in service.allowed_from
        ):
            return False
        uplink_ports = {u.port_id for u in uplinks if u.port_id}
        if service.interfaces and uplink_ports and not (set(service.interfaces) & uplink_ports):
            return False
        if service.transport is ServiceTransport.LAYER2:
            return None if service.interfaces or not service.segments else False
        if service.segments:
            return False
        specific = [a for a in service.listen if a not in _UNSPECIFIED]
        own = {a.ip for u in uplinks for a in u.addresses}
        if specific and not (set(specific) & own):
            return False
        return None

    def uplink_at(self, port_id: str) -> Uplink | None:
        """The uplink that uses this port, where the device says (``Uplink.port_id``)."""
        return next((u for u in self.uplinks if u.port_id == port_id), None)

    # internal port structure (#252, ADR 0008) -------------------------------------------

    def ports_of(self, device_id: str) -> list[Port]:
        return [p for p in self.ports if p.device_id == device_id]

    def external_ports(self, device_id: str, unknown: bool = True) -> list[Port]:
        """The ports of a device a cable can end on: jacks and LAGs, and with ``unknown`` the
        ports whose role is not known (devices that do not report it stay as they were)."""
        return [
            p
            for p in self.ports_of(device_id)
            if p.external is True or (unknown and p.external is None)
        ]

    def lower_ports(self, port_id: str) -> list[Port]:
        """The ports this one runs on (``Port.lower``), where they are known."""
        port = self.port(port_id)
        if port is None:
            return []
        return [p for x in port.lower if x != port_id and (p := self.port(x)) is not None]

    def upper_ports(self, port_id: str) -> list[Port]:
        """The ports that run on this one: bridges it is a member of, its VLAN interfaces."""
        return [p for p in self.ports if port_id in p.lower and p.id != port_id]

    def port_tree(self, device_id: str) -> list[PortNode]:
        """The internal structure of a device as a tree, every port exactly once.

        A port that runs on exactly one other port is that port's child (DSA user port under
        its CPU port, VLAN interface under its parent, a bridge over one port under it); a
        port over several (bridge, LAG) is a root that lists them as ``members``. A Wi-Fi
        interface without a lower port goes under the radio of its SSIDs; radios are roots.
        Lower ids that are unknown, and cycles (an adapter error), are ignored.
        """
        ports = {p.id: p for p in self.ports_of(device_id)}
        radios = {r.id for r in self.radios if r.device_id == device_id}
        wlans = [w for w in self.wlans if w.device_id == device_id]
        lowers = {
            pid: [x for x in dict.fromkeys(p.lower) if x in ports and x != pid]
            for pid, p in ports.items()
        }
        parent: dict[str, str] = {}
        for pid, low in lowers.items():
            if len(low) == 1:
                parent[pid] = low[0]
            elif not low and ports[pid].role in (PortRole.WIRELESS, None):
                radio = next(
                    (w.radio_id for w in wlans if w.port_id == pid and w.radio_id in radios),
                    None,
                )
                if radio is not None:
                    parent[pid] = radio
        children: dict[str, list[str]] = {}
        for child, up in parent.items():
            children.setdefault(up, []).append(child)

        def key(pid: str) -> tuple[int, list[tuple[int, int | str]]]:
            if pid in radios:
                return len(_ROLE_ORDER), natural_key(pid)
            p = ports[pid]
            return _ROLE_ORDER[p.role], natural_key(p.name)

        placed: set[str] = set()

        def build(nid: str) -> PortNode:
            placed.add(nid)
            kids = [build(c) for c in sorted(children.get(nid, []), key=key) if c not in placed]
            if nid in radios:
                own = [w.id for w in wlans if w.radio_id == nid and w.port_id not in ports]
                return PortNode(id=nid, node="radio", children=kids, wlans=sorted(own))
            low = lowers[nid]
            return PortNode(
                id=nid,
                children=kids,
                members=low if len(low) > 1 else [],
                wlans=sorted(w.id for w in wlans if w.port_id == nid),
            )

        roots = [n for n in [*ports, *radios] if n not in parent]
        tree = [build(n) for n in sorted(roots, key=key)]
        # what is left sits in a cycle: start it at its first port
        for pid in sorted(ports, key=key):
            if pid not in placed:
                tree.append(build(pid))
        return tree

    def untagged_segments(self, port_id: str) -> list[str]:
        """Segments the port sends untagged (egress), sorted."""
        return sorted(
            s.id
            for s in self.segments
            if any(m.port_id == port_id and m.mode is Membership.UNTAGGED for m in s.members)
        )


def json_schema() -> dict[str, Any]:
    """JSON Schema of the published model: Snapshot (adapter output) and Network."""
    from pydantic.json_schema import models_json_schema

    _, schema = models_json_schema(
        [(Snapshot, "validation"), (Network, "validation")],
        title="Signalbox network model",
    )
    return schema
