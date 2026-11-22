"""The vendor-neutral network model.

Adapters return a :class:`Snapshot` per device. :func:`signalbox.merge.merge` joins the snapshots
of a site into one :class:`Network` that rules, topology and UI work on.

Identifiers are strings that are unique across the whole installation. Objects of a device are
prefixed with the device id (``<device>/port/<name>``); segments are per site
(``<site>/segment/<vlan>``) so that the same VLAN seen on several devices is one segment.
Use the helper functions below to build them.
"""

from __future__ import annotations

import hashlib
from datetime import datetime
from enum import StrEnum
from ipaddress import IPv4Address, IPv4Interface, IPv6Address, IPv6Interface
from typing import Annotated, Any

from pydantic import BaseModel, ConfigDict, Field, JsonValue

IPAddress = IPv4Address | IPv6Address
IPInterface = IPv4Interface | IPv6Interface

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


class PortKind(StrEnum):
    ETHERNET = "ethernet"
    WIRELESS = "wireless"
    BRIDGE = "bridge"
    LAG = "lag"
    VIRTUAL = "virtual"


class Port(Observed):
    device_id: str
    name: str
    kind: PortKind = PortKind.ETHERNET
    up: bool | None = None
    speed_mbps: int | None = None
    full_duplex: bool | None = None
    poe: bool | None = None
    lag: str | None = None
    mac: Mac | None = None


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


class DhcpPool(Model):
    start: IPAddress
    end: IPAddress


class Reservation(Model):
    mac: Mac
    address: IPAddress
    hostname: str | None = None


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


class HostRecord(Model):
    name: str
    address: IPAddress


class DnsService(Observed):
    device_id: str
    enabled: bool = True
    listen: list[IPAddress] = Field(default_factory=list)
    forwarders: list[IPAddress] = Field(default_factory=list)
    host_records: list[HostRecord] = Field(default_factory=list)


class Band(StrEnum):
    GHZ_2_4 = "2.4"
    GHZ_5 = "5"
    GHZ_6 = "6"


class Radio(Observed):
    device_id: str
    name: str
    band: Band
    channel: int | None = None
    width_mhz: int | None = None
    tx_power_dbm: int | None = None
    country: str | None = None
    enabled: bool = True


class Security(StrEnum):
    OPEN = "open"
    OWE = "owe"
    WPA2 = "wpa2-psk"
    WPA3 = "wpa3-sae"
    WPA2_WPA3 = "wpa2-wpa3"
    WPA2_ENTERPRISE = "wpa2-enterprise"
    WPA3_ENTERPRISE = "wpa3-enterprise"
    OTHER = "other"


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


class Client(Observed):
    mac: Mac
    addresses: list[IPAddress] = Field(default_factory=list)
    hostname: str | None = None
    segment_id: str | None = None
    #: Port or WLAN where the client was seen.
    seen_on: str | None = None
    last_seen: datetime | None = None


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


class LinkKind(StrEnum):
    CABLE = "cable"
    WIRELESS = "wireless"


class Link(Model):
    id: str
    a: str
    b: str
    kind: LinkKind = LinkKind.CABLE
    origin: LinkOrigin


class ReadError(Model):
    """A capability that was declared but could not be read: becomes an "incomplete" finding."""

    device_id: str
    capability: str
    message: str


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
    dhcp_servers: list[DhcpServer] = Field(default_factory=list)
    dns_services: list[DnsService] = Field(default_factory=list)
    radios: list[Radio] = Field(default_factory=list)
    wlans: list[Wlan] = Field(default_factory=list)
    clients: list[Client] = Field(default_factory=list)
    neighbours: list[Neighbour] = Field(default_factory=list)
    errors: list[ReadError] = Field(default_factory=list)
    #: Devices reported through this one (a controller's managed devices). Their ids start with
    #: ``<device id>/`` and their ``managed_by`` is the observed device.
    extra_devices: list[Device] = Field(default_factory=list)
    #: Status per extra device, when the controller knows it (default: the snapshot's status).
    extra_status: dict[str, DeviceStatus] = Field(default_factory=dict)


class Network(Model):
    """The merged view of all sites: what rules, topology and UI work on."""

    sites: list[Site] = Field(default_factory=list)
    devices: list[Device] = Field(default_factory=list)
    statuses: dict[str, DeviceStatus] = Field(default_factory=dict)
    ports: list[Port] = Field(default_factory=list)
    segments: list[Segment] = Field(default_factory=list)
    subnets: list[Subnet] = Field(default_factory=list)
    dhcp_servers: list[DhcpServer] = Field(default_factory=list)
    dns_services: list[DnsService] = Field(default_factory=list)
    radios: list[Radio] = Field(default_factory=list)
    wlans: list[Wlan] = Field(default_factory=list)
    clients: list[Client] = Field(default_factory=list)
    neighbours: list[Neighbour] = Field(default_factory=list)
    links: list[Link] = Field(default_factory=list)
    errors: list[ReadError] = Field(default_factory=list)

    def device(self, device_id: str) -> Device | None:
        return next((d for d in self.devices if d.id == device_id), None)

    def port(self, port_id: str) -> Port | None:
        return next((p for p in self.ports if p.id == port_id), None)

    def segment(self, segment_id: str) -> Segment | None:
        return next((s for s in self.segments if s.id == segment_id), None)


def json_schema() -> dict[str, Any]:
    """JSON Schema of the published model: Snapshot (adapter output) and Network."""
    from pydantic.json_schema import models_json_schema

    _, schema = models_json_schema(
        [(Snapshot, "validation"), (Network, "validation")],
        title="Signalbox network model",
    )
    return schema
