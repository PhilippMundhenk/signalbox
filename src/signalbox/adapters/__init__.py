"""The adapter API: how Signalbox talks to a kind of device.

An adapter is a class with a :class:`Manifest`, constructed with an :class:`AdapterContext`.
It must implement :meth:`Adapter.read_system`; everything else is an optional capability,
declared in the manifest and implemented through the matching protocol (``ReadsInterfaces``,
``ReadsDhcp``, ...). :meth:`Adapter.observe` calls the declared capabilities and builds the
:class:`~signalbox.model.Snapshot`; adapters do not override it.

Adapters are discovered through the ``signalbox.adapters`` entry point group, so a third-party
package only needs::

    [project.entry-points."signalbox.adapters"]
    mydevice = "mypackage.adapter:MyDeviceAdapter"
"""

from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from importlib.metadata import entry_points
from ipaddress import IPv4Address, IPv6Address
from typing import Any, ClassVar, Literal, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field, JsonValue, SecretStr

from signalbox import certificates
from signalbox.changes import Change, ChangeKind
from signalbox.discovery import BroadcastResult, Candidate, HostProbe, NetworkProbe
from signalbox.model import (
    FDB_LIMIT,
    AccountPrivilege,
    Certificate,
    Client,
    Device,
    DeviceAccount,
    DeviceHealth,
    DeviceRole,
    DeviceStatus,
    DeviceTime,
    DhcpRelay,
    DhcpServer,
    DnsService,
    FdbEntry,
    FdbKind,
    Firewall,
    Firmware,
    LogTarget,
    ManagementService,
    MessageParams,
    Neighbour,
    Observed,
    Port,
    Radio,
    ReadError,
    Route,
    RoutingRule,
    Segment,
    ServerSighting,
    Snapshot,
    Source,
    StpBridge,
    Subnet,
    TraceHop,
    Tunnel,
    Uplink,
    Wlan,
)

#: Version of this API. An adapter declares the version it was written for; the major part
#: must match.
API_VERSION = "1.4"


class Capability(StrEnum):
    INTERFACES = "interfaces"  # ports, segments (VLANs), subnets, uplinks, management services
    DHCP = "dhcp"  # DHCP servers (pools, options, leases) and relays
    DNS = "dns"
    WIRELESS = "wireless"  # radios and WLANs
    CLIENTS = "clients"
    NEIGHBOURS = "neighbours"  # LLDP
    HEALTH = "health"  # uptime, CPU, memory, storage, sensors (API 1.2)
    TIME = "time"  # clock, time zone, NTP (API 1.2)
    VPN = "vpn"  # VPN tunnels and their peers (API 1.3)
    FIREWALL = "firewall"  # zones, filter rules, NAT and port forwards (API 1.4)


#: Adapter API version that introduced a capability (absent: 1.0). An adapter declaring a
#: capability must be written for at least that version.
SINCE: dict[Capability, str] = {
    Capability.HEALTH: "1.2",
    Capability.TIME: "1.2",
    Capability.VPN: "1.3",
    Capability.FIREWALL: "1.4",
}


class AdapterError(Exception):
    """A device could not be read; the message is shown to the user.

    ``fix``: what the user can do about it, in plain words (shown as "What to do").
    ``remedy``: the id of a :class:`Remedy` of the integration that repairs it (#215), if any.
    """

    def __init__(
        self,
        *args: object,
        fix: str | None = None,
        remedy: str | None = None,
        fix_id: str | None = None,
        message_id: str | None = None,
        params: MessageParams | None = None,
    ) -> None:
        super().__init__(*args)
        self.fix = fix
        self.remedy = remedy
        #: Translation id of ``fix`` (#204), catalogue ``msg.<id>``; no values.
        self.fix_id = fix_id
        #: Translation id of the message and the values its placeholders take (#204).
        self.message_id = message_id
        self.params: MessageParams = params or {}

    def redacted(self, redact: Callable[[str], str]) -> AdapterError:
        """The same error with the secrets of every text and value removed (#204 keeps ids)."""
        return type(self)(
            redact(str(self)),
            fix=self.fix,
            fix_id=self.fix_id,
            message_id=self.message_id,
            params={k: redact(v) if isinstance(v, str) else v for k, v in self.params.items()},
        )


class Unreachable(AdapterError):
    pass


class AuthFailed(AdapterError):
    pass


class UntrustedCertificate(AdapterError):
    """The device presented a certificate that is not (or no longer) the pinned one."""

    def __init__(self, fingerprint: str, pinned: str | None) -> None:
        self.fingerprint = fingerprint
        self.pinned = pinned
        what = "a new certificate" if pinned else "a certificate not yet trusted"
        super().__init__(f"device presented {what} (SHA-256 {fingerprint})")


class AdapterContractError(Exception):
    """The adapter itself is broken (for example a declared capability is not implemented).

    Not a device problem: raised, never turned into a finding.
    """


class Described(str):
    """A text with its translation id and values (#204): the English text as a string, so code
    and tests that read the text keep working; ``message_id`` and ``params`` ride along."""

    message_id: str
    params: dict[str, str]

    def __new__(cls, message: str, message_id: str, **params: str) -> Described:
        text = super().__new__(cls, message)
        text.message_id = message_id
        text.params = params
        return text


def unexpected_answer(endpoint: str, detail: str) -> AdapterError:
    """A device answered, but not in the shape the integration reads (#204)."""
    return AdapterError(
        f"unexpected answer from {endpoint}: {detail}",
        message_id="transport.unexpected",
        params={"endpoint": endpoint, "detail": detail},
    )


def message_fields(text: str) -> dict[str, Any]:
    """``message_id`` / ``params`` of a :class:`Described` text, for the model that shows it."""
    if isinstance(text, Described):
        return {"message_id": text.message_id, "params": dict(text.params)}
    return {}


class VendorCall(BaseModel):
    """One call an integration makes to apply a change; shown in the review before deploying."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    description: str
    #: Translation id and values of ``description`` (#204), where it has one.
    message_id: str | None = None
    params: MessageParams = Field(default_factory=dict)
    method: str
    target: str
    #: Secrets replaced by "***".
    payload: dict[str, JsonValue] = Field(default_factory=dict)


class Backup(BaseModel):
    """A device's configuration before a change, as the device exports it."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    device_id: str
    taken_at: datetime
    format: str
    content: str


class ApplyResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    #: Set when the device rolls itself back at this time unless ``confirm()`` is called.
    confirm_deadline: datetime | None = None
    calls: list[VendorCall] = Field(default_factory=list)


@runtime_checkable
class WritesConfig(Protocol):
    """Write capability: declared by a non-empty ``Manifest.writes``.

    ``secrets`` maps secret names (e.g. Wi-Fi passphrases) to their values; adapters must never
    log them or put them into a VendorCall payload.
    """

    async def plan_changes(
        self, changes: list[Change], secrets: Mapping[str, str]
    ) -> list[VendorCall]: ...

    async def backup(self) -> Backup: ...

    async def apply(
        self, changes: list[Change], secrets: Mapping[str, str], rollback_seconds: int
    ) -> ApplyResult: ...

    async def confirm(self) -> None: ...

    async def restore(self, backup: Backup) -> None: ...


class PreviewStep(BaseModel):
    """A step an automatic setup or a remedy normally takes, shown before any credential (#279).

    Static, in words: Signalbox cannot inspect the device without the admin login. The steps
    that really are needed come from the plan after the login; if one is not listed here (same
    ``id``), the user must see and confirm the plan again before anything runs.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    #: The id of the :class:`SetupStep` it stands for.
    id: str
    title: str
    #: Translation (#204): catalogue id of ``title`` (``msg.<id>``) and its values.
    title_id: str | None = None
    params: MessageParams = Field(default_factory=dict)
    #: Only when removing what the setup created.
    remove: bool = False
    #: Only with this :class:`SetupExtra` ticked.
    extra: str | None = None


class SetupExtra(BaseModel):
    """An optional extra of the automatic setup, an unticked checkbox in the plan (#278).

    Ticked, it is part of the plan and runs only after the same confirmation as the rest; on
    *Remove* the same checkbox means removing it again (what is not ticked stays installed).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str = Field(pattern=r"^[a-z][a-z0-9_-]*$")
    #: "Also install LLDP (lldpd, luci-app-lldpd)".
    label: str
    #: What it is for and what it changes, shown next to the checkbox.
    note: str = ""
    #: Label when removing ("Also remove the LLDP packages").
    remove_label: str = ""


class AdminLogin(BaseModel):
    """What an integration that sets itself up (#231) asks for: the device's admin login.

    Declared as ``Manifest.admin_login``; the integration then implements
    :meth:`Adapter.plan_setup` and :meth:`Adapter.apply_setup`. Shown in the device form under
    *Set up automatically*. The login is used for that one request and never stored.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    #: How Signalbox reaches the device with it, in plain words ("SSH as root").
    transport: str
    user_label: str = "Admin user"
    user_default: str = "root"
    secret_label: str = "Password"
    #: A port field is shown when set (SSH: 22); None: the address of the settings is used.
    port_default: int | None = None
    #: What must be possible on the device first (shown above the fields).
    note: str = ""
    #: An optional second step over SSH that is off unless the user ticks it (#242).
    ssh_option: SshOption | None = None
    #: Optional extras, offered unticked next to the plan (#278).
    extras: list[SetupExtra] = Field(default_factory=list)
    #: What the setup normally does, shown before the admin login is asked for (#279).
    preview: list[PreviewStep] = Field(default_factory=list)


class SshOption(BaseModel):
    """An optional extra of the automatic setup that needs an SSH login (OPNsense: a script)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    label: str
    #: What it installs and why, shown next to the checkbox.
    note: str
    user: str = "root"
    secret_label: str = "SSH password"
    port_default: int = 22


class StepState(StrEnum):
    TODO = "todo"  # plan: will be done
    UNCHANGED = "unchanged"  # already as needed, nothing to do
    DONE = "done"
    FAILED = "failed"
    SKIPPED = "skipped"  # not run because an earlier step failed


class SetupStep(BaseModel):
    """One step of an automatic setup, as the plan and the result show it.

    ``detail`` shows what is sent (commands, files, settings) with every secret as ``***``.
    """

    model_config = ConfigDict(extra="forbid")

    id: str
    title: str
    detail: str = ""
    state: StepState = StepState.TODO
    message: str = ""
    #: Translation (#204): catalogue id of ``title`` (``msg.<id>``) and its values.
    title_id: str | None = None
    params: MessageParams = Field(default_factory=dict)


class SetupRequest(BaseModel):
    """An automatic setup (or its removal) as the device form asks for it."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    #: The device form's settings without secrets (address, user name, ...), not validated.
    config: Mapping[str, JsonValue] = Field(default_factory=dict)
    admin_user: str
    #: Used for this request only: never stored, logged, or put into a step or an error.
    admin_secret: SecretStr
    port: int | None = Field(None, ge=1, le=65535)
    #: Give the new login the write permissions of the setup guide (*Allow changes*).
    allow_writes: bool = False
    #: Remove what the automatic setup created instead.
    remove: bool = False
    #: The fingerprint (SSH host key or certificate) the user confirmed; None: not yet.
    trust: str | None = None
    timeout: float = 30.0
    #: The optional SSH step (:class:`SshOption`, #242): ticked, with the SSH login of this one
    #: request (never stored) and the SSH host key the user confirmed for it.
    ssh_step: bool = False
    #: Only fetch the identities (HTTPS certificate and, with ``ssh_step``, the SSH host key) to
    #: be confirmed before any password is asked for (#290): no credential is sent, nothing is
    #: trusted yet. The plan then has no steps and ``trusted`` / ``ssh_trusted`` are False.
    identity_only: bool = False
    ssh_secret: SecretStr | None = None
    ssh_port: int | None = Field(None, ge=1, le=65535)
    ssh_trust: str | None = None
    #: Ids of the :class:`SetupExtra` the user ticked (#278); with ``remove``: remove them too.
    extras: list[str] = Field(default_factory=list)
    #: Path traces are on (``traces.enabled``, #253): also give the login the permission to
    #: run traceroutes (``Manifest.traces``). Off: the login gets none.
    traces: bool = False


class SetupPlan(BaseModel):
    """What an automatic setup would do; with an untrusted fingerprint only that."""

    model_config = ConfigDict(extra="forbid")

    #: What the device presented: SSH host key ``SHA256:...`` or certificate SHA-256 (hex).
    fingerprint: str
    fingerprint_kind: Literal["ssh-host-key", "certificate"]
    trusted: bool
    #: How to compare the fingerprint on the device itself.
    compare: str = ""
    #: The optional SSH step (#242): the presented host key and whether it is the confirmed one.
    ssh_fingerprint: str | None = None
    ssh_trusted: bool | None = None
    ssh_compare: str = ""
    steps: list[SetupStep] = Field(default_factory=list)


class SetupResult(BaseModel):
    """The steps as run, and the device settings for the login that was set up."""

    model_config = ConfigDict(extra="forbid")

    ok: bool
    steps: list[SetupStep]
    #: Settings to store (non-secret: address, user name). Empty after a removal.
    settings: dict[str, JsonValue] = Field(default_factory=dict)
    #: Secret settings to store encrypted (generated password, API key); never sent to the UI.
    secrets: dict[str, SecretStr] = Field(default_factory=dict)
    #: Certificate fingerprint to pin for reading, learnt over the pinned setup connection.
    certificate: str | None = None


class Remedy(BaseModel):
    """A repair the integration can make on a device with the admin login (#215, ADR 0012).

    Only what Signalbox's own setup owns: the packages and permissions it reads through, never
    the network configuration. Declared in ``Manifest.remedies``; a read gap or error names it
    with ``remedy=<id>``, and the UI offers *Fix it* next to it.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str = Field(pattern=r"^[a-z][a-z0-9_-]*$")
    #: What it does, in a few words ("Install LLDP").
    title: str
    #: What it changes on the device, in plain words (shown before the plan).
    description: str = ""
    #: How this remedy reaches the device when that differs from ``AdminLogin.transport``.
    transport: str = ""
    #: SSH port shown in the form for this remedy, when it differs from the admin login's.
    port_default: int | None = None
    #: Only adds what Signalbox reads through (packages, permissions for its own login): needs
    #: the admin login and a confirmation, but not *Allow changes* (#278, ADR 0012).
    read_side: bool = False
    #: What it normally does, shown before the admin login is asked for (#279).
    preview: list[PreviewStep] = Field(default_factory=list)


class RemedyRequest(BaseModel):
    """A *Fix it* for one stored device: the remedy, its settings and the admin login."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    remedy: str
    #: The device's stored settings without secrets (address, user name, ...).
    config: Mapping[str, JsonValue] = Field(default_factory=dict)
    #: The device's stored secrets, for identifying its login (never sent to the UI).
    secrets: Mapping[str, SecretStr] = Field(default_factory=dict)
    admin_user: str
    #: Used for this request only: never stored, logged, or put into a step or an error.
    admin_secret: SecretStr
    port: int | None = Field(None, ge=1, le=65535)
    #: The device has *Allow changes*: permissions include the write part of the setup guide.
    allow_writes: bool = False
    #: The fingerprint (SSH host key or certificate) the user confirmed; None: not yet.
    trust: str | None = None
    timeout: float = 30.0
    #: Path traces are on (#253): the permissions include the one for traceroutes.
    traces: bool = False


class UntrustedHostKey(AdapterError):
    """The device presented an SSH host key the user has not confirmed (setup, #231)."""

    def __init__(self, fingerprint: str, pinned: str | None) -> None:
        self.fingerprint = fingerprint
        self.pinned = pinned
        what = "a different SSH host key" if pinned else "an SSH host key not yet trusted"
        super().__init__(f"device presented {what} ({fingerprint})")


class TraceSupport(BaseModel):
    """An integration that can run a traceroute on its device (#253, ``Manifest.traces``).

    It then implements :meth:`Adapter.trace`. Used only while path traces are on
    (``traces.enabled``); the permission is documented and requested only then.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    #: What the device login needs for it, in plain words (shown on the topology page).
    permission: str
    #: How the device runs it ("the diagnostics API", "tracepath over SSH").
    method: str = ""


class TraceAnswer(BaseModel):
    """What a device's traceroute returned: the hops in TTL order, raw (core matches them)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    hops: list[TraceHop] = Field(default_factory=list)
    #: The target itself answered (the last hop is the target).
    reached: bool = False


class AdapterConfig(BaseModel):
    """Base class of an adapter's connection settings; the UI renders a form from its schema.

    Mark secrets with ``pydantic.SecretStr``: they are stored encrypted and never sent back.
    """

    model_config = ConfigDict(extra="forbid")


class Manifest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, arbitrary_types_allowed=True)

    id: str = Field(pattern=r"^[a-z][a-z0-9_-]*$")
    name: str
    version: str
    api_version: str
    vendor: str
    roles: frozenset[DeviceRole]
    capabilities: frozenset[Capability]
    config: type[AdapterConfig]
    description: str = ""
    #: Where the user reads what to prepare on the device (shown in the device form).
    setup_url: str = ""
    #: Commands the user runs once on the device to prepare it (shown in the device form).
    setup_commands: str = ""
    #: What to prepare on the device, step by step, in plain words (shown in the device form).
    setup_steps: tuple[str, ...] = ()
    #: Kinds of change the integration can apply (empty: read only).
    writes: frozenset[ChangeKind] = frozenset()
    #: The integration can set up its own login with the device's admin login (#231):
    #: implements :meth:`Adapter.plan_setup` and :meth:`Adapter.apply_setup`.
    admin_login: AdminLogin | None = None
    #: Repairs the integration can make with the admin login (#215): implements
    #: :meth:`Adapter.plan_remedy` and :meth:`Adapter.apply_remedy`; needs ``admin_login``.
    remedies: tuple[Remedy, ...] = ()
    #: The integration can run a traceroute on the device (#253): implements
    #: :meth:`Adapter.trace`. No adapter API version needed (an optional hook).
    traces: TraceSupport | None = None
    #: The least privilege the integration's documented login needs to read (#175):
    #: ``account.signalbox-privileged`` reports a login with more. ``None``: not said.
    least_privilege: AccountPrivilege | None = None


@dataclass(frozen=True)
class AdapterContext:
    site_id: str
    device_id: str
    device_name: str
    role: DeviceRole
    config: AdapterConfig
    #: SHA-256 fingerprint of the device certificate trusted so far, if any.
    pinned_fingerprint: str | None = None
    timeout: float = 10.0
    extra: Mapping[str, Any] = field(default_factory=dict)


class SystemInfo(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    vendor: str | None = None
    model: str | None = None
    firmware: Firmware | None = None
    management_address: str | None = None
    #: Whether the adapter reads the device encrypted (#173): ``False`` for NSDP, Easy Smart
    #: UDP or plain HTTP (``allow_insecure_http``). Copied to ``Device.transport_encrypted``.
    transport_encrypted: bool | None = None
    #: Vendor fields of the device itself (MAC, serial, protocol details); shown on the
    #: device's advanced tab only, never read by rules.
    vendor_extra: dict[str, JsonValue] = Field(default_factory=dict)


class Gap(BaseModel):
    """Part of a capability the device would not give while the rest was read (old firmware
    protecting a setting, a missing package): reported like a read error, the data is kept."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    message: str
    fix: str | None = None
    #: Translation ids and values of ``message`` / ``fix`` (#204), see ``ReadError``.
    message_id: str | None = None
    fix_id: str | None = None
    params: MessageParams = Field(default_factory=dict)
    #: Id of a :class:`Remedy` of the integration that repairs this (#215).
    remedy: str | None = None
    #: An optional feature is missing (LLDP, #278): shown with its fix, but the device stays
    #: "ok" and the finding is an info at most.
    optional: bool = False


class Observation(BaseModel):
    """What one capability read returns."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    ports: list[Port] = Field(default_factory=list)
    segments: list[Segment] = Field(default_factory=list)
    subnets: list[Subnet] = Field(default_factory=list)
    #: WAN connections of a gateway (#148), read with ``interfaces``; no API version needed.
    uplinks: list[Uplink] = Field(default_factory=list)
    #: Management services (#173), read with ``interfaces``; no API version needed. Report
    #: every service the device has, disabled ones too, or none (not read).
    services: list[ManagementService] = Field(default_factory=list)
    #: Certificates stored on the device (#330), read with ``interfaces``; no API version
    #: needed. Public data only: never a private key, its passphrase or a certificate request,
    #: also not in ``vendor_extra``. Report every certificate the device lists, or none (not
    #: read).
    certificates: list[Certificate] = Field(default_factory=list)
    dhcp_servers: list[DhcpServer] = Field(default_factory=list)
    #: DHCP relays (#183), read with ``dhcp``; no API version needed.
    dhcp_relays: list[DhcpRelay] = Field(default_factory=list)
    dns_services: list[DnsService] = Field(default_factory=list)
    radios: list[Radio] = Field(default_factory=list)
    wlans: list[Wlan] = Field(default_factory=list)
    clients: list[Client] = Field(default_factory=list)
    neighbours: list[Neighbour] = Field(default_factory=list)
    #: Forwarding database (MAC address table) entries (#160), read with ``clients`` (or
    #: ``interfaces`` without a client read); no API version needed. Report what the device
    #: says, on the physical port where it knows it; ``observe()`` keeps at most
    #: :data:`~signalbox.model.FDB_LIMIT` per device.
    fdb: list[FdbEntry] = Field(default_factory=list)
    #: Routing table (#149), read with ``interfaces``; no API version needed. Report static,
    #: default, VPN and dynamic routes; connected routes are derived from ``subnets`` and only
    #: reported by a device that lists its whole table anyway. An integration that cannot read
    #: the table reports nothing (and an optional read error), never an empty table it made up.
    routes: list[Route] = Field(default_factory=list)
    #: Policy routing rules (#149), read with ``interfaces``; no API version needed. Report
    #: every rule, or none when the device cannot say.
    routing_rules: list[RoutingRule] = Field(default_factory=list)
    #: VPN tunnels with their peers (#239), read with ``vpn`` (API 1.3). Never a private or
    #: pre-shared key, also not in ``vendor_extra``.
    tunnels: list[Tunnel] = Field(default_factory=list)
    #: Packet filter and NAT (#135), read with ``firewall`` (API 1.4): at most one per device.
    firewalls: list[Firewall] = Field(default_factory=list)
    #: DHCP servers and routers the device saw answer (#184), read with ``dhcp``; no API
    #: version needed: its own DHCP client's server, rogue-server alerts. Known ones too.
    server_sightings: list[ServerSighting] = Field(default_factory=list)
    #: Devices managed through the observed one (API 1.1). Ids must start with
    #: ``<device id>/``; site, adapter and ``managed_by`` are filled in by ``observe()``.
    devices: list[Device] = Field(default_factory=list)
    #: Reachability of those devices as the controller reports it.
    device_status: dict[str, DeviceStatus] = Field(default_factory=dict)
    #: Health per device id: the observed device or one of ``devices`` (API 1.2).
    health: dict[str, DeviceHealth] = Field(default_factory=dict)
    #: Clock and NTP per device id: the observed device or one of ``devices`` (API 1.2).
    time: dict[str, DeviceTime] = Field(default_factory=dict)
    #: Remote log, flow, trap and metrics targets per device id (#180, ADR 0018), read with
    #: ``interfaces``; no API version needed. A device that was read and sends nothing gets
    #: ``[]``; leave a device out when its targets could not be read (add a gap then).
    log_targets: dict[str, list[LogTarget]] = Field(default_factory=dict)
    #: Local accounts per device id (#175, ADR 0020), read with ``interfaces``; no API version
    #: needed. Leave a device out when its accounts could not be read (add a gap then). Never
    #: a password, key or hash, also not in ``vendor_extra``.
    accounts: dict[str, list[DeviceAccount]] = Field(default_factory=dict)
    #: Spanning tree per bridge, per device id (#155, ADR 0023), read with ``interfaces``; no
    #: API version needed. A device that was read and has no bridge gets ``[]``; the port
    #: state goes into ``Port.stp``.
    stp_bridges: dict[str, list[StpBridge]] = Field(default_factory=dict)
    #: Per device id: the login Signalbox uses is a factory default (#126), compared in
    #: memory with :func:`signalbox.factory_defaults.is_factory_default`; only the boolean.
    default_credentials: dict[str, bool] = Field(default_factory=dict)
    #: Per device id: what the login Signalbox uses may do (#175).
    signalbox_privilege: dict[str, AccountPrivilege] = Field(default_factory=dict)
    #: What this read could not get although the rest was read: the device counts as partly
    #: read for this capability, so checks needing the missing part report incomplete.
    incomplete: list[Gap] = Field(default_factory=list)


@runtime_checkable
class ReadsInterfaces(Protocol):
    async def read_interfaces(self) -> Observation: ...


@runtime_checkable
class ReadsDhcp(Protocol):
    async def read_dhcp(self) -> Observation: ...


@runtime_checkable
class ReadsDns(Protocol):
    async def read_dns(self) -> Observation: ...


@runtime_checkable
class ReadsWireless(Protocol):
    async def read_wireless(self) -> Observation: ...


@runtime_checkable
class ReadsClients(Protocol):
    async def read_clients(self) -> Observation: ...


@runtime_checkable
class ReadsNeighbours(Protocol):
    async def read_neighbours(self) -> Observation: ...


@runtime_checkable
class ReadsHealth(Protocol):
    """Fill ``Observation.health``, keyed by device id (API 1.2)."""

    async def read_health(self) -> Observation: ...


@runtime_checkable
class ReadsTime(Protocol):
    """Fill ``Observation.time``, keyed by device id (API 1.2).

    Set ``DeviceTime.clock`` to the device's time as it answered; leave ``read_at`` empty and
    ``observe()`` fills in the middle of the call and half its duration as uncertainty. An
    adapter that reads the clock among other requests sets both itself.
    """

    async def read_time(self) -> Observation: ...


@runtime_checkable
class ReadsVpn(Protocol):
    """Fill ``Observation.tunnels`` (API 1.3): every VPN interface with its peers."""

    async def read_vpn(self) -> Observation: ...


@runtime_checkable
class ReadsFirewall(Protocol):
    """Fill ``Observation.firewalls`` (API 1.4): zones, policies, filter rules in evaluation
    order, NAT and port forwards; ``rules_complete = False`` where some rules are not
    visible."""

    async def read_firewall(self) -> Observation: ...


PROTOCOLS: dict[Capability, tuple[type, str]] = {
    Capability.INTERFACES: (ReadsInterfaces, "read_interfaces"),
    Capability.DHCP: (ReadsDhcp, "read_dhcp"),
    Capability.DNS: (ReadsDns, "read_dns"),
    Capability.WIRELESS: (ReadsWireless, "read_wireless"),
    Capability.CLIENTS: (ReadsClients, "read_clients"),
    Capability.NEIGHBOURS: (ReadsNeighbours, "read_neighbours"),
    Capability.HEALTH: (ReadsHealth, "read_health"),
    Capability.TIME: (ReadsTime, "read_time"),
    Capability.VPN: (ReadsVpn, "read_vpn"),
    Capability.FIREWALL: (ReadsFirewall, "read_firewall"),
}


def _stamp(obj: Observed, source: Source, when: datetime) -> Observed:
    update: dict[str, object] = {}
    if obj.source is None:
        update["source"] = source
    if obj.observed_at is None:
        update["observed_at"] = when
    return obj.model_copy(update=update) if update else obj


def _complete_health(health: DeviceHealth, when: datetime) -> DeviceHealth:
    """Derive boot time from uptime (or the other way round) at observation time."""
    if health.uptime_seconds is not None and health.boot_time is None:
        boot = when - timedelta(seconds=health.uptime_seconds)
        return health.model_copy(update={"boot_time": boot.replace(microsecond=0)})
    if health.boot_time is not None and health.uptime_seconds is None:
        uptime = int((when - health.boot_time).total_seconds())
        return health.model_copy(update={"uptime_seconds": max(uptime, 0)})
    return health


def _complete_time(value: DeviceTime, start: datetime, end: datetime) -> DeviceTime:
    if value.clock is None or value.read_at is not None:
        return value
    half = (end - start) / 2
    return value.model_copy(
        update={"read_at": start + half, "uncertainty_seconds": half.total_seconds()}
    )


class Adapter(ABC):
    manifest: ClassVar[Manifest]

    #: Fingerprint of the certificate the device presented when it was refused as untrusted,
    #: so the user can be asked to trust it.
    presented_fingerprint: str | None = None

    def __init__(self, context: AdapterContext) -> None:
        if not isinstance(context.config, self.manifest.config):
            raise AdapterContractError(
                f"{self.manifest.id}: config must be {self.manifest.config.__name__}"
            )
        self.context = context
        if self.manifest.writes and not isinstance(self, WritesConfig):
            raise AdapterContractError(
                f"{self.manifest.id} declares writes but does not implement WritesConfig"
            )
        for cap in self.manifest.capabilities:
            proto, _ = PROTOCOLS[cap]
            if not isinstance(self, proto):
                raise AdapterContractError(
                    f"{self.manifest.id} declares {cap.value} but does not implement "
                    f"{proto.__name__}"
                )

    @abstractmethod
    async def read_system(self) -> SystemInfo:
        """Vendor, model, firmware. Raise Unreachable / AuthFailed / UntrustedCertificate."""

    async def close(self) -> None:  # noqa: B027 - optional hook
        """Release connections."""

    # discovery (#203): optional, no adapter API version needed --------------------------

    @classmethod
    async def discover(cls, probe: HostProbe) -> Candidate | None:
        """Optional: is there a device of this kind at ``probe.host``? (docs/DISCOVERY.md)

        Send only unauthenticated, read-only requests, and only through ``probe``
        (``probe.get``/``probe.post``: no credentials, TLS not verified, rate-limited, small
        answers). Return a :class:`~signalbox.discovery.Candidate` with the settings to
        prefill (the address field), or None. Never raise for what a device answers; an
        integration without a probe keeps this default.
        """
        return None

    @classmethod
    async def discover_broadcast(cls, probe: NetworkProbe) -> BroadcastResult | None:
        """Optional: devices that answer a broadcast of this integration's protocol, once per
        run (the UDP protocols of small switches). None: the integration has none."""
        return None

    # automatic setup (#231): optional, no adapter API version needed -------------------

    @classmethod
    async def plan_setup(cls, request: SetupRequest) -> SetupPlan:
        """Optional: what an automatic setup with the admin login would do (docs/ADAPTERS.md).

        Connect with the admin login only over a pinned channel: without ``request.trust``,
        or when it differs, return the presented fingerprint with ``trusted=False`` and send
        no credential. Change nothing on the device. Never put ``request.admin_secret`` or a
        generated secret into a step, a log line or an error.
        """
        raise NotImplementedError

    @classmethod
    async def apply_setup(cls, request: SetupRequest) -> SetupResult:
        """Optional: run the plan (or the removal) and return the settings of the new login.

        Idempotent: steps that are already as needed are ``unchanged``. Raise
        :class:`UntrustedHostKey` / :class:`UntrustedCertificate` when the presented
        fingerprint is not ``request.trust``.
        """
        raise NotImplementedError

    # fix it (#215): optional, needs admin_login ------------------------------------------

    @classmethod
    async def plan_remedy(cls, request: RemedyRequest) -> SetupPlan:
        """Optional: what *Fix it* with ``request.remedy`` would do; nothing is changed.

        The same rules as :meth:`plan_setup`: pinned channel first, no secret in any text.
        Only what Signalbox's own setup owns (packages, permissions), never network settings.
        """
        raise NotImplementedError

    @classmethod
    async def apply_remedy(cls, request: RemedyRequest) -> SetupResult:
        """Optional: run the remedy; steps that are already as needed are ``unchanged``.

        Returns no settings: the device keeps its login."""
        raise NotImplementedError

    # path traces (#253): optional, declared by Manifest.traces -----------------------------

    async def trace(
        self, target: IPv4Address | IPv6Address, max_hops: int, wait: float
    ) -> TraceAnswer:
        """Optional: run a traceroute from the device to ``target`` and return its hops.

        Called only while path traces are on, on a stored device with its stored login, with
        the context's timeout for the whole trace. Send nothing but the traceroute (no DNS
        lookups on the device: numeric output), at most ``max_hops`` hops and one probe per
        hop, waiting ``wait`` seconds per hop. Raise :class:`AuthFailed` (with ``fix`` and
        ``remedy`` where *Fix it* can add the permission) when the login may not run it,
        :class:`AdapterError` for anything else. Return raw hops: core matches them.
        """
        raise NotImplementedError

    async def _call(self, fn: Callable[[], Any]) -> Any:
        return await asyncio.wait_for(fn(), timeout=self.context.timeout)

    async def observe(self) -> Snapshot:
        """Read the device (``read_system`` and the capabilities) into a snapshot. The
        certificate the HTTPS helper saw during its pinning handshake goes to
        ``Device.certificate`` (#174), whichever integration did the reading."""
        with certificates.collecting() as seen:
            snap = await self._observe()
        if not seen:
            return snap
        (host, _port), der = next(iter(seen.items()))
        try:
            info = certificates.describe(der, snap.device.management_address or host)
        except ValueError:  # a certificate the parser cannot read: no card, no checks
            return snap
        from signalbox.adapters.https import normalise_fingerprint  # https imports this module

        pinned = self.context.pinned_fingerprint
        trusted = pinned is not None and info.fingerprint_sha256 == normalise_fingerprint(pinned)
        info = info.model_copy(update={"trusted": trusted})
        return snap.model_copy(
            update={"device": snap.device.model_copy(update={"certificate": info})}
        )

    async def _observe(self) -> Snapshot:
        ctx = self.context
        now = datetime.now(UTC)
        source = Source(adapter=self.manifest.id, device_id=ctx.device_id)
        status = DeviceStatus.OK
        errors: list[ReadError] = []
        info = SystemInfo()
        reads: list[Observation] = []
        health: dict[str, DeviceHealth] = {}
        times: dict[str, DeviceTime] = {}
        logs: dict[str, list[LogTarget]] = {}
        accounts: dict[str, list[DeviceAccount]] = {}
        stp: dict[str, list[StpBridge]] = {}
        defaults: dict[str, bool] = {}
        privileges: dict[str, AccountPrivilege] = {}
        try:
            info = await self._call(self.read_system)
        except UntrustedCertificate as exc:
            self.presented_fingerprint = exc.fingerprint
            status, errors = DeviceStatus.UNTRUSTED, [self._error("system", exc)]
        except AuthFailed as exc:
            status, errors = DeviceStatus.AUTH_FAILED, [self._error("system", exc)]
        except (AdapterError, TimeoutError, OSError) as exc:
            status, errors = DeviceStatus.UNREACHABLE, [self._error("system", exc)]
        else:
            for cap in sorted(self.manifest.capabilities):
                method = getattr(self, PROTOCOLS[cap][1])
                start = datetime.now(UTC)
                try:
                    result = await self._call(method)
                except (AdapterError, TimeoutError, OSError) as exc:
                    errors.append(self._error(cap.value, exc))
                    continue
                if not isinstance(result, Observation):
                    raise AdapterContractError(
                        f"{self.manifest.id}.{PROTOCOLS[cap][1]} returned "
                        f"{type(result).__name__}, not Observation"
                    )
                reads.append(result)
                errors.extend(
                    ReadError(
                        device_id=ctx.device_id,
                        capability=cap.value,
                        message=gap.message,
                        fix=gap.fix,
                        message_id=gap.message_id,
                        fix_id=gap.fix_id,
                        params=gap.params,
                        remedy=gap.remedy,
                        optional=gap.optional,
                    )
                    for gap in result.incomplete
                )
                end = datetime.now(UTC)
                for key, value in result.health.items():
                    health[key] = _complete_health(value, now)
                for key, tvalue in result.time.items():
                    times[key] = _complete_time(tvalue, start, end)
                for key, targets in result.log_targets.items():
                    logs.setdefault(key, []).extend(targets)
                for key, users in result.accounts.items():
                    accounts.setdefault(key, []).extend(users)
                for key, bridges in result.stp_bridges.items():
                    stp.setdefault(key, []).extend(bridges)
                for key, flag in result.default_credentials.items():
                    defaults[key] = defaults.get(key, False) or flag
                privileges.update(result.signalbox_privilege)
            if any(not e.optional for e in errors):
                status = DeviceStatus.PARTIAL

        device = Device(
            id=ctx.device_id,
            site_id=ctx.site_id,
            name=ctx.device_name,
            role=ctx.role,
            adapter=self.manifest.id,
            capabilities=sorted(c.value for c in self.manifest.capabilities),
            source=source,
            observed_at=now,
            **info.model_dump(exclude_none=True, exclude={"firmware"}),
            firmware=info.firmware,
            health=health.get(ctx.device_id),
            time=times.get(ctx.device_id),
            log_targets=logs.get(ctx.device_id),
            accounts=accounts.get(ctx.device_id),
            stp_bridges=stp.get(ctx.device_id),
            default_credentials=defaults.get(ctx.device_id),
            signalbox_account_privilege=privileges.get(ctx.device_id),
            signalbox_account_needed=self.manifest.least_privilege,
        )
        skip = {
            "devices",
            "device_status",
            "health",
            "time",
            "log_targets",
            "accounts",
            "stp_bridges",
            "default_credentials",
            "signalbox_privilege",
            "incomplete",
        }
        lists: dict[str, list[Any]] = {n: [] for n in Observation.model_fields if n not in skip}
        extra: dict[str, Device] = {}
        extra_status: dict[str, DeviceStatus] = {}
        for obs in reads:
            for name in lists:
                lists[name].extend(_stamp(o, source, now) for o in getattr(obs, name))
            for d in obs.devices:
                extra.setdefault(
                    d.id,
                    d.model_copy(
                        update={
                            "site_id": ctx.site_id,
                            "adapter": self.manifest.id,
                            "managed_by": ctx.device_id,
                            "source": source,
                            "observed_at": now,
                            "health": health.get(d.id, d.health),
                            "time": times.get(d.id, d.time),
                            "log_targets": logs.get(d.id, d.log_targets),
                            "accounts": accounts.get(d.id, d.accounts),
                            "stp_bridges": stp.get(d.id, d.stp_bridges),
                            "default_credentials": defaults.get(d.id, d.default_credentials),
                            "signalbox_account_privilege": privileges.get(
                                d.id, d.signalbox_account_privilege
                            ),
                        }
                    ),
                )
            extra_status.update(obs.device_status)
        lists["fdb"], dropped = _cap_fdb(lists["fdb"])
        if dropped:
            errors.append(
                ReadError(
                    device_id=ctx.device_id,
                    capability=Capability.CLIENTS.value
                    if Capability.CLIENTS in self.manifest.capabilities
                    else Capability.INTERFACES.value,
                    message=f"the MAC address table has {dropped} more entries than the "
                    f"{FDB_LIMIT} Signalbox keeps per device; the newest are kept",
                    optional=True,
                )
            )
        return Snapshot(
            device=device,
            observed_at=now,
            status=status,
            errors=errors,
            extra_devices=sorted(extra.values(), key=lambda d: d.id),
            extra_status={k: v for k, v in extra_status.items() if k in extra},
            **lists,
        )

    def _error(self, capability: str, exc: BaseException) -> ReadError:
        message = str(exc) or type(exc).__name__
        message_id = getattr(exc, "message_id", None)
        params: MessageParams = dict(getattr(exc, "params", None) or {})
        if isinstance(exc, TimeoutError):
            message = f"no answer within {self.context.timeout:g} s"
            message_id = "read.timeout"
            params = {"seconds": f"{self.context.timeout:g}"}
        return ReadError(
            device_id=self.context.device_id,
            capability=capability,
            message=message,
            message_id=message_id,
            params=params,
            fix=getattr(exc, "fix", None),
            fix_id=getattr(exc, "fix_id", None),
            remedy=getattr(exc, "remedy", None),
        )


def _cap_fdb(entries: list[FdbEntry]) -> tuple[list[FdbEntry], int]:
    """At most :data:`FDB_LIMIT` entries per device (#160): the device's own and static ones
    first, then the most recently refreshed; the number dropped."""
    per: dict[str, list[FdbEntry]] = {}
    for e in entries:
        per.setdefault(e.device_id, []).append(e)
    kept: list[FdbEntry] = []
    dropped = 0
    for group in per.values():
        if len(group) > FDB_LIMIT:
            group = sorted(
                group,
                key=lambda e: (
                    e.kind is FdbKind.DYNAMIC,
                    e.age_seconds if e.age_seconds is not None else 0,
                ),
            )
            dropped += len(group) - FDB_LIMIT
            group = group[:FDB_LIMIT]
        kept += group
    return kept, dropped


def probes_hosts(cls: type[Adapter]) -> bool:
    """The integration has its own :meth:`Adapter.discover`."""
    return cls.discover.__func__ is not Adapter.discover.__func__  # type: ignore[attr-defined]


def probes_broadcast(cls: type[Adapter]) -> bool:
    """The integration has its own :meth:`Adapter.discover_broadcast`."""
    own = cls.discover_broadcast.__func__  # type: ignore[attr-defined]
    return own is not Adapter.discover_broadcast.__func__  # type: ignore[attr-defined]


def provisions(cls: type[Adapter]) -> bool:
    """The integration can set itself up with an admin login (#231)."""
    return cls.manifest.admin_login is not None


def remedies(cls: type[Adapter]) -> dict[str, Remedy]:
    """The integration's *Fix it* remedies by id (#215)."""
    return {r.id: r for r in cls.manifest.remedies}


def traces(cls: type[Adapter]) -> bool:
    """The integration can run traceroutes on its devices (#253)."""
    return cls.manifest.traces is not None


def _overrides(cls: type[Adapter], name: str) -> bool:
    own = getattr(cls, name).__func__
    return bool(own is not getattr(Adapter, name).__func__)


def _version(text: str) -> tuple[int, ...]:
    try:
        return tuple(int(part) for part in text.split("."))
    except ValueError:
        raise AdapterContractError(f"not an adapter API version: {text!r}") from None


def check_manifest(manifest: Manifest) -> None:
    wanted = _version(manifest.api_version)
    if wanted[0] != _version(API_VERSION)[0]:
        raise AdapterContractError(
            f"{manifest.id} was written for adapter API {manifest.api_version}, "
            f"this Signalbox provides {API_VERSION}"
        )
    for cap in sorted(manifest.capabilities):
        if cap in SINCE and wanted < _version(SINCE[cap]):
            raise AdapterContractError(
                f"{manifest.id} declares {cap.value}, which needs adapter API {SINCE[cap]}, "
                f"but was written for {manifest.api_version}"
            )


def check_setup(cls: type[Adapter]) -> None:
    """An integration that declares ``admin_login`` implements both setup hooks."""
    if traces(cls) and cls.trace is Adapter.trace:
        raise AdapterContractError(
            f"{cls.manifest.id} declares traces but does not implement trace"
        )
    if provisions(cls) and not (_overrides(cls, "plan_setup") and _overrides(cls, "apply_setup")):
        raise AdapterContractError(
            f"{cls.manifest.id} declares admin_login but does not implement plan_setup and "
            "apply_setup"
        )
    if cls.manifest.remedies:
        if not provisions(cls):
            raise AdapterContractError(f"{cls.manifest.id} declares remedies but no admin_login")
        if not (_overrides(cls, "plan_remedy") and _overrides(cls, "apply_remedy")):
            raise AdapterContractError(
                f"{cls.manifest.id} declares remedies but does not implement plan_remedy and "
                "apply_remedy"
            )
        if len(remedies(cls)) != len(cls.manifest.remedies):
            raise AdapterContractError(f"{cls.manifest.id} declares a remedy id twice")


def load_adapters(group: str = "signalbox.adapters") -> dict[str, type[Adapter]]:
    """All installed adapters by id. Broken or incompatible ones raise, loudly."""
    found: dict[str, type[Adapter]] = {}
    for ep in entry_points(group=group):
        cls = ep.load()
        if not (isinstance(cls, type) and issubclass(cls, Adapter)):
            raise AdapterContractError(f"entry point {ep.name} is not an Adapter subclass")
        check_manifest(cls.manifest)
        check_setup(cls)
        if cls.manifest.id in found:
            raise AdapterContractError(f"two adapters with id {cls.manifest.id}")
        found[cls.manifest.id] = cls
    return found
