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
from typing import Any, ClassVar, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field, JsonValue

from signalbox.changes import Change, ChangeKind
from signalbox.discovery import BroadcastResult, Candidate, HostProbe, NetworkProbe
from signalbox.model import (
    Client,
    Device,
    DeviceHealth,
    DeviceRole,
    DeviceStatus,
    DeviceTime,
    DhcpServer,
    DnsService,
    Firmware,
    Neighbour,
    Observed,
    Port,
    Radio,
    ReadError,
    Segment,
    Snapshot,
    Source,
    Subnet,
    Uplink,
    Wlan,
)

#: Version of this API. An adapter declares the version it was written for; the major part
#: must match.
API_VERSION = "1.2"


class Capability(StrEnum):
    INTERFACES = "interfaces"  # ports, segments (VLANs), subnets and uplinks
    DHCP = "dhcp"
    DNS = "dns"
    WIRELESS = "wireless"  # radios and WLANs
    CLIENTS = "clients"
    NEIGHBOURS = "neighbours"  # LLDP
    HEALTH = "health"  # uptime, CPU, memory, storage, sensors (API 1.2)
    TIME = "time"  # clock, time zone, NTP (API 1.2)


#: Adapter API version that introduced a capability (absent: 1.0). An adapter declaring a
#: capability must be written for at least that version.
SINCE: dict[Capability, str] = {Capability.HEALTH: "1.2", Capability.TIME: "1.2"}


class AdapterError(Exception):
    """A device could not be read; the message is shown to the user.

    ``fix``: what the user can do about it, in plain words (shown as "What to do").
    """

    def __init__(self, *args: object, fix: str | None = None) -> None:
        super().__init__(*args)
        self.fix = fix


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


class VendorCall(BaseModel):
    """One call an integration makes to apply a change; shown in the review before deploying."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    description: str
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
    #: Vendor fields of the device itself (MAC, serial, protocol details); shown on the
    #: device's advanced tab only, never read by rules.
    vendor_extra: dict[str, JsonValue] = Field(default_factory=dict)


class Observation(BaseModel):
    """What one capability read returns."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    ports: list[Port] = Field(default_factory=list)
    segments: list[Segment] = Field(default_factory=list)
    subnets: list[Subnet] = Field(default_factory=list)
    #: WAN connections of a gateway (#148), read with ``interfaces``; no API version needed.
    uplinks: list[Uplink] = Field(default_factory=list)
    dhcp_servers: list[DhcpServer] = Field(default_factory=list)
    dns_services: list[DnsService] = Field(default_factory=list)
    radios: list[Radio] = Field(default_factory=list)
    wlans: list[Wlan] = Field(default_factory=list)
    clients: list[Client] = Field(default_factory=list)
    neighbours: list[Neighbour] = Field(default_factory=list)
    #: Devices managed through the observed one (API 1.1). Ids must start with
    #: ``<device id>/``; site, adapter and ``managed_by`` are filled in by ``observe()``.
    devices: list[Device] = Field(default_factory=list)
    #: Reachability of those devices as the controller reports it.
    device_status: dict[str, DeviceStatus] = Field(default_factory=dict)
    #: Health per device id: the observed device or one of ``devices`` (API 1.2).
    health: dict[str, DeviceHealth] = Field(default_factory=dict)
    #: Clock and NTP per device id: the observed device or one of ``devices`` (API 1.2).
    time: dict[str, DeviceTime] = Field(default_factory=dict)


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


PROTOCOLS: dict[Capability, tuple[type, str]] = {
    Capability.INTERFACES: (ReadsInterfaces, "read_interfaces"),
    Capability.DHCP: (ReadsDhcp, "read_dhcp"),
    Capability.DNS: (ReadsDns, "read_dns"),
    Capability.WIRELESS: (ReadsWireless, "read_wireless"),
    Capability.CLIENTS: (ReadsClients, "read_clients"),
    Capability.NEIGHBOURS: (ReadsNeighbours, "read_neighbours"),
    Capability.HEALTH: (ReadsHealth, "read_health"),
    Capability.TIME: (ReadsTime, "read_time"),
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

    async def _call(self, fn: Callable[[], Any]) -> Any:
        return await asyncio.wait_for(fn(), timeout=self.context.timeout)

    async def observe(self) -> Snapshot:
        ctx = self.context
        now = datetime.now(UTC)
        source = Source(adapter=self.manifest.id, device_id=ctx.device_id)
        status = DeviceStatus.OK
        errors: list[ReadError] = []
        info = SystemInfo()
        reads: list[Observation] = []
        health: dict[str, DeviceHealth] = {}
        times: dict[str, DeviceTime] = {}
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
                end = datetime.now(UTC)
                for key, value in result.health.items():
                    health[key] = _complete_health(value, now)
                for key, tvalue in result.time.items():
                    times[key] = _complete_time(tvalue, start, end)
            if errors:
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
        )
        skip = {"devices", "device_status", "health", "time"}
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
                        }
                    ),
                )
            extra_status.update(obs.device_status)
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
        if isinstance(exc, TimeoutError):
            message = f"no answer within {self.context.timeout:g} s"
        return ReadError(
            device_id=self.context.device_id,
            capability=capability,
            message=message,
            fix=getattr(exc, "fix", None),
        )


def probes_hosts(cls: type[Adapter]) -> bool:
    """The integration has its own :meth:`Adapter.discover`."""
    return cls.discover.__func__ is not Adapter.discover.__func__  # type: ignore[attr-defined]


def probes_broadcast(cls: type[Adapter]) -> bool:
    """The integration has its own :meth:`Adapter.discover_broadcast`."""
    own = cls.discover_broadcast.__func__  # type: ignore[attr-defined]
    return own is not Adapter.discover_broadcast.__func__  # type: ignore[attr-defined]


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


def load_adapters(group: str = "signalbox.adapters") -> dict[str, type[Adapter]]:
    """All installed adapters by id. Broken or incompatible ones raise, loudly."""
    found: dict[str, type[Adapter]] = {}
    for ep in entry_points(group=group):
        cls = ep.load()
        if not (isinstance(cls, type) and issubclass(cls, Adapter)):
            raise AdapterContractError(f"entry point {ep.name} is not an Adapter subclass")
        check_manifest(cls.manifest)
        if cls.manifest.id in found:
            raise AdapterContractError(f"two adapters with id {cls.manifest.id}")
        found[cls.manifest.id] = cls
    return found
