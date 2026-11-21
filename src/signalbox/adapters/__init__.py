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
from datetime import UTC, datetime
from enum import StrEnum
from importlib.metadata import entry_points
from typing import Any, ClassVar, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field

from signalbox.model import (
    Client,
    Device,
    DeviceRole,
    DeviceStatus,
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
    Wlan,
)

#: Version of this API. An adapter declares the version it was written for; the major part
#: must match.
API_VERSION = "1.0"


class Capability(StrEnum):
    INTERFACES = "interfaces"  # ports, segments (VLANs) and subnets
    DHCP = "dhcp"
    DNS = "dns"
    WIRELESS = "wireless"  # radios and WLANs
    CLIENTS = "clients"
    NEIGHBOURS = "neighbours"  # LLDP


class AdapterError(Exception):
    """A device could not be read; the message is shown to the user."""


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


class Observation(BaseModel):
    """What one capability read returns."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    ports: list[Port] = Field(default_factory=list)
    segments: list[Segment] = Field(default_factory=list)
    subnets: list[Subnet] = Field(default_factory=list)
    dhcp_servers: list[DhcpServer] = Field(default_factory=list)
    dns_services: list[DnsService] = Field(default_factory=list)
    radios: list[Radio] = Field(default_factory=list)
    wlans: list[Wlan] = Field(default_factory=list)
    clients: list[Client] = Field(default_factory=list)
    neighbours: list[Neighbour] = Field(default_factory=list)


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


PROTOCOLS: dict[Capability, tuple[type, str]] = {
    Capability.INTERFACES: (ReadsInterfaces, "read_interfaces"),
    Capability.DHCP: (ReadsDhcp, "read_dhcp"),
    Capability.DNS: (ReadsDns, "read_dns"),
    Capability.WIRELESS: (ReadsWireless, "read_wireless"),
    Capability.CLIENTS: (ReadsClients, "read_clients"),
    Capability.NEIGHBOURS: (ReadsNeighbours, "read_neighbours"),
}


def _stamp(obj: Observed, source: Source, when: datetime) -> Observed:
    update: dict[str, object] = {}
    if obj.source is None:
        update["source"] = source
    if obj.observed_at is None:
        update["observed_at"] = when
    return obj.model_copy(update=update) if update else obj


class Adapter(ABC):
    manifest: ClassVar[Manifest]

    def __init__(self, context: AdapterContext) -> None:
        if not isinstance(context.config, self.manifest.config):
            raise AdapterContractError(
                f"{self.manifest.id}: config must be {self.manifest.config.__name__}"
            )
        self.context = context
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
        try:
            info = await self._call(self.read_system)
        except UntrustedCertificate as exc:
            status, errors = DeviceStatus.UNTRUSTED, [self._error("system", exc)]
        except AuthFailed as exc:
            status, errors = DeviceStatus.AUTH_FAILED, [self._error("system", exc)]
        except (AdapterError, TimeoutError, OSError) as exc:
            status, errors = DeviceStatus.UNREACHABLE, [self._error("system", exc)]
        else:
            for cap in sorted(self.manifest.capabilities):
                method = getattr(self, PROTOCOLS[cap][1])
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
        )
        lists: dict[str, list[Any]] = {name: [] for name in Observation.model_fields}
        for obs in reads:
            for name in lists:
                lists[name].extend(_stamp(o, source, now) for o in getattr(obs, name))
        return Snapshot(device=device, observed_at=now, status=status, errors=errors, **lists)

    def _error(self, capability: str, exc: BaseException) -> ReadError:
        message = str(exc) or type(exc).__name__
        if isinstance(exc, TimeoutError):
            message = f"no answer within {self.context.timeout:g} s"
        return ReadError(device_id=self.context.device_id, capability=capability, message=message)


def check_manifest(manifest: Manifest) -> None:
    major = manifest.api_version.split(".")[0]
    if major != API_VERSION.split(".")[0]:
        raise AdapterContractError(
            f"{manifest.id} was written for adapter API {manifest.api_version}, "
            f"this Signalbox provides {API_VERSION}"
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
