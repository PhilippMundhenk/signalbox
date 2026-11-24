"""Small "plus"-managed switches: NETGEAR ProSAFE Plus (NSDP), TP-Link Easy Smart.

Both protocols are spoken by `Switchyard <https://github.com/PhilippMundhenk/switchyard>`_,
installed with the optional extra ``signalbox-net[switches]`` (docs/adr/0003). Switchyard is
imported only when a switch is read, so Signalbox works without it; a switch then reports
"could not be read" with the install hint.

Both are UDP protocols without TLS: the switches have no certificate, and the password crosses
the network obfuscated, not encrypted. Signalbox therefore has to sit in the switch's own
network; see docs/adapters/plusswitch.md.

One observation is one short session: find the switch at its address, check the password
(a write that changes nothing, as the vendor tools do), read identity, ports, VLANs and link
aggregation, close the socket. The UDP client ports are fixed by the protocols, so sessions on
the same port take turns.

Port changes (802.1Q membership and PVIDs, :mod:`signalbox.adapters.plusswitch.writes`) use the
same kind of session and the same safeguard against resending a refused password.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import struct
import time
import weakref
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from ipaddress import IPv4Address
from typing import Any, ClassVar, TypeVar

from pydantic import Field, SecretStr, field_validator

from signalbox.adapters import (
    Adapter,
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
    Unreachable,
    VendorCall,
)
from signalbox.adapters.plusswitch import discovery as _discovery
from signalbox.adapters.plusswitch import mapping, writes
from signalbox.changes import Change, ChangeKind
from signalbox.discovery import BroadcastResult, NetworkProbe
from signalbox.factory_defaults import is_factory_default
from signalbox.model import (
    SERVICE_PORTS,
    AccountPrivilege,
    DeviceAccount,
    DeviceRole,
    ManagementService,
    ServiceKind,
    StpBridge,
    StpProtocol,
    object_id,
)

_T = TypeVar("_T")

__all__ = ["EasySmartAdapter", "EasySmartConfig", "ProsafeAdapter", "ProsafeConfig"]

INSTALL_HINT = (
    "this adapter needs Switchyard: install signalbox-net[switches] "
    "(the container image includes it)"
)
#: how long a password the switch refused is not sent again (NSDP locks after 3 failures
#: for 30 minutes)
REFUSED_FOR = 30 * 60.0

log = logging.getLogger(__name__)


def _address(value: str) -> str:
    try:
        ip = IPv4Address(value.strip())
    except ValueError:
        raise ValueError("enter the switch's IPv4 address, for example 192.0.2.10") from None
    if ip.is_multicast or ip.is_unspecified or ip == IPv4Address("255.255.255.255"):
        raise ValueError("enter the switch's own (unicast) IPv4 address")
    return str(ip)


class ProsafeConfig(AdapterConfig):
    address: str = Field(description="IPv4 address of the switch, for example 192.0.2.10")
    password: SecretStr | None = Field(
        default=None,
        description="The switch's management password. Only needed to deploy changes: NETGEAR "
        "switches are read without logging in. Sent obfuscated, not encrypted.",
    )

    @field_validator("address")
    @classmethod
    def _unicast(cls, value: str) -> str:
        return _address(value)


class EasySmartConfig(AdapterConfig):
    address: str = Field(description="IPv4 address of the switch, for example 192.0.2.11")
    username: str = Field(default="admin", description="the switch's user name")
    password: SecretStr = Field(description="the switch's password; sent obfuscated, not encrypted")

    @field_validator("address")
    @classmethod
    def _unicast(cls, value: str) -> str:
        return _address(value)


@dataclass
class _Reading:
    """Everything one session read."""

    info: dict[str, Any]
    ports: list[dict[str, Any]] = field(default_factory=list)
    vlan: dict[str, Any] | None = None
    lag: dict[str, Any] | None = None
    #: speed and flow-control settings per port (``read_port_admin``), None if not answered
    admin: dict[int, dict[str, Any]] | None = None
    #: why ports/VLANs could not be read (the identity could)
    error: AdapterError | None = None
    #: optional parts the switch refused to read (old firmware protects some settings)
    skipped: list[str] = field(default_factory=list)
    #: loop detection / loop prevention on (#155); None: not answered
    loop_detection: bool | None = None


# -- sessions take turns per UDP port; refused passwords are not resent ------------------

_LOCKS: weakref.WeakKeyDictionary[asyncio.AbstractEventLoop, dict[tuple[str, int], asyncio.Lock]]
_LOCKS = weakref.WeakKeyDictionary()
_REFUSED: dict[tuple[str, str, str], float] = {}


def _port_lock(protocol: str, port: int) -> asyncio.Lock:
    locks = _LOCKS.setdefault(asyncio.get_running_loop(), {})
    return locks.setdefault((protocol, port), asyncio.Lock())


def _secret_key(username: str, password: str) -> str:
    return hashlib.sha256(f"{username}\0{password}".encode()).hexdigest()


def _translate(exc: BaseException, errors: Any, address: str) -> AdapterError:
    """Switchyard's exceptions → Signalbox's (``errors`` is ``switchyard.drivers.base``)."""
    if isinstance(exc, AdapterError):
        return exc
    if isinstance(exc, errors.AuthError):
        return AuthFailed(
            f"{address}: {exc}",
            fix="Check the switch's management password in the device settings (the one of "
            "its web interface). The switch locks after a few wrong tries; Signalbox does not "
            "resend a refused password for a while.",
            message_id="plusswitch.authFailed",
            fix_id="plusswitch.authFailed.fix",
            params={"address": address, "cause": str(exc)},
        )
    if isinstance(exc, errors.Unreachable | TimeoutError):
        return Unreachable(
            f"{address}: the switch does not answer",
            message_id="plusswitch.noAnswer",
            params={"address": address},
        )
    if isinstance(exc, errors.SwitchError):
        tag = getattr(exc, "tag", 0)
        if tag and getattr(exc, "status", None) in (7, 9, 13, 14):  # NSDP "password" answers
            from switchyard.nsdp import tags

            name = tags.NAMES.get(tag, f"0x{tag:04x}")
            return AdapterError(
                f"{address}: the switch refuses to read the setting {name!r} without a "
                f"password ({exc})",
                fix="Older NETGEAR firmware protects some settings even for reading. Enter "
                "the switch's management password in the device settings, or report the "
                "model and firmware so the setting can be skipped.",
                message_id="plusswitch.needsPassword",
                fix_id="plusswitch.needsPassword.fix",
                params={"address": address, "setting": name, "cause": str(exc)},
            )
        return AdapterError(
            f"{address}: {exc}",
            message_id="plusswitch.error",
            params={"address": address, "detail": str(exc)},
        )
    return AdapterError(
        f"{address}: unexpected answer from the switch ({type(exc).__name__})",
        message_id="plusswitch.badAnswer",
        params={"address": address, "detail": type(exc).__name__},
    )


#: what a garbled answer raises inside Switchyard's parsers
_PARSE_ERRORS = (ValueError, IndexError, KeyError, TypeError, struct.error, UnicodeError)


class _PlusSwitch(Adapter):
    """One session per observation; read_system reads everything, read_interfaces maps it."""

    protocol: ClassVar[str]
    #: the switch's own UDP protocol as a management service: its name and port
    service_name: ClassVar[str]
    service_port: ClassVar[int]
    vendor: ClassVar[str]

    def __init__(self, context: AdapterContext) -> None:
        super().__init__(context)
        self._reading: _Reading | None = None
        self._info: dict[str, Any] = {}  # the identity read of the current session
        self._errors: Any = None  # switchyard.drivers.base, once imported

    @property
    def _username(self) -> str:
        return ""

    @property
    def _password(self) -> str:
        cfg = self.context.config
        assert isinstance(cfg, ProsafeConfig | EasySmartConfig)
        return cfg.password.get_secret_value() if cfg.password is not None else ""

    @property
    def _host(self) -> str:
        cfg = self.context.config
        assert isinstance(cfg, ProsafeConfig | EasySmartConfig)
        return cfg.address

    def _option(self, name: str, default: int) -> int:
        """Ports (and the simulator's RSA key) can be changed through the context, for tests."""
        return int(self.context.extra.get(name, default))

    @property
    def _request_timeout(self) -> float:
        """Per UDP request; several requests (with retries) fit into the read timeout."""
        return max(0.2, min(1.5, self.context.timeout / 8))

    def _switchyard(self) -> Any:
        try:
            import switchyard.drivers.base as errors
        except ImportError:
            raise AdapterError(INSTALL_HINT, message_id="plusswitch.install") from None
        self._errors = errors
        return errors

    async def _with_switch(self, work: Callable[[Any], Awaitable[_T]], *, login: bool = True) -> _T:
        """One session: find the switch, check the password (``login``; switches that can be
        read without one skip it for reads), run ``work`` with the client."""
        errors = self._switchyard()
        client_port = self._client_port()
        async with _port_lock(self.protocol, client_port):
            try:
                return await self._session(client_port, work, login)
            except (errors.SwitchError, errors.Unreachable, TimeoutError, *_PARSE_ERRORS) as exc:
                raise _translate(exc, errors, self._host) from exc
            except OSError as exc:
                raise AdapterError(
                    f"cannot use UDP port {client_port}: {exc}",
                    message_id="plusswitch.udpPort",
                    params={"port": client_port, "detail": str(exc)},
                ) from exc

    async def read_system(self) -> SystemInfo:
        self._reading = await self._with_switch(self._read_all, login=False)
        return mapping.system_info(self._reading.info, self.vendor, self._host)

    async def read_interfaces(self) -> Observation:
        reading = self._reading
        if reading is None:
            raise AdapterError("read_system has not run")
        if reading.error is not None:
            raise reading.error
        try:
            observed = mapping.interfaces(
                self.context.device_id,
                self.context.site_id,
                reading.ports,
                reading.vlan,
                reading.lag,
                reading.admin,
            )
            gaps = [
                Gap(
                    message=f"{self._host}: the switch did not give its {what} without a "
                    "password; ports are read, the checks that need them are incomplete",
                    fix='This firmware answers these reads only with "incorrect password"; '
                    "Signalbox reads without logging in, as Switchyard does. A newer firmware "
                    "for the switch may answer them. Until then the VLAN and link checks for "
                    "this switch are incomplete; acknowledge them if that is fine.",
                    message_id="plusswitch.skipped",
                    fix_id="plusswitch.skipped.fix",
                    params={"host": self._host, "what": what},
                )
                for what in reading.skipped
            ]
        except (ValueError, TypeError, AttributeError) as exc:
            raise AdapterError(
                f"{self._host}: unexpected port or VLAN answer: {exc}",
                message_id="plusswitch.badPorts",
                params={"host": self._host, "detail": str(exc)},
            ) from exc
        return observed.model_copy(
            update={
                "services": self._services(),
                "incomplete": gaps,
                "stp_bridges": self._stp(reading),
                **self._login_facts(),
            }
        )

    def _login_facts(self) -> dict[str, Any]:
        """The switch has one management login (#126, #175): whether the configured
        password is the factory one, compared here in memory (no extra login is ever tried),
        and that it can change everything. Nothing without a configured password."""
        if not self._password:
            return {}
        d = self.context.device_id
        default = is_factory_default(self.manifest.id, self._password, self._username or None)
        out: dict[str, Any] = {
            "default_credentials": {d: default},
            "signalbox_privilege": {d: AccountPrivilege.ADMIN},
        }
        if self._username:
            out["accounts"] = {
                d: [
                    DeviceAccount(
                        name=self._username,
                        privilege=AccountPrivilege.ADMIN,
                        password_set=True,
                        is_signalbox=True,
                    )
                ]
            }
        return out

    def _services(self) -> list[ManagementService]:
        """Management services (#173), fixed by the product line and not read from the
        switch: its own UDP protocol (NSDP, Easy Smart) and the web interface on port 80
        (most models have no HTTPS). Both are always on and unencrypted."""
        d = self.context.device_id
        return [
            ManagementService(
                id=object_id(d, "service", self.service_name),
                device_id=d,
                kind=ServiceKind.VENDOR,
                name=self.service_name,
                enabled=True,
                port=self.service_port,
                encrypted=False,
            ),
            ManagementService(
                id=object_id(d, "service", "http"),
                device_id=d,
                kind=ServiceKind.HTTP,
                name="http",
                enabled=True,
                port=SERVICE_PORTS[ServiceKind.HTTP],
            ),
        ]

    # -- writes (802.1Q port membership) -----------------------------------------------------

    async def plan_changes(
        self, changes: list[Change], secrets: Mapping[str, str]
    ) -> list[VendorCall]:
        return writes.plan(self.context.device_id, self._host, changes)

    async def _table(self, client: Any) -> writes.Table:
        return writes.Table.read(await self._read_vlan(client), self._host)

    async def _write_table(self, client: Any, table: writes.Table) -> None:
        try:
            await client.apply_dot1q(table.rows(), table.pvid)
        except ValueError as exc:  # Switchyard's checks before anything is written
            raise AdapterError(
                f"{self._host}: VLAN table refused: {exc}",
                message_id="plusswitch.vlanRefused",
                params={"host": self._host, "detail": str(exc)},
            ) from exc

    async def backup(self) -> Backup:
        table = await self._with_switch(self._table)  # part of a change: password checked
        return Backup(
            device_id=self.context.device_id,
            taken_at=datetime.now(UTC),
            format=writes.BACKUP_FORMAT,
            content=table.to_json(),
        )

    async def apply(
        self, changes: list[Change], secrets: Mapping[str, str], rollback_seconds: int
    ) -> ApplyResult:
        calls = writes.plan(self.context.device_id, self._host, changes)

        async def work(client: Any) -> None:
            table = await self._table(client)
            ports = len(await client.read_ports())
            target = writes.apply(table, self.context.device_id, changes, ports)
            if target != table:
                await self._write_table(client, target)

        await self._with_switch(work)
        return ApplyResult(calls=calls)

    async def confirm(self) -> None:
        """Nothing to do: these switches have no rollback timer."""

    async def restore(self, backup: Backup) -> None:
        if backup.format != writes.BACKUP_FORMAT:
            raise AdapterError(f"cannot restore a backup in the format {backup.format!r}")
        wanted = writes.Table.from_json(backup.content)

        async def work(client: Any) -> None:
            if await self._table(client) != wanted:
                await self._write_table(client, wanted)

        await self._with_switch(work)

    def _client_port(self) -> int:
        raise NotImplementedError

    async def _session(
        self, client_port: int, work: Callable[[Any], Awaitable[_T]], login: bool
    ) -> _T:
        raise NotImplementedError

    async def _read_vlan(self, client: Any) -> Any:
        return await client.read_vlan()

    async def _read_all(self, client: Any) -> _Reading:
        reading = _Reading(info=await client.read_info())

        async def vlan() -> Any:
            return await self._read_vlan(client)

        await self._read_rest(reading, client.read_ports, vlan, client.read_lag)
        await self._read_admin(reading, client)
        await self._read_features(reading, client)
        return reading

    async def _login(self, login: Callable[[], Awaitable[None]]) -> None:
        """Check the password once, but never resend one the switch already refused."""
        key = (self.protocol, f"{self._host}:{self._device_port()}", self._secret)
        refused = _REFUSED.get(key)
        if refused is not None and time.monotonic() - refused < REFUSED_FOR:
            raise AuthFailed(
                f"{self._host}: the switch refused this password; not sent again for "
                f"{REFUSED_FOR / 60:.0f} minutes so that the switch does not lock (change "
                "the password in the device settings to try again)",
                message_id="plusswitch.passwordRefused",
                params={"host": self._host, "minutes": f"{REFUSED_FOR / 60:.0f}"},
            )
        try:
            await login()
        except Exception as exc:
            if isinstance(_translate(exc, self._errors, self._host), AuthFailed):
                _REFUSED[key] = time.monotonic()
            raise
        _REFUSED.pop(key, None)

    @property
    def _secret(self) -> str:
        return _secret_key(self._username, self._password)

    def _device_port(self) -> int:
        raise NotImplementedError

    async def _read_rest(
        self,
        reading: _Reading,
        ports: Callable[[], Awaitable[Any]],
        vlan: Callable[[], Awaitable[Any]],
        lag: Callable[[], Awaitable[Any]],
    ) -> None:
        """Ports, VLANs and LAGs; a failure here leaves the identity usable.

        VLANs and LAGs are optional: old NETGEAR firmware answers some of these reads with
        "incorrect password" even when read without one; the ports are kept then.
        """
        errors = self._errors
        try:
            reading.ports = list(await ports())
        except (errors.SwitchError, errors.Unreachable, *_PARSE_ERRORS) as exc:
            reading.error = _translate(exc, errors, self._host)
            return
        for name, read in (("VLANs", vlan), ("link aggregation", lag)):
            try:
                value = await read()
            except errors.Unreachable as exc:
                reading.error = _translate(exc, errors, self._host)
                return
            except (errors.SwitchError, *_PARSE_ERRORS) as exc:
                log.info("%s: %s not read: %s", self._host, name, exc)
                reading.skipped.append(name)
                continue
            if name == "VLANs":
                reading.vlan = value
            else:
                reading.lag = value

    async def _read_features(self, reading: _Reading, client: Any) -> None:
        """Loop detection (NETGEAR) or loop prevention (TP-Link), read through Switchyard's
        ``read_features`` (#155): optional, the rest stands without."""
        if reading.error is not None:
            return
        try:
            features = await client.read_features()
        except (self._errors.SwitchError, self._errors.Unreachable, *_PARSE_ERRORS):
            return
        loop = features.get("loop_detection") if isinstance(features, Mapping) else None
        reading.loop_detection = loop if isinstance(loop, bool) else None

    def _stp(self, reading: _Reading) -> dict[str, list[StpBridge]]:
        """These switches have no spanning tree: the whole switch is one bridge with loop
        detection on or nothing (#155). Nothing when the switch did not say."""
        if reading.loop_detection is None:
            return {}
        proto = StpProtocol.LOOP_DETECT if reading.loop_detection else StpProtocol.NONE
        return {self.context.device_id: [StpBridge(name="switch", protocol=proto)]}

    async def _read_admin(self, reading: _Reading, client: Any) -> None:
        """Port settings (enabled, speed, flow control): optional, the rest stands without."""
        if reading.error is not None:
            return
        try:
            admin = await client.read_port_admin()
        except (self._errors.SwitchError, self._errors.Unreachable, *_PARSE_ERRORS):
            return
        reading.admin = dict(admin) if isinstance(admin, Mapping) else None


#: Shown in the device form ("Before you add it").
PLUSSWITCH_STEPS = (
    (
        "Signalbox must be in the same network as the switch (it talks UDP broadcast; in Docker"
        " use host networking, see the setup guide)."
    ),
    (
        "Below: the switch's IPv4 address. NETGEAR switches are read without a password; "
        "enter it only to deploy changes (TP-Link Easy Smart needs user and password). "
        "Then Test connection."
    ),
)


class ProsafeAdapter(_PlusSwitch):
    protocol = "nsdp"
    service_name = "nsdp"
    service_port = 63322
    vendor = "NETGEAR"
    manifest = Manifest(
        setup_steps=PLUSSWITCH_STEPS,
        setup_url="https://github.com/PhilippMundhenk/signalbox/blob/main/docs/adapters/plusswitch.md#settings",
        id="prosafe",
        least_privilege=AccountPrivilege.ADMIN,
        name="NETGEAR ProSAFE Plus",
        version="0.2.0",
        api_version="1.0",
        vendor="NETGEAR",
        roles=frozenset({DeviceRole.SWITCH}),
        capabilities=frozenset({Capability.INTERFACES}),
        config=ProsafeConfig,
        writes=frozenset({ChangeKind.PORT}),
        description="GS105E, GS108E, GS116E and other Plus switches over NSDP (UDP), "
        "through Switchyard",
    )

    @classmethod
    async def discover_broadcast(cls, probe: NetworkProbe) -> BroadcastResult | None:
        """The NSDP identity broadcast (no password)."""
        return await _discovery.prosafe(probe, _port_lock)

    def _client_port(self) -> int:
        from switchyard.nsdp.transport import CLIENT_PORT

        return self._option("client_port", CLIENT_PORT)

    def _device_port(self) -> int:
        from switchyard.nsdp.transport import DEVICE_PORT

        return self._option("device_port", DEVICE_PORT)

    async def _identify(self, client: Any, identity: Mapping[str, Any]) -> dict[str, Any]:
        """The full identity read; if the switch refuses it (old firmware answers some
        settings with "incorrect password" when read without one), the discovery answer."""
        try:
            info: dict[str, Any] = await client.read_info()
            return info
        except self._errors.SwitchError as exc:
            from switchyard.nsdp.client import _ports_from_model

            log.info("%s: identity read refused (%s); using the discovery answer", self._host, exc)
            model = str(identity.get("model") or "")
            client.model = model
            client.ports = client.ports or _ports_from_model(model)
            return {**identity, "ports": client.ports}

    async def _read_all(self, client: Any) -> _Reading:
        reading = _Reading(info=self._info)

        async def vlan() -> Any:
            return await self._read_vlan(client)

        await self._read_rest(reading, client.read_ports, vlan, client.read_lag)
        await self._read_admin(reading, client)
        await self._read_features(reading, client)
        return reading

    async def _session(
        self, client_port: int, work: Callable[[Any], Awaitable[_T]], login: bool
    ) -> _T:
        from switchyard.nsdp import SwitchClient, Transport, parse_mac, probe

        timeout = self._request_timeout
        # As Switchyard runs against real switches: no fixed target, so the transport uses the
        # host's interfaces and puts a real interface MAC into every request (old firmware
        # answers requests with the broadcast MAC as sender with "incorrect password"); the
        # switch is still asked by unicast to its address. A fixed target only for the
        # simulator (tests set ``device_port``).
        simulated = "device_port" in self.context.extra
        transport = Transport(
            client_port=client_port,
            device_port=self._device_port(),
            targets=[f"{self._host}:{self._device_port()}"] if simulated else None,
            timeout=timeout,
            retries=2,
        )
        await transport.start()
        try:
            identity = await probe(transport, self._host, timeout)
            if identity is None:
                raise Unreachable(
                    f"{self._host}: no NETGEAR Plus switch answers (NSDP)",
                    message_id="plusswitch.noNetgear",
                    params={"host": self._host},
                )
            client = SwitchClient(transport, parse_mac(identity["mac"]), self._host)
            # like Switchyard: read the identity first; it tells the password scheme
            # (old firmware does not answer a lone password-scheme read reliably)
            self._info = await self._identify(client, identity)
            if login:  # NSDP reads need no password, only changes do
                if not self._password:
                    raise AuthFailed(
                        f"{self._host}: changing the switch needs its password",
                        fix="Enter the switch's management password in the device settings.",
                        message_id="plusswitch.changeNeedsPassword",
                        fix_id="plusswitch.changeNeedsPassword.fix",
                        params={"host": self._host},
                    )
                await self._login(lambda: client.login(self._password))
            return await work(client)
        finally:
            await transport.stop()


class EasySmartAdapter(_PlusSwitch):
    protocol = "easysmart"
    service_name = "easy-smart"
    service_port = 29808
    vendor = "TP-Link"
    manifest = Manifest(
        setup_steps=PLUSSWITCH_STEPS,
        setup_url="https://github.com/PhilippMundhenk/signalbox/blob/main/docs/adapters/plusswitch.md#settings",
        id="easysmart",
        least_privilege=AccountPrivilege.ADMIN,
        name="TP-Link Easy Smart",
        version="0.2.0",
        api_version="1.0",
        vendor="TP-Link",
        roles=frozenset({DeviceRole.SWITCH}),
        capabilities=frozenset({Capability.INTERFACES}),
        config=EasySmartConfig,
        writes=frozenset({ChangeKind.PORT}),
        description="TL-SG105E, TL-SG108E, TL-SG108PE, TL-SG116E and other Easy Smart "
        "switches (UDP), through Switchyard",
    )

    @classmethod
    async def discover_broadcast(cls, probe: NetworkProbe) -> BroadcastResult | None:
        """The Easy Smart discovery broadcast (no password)."""
        return await _discovery.easysmart(probe, _port_lock)

    @property
    def _username(self) -> str:
        cfg = self.context.config
        assert isinstance(cfg, EasySmartConfig)
        return cfg.username

    def _client_port(self) -> int:
        from switchyard.easysmart.transport import CLIENT_PORT

        return self._option("client_port", CLIENT_PORT)

    def _device_port(self) -> int:
        from switchyard.easysmart.transport import DEVICE_PORT

        return self._option("device_port", DEVICE_PORT)

    async def _session(
        self, client_port: int, work: Callable[[Any], Awaitable[_T]], login: bool
    ) -> _T:
        from switchyard.easysmart.client import EasySmartClient, parse_identity
        from switchyard.easysmart.packet import RSA_MODULUS, Op
        from switchyard.easysmart.transport import EasySmartTransport
        from switchyard.nsdp.packet import parse_mac

        timeout = self._request_timeout
        transport = EasySmartTransport(
            client_port=client_port,
            targets=[f"{self._host}:{self._device_port()}"],
            timeout=timeout,
            retries=2,
        )
        await transport.start()
        try:
            replies = await transport.collect(Op.DISCOVERY, [], 2 * timeout)
            found = {
                packet.switch_mac: parse_identity(packet)
                for packet, addr in replies
                if addr[0] == self._host
            }
            if not found:
                raise Unreachable(
                    f"{self._host}: no TP-Link Easy Smart switch answers",
                    message_id="plusswitch.noTplink",
                    params={"host": self._host},
                )
            if len(found) > 1:
                raise AdapterError(
                    f"{self._host}: {len(found)} switches answer for this address",
                    message_id="plusswitch.several",
                    params={"host": self._host, "count": len(found)},
                )
            identity = next(iter(found.values()))
            client = EasySmartClient(
                transport,
                parse_mac(identity["mac"]),
                None,
                self._username,
                rsa_modulus=self._option("rsa_modulus", RSA_MODULUS),
            )
            await self._login(lambda: client.login(self._password, self._username))
            return await work(client)
        finally:
            await transport.stop()

    async def _read_vlan(self, client: Any) -> Any:
        async with client.lock:
            return await client.read_vlan()

    async def _read_all(self, client: Any) -> _Reading:
        reading = _Reading(info=await client.read_info())

        async def vlan() -> Any:
            return await self._read_vlan(client)

        async def lag() -> Any:
            async with client.lock:
                return await client.read_lag()

        await self._read_rest(reading, client.read_ports, vlan, lag)
        await self._read_admin(reading, client)
        await self._read_features(reading, client)
        return reading
