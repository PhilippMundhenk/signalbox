"""Small "plus"-managed switches (read): NETGEAR ProSAFE Plus (NSDP), TP-Link Easy Smart.

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
"""

from __future__ import annotations

import asyncio
import hashlib
import struct
import time
import weakref
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from ipaddress import IPv4Address
from typing import Any, ClassVar

from pydantic import Field, SecretStr, field_validator

from signalbox.adapters import (
    Adapter,
    AdapterConfig,
    AdapterContext,
    AdapterError,
    AuthFailed,
    Capability,
    Manifest,
    Observation,
    SystemInfo,
    Unreachable,
)
from signalbox.adapters.plusswitch import mapping
from signalbox.model import DeviceRole

__all__ = ["EasySmartAdapter", "EasySmartConfig", "ProsafeAdapter", "ProsafeConfig"]

INSTALL_HINT = (
    "this adapter needs Switchyard: install signalbox-net[switches] "
    "(the container image includes it)"
)
#: how long a password the switch refused is not sent again (NSDP locks after 3 failures
#: for 30 minutes)
REFUSED_FOR = 30 * 60.0


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
    password: SecretStr = Field(
        description="the switch's management password; sent obfuscated, not encrypted"
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
    #: why ports/VLANs could not be read (the identity could)
    error: AdapterError | None = None


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
        return AuthFailed(f"{address}: {exc}")
    if isinstance(exc, errors.Unreachable | TimeoutError):
        return Unreachable(f"{address}: the switch does not answer")
    if isinstance(exc, errors.SwitchError):
        return AdapterError(f"{address}: {exc}")
    return AdapterError(f"{address}: unexpected answer from the switch ({type(exc).__name__})")


#: what a garbled answer raises inside Switchyard's parsers
_PARSE_ERRORS = (ValueError, IndexError, KeyError, TypeError, struct.error, UnicodeError)


class _PlusSwitch(Adapter):
    """One session per observation; read_system reads everything, read_interfaces maps it."""

    protocol: ClassVar[str]
    vendor: ClassVar[str]

    def __init__(self, context: AdapterContext) -> None:
        super().__init__(context)
        self._reading: _Reading | None = None
        self._errors: Any = None  # switchyard.drivers.base, once imported

    @property
    def _username(self) -> str:
        return ""

    @property
    def _password(self) -> str:
        cfg = self.context.config
        assert isinstance(cfg, ProsafeConfig | EasySmartConfig)
        return cfg.password.get_secret_value()

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

    async def read_system(self) -> SystemInfo:
        try:
            import switchyard.drivers.base as errors
        except ImportError:
            raise AdapterError(INSTALL_HINT) from None
        self._errors = errors
        client_port = self._client_port()
        async with _port_lock(self.protocol, client_port):
            try:
                self._reading = await self._session(client_port)
            except (errors.SwitchError, errors.Unreachable, TimeoutError, *_PARSE_ERRORS) as exc:
                raise _translate(exc, errors, self._host) from exc
            except OSError as exc:
                raise AdapterError(f"cannot use UDP port {client_port}: {exc}") from exc
        return mapping.system_info(self._reading.info, self.vendor, self._host)

    async def read_interfaces(self) -> Observation:
        reading = self._reading
        if reading is None:
            raise AdapterError("read_system has not run")
        if reading.error is not None:
            raise reading.error
        try:
            return mapping.interfaces(
                self.context.device_id,
                self.context.site_id,
                reading.ports,
                reading.vlan,
                reading.lag,
            )
        except (ValueError, TypeError, AttributeError) as exc:
            raise AdapterError(f"{self._host}: unexpected port or VLAN answer: {exc}") from exc

    def _client_port(self) -> int:
        raise NotImplementedError

    async def _session(self, client_port: int) -> _Reading:
        raise NotImplementedError

    async def _login(self, login: Callable[[], Awaitable[None]]) -> None:
        """Check the password once, but never resend one the switch already refused."""
        key = (self.protocol, f"{self._host}:{self._device_port()}", self._secret)
        refused = _REFUSED.get(key)
        if refused is not None and time.monotonic() - refused < REFUSED_FOR:
            raise AuthFailed(
                f"{self._host}: the switch refused this password; not sent again for "
                f"{REFUSED_FOR / 60:.0f} minutes so that the switch does not lock (change "
                "the password in the device settings to try again)"
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

    async def _read_rest(self, reading: _Reading, *reads: Callable[[], Awaitable[Any]]) -> None:
        """Ports, VLANs and LAGs; a failure here leaves the identity usable."""
        try:
            ports, vlan, lag = [await read() for read in reads]
        except (self._errors.SwitchError, self._errors.Unreachable, *_PARSE_ERRORS) as exc:
            reading.error = _translate(exc, self._errors, self._host)
            return
        reading.ports, reading.vlan, reading.lag = list(ports), vlan, lag


class ProsafeAdapter(_PlusSwitch):
    protocol = "nsdp"
    vendor = "NETGEAR"
    manifest = Manifest(
        id="prosafe",
        name="NETGEAR ProSAFE Plus",
        version="0.1.0",
        api_version="1.0",
        vendor="NETGEAR",
        roles=frozenset({DeviceRole.SWITCH}),
        capabilities=frozenset({Capability.INTERFACES}),
        config=ProsafeConfig,
        description="GS105E, GS108E, GS116E and other Plus switches over NSDP (UDP), "
        "through Switchyard",
    )

    def _client_port(self) -> int:
        from switchyard.nsdp.transport import CLIENT_PORT

        return self._option("client_port", CLIENT_PORT)

    def _device_port(self) -> int:
        from switchyard.nsdp.transport import DEVICE_PORT

        return self._option("device_port", DEVICE_PORT)

    async def _session(self, client_port: int) -> _Reading:
        from switchyard.nsdp import SwitchClient, Transport, parse_mac, probe

        timeout = self._request_timeout
        transport = Transport(
            client_port=client_port,
            targets=[f"{self._host}:{self._device_port()}"],
            timeout=timeout,
            retries=2,
        )
        await transport.start()
        try:
            identity = await probe(transport, self._host, timeout)
            if identity is None:
                raise Unreachable(f"{self._host}: no NETGEAR Plus switch answers (NSDP)")
            client = SwitchClient(transport, parse_mac(identity["mac"]), self._host)
            await self._login(lambda: client.login(self._password))
            reading = _Reading(info=await client.read_info())
            await self._read_rest(reading, client.read_ports, client.read_vlan, client.read_lag)
            return reading
        finally:
            await transport.stop()


class EasySmartAdapter(_PlusSwitch):
    protocol = "easysmart"
    vendor = "TP-Link"
    manifest = Manifest(
        id="easysmart",
        name="TP-Link Easy Smart",
        version="0.1.0",
        api_version="1.0",
        vendor="TP-Link",
        roles=frozenset({DeviceRole.SWITCH}),
        capabilities=frozenset({Capability.INTERFACES}),
        config=EasySmartConfig,
        description="TL-SG105E, TL-SG108E, TL-SG108PE, TL-SG116E and other Easy Smart "
        "switches (UDP), through Switchyard",
    )

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

    async def _session(self, client_port: int) -> _Reading:
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
                raise Unreachable(f"{self._host}: no TP-Link Easy Smart switch answers")
            if len(found) > 1:
                raise AdapterError(f"{self._host}: {len(found)} switches answer for this address")
            identity = next(iter(found.values()))
            client = EasySmartClient(
                transport,
                parse_mac(identity["mac"]),
                None,
                self._username,
                rsa_modulus=self._option("rsa_modulus", RSA_MODULUS),
            )
            await self._login(lambda: client.login(self._password, self._username))
            reading = _Reading(info=await client.read_info())

            async def vlan() -> Any:
                async with client.lock:
                    return await client.read_vlan()

            async def lag() -> Any:
                async with client.lock:
                    return await client.read_lag()

            await self._read_rest(reading, client.read_ports, vlan, lag)
            return reading
        finally:
            await transport.stop()
