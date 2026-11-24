"""SNMP access: a small read-only transport and its pysnmp implementation.

The adapter only needs two requests, GET of a few scalars and a walk of a table column, so the
rest of the package talks to the :class:`SnmpTransport` protocol. The real transport
(:class:`PysnmpTransport`) uses pysnmp 7 (``pip install signalbox-net[snmp]``), imported only
when a switch is read. The simulator (:mod:`signalbox.sim.snmp`) answers the same two requests
from ``.snmprec`` recordings, so the adapter is tested without any network.

Values are plain Python: ``int`` (INTEGER, Gauge32, Counter, TimeTicks), ``bytes``
(OCTET STRING, Opaque), ``str`` (an OBJECT IDENTIFIER or an IpAddress, dotted). OIDs are
dotted strings without a leading dot. A request never changes anything: only GET, GETNEXT and
GETBULK are sent.
"""

from __future__ import annotations

import importlib
from collections.abc import Callable
from typing import Any, Protocol

from signalbox.adapters.snmp.config import SnmpConfig

Value = int | bytes | str

#: stop a walk after this many values (a defective agent that never ends)
MAX_ROWS = 200_000
#: values per GETBULK answer
BULK = 25

INSTALL_HINT = "this adapter needs pysnmp: install signalbox-net[snmp] (the container image has it)"

#: error indications of pysnmp that mean "the credentials were refused" (SNMPv3)
_AUTH_ERRORS = {
    "wrongDigest",
    "unknownUserName",
    "unsupportedSecurityLevel",
    "decryptionError",
    "authenticationFailure",
    "authenticationError",
    "unknownSecurityName",
    "unsupportedAuthProtocol",
    "unsupportedPrivProtocol",
    "noAccessEntry",
    "notInView",
    "unknownCommunityName",
}


class SnmpError(Exception):
    """A request failed; ``kind`` is ``timeout``, ``auth`` or ``other``."""

    def __init__(self, kind: str, detail: str) -> None:
        super().__init__(detail)
        self.kind = kind
        self.detail = detail


class SnmpUnavailable(Exception):
    """pysnmp is not installed."""


class SnmpTransport(Protocol):
    async def get(self, *oids: str) -> dict[str, Value]:
        """The values of these scalars; one the agent does not have is missing from the
        answer."""
        ...

    async def walk(self, oid: str) -> dict[str, Value]:
        """Every value below ``oid`` in the agent's order (empty: nothing there)."""
        ...

    async def close(self) -> None: ...


def oid_tuple(oid: str) -> tuple[int, ...]:
    return tuple(int(part) for part in oid.strip(".").split("."))


def suffix(oid: str, base: str) -> str | None:
    """The part of ``oid`` below ``base`` (``None``: not below it)."""
    if oid.startswith(base + "."):
        return oid[len(base) + 1 :]
    return None


def column(rows: dict[str, Value], base: str) -> dict[str, Value]:
    """The values of a walk keyed by their index below ``base``."""
    out: dict[str, Value] = {}
    for oid, value in rows.items():
        tail = suffix(oid, base)
        if tail is not None:
            out[tail] = value
    return out


def convert(value: Any, hlapi: Any) -> Value | None:
    """A pysnmp value as plain Python; ``None`` for noSuchObject, noSuchInstance, endOfMibView."""
    if isinstance(value, hlapi.NoSuchObject | hlapi.NoSuchInstance | hlapi.EndOfMibView):
        return None
    if isinstance(value, hlapi.IpAddress):
        return str(value.prettyPrint())
    if isinstance(value, hlapi.OctetString | hlapi.Opaque):
        return bytes(value.asOctets())
    if isinstance(value, hlapi.ObjectIdentifier):
        return str(value.prettyPrint()).strip(".")
    if isinstance(value, hlapi.Null):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _failure(indication: Any) -> SnmpError:
    text = str(indication)
    if text in _AUTH_ERRORS:
        return SnmpError("auth", text)
    if text == "requestTimedOut":
        return SnmpError("timeout", text)
    return SnmpError("other", text)


class PysnmpTransport:
    """SNMP v2c (community) or v3 (authPriv) with pysnmp, read only."""

    def __init__(self, config: SnmpConfig, timeout: float) -> None:
        try:
            self._h: Any = importlib.import_module("pysnmp.hlapi.v3arch.asyncio")
        except ImportError:
            raise SnmpUnavailable(INSTALL_HINT) from None
        self._config = config
        #: per request; a walk takes many
        self._timeout = max(0.5, min(3.0, timeout / 4))
        self._engine: Any = None
        self._target: Any = None
        self._auth: Any = None
        self._context: Any = None

    async def _open(self) -> None:
        if self._engine is not None:
            return
        h, cfg = self._h, self._config
        self._engine = h.SnmpEngine()
        host = cfg.address
        target = h.Udp6TransportTarget if ":" in host else h.UdpTransportTarget
        self._target = await target.create((host, cfg.port), timeout=self._timeout, retries=1)
        self._context = h.ContextData(contextName=cfg.context_name)
        if cfg.version == "v2c":
            assert cfg.community is not None
            self._auth = h.CommunityData(cfg.community.get_secret_value(), mpModel=1)
        else:
            assert cfg.auth_password is not None and cfg.priv_password is not None
            auth = {
                "sha": h.usmHMACSHAAuthProtocol,
                "sha256": h.usmHMAC192SHA256AuthProtocol,
            }[cfg.auth_protocol]
            self._auth = h.UsmUserData(
                cfg.username,
                authKey=cfg.auth_password.get_secret_value(),
                privKey=cfg.priv_password.get_secret_value(),
                authProtocol=auth,
                privProtocol=h.usmAesCfb128Protocol,
            )

    def _object(self, oid: str) -> Any:
        return self._h.ObjectType(self._h.ObjectIdentity(oid))

    async def get(self, *oids: str) -> dict[str, Value]:
        await self._open()
        h = self._h
        indication, status, _, binds = await h.get_cmd(
            self._engine,
            self._auth,
            self._target,
            self._context,
            *(self._object(o) for o in oids),
            lookupMib=False,
        )
        if indication:
            raise _failure(indication)
        out: dict[str, Value] = {}
        if status:  # a scalar the agent does not have: ask one by one
            if len(oids) > 1:
                for oid in oids:
                    out.update(await self.get(oid))
            return out
        for name, raw in binds:
            value = convert(raw, h)
            if value is not None:
                out[str(name.prettyPrint()).strip(".")] = value
        return out

    async def walk(self, oid: str) -> dict[str, Value]:
        await self._open()
        h = self._h
        out: dict[str, Value] = {}
        walker = h.bulk_walk_cmd(
            self._engine,
            self._auth,
            self._target,
            self._context,
            0,
            BULK,
            self._object(oid),
            lexicographicMode=False,
            lookupMib=False,
        )
        async for indication, status, _, binds in walker:
            if indication:
                raise _failure(indication)
            if status:  # noSuchName, tooBig, ...: this part of the MIB is not offered
                break
            for name, raw in binds:
                key = str(name.prettyPrint()).strip(".")
                value = convert(raw, h)
                if value is not None and suffix(key, oid) is not None:
                    out[key] = value
            if len(out) >= MAX_ROWS:
                break
        return out

    async def close(self) -> None:
        engine, self._engine = self._engine, None
        if engine is not None:
            closer: Callable[[], Any] = engine.close_dispatcher
            closer()
