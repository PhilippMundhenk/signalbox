"""Discovery of ProSAFE Plus and Easy Smart switches (#203): their own broadcast, through
Switchyard (the optional extra ``switches``).

- NETGEAR (NSDP): one read request for the identity tags (model, name, MAC, IP, firmware)
  from UDP port 63321 to the broadcast address, port 63322, on every interface.
- TP-Link Easy Smart: one discovery request from UDP port 29809 to the broadcast address,
  port 29808; switches answer by broadcast to port 29809.

No password is sent: the identity is answered to anyone, as the vendors' own tools find the
switches. Both answer only in the same layer-2 network, so in Docker this needs host
networking; a run without answers says so.
"""

from __future__ import annotations

import asyncio
import struct
from collections.abc import Callable
from ipaddress import IPv4Address
from typing import Any

from signalbox.discovery import BroadcastResult, Candidate, NetworkProbe
from signalbox.model import DeviceRole

LockFor = Callable[[str, int], asyncio.Lock]

INSTALL = "needs Switchyard (install signalbox-net[switches]; the container image has it)"
NO_ANSWER = (
    "No {name} switch answered the broadcast. These switches answer only in the same network "
    "segment as Signalbox: run it there, and in Docker with host networking "
    "(network_mode: host); see docs/DISCOVERY.md."
)
_PARSE_ERRORS = (ValueError, IndexError, KeyError, TypeError, struct.error, UnicodeError)


def _address(identity: dict[str, Any], source: str | None) -> str | None:
    for value in (identity.get("ip"), source):
        try:
            ip = IPv4Address(str(value))
        except ValueError:
            continue
        if not (ip.is_unspecified or ip.is_multicast or ip == IPv4Address("255.255.255.255")):
            return str(ip)
    return None


def _candidates(
    found: list[tuple[dict[str, Any], str | None]], vendor: str, product: str
) -> list[Candidate]:
    out: list[Candidate] = []
    for identity, source in found:
        address = _address(identity, source)
        if address is None:
            continue
        model = identity.get("model") or None
        out.append(
            Candidate(
                address=address,
                role=DeviceRole.SWITCH,
                config={"address": address},
                vendor=vendor,
                model=model,
                name=identity.get("name") or model or product,
                firmware=identity.get("firmware") or None,
                mac=identity.get("mac"),
                evidence=f"{product} broadcast answer",
            )
        )
    return out


def _settings(probe: NetworkProbe, adapter: str, client: int) -> tuple[int, list[str], float]:
    s = probe.settings(adapter)
    seconds = float(s.get("seconds", min(3.0, max(1.0, probe.timeout))))
    return int(s.get("client_port", client)), [str(t) for t in s.get("targets", [])], seconds


async def prosafe(probe: NetworkProbe, lock_for: LockFor) -> BroadcastResult:
    name = "NETGEAR ProSAFE Plus"
    try:
        from switchyard.nsdp import Transport, discover
        from switchyard.nsdp.transport import CLIENT_PORT
    except ImportError:
        return BroadcastResult(note=f"{name} switches were not searched: {INSTALL}.")
    client_port, targets, seconds = _settings(probe, "prosafe", CLIENT_PORT)
    await probe.limiter.acquire()
    async with lock_for("nsdp", client_port):
        transport = Transport(
            client_port=client_port, targets=targets or None, timeout=seconds, retries=1
        )
        try:
            await transport.start()
            replies = await discover(transport, seconds)
        except OSError as exc:
            return BroadcastResult(note=f"{name}: cannot send the broadcast ({exc}).")
        except _PARSE_ERRORS:
            return BroadcastResult(note=f"{name}: an answer to the broadcast was garbled.")
        finally:
            await transport.stop()
    found = [(r, r.get("source_ip")) for r in replies]
    candidates = _candidates(found, "NETGEAR", name)
    return BroadcastResult(candidates, None if candidates else NO_ANSWER.format(name=name))


async def easysmart(probe: NetworkProbe, lock_for: LockFor) -> BroadcastResult:
    name = "TP-Link Easy Smart"
    try:
        from switchyard.easysmart.client import parse_identity
        from switchyard.easysmart.packet import Op
        from switchyard.easysmart.transport import CLIENT_PORT, EasySmartTransport
    except ImportError:
        return BroadcastResult(note=f"{name} switches were not searched: {INSTALL}.")
    client_port, targets, seconds = _settings(probe, "easysmart", CLIENT_PORT)
    await probe.limiter.acquire()
    async with lock_for("easysmart", client_port):
        transport = EasySmartTransport(
            client_port=client_port, targets=targets or None, timeout=seconds, retries=1
        )
        try:
            await transport.start()
            replies = await transport.collect(Op.DISCOVERY, [], seconds)
            found = [(parse_identity(packet), addr[0]) for packet, addr in replies]
        except OSError as exc:
            return BroadcastResult(note=f"{name}: cannot send the broadcast ({exc}).")
        except _PARSE_ERRORS:
            return BroadcastResult(note=f"{name}: an answer to the broadcast was garbled.")
        finally:
            await transport.stop()
    candidates = _candidates(found, "TP-Link", name)
    return BroadcastResult(candidates, None if candidates else NO_ANSWER.format(name=name))
