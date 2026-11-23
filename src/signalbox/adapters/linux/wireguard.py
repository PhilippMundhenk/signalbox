"""WireGuard interfaces and peers from ``wg show all <field>`` (#240).

Every line is ``<interface>\\t<value>`` (``public-key``, ``listen-port``) or
``<interface>\\t<peer public key>\\t<value...>`` (``peers``, ``endpoints``, ``allowed-ips``,
``latest-handshakes``, ``transfer``). Only public keys are ever printed by these commands; a
value that does not look like a WireGuard public key is dropped rather than kept.
"""

from __future__ import annotations

import contextlib
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from ipaddress import ip_network

from signalbox.adapters.linux.collect import WG_FIELDS, Answer
from signalbox.model import IPNetwork

KEY = re.compile(r"^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$")


@dataclass
class WgPeer:
    public_key: str
    endpoint_host: str | None = None
    endpoint_port: int | None = None
    allowed_ips: list[IPNetwork] = field(default_factory=list)
    latest_handshake: datetime | None = None
    rx_bytes: int | None = None
    tx_bytes: int | None = None
    keepalive_seconds: int | None = None


@dataclass
class WgInterface:
    name: str
    public_key: str | None = None
    listen_port: int | None = None
    peers: dict[str, WgPeer] = field(default_factory=dict)


def endpoint(text: str) -> tuple[str | None, int | None]:
    """``198.51.100.1:51820``, ``[2001:db8::1]:51820``; ``(none)``: no endpoint."""
    if text in ("(none)", ""):
        return None, None
    host, _, port = text.rpartition(":")
    host = host.strip("[]")
    try:
        number = int(port)
    except ValueError:
        return None, None
    return (host or None), (number if 1 <= number <= 65535 else None)


def read(answer: Answer) -> tuple[dict[str, WgInterface], bool]:
    """Interfaces by name, and whether ``wg`` was refused (no root, no sudoers rule)."""
    out: dict[str, WgInterface] = {}
    for what in WG_FIELDS:
        for line in answer.lines(f"wg-{what}"):
            cols = line.split("\t")
            name = cols[0].strip()
            if not name:
                continue
            iface = out.setdefault(name, WgInterface(name))
            if what == "public-key":
                if len(cols) > 1 and KEY.match(cols[1].strip()):
                    iface.public_key = cols[1].strip()
                continue
            if what == "listen-port":
                with contextlib.suppress(IndexError, ValueError):
                    port = int(cols[1])
                    iface.listen_port = port if 1 <= port <= 65535 else None
                continue
            if len(cols) < 2 or not KEY.match(cols[1].strip()):
                continue
            peer = iface.peers.setdefault(cols[1].strip(), WgPeer(cols[1].strip()))
            values = cols[2:]
            if what == "endpoints" and values:
                peer.endpoint_host, peer.endpoint_port = endpoint(values[0].strip())
            elif what == "allowed-ips" and values:
                for text in values[0].split():
                    with contextlib.suppress(ValueError):
                        peer.allowed_ips.append(ip_network(text, strict=False))
            elif what == "latest-handshakes" and values:
                with contextlib.suppress(ValueError):
                    stamp = int(values[0])
                    peer.latest_handshake = datetime.fromtimestamp(stamp, UTC) if stamp else None
            elif what == "persistent-keepalive" and values:
                text = values[0].strip()
                if text == "off":
                    peer.keepalive_seconds = 0
                elif text.isdigit() and int(text) <= 65535:
                    peer.keepalive_seconds = int(text)
            elif what == "transfer" and len(values) >= 2:
                with contextlib.suppress(ValueError):
                    peer.rx_bytes, peer.tx_bytes = int(values[0]), int(values[1])
    return out, answer.has("wg-denied")
