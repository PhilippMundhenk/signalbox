"""The shared mapping of a DNS server's settings to the model (AdGuard Home, Pi-hole; #304).

A DNS filter is a device of role ``other`` that runs one DNS service and sometimes a DHCP
server. Both integrations map their vendor settings onto the same objects, so the DNS rules
(forwarder loops, a missing resolver, a single upstream) and the DHCP rules (one server per
network, foreign servers) see real data:

- **Upstream servers** become :class:`~signalbox.model.DnsForwarder` (address and port). An
  upstream given by a name (``tls://dns.example.net``, ``https://...``, a DNS stamp) has no
  address Signalbox can match with a device: it is listed in ``vendor_extra["named_upstreams"]``
  (scheme and host only, never a path that could carry a token), not as a forwarder. Upstreams
  for single domains (``[/example.lan/]192.0.2.1``, Pi-hole's conditional forwarding) are
  ``vendor_extra["domain_forwards"]`` like Unbound's: they are not where lookups in general go.
- **DHCP** is reported on the site's native (untagged) segment: the device does not know which
  VLAN it sits in, and core moves it to the segment of the router it shares a network with.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from ipaddress import ip_address
from typing import Any

from signalbox.model import (
    DNS_PORT,
    DhcpLease,
    DhcpPool,
    DhcpServer,
    DnsForwarder,
    DnsService,
    IPAddress,
    LeaseState,
    Reservation,
    Segment,
    normalise_mac,
    object_id,
    segment_id,
)

#: Default port of an upstream by its scheme (the port a plain address uses is 53).
_SCHEME_PORT = {"tls": 853, "quic": 853, "https": 443, "h3": 443}


@dataclass
class Upstreams:
    """Upstream servers split by what the model can say about them."""

    forwarders: list[DnsForwarder] = field(default_factory=list)
    #: ``scheme://host[:port]`` of upstreams without an address (sdns stamps: ``sdns://``).
    named: list[str] = field(default_factory=list)
    #: domain -> the upstreams of that domain only, as text.
    domains: dict[str, list[str]] = field(default_factory=dict)

    def extra(self) -> dict[str, Any]:
        out: dict[str, Any] = {}
        if self.named:
            out["named_upstreams"] = self.named
        if self.domains:
            out["domain_forwards"] = self.domains
        return out


def host_port(text: str) -> tuple[str, int | None]:
    """``192.0.2.1``, ``192.0.2.1:53``, ``192.0.2.1#53``, ``[2001:db8::1]:53`` -> host, port."""
    text = text.strip()
    if text.startswith("["):
        host, _, rest = text[1:].partition("]")
        return host, int(rest[1:]) if rest.startswith(":") and rest[1:].isdigit() else None
    if "#" in text:
        host, _, port = text.partition("#")
        return host, int(port) if port.isdigit() else None
    if text.count(":") == 1:
        host, _, port = text.partition(":")
        return host, int(port) if port.isdigit() else None
    return text, None


def _one(spec: str) -> tuple[DnsForwarder | None, str | None]:
    """One upstream without a domain prefix: (forwarder, None) or (None, name to list)."""
    scheme, sep, rest = spec.partition("://")
    if not sep:
        scheme, rest = "", spec
    scheme = scheme.lower()
    if scheme == "sdns":
        return None, "sdns://"
    where = rest.split("/", 1)[0]
    host, port = host_port(where)
    try:
        address = ip_address(host)
    except ValueError:
        label = f"{scheme}://{where}" if scheme else where
        return None, label
    number = port if port is not None else _SCHEME_PORT.get(scheme, DNS_PORT)
    if not 1 <= number <= 65535:
        return None, f"{scheme}://{where}" if scheme else where
    return DnsForwarder(address=address, port=number), None


def parse_upstreams(items: Iterable[str]) -> Upstreams:
    """AdGuard Home's ``upstream_dns`` lines or Pi-hole's ``dns.upstreams``.

    ``[/domain/]server`` (AdGuard Home, ``[//]server`` for names without a dot) limits a
    server to those domains; a ``#`` instead of a server (use the default upstreams for it) is
    skipped. Duplicates are kept once.
    """
    out = Upstreams()
    for raw in items:
        spec = str(raw).strip()
        if not spec or spec.startswith("#"):
            continue
        domains: list[str] = []
        if spec.startswith("[/") and "/]" in spec:
            head, _, spec = spec[2:].partition("/]")
            domains = [d for d in head.split("/") if d] or ["(names without a dot)"]
            spec = spec.strip()
        if not spec or spec == "#":
            continue
        # several servers for one domain list are separated by spaces
        for part in spec.split():
            forwarder, name = _one(part)
            text = str(forwarder) if forwarder is not None else name or part
            if domains:
                for d in domains:
                    out.domains.setdefault(d, [])
                    if text not in out.domains[d]:
                        out.domains[d].append(text)
            elif forwarder is not None:
                if forwarder not in out.forwarders:
                    out.forwarders.append(forwarder)
            elif name is not None and name not in out.named:
                out.named.append(name)
    return out


def dns_service(
    device_id: str,
    name: str,
    *,
    upstreams: Upstreams | None,
    port: int = DNS_PORT,
    listen: Iterable[IPAddress] = (),
    host_records: list[Any] | None = None,
    enabled: bool = True,
    extra: dict[str, Any] | None = None,
) -> DnsService:
    """The device's DNS service. ``upstreams`` None: their list could not be read, so the
    service is reported as not read (``config_read=False``) and the loop checks say so."""
    return DnsService(
        id=object_id(device_id, "dns", name),
        device_id=device_id,
        name=name,
        enabled=enabled,
        listen=sorted(set(listen), key=lambda a: (a.version, int(a))),
        port=port,
        forwarders=upstreams.forwarders if upstreams else [],
        host_records=host_records or [],
        config_read=upstreams is not None,
        vendor_extra={**(upstreams.extra() if upstreams else {}), **(extra or {})},
    )


def lease_seconds(text: object) -> int | None:
    """dnsmasq's lease time (Pi-hole): ``3600``, ``90m``, ``24h``, ``7d``, ``1w``; ``infinite``
    and anything else: None."""
    value = str(text or "").strip().lower()
    if not value:
        return None
    factor = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}.get(value[-1], 1)
    digits = value[:-1] if value[-1] in "smhdw" else value
    return int(digits) * factor if digits.isdigit() else None


def address(value: object) -> IPAddress | None:
    try:
        return ip_address(str(value).strip())
    except ValueError:
        return None


def mac(value: object) -> str | None:
    try:
        return normalise_mac(str(value))
    except ValueError:
        return None


def text(value: object) -> str:
    return value.strip() if isinstance(value, str) else ""


def epoch(value: object) -> datetime | None:
    """A Unix time as a UTC time; 0 or nothing: None (a lease that does not end)."""
    if isinstance(value, bool) or not isinstance(value, int | float) or value <= 0:
        return None
    try:
        return datetime.fromtimestamp(value, UTC)
    except (OverflowError, OSError, ValueError):
        return None


def lease(
    ip: object,
    hw: object,
    hostname: object,
    expires: datetime | None,
    *,
    client_id: object = None,
    reserved: bool | None = None,
    state: LeaseState = LeaseState.ACTIVE,
) -> DhcpLease | None:
    """One lease, None when it has no address or neither a MAC address nor a client id."""
    addr = address(ip)
    hw_mac = mac(hw)
    cid = text(client_id) or None
    if addr is None or (hw_mac is None and cid is None):
        return None
    name = text(hostname)
    return DhcpLease(
        address=addr,
        mac=hw_mac,
        client_id=cid,
        hostname=None if name in ("", "*") else name,
        state=state,
        reserved=reserved,
        expires=expires,
    )


def dhcp_server(
    device_id: str,
    site_id: str,
    key: str,
    *,
    start: object,
    end: object,
    router: object,
    lease_time: int | None,
    reservations: list[Reservation],
    leases: list[DhcpLease] | None,
    domain: str | None = None,
    extra: dict[str, Any] | None = None,
) -> tuple[DhcpServer, Segment]:
    """An enabled IPv4 DHCP server and the native segment it is on."""
    first, last = address(start), address(end)
    pools = [DhcpPool(start=first, end=last)] if first and last and first.version == 4 else []
    seg = segment_id(site_id, None)
    server = DhcpServer(
        id=object_id(device_id, "dhcp", key),
        device_id=device_id,
        segment_id=seg,
        enabled=True,
        pools=pools,
        lease_seconds=lease_time,
        router=address(router),
        domain=domain or None,
        reservations=reservations,
        leases=leases,
        vendor_extra=extra or {},
    )
    return server, Segment(id=seg, site_id=site_id)
