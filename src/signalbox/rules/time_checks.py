"""Clock, NTP and time zone rules (check #129, model #179).

They read :class:`~signalbox.model.DeviceTime` and ``DhcpServer.ntp_servers`` and stay silent
for devices that do not report a value. Thresholds are fixed for now (rule parameters are issue
#187); they are all here.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterator
from datetime import datetime
from ipaddress import ip_network
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from signalbox.model import Device, DeviceRole, DeviceTime, IPAddress, Network
from signalbox.rules import Result, Rule, Severity, found, rule
from signalbox.rules._names import device_name, segment_name
from signalbox.rules.dns import _Index, _local_segment, _parse

#: A clock that differs from Signalbox's by more than this (plus the read's uncertainty) is
#: reported, in seconds.
OFFSET_SECONDS = 60.0
#: Names of public NTP services: a device that only uses these asks the internet. Other names
#: may be local (``router.lan``) and are not counted as public.
PUBLIC_NTP_DOMAINS = (
    "ntp.org",
    "time.google.com",
    "time.cloudflare.com",
    "time.apple.com",
    "time.windows.com",
    "time.facebook.com",
    "time.aws.com",
    "nist.gov",
    "ptb.de",
    "ntp.ubuntu.com",
)


def _timed(net: Network) -> Iterator[tuple[Device, DeviceTime]]:
    for dev in net.devices:
        if dev.time is not None:
            yield dev, dev.time


def _duration(seconds: float) -> str:
    s = int(abs(seconds))
    if s < 120:
        return f"{s} seconds"
    if s < 120 * 60:
        return f"{s // 60} minutes"
    if s < 48 * 3600:
        return f"{s // 3600} hours"
    return f"{s // 86400} days"


def _serves(dev: Device) -> bool:
    return bool(dev.time and dev.time.ntp_server and dev.time.ntp_server.enabled)


def _address_of(net: Network, dev: Device) -> str:
    """Management address, else the first subnet address, else the name."""
    if dev.management_address:
        return dev.management_address
    for sub in sorted(net.subnets, key=lambda s: s.id):
        if sub.device_id == dev.id:
            return str(sub.interface.ip)
    return dev.name


def _local_servers(net: Network, site: str) -> list[Device]:
    return [d for d in net.devices if d.site_id == site and _serves(d)]


def _site_name(net: Network, site: str) -> str:
    return next((s.name for s in net.sites if s.id == site), site)


def _servers_text(net: Network, servers: list[Device]) -> str:
    return ", ".join(f"{d.name} ({_address_of(net, d)})" for d in servers)


@rule(
    "time.offset",
    "Device clock is wrong",
    Severity.WARNING,
    "Wrong clocks make logs useless when tracing a problem across devices and break TLS "
    '(certificates "not yet valid"), WPA3 and 802.1X, VPN handshakes and scheduled Wi-Fi or '
    "parental-control times. A device without a battery-backed clock starts in 1970 after a "
    "power cut until NTP corrects it. The device's clock is compared with Signalbox's at the "
    "moment it was read; the request's round trip is allowed for.",
)
def offset(net: Network) -> Iterator[Result]:
    for dev, t in _timed(net):
        off = t.offset_seconds()
        if off is None or abs(off) <= OFFSET_SECONDS + (t.uncertainty_seconds or 0.0):
            continue
        way = "ahead" if off > 0 else "behind"
        local = [d for d in _local_servers(net, dev.site_id) if d.id != dev.id]
        hint = f" ({_servers_text(net, local)} can serve time)" if local else ""
        yield found(
            f"The clock of {dev.name} is {_duration(off)} {way}",
            [dev.id],
            fix=f"Configure NTP on it{hint} and check that it can reach the NTP server.",
        )


@rule(
    "time.not-synchronised",
    "Device clock not synchronised",
    Severity.WARNING,
    "A device without NTP drifts by seconds a day and loses the time at every power cut; one "
    "with NTP configured but not synchronised cannot reach its servers (a wrong address, a "
    "firewall, no DNS). Warning when NTP is configured but not synchronised, info when no NTP "
    "server is configured. Silent where the device does not report its NTP client.",
)
def not_synchronised(net: Network) -> Iterator[Result]:
    for dev, t in _timed(net):
        client = t.ntp_client
        if client is None:
            continue
        if not client.enabled or not client.servers:
            local = [d for d in _local_servers(net, dev.site_id) if d.id != dev.id]
            hint = f" (for example {_servers_text(net, local)})" if local else ""
            yield found(
                f"{dev.name} has no NTP server configured",
                [dev.id],
                fix=f"Turn on its NTP client with a server{hint}.",
                severity=Severity.INFO,
            )
        elif client.synchronised is False:
            yield found(
                f"{dev.name} is not synchronised with its NTP servers "
                f"({', '.join(client.servers)})",
                [dev.id],
                fix="Check that the servers are right and reachable from the device (firewall, "
                "DNS for names); use the gateway if it serves time.",
            )


def _not_serving(net: Network, idx: _Index, address: IPAddress) -> str | None:
    """Why ``address`` cannot answer NTP, or None if it may (or nothing is known)."""
    seg = _local_segment(net, None, address)
    if seg is None:
        return None  # outside every known network: a public or remote server, not checked
    if not idx.used(address):
        seg_obj = net.segment(seg)
        if seg_obj is None or (seg_obj.site_id, address.version) not in idx.client_data:
            return None  # no client data: the server may just be unknown to Signalbox
        return f"no device on {segment_name(net, seg)} uses that address"
    dev = net.device(idx.target(address))
    if dev is None or dev.time is None or dev.time.ntp_server is None:
        return None
    srv = dev.time.ntp_server
    if not srv.enabled:
        return f"{dev.name} does not serve time"
    if srv.segments and seg not in srv.segments:
        return f"{dev.name} does not serve time on {segment_name(net, seg)}"
    return None


@rule(
    "time.ntp-unreachable",
    "NTP server of a device does not exist or serve time",
    Severity.WARNING,
    "A device whose NTP server is an address in a local network that no device uses, or a known "
    "device that does not serve time (there), never synchronises its clock. Names and addresses "
    "outside the known networks are not checked.",
)
def ntp_unreachable(net: Network) -> Iterator[Result]:
    idx = _Index.of(net)
    for dev, t in _timed(net):
        if t.ntp_client is None or not t.ntp_client.enabled:
            continue
        for server in t.ntp_client.servers:
            address = _parse(server)
            why = _not_serving(net, idx, address) if address is not None else None
            if why is not None:
                yield found(
                    f"{dev.name} uses the NTP server {address}, but {why}",
                    [dev.id],
                    fix="Point it to a device that serves time, or turn on the NTP server of "
                    "that device for this network.",
                    key=str(address),
                )


@rule(
    "time.dhcp-ntp-mismatch",
    "DHCP hands out an NTP server that does not serve time",
    Severity.WARNING,
    "DHCP option 42 tells clients where to get the time. An address in a local network that no "
    "device uses, or a known device that does not serve time on that network, leaves the clients "
    "that use it (many IoT devices, cameras, phones on some systems) with a wrong clock.",
)
def dhcp_ntp_mismatch(net: Network) -> Iterator[Result]:
    idx = _Index.of(net)
    for srv in sorted(net.dhcp_servers, key=lambda s: s.id):
        if not srv.enabled:
            continue
        for address in srv.ntp_servers:
            why = _not_serving(net, idx, address)
            if why is not None:
                yield found(
                    f"{device_name(net, srv.device_id)} hands out the NTP server {address} on "
                    f"{segment_name(net, srv.segment_id)}, but {why}",
                    [srv.id],
                    fix="Hand out the address of a device that serves time (usually the "
                    "gateway), or turn on its NTP server for this network.",
                    key=str(address),
                )


#: Address ranges of local networks (RFC 1918, CGNAT, loopback, link-local, ULA).
LOCAL_RANGES = tuple(
    ip_network(n)
    for n in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
    )
)


def _public(net: Network, server: str) -> bool:
    """True for an address outside the known and the private networks, or the name of a
    well-known public NTP service."""
    address = _parse(server)
    if address is not None:
        local = _local_segment(net, None, address) is not None or any(
            address in r for r in LOCAL_RANGES if r.version == address.version
        )
        return not local
    name = server.lower().rstrip(".")
    return any(name == d or name.endswith("." + d) for d in PUBLIC_NTP_DOMAINS)


@rule(
    "time.no-local-ntp",
    "Devices ask the internet for the time",
    Severity.INFO,
    "With one device (usually the gateway) serving time for the site and every other device "
    "using it, clocks agree with each other and keep working while the internet is down. "
    "Reported per site for devices other than gateways that use only public NTP servers: "
    "when a device of the site serves time, or when a gateway reports that it does not. "
    "Server names that are not well-known public services may be local and are not counted.",
)
def no_local_ntp(net: Network) -> Iterator[Result]:
    by_site: dict[str, list[Device]] = defaultdict(list)
    for dev, t in _timed(net):
        client = t.ntp_client
        if (
            dev.role is not DeviceRole.GATEWAY
            and not _serves(dev)
            and client is not None
            and client.enabled
            and client.servers
            and all(_public(net, s) for s in client.servers)
        ):
            by_site[dev.site_id].append(dev)
    for site, devices in sorted(by_site.items()):
        names = ", ".join(sorted(d.name for d in devices))
        local = _local_servers(net, site)
        if local:
            yield found(
                f"{names} use only internet NTP servers, although {_servers_text(net, local)} "
                f"serves time at {_site_name(net, site)}",
                [d.id for d in devices],
                fix=f"Point their NTP client to {_address_of(net, local[0])}.",
            )
            continue
        gateways = [
            d
            for d in net.devices
            if d.site_id == site and d.role is DeviceRole.GATEWAY and d.time is not None
        ]
        if not any(g.time and g.time.ntp_server is not None for g in gateways):
            continue  # nobody says whether the gateway serves time
        gw = gateways[0]
        yield found(
            f"No device at {_site_name(net, site)} serves time: {names} ask the internet",
            [d.id for d in devices],
            fix=f"Turn on the NTP server of {gw.name} and point the devices (and DHCP option "
            f"42) to {_address_of(net, gw)}.",
        )


def _utc_offset(t: DeviceTime) -> int | None:
    """The device's offset from UTC in minutes, reported or derived from an IANA zone name."""
    if t.utc_offset_minutes is not None:
        return t.utc_offset_minutes
    at = t.clock or t.read_at
    if t.timezone is None or at is None or ("/" not in t.timezone and t.timezone != "UTC"):
        return None
    try:
        delta = datetime.fromtimestamp(at.timestamp(), ZoneInfo(t.timezone)).utcoffset()
    except (ZoneInfoNotFoundError, ValueError):
        return None
    return None if delta is None else int(delta.total_seconds() // 60)


def _zone(t: DeviceTime, minutes: int) -> str:
    sign = "+" if minutes >= 0 else "-"
    utc = f"UTC{sign}{abs(minutes) // 60:02d}:{abs(minutes) % 60:02d}"
    return f"{t.timezone}, {utc}" if t.timezone else utc


@rule(
    "time.timezone",
    "Devices of one site use different time zones",
    Severity.INFO,
    "Devices with different time zones show the same event at different times in their logs "
    "and run scheduled Wi-Fi times, parental controls and reboots at the wrong hour. Compared "
    "by the offset from UTC at the time of reading, so equal zones with different names (an "
    "IANA name and a POSIX string) are not reported.",
)
def timezone(net: Network) -> Iterator[Result]:
    by_site: dict[str, dict[int, list[tuple[Device, DeviceTime]]]] = defaultdict(
        lambda: defaultdict(list)
    )
    for dev, t in _timed(net):
        minutes = _utc_offset(t)
        if minutes is not None:
            by_site[dev.site_id][minutes].append((dev, t))
    for site, zones in sorted(by_site.items()):
        if len(zones) < 2:
            continue
        parts = []
        ids = []
        for minutes, members in sorted(zones.items()):
            for dev, t in sorted(members, key=lambda m: m[0].name):
                parts.append(f"{dev.name}: {_zone(t, minutes)}")
                ids.append(dev.id)
        yield found(
            f"Devices at {_site_name(net, site)} use {len(zones)} time zones ({'; '.join(parts)})",
            ids,
            fix="Set the same time zone on every device of the site.",
        )


RULES: list[Rule] = [
    offset,
    not_synchronised,
    ntp_unreachable,
    dhcp_ntp_mismatch,
    no_local_ntp,
    timezone,
]
