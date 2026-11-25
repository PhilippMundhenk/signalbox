"""Access control: RADIUS servers, 802.1X, MAC filters (issue #162, ADR 0030).

The checks use what devices report: the RADIUS servers they know (``Device.radius_servers``)
and the ones an enterprise SSID uses (``Wlan.radius``), the access control of a port
(``Port.access_control``) and the MAC filter of an SSID (``Wlan.mac_filter``). Shared secrets
and MAC lists are never in the model. Everything stays quiet where a device reports nothing.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterator
from ipaddress import ip_address

from signalbox.model import (
    AccessControlMode,
    ClientCategory,
    Membership,
    Network,
    RadiusPurpose,
    Security,
    Wlan,
    client_target,
)
from signalbox.rules import Result, Severity, ctx, found, rule
from signalbox.rules._names import device_name, site_of_device
from signalbox.rules._params import RuleParams, param

_ENTERPRISE = {
    Security.WPA_ENTERPRISE,
    Security.WPA2_ENTERPRISE,
    Security.WPA3_ENTERPRISE,
    Security.WPA3_ENTERPRISE_192,
}
_DEFAULT_AUTH_PORT = 1812
_SECOND_SERVER = (
    "Add a second RADIUS server on another machine to the settings of the network or switch."
)
#: Devices that usually have no 802.1X supplicant (the kinds a user can declare in an annotation).
_NO_SUPPLICANT = frozenset(
    {ClientCategory.PRINTER, ClientCategory.IOT, ClientCategory.CAMERA, ClientCategory.MEDIA}
)


class RadiusSingleParams(RuleParams):
    """``radius.single``."""

    min_servers: int = param(
        2,
        unit="count",
        ge=1,
        le=10,
        description="Fewest RADIUS servers an enterprise network or an 802.1X switch should "
        "have; fewer are reported (1 turns the rule off).",
    )


class NoFallbackParams(RuleParams):
    """``port.dot1x-no-fallback``."""

    min_clients: int = param(
        1,
        unit="count",
        ge=1,
        le=100,
        description="Number of printers, IoT devices, cameras or media players seen on an "
        "802.1X port from which it is reported.",
    )


def _wlans(net: Network) -> list[Wlan]:
    return sorted((w for w in net.wlans if w.enabled and not w.backhaul), key=lambda w: w.id)


# --- radius.unreachable ----------------------------------------------------------------------


def _reachable(net: Network, address: str) -> bool:
    """True unless the address is a private one that no known network or route contains."""
    try:
        ip = ip_address(address)
    except ValueError:
        return True  # a host name: cannot say
    if not ip.is_private or ip.is_loopback:
        return True  # a public server (or this device itself)
    if not net.subnets:
        return True  # nothing to compare with
    if any(ip in s.interface.network for s in net.subnets if s.interface.version == ip.version):
        return True
    return any(
        r.enabled and r.destination.prefixlen > 0 and ip in r.destination
        for r in net.routes
        if r.destination.version == ip.version
    )


@rule(
    "radius.unreachable",
    "RADIUS server outside every known network",
    Severity.WARNING,
    "An enterprise Wi-Fi network or an 802.1X port asks a RADIUS server to let clients in. "
    "When the server's address is in a private range that none of the networks Signalbox knows "
    "contains, and no route leads there, the access point or switch cannot reach it and nobody "
    "can connect. Reported for private addresses only; a public address or a host name is not "
    "checked, and neither is a site without known networks.",
)
def radius_unreachable(net: Network) -> Iterator[Result]:
    users: dict[str, set[str]] = defaultdict(set)
    for d in net.devices:
        for s in d.radius_servers or []:
            if {RadiusPurpose.WLAN, RadiusPurpose.DOT1X} & set(s.purposes):
                users[s.address].add(d.id)
    for w in _wlans(net):
        for ep in w.radius.auth if w.radius else []:
            users[ep.address].add(w.device_id)
    for address, devices in sorted(users.items()):
        if _reachable(net, address):
            continue
        names = ", ".join(sorted(device_name(net, d) for d in devices))
        yield found(
            f"The RADIUS server {address} used by {names} is not in any network Signalbox "
            "knows and no route leads there: clients cannot sign in",
            sorted(devices),
            fix="Check the address of the RADIUS server in the device's settings, and add a "
            "route if it is in a network behind another router.",
            key=address,
            mid="radius.unreachable",
            fix_id="radius.unreachable.fix",
            params={"address": address, "devices": names},
        )


# --- port.dot1x-trunk ------------------------------------------------------------------------


@rule(
    "port.dot1x-trunk",
    "802.1X on a port that carries several VLANs",
    Severity.WARNING,
    "802.1X lets one device per port authenticate (or, with multi-host, the first one). A port "
    "that carries tagged VLANs leads to an access point, a switch or a router, which cannot sign "
    "in as the user and then take every device behind it with it. Reported for ports with 802.1X "
    "or MAC authentication on that are a tagged member of a network.",
)
def dot1x_trunk(net: Network) -> Iterator[Result]:
    tagged: dict[str, list[str]] = defaultdict(list)
    for seg in net.segments:
        for m in seg.members:
            if m.mode is Membership.TAGGED:
                tagged[m.port_id].append(seg.id)
    for p in sorted(net.ports, key=lambda p: p.id):
        ac = p.access_control
        if ac is None or ac.mode in (AccessControlMode.OPEN, AccessControlMode.STATIC_MACS):
            continue
        if p.id not in tagged:
            continue
        yield found(
            f"{device_name(net, p.device_id)} {p.label()} has 802.1X or MAC authentication on "
            "but carries tagged VLANs: the device behind it cannot authenticate",
            [p.id],
            fix="Turn 802.1X off on the port, or move the access point or switch to a port "
            "without it.",
            mid="port.dot1xTrunk",
            fix_id="port.dot1xTrunk.fix",
            params={"device": device_name(net, p.device_id), "port": p.label()},
        )


# --- wifi.mac-filter-as-security -------------------------------------------------------------


@rule(
    "wifi.mac-filter-as-security",
    "MAC filter on an open Wi-Fi network",
    Severity.INFO,
    "A list of allowed MAC addresses on an open Wi-Fi network looks like protection, but MAC "
    "addresses are sent unencrypted and can be copied in seconds: anybody within range who "
    "listens for a while can join, and read the traffic of everyone, since an open network is "
    "not encrypted. Only the mode and the number of entries are read, never the addresses.",
)
def mac_filter_as_security(net: Network) -> Iterator[Result]:
    for w in _wlans(net):
        f = w.mac_filter
        if w.security is not Security.OPEN or f is None or f.mode.value != "allow":
            continue
        yield found(
            f"The open Wi-Fi network {w.ssid} on {device_name(net, w.device_id)} relies on a "
            f"MAC filter ({f.count} allowed addresses): it keeps nobody out and encrypts nothing",
            [w.id],
            fix="Use WPA2 or WPA3 with a passphrase (or WPA-Enterprise); keep the MAC filter "
            "only as an addition if you want it.",
            mid="wifi.macFilterAsSecurity",
            fix_id="wifi.macFilterAsSecurity.fix",
            params={
                "ssid": w.ssid,
                "device": device_name(net, w.device_id),
                "count": f.count,
            },
        )


# --- wifi.enterprise-consistent --------------------------------------------------------------


@rule(
    "wifi.enterprise-consistent",
    "The same enterprise Wi-Fi network uses different RADIUS servers",
    Severity.WARNING,
    "Access points of one enterprise SSID should ask the same RADIUS servers. When they differ, "
    "users can sign in on one access point and be refused on the next, and a change of the "
    "server has to be made everywhere. Compared are the authentication servers (address and "
    "port) of the enabled WPA-Enterprise networks with the same name in one site; the shared "
    "secrets are never read.",
)
def enterprise_consistent(net: Network) -> Iterator[Result]:
    groups: dict[tuple[str, str], dict[frozenset[tuple[str, int]], list[Wlan]]] = defaultdict(
        lambda: defaultdict(list)
    )
    for w in _wlans(net):
        if w.security not in _ENTERPRISE or w.radius is None or not w.radius.auth:
            continue
        site = site_of_device(net, w.device_id) or ""
        servers = frozenset((e.address, e.port or _DEFAULT_AUTH_PORT) for e in w.radius.auth)
        groups[(site, w.ssid)][servers].append(w)
    for (_, ssid), variants in sorted(groups.items()):
        if len(variants) < 2:
            continue
        wlans = sorted((w for ws in variants.values() for w in ws), key=lambda w: w.id)
        names = ", ".join(sorted({device_name(net, w.device_id) for w in wlans}))
        yield found(
            f"The Wi-Fi network {ssid} uses different RADIUS servers on its access points "
            f"({names})",
            [w.id for w in wlans],
            fix="Give every access point of the network the same RADIUS servers.",
            key=ssid,
            mid="wifi.enterpriseInconsistent",
            fix_id="wifi.enterpriseInconsistent.fix",
            params={"ssid": ssid, "devices": names},
        )


# --- radius.single ---------------------------------------------------------------------------


@rule(
    "radius.single",
    "Only one RADIUS server for 802.1X or an enterprise Wi-Fi network",
    Severity.INFO,
    "An enterprise Wi-Fi network or an 802.1X switch that knows a single RADIUS server has no "
    "failover: when that server is down, restarting or unreachable, nobody can sign in, and "
    "devices that reconnect (after a power cut, a roaming step) stay out. A second server, "
    "on another machine, avoids that. Reported when the servers an enterprise SSID uses (all its "
    "access points together) or the 802.1X servers of a switch number fewer than min_servers "
    "(default 2); nothing is said where a device does not report its servers.",
    params=RadiusSingleParams,
)
def radius_single(net: Network) -> Iterator[Result]:
    groups: dict[tuple[str, str], list[Wlan]] = defaultdict(list)
    for w in _wlans(net):
        if w.security in _ENTERPRISE and w.radius is not None and w.radius.auth:
            groups[(site_of_device(net, w.device_id) or "", w.ssid)].append(w)
    for (_, ssid), wlans in sorted(groups.items()):
        servers = {
            (e.address, e.port or _DEFAULT_AUTH_PORT)
            for w in wlans
            for e in (w.radius.auth if w.radius else [])
        }
        limit = ctx.params(RadiusSingleParams, wlans[0].device_id).min_servers
        if len(servers) >= limit:
            continue
        address = sorted(a for a, _ in servers)[0]
        yield found(
            f"The Wi-Fi network {ssid} has a single RADIUS server ({address}): nobody can sign "
            "in while it is down",
            [w.id for w in sorted(wlans, key=lambda w: w.id)],
            fix=_SECOND_SERVER,
            key=ssid,
            mid="radius.singleWifi",
            fix_id="radius.single.fix",
            params={"ssid": ssid, "address": address},
        )
    for d in sorted(net.devices, key=lambda d: d.id):
        if d.radius_servers is None:
            continue
        ports = [
            p
            for p in net.ports
            if p.device_id == d.id
            and p.access_control is not None
            and p.access_control.mode
            in (AccessControlMode.DOT1X, AccessControlMode.DOT1X_OR_MAC, AccessControlMode.MAC_AUTH)
        ]
        used = {s.address for s in d.radius_servers if RadiusPurpose.DOT1X in s.purposes}
        if not ports or not used or len(used) >= ctx.params(RadiusSingleParams, d).min_servers:
            continue
        address = sorted(used)[0]
        yield found(
            f"{device_name(net, d.id)} has a single RADIUS server for 802.1X ({address}): its "
            "ports stay closed while it is down",
            [d.id],
            fix=_SECOND_SERVER,
            key="dot1x",
            mid="radius.singleDot1x",
            fix_id="radius.single.fix",
            params={"device": device_name(net, d.id), "address": address},
        )


# --- port.dot1x-no-fallback ------------------------------------------------------------------


@rule(
    "port.dot1x-no-fallback",
    "802.1X port without fallback for devices that cannot sign in",
    Severity.WARNING,
    "Printers, cameras, media players and most IoT devices have no 802.1X supplicant. A port that "
    "demands 802.1X and has neither MAC authentication (MAB) nor a guest or authentication-failed "
    "VLAN leaves them without network, or tempts people to switch 802.1X off on the whole port. "
    "Reported for ports in 802.1X-only mode with neither VLAN, where at least min_clients "
    "devices that you declared as printer, IoT, camera or media (annotation) were seen.",
    params=NoFallbackParams,
)
def dot1x_no_fallback(net: Network) -> Iterator[Result]:
    seen: dict[str, list[str]] = defaultdict(list)
    for c in net.clients:
        if c.seen_on and net.expected(client_target(c.mac)).category in _NO_SUPPLICANT:
            seen[c.seen_on].append(c.hostname or c.mac)
    for p in sorted(net.ports, key=lambda p: p.id):
        ac = p.access_control
        if ac is None or ac.mode is not AccessControlMode.DOT1X:
            continue
        if ac.guest_vlan is not None or ac.auth_fail_vlan is not None:
            continue
        names = sorted(seen.get(p.id, []))
        if not names or len(names) < ctx.params(NoFallbackParams, p).min_clients:
            continue
        yield found(
            f"{device_name(net, p.device_id)} {p.label()} requires 802.1X without a fallback, "
            f"but {', '.join(names)} cannot sign in",
            [p.id],
            fix="Allow MAC authentication (MAB) on the port, or give it a guest VLAN, or plug "
            "these devices into a port without 802.1X.",
            mid="port.dot1xNoFallback",
            fix_id="port.dot1xNoFallback.fix",
            params={
                "device": device_name(net, p.device_id),
                "port": p.label(),
                "clients": ", ".join(names),
            },
        )


RULES = [
    radius_unreachable,
    radius_single,
    dot1x_trunk,
    dot1x_no_fallback,
    mac_filter_as_security,
    enterprise_consistent,
]
