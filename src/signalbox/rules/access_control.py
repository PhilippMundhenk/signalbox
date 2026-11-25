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
    Membership,
    Network,
    RadiusPurpose,
    Security,
    Wlan,
)
from signalbox.rules import Result, Severity, found, rule
from signalbox.rules._names import device_name, site_of_device

_ENTERPRISE = {
    Security.WPA_ENTERPRISE,
    Security.WPA2_ENTERPRISE,
    Security.WPA3_ENTERPRISE,
    Security.WPA3_ENTERPRISE_192,
}
_DEFAULT_AUTH_PORT = 1812


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


RULES = [radius_unreachable, dot1x_trunk, mac_filter_as_security, enterprise_consistent]
