"""Management service rules: plaintext protocols, exposure to the internet and to untrusted
networks, and devices read without encryption (issues #122, #123, #120 level 1, #127).

They read :class:`~signalbox.model.ManagementService` (#173). A device that reported no services
has none here: an empty list means "not read", so these rules stay quiet for it. Firewall rules
are not read yet (#135); where they would decide, a rule says "not checked" instead.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterator

from signalbox.model import (
    DeviceRole,
    ManagementService,
    Network,
    ServiceKind,
    SnmpVersion,
)
from signalbox.purpose import untrusted
from signalbox.rules import Result, Rule, Severity, found, incomplete, rule
from signalbox.rules._names import device_name, segment_name
from signalbox.rules.vlan import address_segment

#: Services that are insecure whenever they are on (the generic test is ``plaintext()``).
_PLAIN_KINDS = (
    ServiceKind.TELNET,
    ServiceKind.FTP,
    ServiceKind.HTTP,
    ServiceKind.TFTP,
    ServiceKind.MAC_TELNET,
)


def _join(items: list[str]) -> str:
    return ", ".join(items[:-1]) + " and " + items[-1] if len(items) > 1 else "".join(items)


def _by_device(net: Network) -> Iterator[tuple[str, list[ManagementService]]]:
    groups: dict[str, list[ManagementService]] = defaultdict(list)
    for s in net.services:
        groups[s.device_id].append(s)
    for dev, items in sorted(groups.items()):
        yield dev, sorted(items, key=lambda s: s.id)


# --- security.insecure-services (#122) -----------------------------------------------------


def _insecure(s: ManagementService) -> tuple[str, str] | None:
    """(what is wrong, what to do) for an enabled service, or None."""
    if s.kind in _PLAIN_KINDS and s.plaintext():
        if s.kind is ServiceKind.HTTP:
            return f"{s.label()} without redirect to HTTPS", "turn off HTTP or redirect it to HTTPS"
        return s.label(), f"turn off {s.label()} and use an encrypted protocol (SSH, HTTPS)"
    if s.enabled and s.kind is ServiceKind.SNMP and s.snmp is not None:
        old = [v for v in s.snmp.versions if v is not SnmpVersion.V3]
        if old and s.snmp.default_community:
            return (
                "SNMP with the default community (public or private)",
                "change the community or use SNMPv3",
            )
    if s.enabled and s.kind is ServiceKind.SSH and s.allows_root_password():
        return "SSH login of root with a password", "allow SSH keys only for root"
    return None


@rule(
    "security.insecure-services",
    "Insecure management services are on",
    Severity.WARNING,
    "Telnet, FTP, plain HTTP without redirect, SNMP v1/v2c with the default community, SSH login "
    "of root with a password and MAC telnet send passwords in clear text or are common attack "
    "targets, and several vendors turn them on by default (MikroTik: telnet, ftp, www, api, "
    "winbox; OpenWrt: HTTP and root password login). A service that is limited to a management "
    "network (the device's own address filter or listen setting) is reported as information only.",
)
def insecure_services(net: Network) -> Iterator[Result]:
    for dev, items in _by_device(net):
        groups: dict[bool, list[tuple[ManagementService, str, str]]] = defaultdict(list)
        for s in items:
            problem = _insecure(s)
            if problem is not None:
                groups[s.unrestricted()].append((s, *problem))
        name = device_name(net, dev)
        for open_, rows in sorted(groups.items(), reverse=True):
            what = _join([r[1] for r in rows])
            fix = f"On {name}: {'; '.join(dict.fromkeys(r[2] for r in rows))}."
            if open_:
                yield found(
                    f"{name} has {what} enabled",
                    [dev, *(r[0].id for r in rows)],
                    fix=fix,
                    key="open",
                )
            else:
                yield found(
                    f"{name} has {what} enabled, limited to some networks or addresses",
                    [dev, *(r[0].id for r in rows)],
                    severity=Severity.INFO,
                    fix=fix,
                    key="limited",
                )


# --- security.wan-management (#123) --------------------------------------------------------


@rule(
    "security.wan-management",
    "Management reachable from the internet",
    Severity.ERROR,
    "A gateway that offers its web interface, SSH, API or another management service on the "
    "internet side is the main way home routers get compromised; remote access is often turned "
    "on once for a fix and forgotten. The device says it (Fritz!Box remote access) or the "
    "service listens on the uplink without an address filter. Whether the firewall blocks it is "
    "not read yet, so that case is reported as not checked. Only gateways with a reported "
    "uplink are checked.",
)
def wan_management(net: Network) -> Iterator[Result]:
    for dev, items in _by_device(net):
        device = net.device(dev)
        if device is None or device.role is not DeviceRole.GATEWAY or not net.uplinks_of(dev):
            continue
        name = device_name(net, dev)
        exposed = [s for s in items if net.service_from_wan(s) is True]
        unknown = [s for s in items if net.service_from_wan(s) is None]
        if exposed:
            yield found(
                f"{name} accepts {_join([_with_port(s) for s in exposed])} from the internet",
                [dev, *(s.id for s in exposed)],
                fix=f"Turn off remote access to {name} (or restrict it to your VPN) and use a "
                "VPN for administration from outside.",
                key="exposed",
            )
        if unknown:
            yield incomplete(
                f"{name} offers {_join([_with_port(s) for s in unknown])} on its internet "
                "connection; without its firewall rules (not read yet) it is not known "
                "whether they are blocked from the internet",
                [dev, *(s.id for s in unknown)],
                key="unknown",
            )


def _with_port(s: ManagementService) -> str:
    return f"{s.label()} (port {s.port})" if s.port else s.label()


# --- security.service-exposure (#120 level 1) ----------------------------------------------


@rule(
    "security.service-exposure",
    "Management service offered in a guest or IoT network",
    Severity.ERROR,
    "A management service (web interface, SSH, telnet, API, SNMP) is offered in a guest, IoT "
    "or camera network, so guests or a compromised smart plug can try to log in. Complements "
    "security.management-exposure, which looks at addresses: this one looks at where the "
    "device says it listens. A router serves every network it has an address in; whether its "
    "firewall blocks the services there is not read yet, so that case is reported as not "
    "checked, unless the device says it offers the service in that network.",
)
def service_exposure(net: Network) -> Iterator[Result]:
    groups: dict[tuple[str, str], list[tuple[ManagementService, bool]]] = defaultdict(list)
    for s in sorted(net.services, key=lambda s: s.id):
        device = net.device(s.device_id)
        if device is None or not s.enabled:
            continue
        explicit = bool(s.segments)
        if not explicit and device.role is not DeviceRole.GATEWAY:
            continue  # a switch or AP in such a network: security.management-exposure
        for sid in net.service_segments(s):
            seg = net.segment(sid)
            if seg is None or seg.isolated or not untrusted(seg.purpose):
                continue
            groups[(s.device_id, sid)].append((s, explicit))
    for (dev, sid), items in sorted(groups.items()):
        name, where = device_name(net, dev), segment_name(net, sid)
        sure = [s for s, explicit in items if explicit]
        unsure = [s for s, explicit in items if not explicit]
        if sure:
            yield found(
                f"{name} offers {_join([s.label() for s in sure])} in {where}",
                [dev, sid, *(s.id for s in sure)],
                fix=f"Offer the services only in the LAN or a management VLAN on {name}, or "
                f"block {where} from reaching them.",
                key=f"{sid}/offered",
            )
        if unsure:
            yield incomplete(
                f"{name} has an address in {where} and offers "
                f"{_join([s.label() for s in unsure])} on it; without firewall rules (not read "
                "yet) it is not known whether they are blocked from there",
                [dev, sid, *(s.id for s in unsure)],
                key=f"{sid}/unknown",
            )


# --- security.plaintext-read (#127) --------------------------------------------------------


@rule(
    "security.plaintext-read",
    "Device managed without encryption in a network with clients",
    Severity.INFO,
    "Signalbox reads this device without encryption (NETGEAR Plus NSDP, TP-Link Easy Smart, "
    "plain HTTP), so its password can be captured by any device in the network of its "
    "management address; for such switches that is the whole admin access. Reported when the "
    "network also holds clients or Wi-Fi networks: a warning if it is a guest, IoT or camera "
    "network. A separate management network without clients is quiet.",
)
def plaintext_read(net: Network) -> Iterator[Result]:
    for d in sorted(net.devices, key=lambda d: d.id):
        if d.transport_encrypted is not False:
            continue
        sid = address_segment(net, d)
        if sid is None:
            continue
        clients = sum(1 for c in net.clients if c.segment_id == sid)
        ssids = {w.ssid for w in net.wlans if w.enabled and w.segment_id == sid}
        if not clients and not ssids:
            continue
        seg = net.segment(sid)
        bad = seg is not None and untrusted(seg.purpose)
        here = []
        if clients:
            here.append(f"{clients} client{'s' if clients != 1 else ''}")
        if ssids:
            here.append(f"{len(ssids)} Wi-Fi network{'s' if len(ssids) != 1 else ''}")
        yield found(
            f"Signalbox sends the password of {d.name} unencrypted in {segment_name(net, sid)}, "
            f"where {_join(here)} are",
            [d.id, sid],
            severity=Severity.WARNING if bad else Severity.INFO,
            fix="Move the management of the device to a separate VLAN without clients or "
            "Wi-Fi, so nobody else can capture the password.",
        )


RULES: list[Rule] = [insecure_services, wan_management, service_exposure, plaintext_read]
