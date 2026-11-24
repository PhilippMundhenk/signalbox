"""Management service rules: plaintext protocols, exposure to the internet and to untrusted
networks, and devices read without encryption (issues #122, #123, #120 level 1, #127).

They read :class:`~signalbox.model.ManagementService` (#173). A device that reported no services
has none here: an empty list means "not read", so these rules stay quiet for it. Where the
device's firewall decides (#135), :mod:`signalbox.firewall` answers; where it is not read or
cannot be evaluated exactly, a rule says "not checked" instead.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterator

from signalbox.firewall import service_from_internet, service_reach
from signalbox.model import (
    DeviceRole,
    FirewallVerdict,
    ManagementService,
    Network,
    ServiceKind,
    SnmpVersion,
    Verdict,
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
    return ", ".join(items)


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
            return f"{s.label()} (no HTTPS redirect)", ""
        return s.label(), ""
    if s.enabled and s.kind is ServiceKind.SNMP and s.snmp is not None:
        old = [v for v in s.snmp.versions if v is not SnmpVersion.V3]
        if old and s.snmp.default_community:
            return "SNMP (default community)", ""
    if s.enabled and s.kind is ServiceKind.SSH and s.allows_root_password():
        return "SSH (root password)", ""
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
            fix = (
                f"On {name}: turn off what is not needed, or restrict it to a management "
                "network; use SSH or HTTPS instead of plain text, SNMPv3 instead of a community "
                "and SSH keys only for root."
            )
            values = {"name": name, "what": what}
            if open_:
                yield found(
                    f"{name} has {what} enabled",
                    [dev, *(r[0].id for r in rows)],
                    fix=fix,
                    key="open",
                    mid="mgmt.insecure",
                    fix_id="mgmt.insecure.fix",
                    params=values,
                )
            else:
                yield found(
                    f"{name} has {what} enabled, limited to some networks or addresses",
                    [dev, *(r[0].id for r in rows)],
                    severity=Severity.INFO,
                    fix=fix,
                    key="limited",
                    mid="mgmt.insecureLimited",
                    fix_id="mgmt.insecure.fix",
                    params=values,
                )


# --- cloud.enabled (#327) ------------------------------------------------------------------

#: What each vendor cloud means, as a message id (the text is in the catalogues).
_CLOUD_MESSAGES = {
    "myfritz-cloud": "cloud.myfritz",
    "mikrotik-cloud": "cloud.mikrotik",
    "omada-cloud": "cloud.omada",
}
_CLOUD_TEXTS = {
    "myfritz-cloud": "AVM's MyFRITZ! relays access to its web interface and home network from "
    "the internet and keeps a dynamic DNS name for it",
    "mikrotik-cloud": "it reports its public address to MikroTik for a dynamic DNS name (and "
    "relays Back to Home VPN connections)",
    "omada-cloud": "the controller keeps a connection to TP-Link's cloud, so it can be managed "
    "from outside with a TP-Link ID",
}


@rule(
    "cloud.enabled",
    "Vendor cloud management is on",
    Severity.INFO,
    "MyFRITZ! (Fritz!Box), MikroTik Cloud (`/ip/cloud`) and Omada Cloud access (controller "
    "setting) connect the device to its vendor's servers: the vendor then knows the device and "
    "its public address, and a vendor account can be a way to manage it from the internet. "
    "Often wanted for remote access or a dynamic DNS name, often forgotten; the check only "
    "says that it is on and what it means, and does not judge it. Reported once per device "
    "and service.",
)
def cloud_enabled(net: Network) -> Iterator[Result]:
    for dev, items in _by_device(net):
        name = device_name(net, dev)
        for s in items:
            if s.kind is not ServiceKind.CLOUD or not s.enabled:
                continue
            service = s.label()
            meaning = _CLOUD_TEXTS.get(s.name or "", "it is managed through the vendor's cloud")
            yield found(
                f"{name} has {service} turned on: {meaning}",
                [dev, s.id],
                key=s.id,
                mid=_CLOUD_MESSAGES.get(s.name or "", "cloud.enabled"),
                params={"name": name, "service": service},
            )


# --- security.wan-management (#123) --------------------------------------------------------


@rule(
    "security.wan-management",
    "Management reachable from the internet",
    Severity.ERROR,
    "A gateway that offers its web interface, SSH, API or another management service on the "
    "internet side is the main way home routers get compromised; remote access is often turned "
    "on once for a fix and forgotten. The device says it (Fritz!Box remote access) or the "
    "service listens on the uplink without an address filter and its firewall lets the internet "
    "in. Where the firewall is not read or does not decide exactly, the case is reported as not "
    "checked. Only gateways with a reported uplink are checked.",
)
def wan_management(net: Network) -> Iterator[Result]:
    for dev, items in _by_device(net):
        device = net.device(dev)
        if device is None or device.role is not DeviceRole.GATEWAY or not net.uplinks_of(dev):
            continue
        name = device_name(net, dev)
        verdicts = {s.id: service_from_internet(net, s) for s in items}
        exposed = [s for s in items if verdicts[s.id].verdict is Verdict.ALLOWED]
        unknown = [s for s in items if verdicts[s.id].verdict is Verdict.UNKNOWN]
        if exposed:
            yield found(
                f"{name} accepts {_join([_with_port(s) for s in exposed])} from the internet",
                [dev, *(s.id for s in exposed)],
                fix=f"Turn off remote access to {name} (or restrict it to your VPN) and use a "
                "VPN for administration from outside.",
                key="exposed",
                mid="mgmt.wanExposed",
                fix_id="mgmt.wanExposed.fix",
                params={"name": name, "services": _join([_with_port(s) for s in exposed])},
            )
        if unknown:
            yield incomplete(
                f"{name} offers {_join([_with_port(s) for s in unknown])} on its internet "
                f"connection; {_why_unknown(net, dev, [verdicts[s.id] for s in unknown])} "
                "whether they are blocked from the internet",
                [dev, *(s.id for s in unknown)],
                key="unknown",
                mid="mgmt.wanUnknownNoFirewall"
                if net.firewall_of(dev) is None
                else "mgmt.wanUnknown",
                params={
                    "name": name,
                    "services": _join([_with_port(s) for s in unknown]),
                    "reasons": "; ".join(dict.fromkeys(verdicts[s.id].reason for s in unknown)),
                },
            )


def _why_unknown(net: Network, dev: str, verdicts: list[FirewallVerdict]) -> str:
    if net.firewall_of(dev) is None:
        return "without its firewall rules (not read) it is not known"
    reasons = list(dict.fromkeys(v.reason for v in verdicts))
    return f"its firewall does not decide it exactly ({'; '.join(reasons)}), so it is not known"


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
    "device says it listens. A router serves every network it has an address in unless its "
    "firewall blocks the services there; where the firewall is not read or does not decide "
    "exactly, that case is reported as not checked.",
)
def service_exposure(net: Network) -> Iterator[Result]:
    groups: dict[tuple[str, str], list[tuple[ManagementService, FirewallVerdict | None]]] = (
        defaultdict(list)
    )
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
            verdict = service_reach(net, s, sid)
            if verdict.verdict is Verdict.DENIED:
                continue
            decided = explicit or verdict.verdict is Verdict.ALLOWED
            groups[(s.device_id, sid)].append((s, None if decided else verdict))
    for (dev, sid), items in sorted(groups.items()):
        name, where = device_name(net, dev), segment_name(net, sid)
        sure = [s for s, v in items if v is None]
        unsure = [s for s, v in items if v is not None]
        if sure:
            yield found(
                f"{name} offers {_join([s.label() for s in sure])} in {where}",
                [dev, sid, *(s.id for s in sure)],
                fix=f"Offer the services only in the LAN or a management VLAN on {name}, or "
                f"block {where} from reaching them.",
                key=f"{sid}/offered",
                mid="mgmt.offered",
                fix_id="mgmt.offered.fix",
                params={
                    "name": name,
                    "services": _join([s.label() for s in sure]),
                    "segment": where,
                },
            )
        if unsure:
            why = _why_unknown(net, dev, [v for _, v in items if v is not None])
            yield incomplete(
                f"{name} has an address in {where} and offers "
                f"{_join([s.label() for s in unsure])} on it; {why} whether they are blocked "
                "from there",
                [dev, sid, *(s.id for s in unsure)],
                key=f"{sid}/unknown",
                mid="mgmt.offeredUnknownNoFirewall"
                if net.firewall_of(dev) is None
                else "mgmt.offeredUnknown",
                params={
                    "name": name,
                    "segment": where,
                    "services": _join([s.label() for s in unsure]),
                    "reasons": "; ".join(
                        dict.fromkeys(v.reason for _, v in items if v is not None)
                    ),
                },
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
            here.append(f"clients: {clients}")
        if ssids:
            here.append(f"Wi-Fi networks: {len(ssids)}")
        yield found(
            f"Signalbox sends the password of {d.name} unencrypted in {segment_name(net, sid)} "
            f"({_join(here)})",
            [d.id, sid],
            severity=Severity.WARNING if bad else Severity.INFO,
            fix="Move the management of the device to a separate VLAN without clients or "
            "Wi-Fi, so nobody else can capture the password.",
            mid="mgmt.plaintext.both"
            if clients and ssids
            else "mgmt.plaintext.clients"
            if clients
            else "mgmt.plaintext.ssids",
            fix_id="mgmt.plaintext.fix",
            params={
                "name": d.name,
                "segment": segment_name(net, sid),
                "clients": clients,
                "ssids": len(ssids),
            },
        )


RULES: list[Rule] = [
    insecure_services,
    wan_management,
    service_exposure,
    plaintext_read,
    cloud_enabled,
]
