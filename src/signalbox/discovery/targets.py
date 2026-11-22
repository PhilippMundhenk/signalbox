"""Which addresses a discovery run probes: only networks Signalbox already knows, or what the
user typed (#203). A pure function of the network model and the input, so it is easy to test
and to show the user beforehand.

From the devices already added:

- **gateway subnets** (``Subnet.gateway``) of IPv4 with a prefix of ``sweep_prefix`` (/24) or
  longer: every address; larger ones and IPv6: only the gateway address;
- **clients and DHCP reservations** (their IPv4 addresses) and **LLDP neighbours** (their
  management address).

Infrastructure is probed first: gateways, neighbours, and clients whose MAC belongs to a
vendor of a supported integration (:data:`VENDOR_OUIS`) or whose host name looks like a
network device. The order only decides how soon a device shows up; every planned address is
probed.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from ipaddress import IPv4Address, IPv4Network, IPv6Address

from signalbox.model import Network

Address = IPv4Address | IPv6Address
Add = Callable[..., None]

#: Priorities, lowest first.
INFRASTRUCTURE, USER, CLIENT, SWEEP = 0, 1, 2, 3

#: MAC prefixes (OUI) of vendors with a built-in integration: AVM, MikroTik, TP-Link, NETGEAR,
#: PC Engines (APU boards that often run OPNsense or OpenWrt). A short list, only used to
#: probe those clients first; a missing prefix only costs a few seconds.
VENDOR_OUIS = frozenset(
    {
        # AVM
        "00:04:0e", "08:96:d7", "1c:ed:6f", "2c:3a:fd", "2c:91:ab", "34:31:c4", "38:10:d5",
        "3c:a6:2f", "44:4e:6d", "5c:49:79", "7c:ff:4d", "98:9b:cb", "9c:c7:a6", "b0:f2:08",
        "bc:05:43", "c0:25:06", "c8:0e:14", "cc:ce:1e", "dc:15:c8", "dc:39:6f", "e0:28:6d",
        "e8:df:70", "f0:b0:14",
        # MikroTik
        "00:0c:42", "18:fd:74", "2c:c8:1b", "48:8f:5a", "4c:5e:0c", "64:d1:54", "6c:3b:6b",
        "74:4d:28", "b8:69:f4", "cc:2d:e0", "d4:ca:6d", "dc:2c:6e", "e4:8d:8c",
        # TP-Link
        "14:eb:b6", "30:de:4b", "50:c7:bf", "54:af:97", "5c:a6:e6", "60:32:b1", "98:da:c4",
        "a8:42:a1", "b0:4e:26", "e8:48:b8",
        # NETGEAR
        "00:14:6c", "00:1e:2a", "20:4e:7f", "28:c6:8e", "3c:37:86", "44:94:fc", "6c:b0:ce",
        "84:1b:5e", "a0:40:a0", "c4:04:15", "e0:91:f5",
        # PC Engines
        "00:0d:b9",
    }
)  # fmt: skip

_NETWORK_NAME = re.compile(
    r"fritz|openwrt|lede|mikrotik|routeros|opnsense|pfsense|omada|router|gateway|switch|"
    r"(^|[-_.])(ap|eap|gw|sw)\d*($|[-_.])|^(gs|tl-sg|sg|crs|css|rb|hap|cap)\d",
    re.IGNORECASE,
)
_HOSTNAME = re.compile(
    r"^(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$",
    re.IGNORECASE,
)


class RangeError(ValueError):
    """An address or range the user typed cannot be probed; the message says why."""


@dataclass(frozen=True)
class Target:
    address: str
    #: Why it is probed, for the user ("subnet 192.0.2.0/24 of Main router").
    why: str
    priority: int
    #: The address is a router's own address in one of its subnets.
    gateway: bool = False


@dataclass
class Plan:
    targets: list[Target] = field(default_factory=list)
    #: What will be probed, one line per source, for the user.
    scope: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def infrastructure(mac: str | None, hostname: str | None) -> bool:
    """Looks like a network device: a supported vendor's MAC or a network-ish host name."""
    if mac and mac.lower()[:8] in VENDOR_OUIS:
        return True
    return bool(hostname and _NETWORK_NAME.search(hostname))


def _probeable(ip: object) -> bool:
    if not isinstance(ip, IPv4Address | IPv6Address):
        return False
    return not (
        ip.is_multicast
        or ip.is_unspecified
        or ip == IPv4Address("255.255.255.255")
        or (isinstance(ip, IPv6Address) and ip.is_link_local)
    )


def parse_range(text: str, max_hosts: int) -> list[str]:
    """Addresses of one entry the user typed: an address, a host name, a CIDR network
    (``192.0.2.0/28``) or an IPv4 range (``192.0.2.10-192.0.2.20`` or ``192.0.2.10-20``)."""
    value = text.strip()
    if not value:
        raise RangeError("empty entry")
    if "/" in value:
        try:
            net = ipaddress.ip_network(value, strict=False)
        except ValueError:
            raise RangeError(f"{value}: not a network (example: 192.0.2.0/24)") from None
        if net.num_addresses > max_hosts + 2:
            raise RangeError(f"{value}: {net.num_addresses} addresses, at most {max_hosts}")
        hosts = list(net.hosts()) if net.num_addresses > 2 else list(net)
        return [str(ip) for ip in hosts if _probeable(ip)]
    if "-" in value and _is_ipv4(value.partition("-")[0]):
        return _span(value, max_hosts)
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        if _HOSTNAME.match(value):
            return [value.lower()]
        raise RangeError(f"{value}: not an address, network, range or host name") from None
    if not _probeable(ip):
        raise RangeError(f"{value}: multicast, broadcast and unspecified addresses are not probed")
    return [str(ip)]


def _is_ipv4(text: str) -> bool:
    try:
        IPv4Address(text.strip())
    except ValueError:
        return False
    return True


def _span(value: str, max_hosts: int) -> list[str]:
    first_text, _, last_text = value.partition("-")
    try:
        first = IPv4Address(first_text.strip())
        last_text = last_text.strip()
        if last_text.isdigit():
            last = IPv4Address(f"{first_text.strip().rsplit('.', 1)[0]}.{last_text}")
        else:
            last = IPv4Address(last_text)
    except ValueError:
        raise RangeError(f"{value}: not an IPv4 range (example: 192.0.2.10-192.0.2.20)") from None
    if last < first:
        raise RangeError(f"{value}: the range ends before it starts")
    count = int(last) - int(first) + 1
    if count > max_hosts:
        raise RangeError(f"{value}: {count} addresses, at most {max_hosts}")
    return [str(IPv4Address(n)) for n in range(int(first), int(last) + 1)]


def plan(
    net: Network,
    ranges: list[str],
    *,
    known_networks: bool = True,
    sweep_prefix: int = 24,
    max_hosts: int = 1024,
) -> Plan:
    """The addresses to probe, infrastructure first. Raises RangeError for bad input."""
    found: dict[str, Target] = {}
    out = Plan()

    def add(address: str, why: str, priority: int, gateway: bool = False) -> None:
        old = found.get(address)
        new = Target(address, why, priority, gateway)
        if old is not None:
            best = old if old.priority <= priority else new
            new = replace(best, gateway=old.gateway or gateway)
        found[address] = new

    for entry in ranges:
        addresses = parse_range(entry, max_hosts)
        out.scope.append(f"{entry.strip()}: {len(addresses)} address(es) you entered")
        for address in addresses:
            add(address, "entered by you", USER)
    if known_networks:
        _known(net, add, out, sweep_prefix)
    targets = sorted(found.values(), key=lambda t: (t.priority, sort_key(t.address)))
    if len(targets) > max_hosts:
        out.notes.append(
            f"{len(targets)} addresses known, only the first {max_hosts} are probed "
            "(infrastructure first). Enter a smaller range to probe the rest."
        )
        targets = targets[:max_hosts]
    out.targets = targets
    return out


def _known(net: Network, add: Add, out: Plan, sweep_prefix: int) -> None:
    names = {d.id: d.name for d in net.devices}
    for sub in net.subnets:
        if not sub.gateway:
            continue
        owner = names.get(sub.device_id, sub.device_id)
        gw = sub.interface.ip
        if not _probeable(gw):
            continue
        add(str(gw), f"gateway of {sub.interface.network} ({owner})", INFRASTRUCTURE, True)
        network = sub.interface.network
        if isinstance(network, IPv4Network) and network.prefixlen >= sweep_prefix:
            hosts = [h for h in network.hosts() if h != gw]
            for host in hosts:
                add(str(host), f"subnet {network} of {owner}", SWEEP)
            out.scope.append(f"{network} of {owner}: every address ({len(hosts) + 1})")
        else:
            out.scope.append(
                f"{network} of {owner}: only the gateway and known clients "
                f"(larger than /{sweep_prefix} or IPv6)"
            )
    clients = 0
    for client in net.clients:
        infra = infrastructure(client.mac, client.hostname)
        for ip in client.addresses:
            if isinstance(ip, IPv4Address) and _probeable(ip):
                clients += 1
                label = client.hostname or client.mac
                add(str(ip), f"client {label}", INFRASTRUCTURE if infra else CLIENT)
    for server in net.dhcp_servers:
        for res in server.reservations:
            if isinstance(res.address, IPv4Address) and _probeable(res.address):
                clients += 1
                infra = infrastructure(res.mac, res.hostname)
                label = res.hostname or res.mac
                add(str(res.address), f"DHCP lease {label}", INFRASTRUCTURE if infra else CLIENT)
    neighbours = 0
    for n in net.neighbours:
        try:
            mgmt = ipaddress.ip_address(n.management_address or "")
        except ValueError:
            continue
        if _probeable(mgmt):
            neighbours += 1
            add(str(mgmt), f"LLDP neighbour {n.system_name or n.chassis_id}", INFRASTRUCTURE)
    if clients:
        out.scope.append(f"{clients} client and DHCP lease address(es) of added routers")
    if neighbours:
        out.scope.append(f"{neighbours} LLDP neighbour(s)")


def sort_key(address: str) -> tuple[int, int, str]:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return (2, 0, address)
    return (ip.version, int(ip), "")
