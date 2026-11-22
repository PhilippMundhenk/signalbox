"""WAN uplink rules: carrier-grade NAT, uplink down, provider DNS, unused IPv6 prefix (#148).

They read :class:`~signalbox.model.Uplink` and only act on uplinks a gateway reported: an empty
list means the integration does not read uplinks, not that the site has no internet. Double NAT
is ``addr.double-nat`` (#60).
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterator
from ipaddress import IPv4Network, IPv6Network, ip_address, ip_network

from signalbox.model import IPAddress, NatClass, Network, Uplink, UplinkKind
from signalbox.rules import Result, Rule, Severity, found, incomplete, rule
from signalbox.rules._names import device_name, router_subnets, site_of_device

_GLOBAL = ip_network("2000::/3")


def _label(net: Network, up: Uplink, *, start: bool = False) -> str:
    """``the internet connection (pppoe-out1) of Router`` (``The …`` at the start)."""
    name = f" ({up.name})" if up.name else ""
    text = f"internet connection{name} of {device_name(net, up.device_id)}"
    return f"{'The' if start else 'the'} {text}"


def _in(address: IPAddress, network: IPv4Network | IPv6Network) -> bool:
    return address.version == network.version and address in network


def _connected(up: Uplink) -> bool:
    """Reported up, or not said: a down uplink keeps stale addresses."""
    return up.up is not False


def _by_site(net: Network) -> dict[str | None, list[Uplink]]:
    out: dict[str | None, list[Uplink]] = defaultdict(list)
    for up in net.uplinks:
        out[site_of_device(net, up.device_id)].append(up)
    return out


def _has_ipv6(up: Uplink) -> bool:
    return bool(up.ipv6() or up.delegated_prefixes)


@rule(
    "wan.cgnat",
    "Internet connection is behind carrier-grade NAT",
    Severity.INFO,
    "The provider does not give the router an IPv4 address of its own on the internet: it shares "
    "one address among many customers (carrier-grade NAT, 100.64.0.0/10, or DS-Lite). Outgoing "
    "connections work, but nothing on the internet can connect in over IPv4: port forwards, a "
    "VPN server at home and remote access to cameras or a NAS do not work.",
)
def cgnat(net: Network) -> Iterator[Result]:
    for _site, uplinks in sorted(_by_site(net).items(), key=lambda i: i[0] or ""):
        live = [u for u in uplinks if _connected(u)]
        if any(u.nat_class() is NatClass.PUBLIC for u in live):
            continue  # another line of the site has a public IPv4: forwards work there
        for up in sorted(live, key=lambda u: u.id):
            if up.nat_class() is NatClass.CGNAT:
                if net.upstream_router(up) is not None:
                    continue  # a known router of the site uses that range: double NAT (#60)
                how = "carrier-grade NAT"
            elif up.kind is UplinkKind.DSLITE:
                how = "DS-Lite (IPv4 through the provider's carrier-grade NAT)"
            else:
                continue
            if _has_ipv6(up):
                fix = (
                    "Reach the devices at home over IPv6 (open the port for IPv6 in the "
                    "firewall), or ask the provider for a public IPv4 address."
                )
            else:
                fix = (
                    "Ask the provider for a public IPv4 address (or IPv6), or use a VPN or "
                    "tunnel service that connects outwards."
                )
            yield found(
                f"{_label(net, up, start=True)} is behind {how}: "
                "connections from the internet over IPv4 cannot reach the site",
                [up.id],
                fix=fix,
            )


@rule(
    "wan.down",
    "Internet connection is down",
    Severity.WARNING,
    "A gateway reports that one of its internet connections is not connected (no address, no "
    "PPP session). With no other connection, the site is offline; with a backup line, the site "
    "runs on the backup.",
)
def down(net: Network) -> Iterator[Result]:
    for dev_id in sorted({u.device_id for u in net.uplinks}):
        uplinks = net.uplinks_of(dev_id)
        working = sorted(u.name or u.id for u in uplinks if u.up is True)
        for up in sorted(uplinks, key=lambda u: u.id):
            if up.up is not False:
                continue
            label = _label(net, up, start=True)
            if working:
                yield found(
                    f"{label} is down; the internet works through {', '.join(working)}",
                    [up.id],
                    fix="Check the cable or modem of this line, and the account details if it "
                    "logs in (PPPoE). Turn the rule off for this line if it is a standby line.",
                    severity=Severity.INFO,
                )
            else:
                yield found(
                    f"{label} is down",
                    [up.id],
                    fix="Check the cable and the modem, the account details if it logs in "
                    "(PPPoE), and whether the provider reports an outage.",
                )


def _known(net: Network) -> set[IPAddress]:
    """Addresses used by a device, DNS service or client Signalbox knows."""
    out: set[IPAddress] = set()
    for dev in net.devices:
        try:
            if dev.management_address:
                out.add(ip_address(dev.management_address))
        except ValueError:
            pass
    out |= {s.interface.ip for s in net.subnets}
    out |= {a for d in net.dns_services for a in d.listen}
    out |= {a for c in net.clients for a in c.addresses}
    return out


@rule(
    "wan.dns-mismatch",
    "Router forwards DNS to an address the provider no longer hands out",
    Severity.INFO,
    "The router forwards DNS lookups to an address on the network of its internet connection "
    "(the provider's or the modem's side), but the provider now hands out other DNS servers "
    "there and no known device uses that address. Typical after a modem or provider change: "
    "the old address was typed in and now answers slowly or not at all. Forwarding to any "
    "other resolver (a public one, a Pi-hole, a filter) is a choice and not reported.",
)
def dns_mismatch(net: Network) -> Iterator[Result]:
    known = _known(net)
    for up in sorted(net.uplinks, key=lambda u: u.id):
        if not _connected(up) or not up.dns_servers:
            continue
        own = {a.ip for a in up.addresses}
        networks = [a.network for a in up.addresses if not a.is_link_local]
        handed = set(up.dns_servers)
        for dns in sorted(net.dns_services, key=lambda d: d.id):
            if dns.device_id != up.device_id or not dns.enabled:
                continue
            for fwd in dns.forwarders:
                if fwd in handed or fwd in own or fwd == up.upstream_gateway or fwd in known:
                    continue
                if not any(_in(fwd, n) for n in networks):
                    continue
                servers = ", ".join(
                    str(a) for a in sorted(handed, key=lambda a: (a.version, int(a)))
                )
                yield found(
                    f"{device_name(net, dns.device_id)} forwards DNS to {fwd} on the network "
                    f"of {_label(net, up)}, but the provider hands out {servers}",
                    [dns.id, up.id],
                    fix=f"Forward to the DNS servers the provider hands out ({servers}), or to "
                    "a resolver you chose, instead of the old address.",
                    key=str(fwd),
                )


@rule(
    "wan.no-ipv6",
    "Provider gives IPv6, but no network uses it",
    Severity.INFO,
    "The provider delegated an IPv6 prefix to the router, but none of the site's networks with "
    "clients has a global IPv6 subnet. Devices only use IPv4, through NAT, although the line "
    "has native IPv6: no direct reachability from the internet (useful behind carrier-grade "
    "NAT) and some services are slower. ``ipv6.partial`` reports a site where only some "
    "networks have IPv6.",
)
def no_ipv6(net: Network) -> Iterator[Result]:
    used = {w.segment_id for w in net.wlans if w.enabled and w.segment_id}
    used |= {c.segment_id for c in net.clients if c.segment_id}
    routers = router_subnets(net)
    for site, uplinks in sorted(_by_site(net).items(), key=lambda i: i[0] or ""):
        with_prefix = [u for u in uplinks if _connected(u) and u.delegated_prefixes]
        if not with_prefix or site is None:
            continue
        subs = [s for s in routers if site_of_device(net, s.device_id) == site]
        clients = {s.segment_id for s in subs if s.segment_id in used}
        if not clients:
            continue  # no network with clients known: nothing to compare
        if any(_in(s.interface.ip, _GLOBAL) for s in subs if s.segment_id in clients) or any(
            _in(s.interface.ip, p) for s in subs for u in with_prefix for p in u.delegated_prefixes
        ):
            continue  # IPv6 from this or another prefix (ipv6.partial covers the rest)
        for up in sorted(with_prefix, key=lambda u: u.id):
            prefixes = ", ".join(f"/{p.prefixlen}" for p in up.delegated_prefixes)
            if not any(s.interface.version == 6 for s in subs if s.device_id == up.device_id):
                yield incomplete(
                    f"{_label(net, up, start=True)} has a delegated IPv6 "
                    f"prefix ({prefixes}), but {device_name(net, up.device_id)} reported no "
                    "IPv6 on its networks, so it is not known whether they use it",
                    [up.id],
                )
                continue
            yield found(
                f"{_label(net, up, start=True)} has a delegated IPv6 "
                f"prefix ({prefixes}), but no network with clients has IPv6 from it",
                [up.id],
                fix="Give each client network a /64 from the delegated prefix (router "
                "advertisements on), or turn this rule off if IPv6 stays off on purpose.",
            )


RULES: list[Rule] = [cgnat, down, dns_mismatch, no_ipv6]
