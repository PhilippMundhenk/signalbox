"""Client rules: host names and randomised MAC addresses (issues #82, #83)."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterator

from signalbox.model import Client, Network
from signalbox.rules import Result, Rule, Severity, found, rule
from signalbox.rules._names import segment_name

#: Names that many devices use for themselves: two of them on one network say nothing.
GENERIC_HOSTNAMES = frozenset(
    {
        "android",
        "espressif",
        "esp32",
        "esp8266",
        "ipad",
        "iphone",
        "localhost",
        "none",
        "unknown",
        "*",
    }
)


def is_randomised(mac: str) -> bool:
    """True for a locally administered MAC: the second-lowest bit of the first octet is set.

    Phones, tablets and laptops use such addresses as "private Wi-Fi address" and rotate them;
    virtual machines and containers use them too, but keep them.
    """
    return bool(int(mac[:2], 16) & 0x02)


def _short_name(hostname: str | None, mac: str) -> str | None:
    """Host name without domain, lower case; None for empty, generic or MAC-like names."""
    if not hostname:
        return None
    name = hostname.strip().lower().rstrip(".").split(".")[0]
    digits = "".join(c for c in name if c not in ":-_")
    if not name or name in GENERIC_HOSTNAMES or digits == mac.replace(":", ""):
        return None
    return name


def _domains(net: Network) -> dict[str, str]:
    """Segment -> DNS domain its DHCP server hands out, where exactly one is known."""
    seen: dict[str, set[str]] = defaultdict(set)
    for srv in net.dhcp_servers:
        if srv.enabled and srv.domain:
            seen[srv.segment_id].add(srv.domain.strip().lower().rstrip("."))
    return {seg: next(iter(d)) for seg, d in seen.items() if len(d) == 1}


@rule(
    "clients.duplicate-hostname",
    "Two devices use the same host name",
    Severity.WARNING,
    "Local DNS (Unbound, dnsmasq, the router) registers devices by the name they announce. When "
    "two devices on one network call themselves the same, only one of them is reachable by that "
    "name and the name flips between them: remote access, printing or backups go to the wrong "
    "machine. Often a cloned SD card or virtual machine, or two devices with their factory name. "
    "Generic names such as 'android' or 'iphone' are ignored.",
)
def duplicate_hostname(net: Network) -> Iterator[Result]:
    domains = _domains(net)
    groups: dict[tuple[str, str], list[Client]] = defaultdict(list)
    for client in net.clients:
        name = _short_name(client.hostname, client.mac)
        if name is None or client.segment_id is None:
            continue
        # networks that share a DNS domain share the names in it
        domain = domains.get(client.segment_id)
        scope = f"domain {domain}" if domain else client.segment_id
        groups[(scope, name)].append(client)
    for (scope, name), clients in sorted(groups.items()):
        macs = sorted({c.mac for c in clients})
        if len(macs) < 2:
            continue
        segments = sorted({str(c.segment_id) for c in clients})
        where = ", ".join(segment_name(net, s) for s in segments)
        if len(segments) > 1:
            where = f"networks sharing the {scope} ({where})"
        shared = len(segments) > 1
        names = ", ".join(segment_name(net, s) for s in segments)
        message = f"{len(macs)} devices on {where} call themselves {name} ({', '.join(macs)})"
        values: dict[str, str | int] = {
            "count": len(macs),
            "name": name,
            "macs": ", ".join(macs),
            "where": names,
            "domain": scope.removeprefix("domain "),
        }
        if any(is_randomised(m) for m in macs):
            yield found(
                message + ". This may be one device that uses a private (randomised) Wi-Fi "
                "address next to its real one",
                sorted(c.id for c in clients),
                fix="If these are different devices, rename one of them. If it is one phone or "
                "laptop, nothing is wrong; turn off its private address for this network if it "
                "should keep one name and address.",
                severity=Severity.INFO,
                key=f"{scope}:{name}",
                mid="clients.duplicateName.random.shared" if shared else "clients.duplicateName.random",
                fix_id="clients.duplicateName.random.fix",
                params=values,
            )
        else:
            yield found(
                message,
                sorted(c.id for c in clients),
                fix="Rename one of them (in its own settings, not only on the router).",
                key=f"{scope}:{name}",
                mid="clients.duplicateName.shared" if shared else "clients.duplicateName",
                fix_id="clients.duplicateName.fix",
                params=values,
            )


@rule(
    "clients.random-mac",
    "DHCP reservation or DNS name for a randomised MAC address",
    Severity.WARNING,
    "Phones, tablets and laptops use a private (randomised) MAC address per Wi-Fi network by "
    "default (Android 10, iOS 14, Windows 11 and later) and change it from time to time. A DHCP "
    "reservation or a DNS name for such an address works until the device picks a new one; "
    "then it gets another address and port forwards, firewall rules and parental controls stop "
    "applying to it. Virtual machines and containers use such addresses too, but keep them. "
    "The share of randomised addresses per network is shown for information: it explains why "
    "client lists grow and reservations do not stick.",
)
def random_mac(net: Network) -> Iterator[Result]:
    reservations: dict[tuple[str, str], list[str]] = defaultdict(list)
    labels: dict[tuple[str, str], str] = {}
    parts: dict[tuple[str, str], dict[str, str | int]] = {}
    for srv in net.dhcp_servers:
        for res in srv.reservations:
            if not is_randomised(res.mac):
                continue
            k = (res.mac, str(res.address))
            reservations[k].append(srv.id)
            host = f" ({res.hostname})" if res.hostname else ""
            labels.setdefault(k, f"{res.address}{host} on {segment_name(net, srv.segment_id)}")
            parts[k] = {
                "address": str(res.address),
                "host": host,
                "segment": segment_name(net, srv.segment_id),
            }
    for (mac, address), servers in sorted(reservations.items()):
        yield found(
            f"The reservation {labels[(mac, address)]} is for a randomised MAC address ({mac})",
            sorted(set(servers)),
            fix="Turn off the private (random) address for this network on the device, then "
            "reserve its real MAC. If it is a virtual machine or container that keeps this "
            "address, nothing is wrong.",
            key=f"reservation:{mac}:{address}",
            mid="clients.randomReservation",
            fix_id="clients.randomReservation.fix",
            params={**parts[(mac, address)], "mac": mac},
        )

    by_address: dict[str, list[Client]] = defaultdict(list)
    for client in net.clients:
        for addr in client.addresses:
            if not addr.is_link_local:
                by_address[str(addr)].append(client)
    for dns in net.dns_services:
        for rec in dns.host_records:
            randomised = [c for c in by_address.get(str(rec.address), []) if is_randomised(c.mac)]
            if not randomised:
                continue
            macs = ", ".join(sorted(c.mac for c in randomised))
            yield found(
                f"The DNS name {rec.name} points to {rec.address}, which a device with a "
                f"randomised MAC address uses ({macs})",
                [dns.id, *sorted(c.id for c in randomised)],
                fix="Turn off the private (random) address for this network on the device and "
                "reserve its real MAC, so that the name keeps pointing to it.",
                key=f"dns:{rec.name}:{rec.address}",
                mid="clients.randomDns",
                fix_id="clients.randomDns.fix",
                params={"name": rec.name, "address": str(rec.address), "macs": macs},
            )

    per_segment: dict[str, list[Client]] = defaultdict(list)
    for client in net.clients:
        if client.segment_id is not None:
            per_segment[client.segment_id].append(client)
    for seg, clients in sorted(per_segment.items()):
        n = sum(is_randomised(c.mac) for c in clients)
        if n == 0:
            continue
        yield found(
            f"{n} of {len(clients)} known clients on {segment_name(net, seg)} "
            f"{'uses' if n == 1 else 'use'} a randomised MAC address "
            f"({round(100 * n / len(clients))} %)",
            [seg],
            mid="clients.randomShare",
            fix_id="clients.randomShare.fix",
            params={
                "count": n,
                "total": len(clients),
                "segment": segment_name(net, seg),
                "percent": round(100 * n / len(clients)),
            },
            fix="Nothing to fix. A device that must keep its address, name or parental controls "
            "needs its private address turned off for this network.",
            severity=Severity.INFO,
            key=f"share:{seg}",
        )


RULES: list[Rule] = [duplicate_hostname, random_mac]
