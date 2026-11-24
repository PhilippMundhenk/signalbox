"""Log and monitoring target rules (#180): targets nobody answers at, and sites whose devices
log to different places.

They read :attr:`~signalbox.model.Device.log_targets`. A device whose targets were not read
(``None``) is left out; an empty list means it sends nothing anywhere. SNMP v1/v2c with a
default community is :mod:`signalbox.rules.management` (``security.insecure-services``).
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterator

from signalbox.model import Device, DeviceStatus, IPAddress, LogKind, LogTarget, Network
from signalbox.rules import Result, Rule, Severity, found, incomplete, rule
from signalbox.rules._names import segment_name
from signalbox.rules.dns import _Index, _local_segment
from signalbox.rules.time_checks import LOCAL_RANGES

#: Kinds whose target must answer for the data to arrive somewhere.
_CHECKED = (LogKind.SYSLOG, LogKind.NETFLOW, LogKind.IPFIX, LogKind.SFLOW, LogKind.SNMP_TRAP)
_LABELS = {
    LogKind.SYSLOG: "syslog",
    LogKind.NETFLOW: "NetFlow",
    LogKind.IPFIX: "IPFIX",
    LogKind.SFLOW: "sFlow",
    LogKind.SNMP_TRAP: "SNMP traps",
    LogKind.METRICS: "metrics",
    LogKind.OTHER: "logs",
}


def _site_name(net: Network, site: str) -> str:
    return next((s.name for s in net.sites if s.id == site), site)


def _logging(net: Network) -> Iterator[tuple[Device, list[LogTarget]]]:
    for dev in sorted(net.devices, key=lambda d: d.id):
        if dev.log_targets is not None:
            yield dev, dev.log_targets


def _private(address: IPAddress) -> bool:
    return any(address in r for r in LOCAL_RANGES if r.version == address.version)


def _tunnelled(net: Network, address: IPAddress) -> bool:
    """Behind a VPN tunnel: inside the networks some peer routes (full tunnels excluded)."""
    for t in net.tunnels:
        for p in t.peers:
            for n in t.remote_networks(p):
                if n.prefixlen and n.version == address.version and address in n:
                    return True
    return False


def _site_complete(net: Network, site: str) -> bool:
    """Every device of the site was read: an address outside its networks means something."""
    return all(
        net.statuses.get(d.id, DeviceStatus.OK) in (DeviceStatus.OK, DeviceStatus.PARTIAL)
        for d in net.devices
        if d.site_id == site
    )


# --- log.target-unknown -------------------------------------------------------------------


@rule(
    "log.target-unknown",
    "Logs are sent to an address nobody uses",
    Severity.WARNING,
    "A device that sends its syslog, flow records or SNMP traps to a private address outside "
    "every known network, or to an address in a known network that no device or client uses, "
    "most likely still points to an old collector: its messages are lost, and nobody notices "
    "until they are needed. Host names, public addresses outside the known networks and "
    "addresses behind a VPN tunnel are not checked; an unused address is only reported where "
    "clients are read for that network.",
)
def target_unknown(net: Network) -> Iterator[Result]:
    idx = _Index.of(net)
    for dev, targets in _logging(net):
        for t in targets:
            address = t.ip()
            if not t.enabled or t.kind not in _CHECKED or address is None:
                continue
            if address.is_loopback or _tunnelled(net, address):
                continue
            what = _LABELS[t.kind]
            params = {"device": dev.name, "what": what, "target": t.endpoint()}
            seg = _local_segment(net, None, address)
            if seg is None:
                if not _private(address):
                    continue  # a public collector or one at another site: not checked
                if not _site_complete(net, dev.site_id):
                    yield incomplete(
                        f"{dev.name} sends {what} to {t.endpoint()}, which is in no known "
                        "network; not every device of the site was read",
                        [dev.id],
                        key=t.endpoint(),
                        mid="log.targetUnchecked",
                        params=params,
                    )
                    continue
                yield found(
                    f"{dev.name} sends {what} to {t.endpoint()}, which is in no known network",
                    [dev.id],
                    fix="Point the target to the address of your log collector, or remove it "
                    "if there is none any more.",
                    key=t.endpoint(),
                    mid="log.targetOutside",
                    fix_id="log.target.fix",
                    params=params,
                )
                continue
            seg_obj = net.segment(seg)
            if idx.used(address) or seg_obj is None:
                continue
            if (seg_obj.site_id, address.version) not in idx.client_data:
                continue  # no client data for that network: the collector may just be unknown
            label = segment_name(net, seg)
            yield found(
                f"{dev.name} sends {what} to {t.endpoint()}, but no device on {label} uses "
                "that address",
                [dev.id],
                fix="Point the target to the address of your log collector, or remove it if "
                "there is none any more.",
                key=t.endpoint(),
                mid="log.targetUnused",
                fix_id="log.target.fix",
                params={**params, "segment": label},
            )


# --- log.inconsistent ---------------------------------------------------------------------


@rule(
    "log.inconsistent",
    "Devices of a site log to different targets",
    Severity.INFO,
    "When the devices of one site send their syslog to different collectors, or some send it "
    "nowhere, the logs of an incident are spread over several places or missing. Reported per "
    "site when at least one device sends syslog to a remote target; devices whose log targets "
    "are not read are left out.",
)
def inconsistent(net: Network) -> Iterator[Result]:
    sites: dict[str, dict[tuple[str, ...], list[Device]]] = defaultdict(lambda: defaultdict(list))
    for dev, targets in _logging(net):
        addresses = tuple(
            sorted({t.address for t in targets if t.enabled and t.kind is LogKind.SYSLOG})
        )
        sites[dev.site_id][addresses].append(dev)
    for site, groups in sorted(sites.items()):
        if len(groups) < 2 or not any(groups):
            continue
        parts = []
        for addresses, devices in sorted(groups.items(), key=lambda g: (not g[0], g[0])):
            names = ", ".join(sorted(d.name for d in devices))
            where = ", ".join(addresses) if addresses else "no remote syslog"
            parts.append(f"{where}: {names}")
        detail = "; ".join(parts)
        name = _site_name(net, site)
        yield found(
            f"The devices of {name} log to different targets ({detail})",
            [d.id for devices in groups.values() for d in sorted(devices, key=lambda d: d.id)],
            fix="Send the syslog of every device of the site to the same collector.",
            key=site,
            mid="log.inconsistent",
            fix_id="log.inconsistent.fix",
            params={"site": name, "detail": detail},
        )


RULES: list[Rule] = [target_unknown, inconsistent]
