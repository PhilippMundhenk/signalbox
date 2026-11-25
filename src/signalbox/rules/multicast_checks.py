"""Multicast: snooping and querier, mDNS and SSDP reflection, the IGMP proxy (issue #161,
ADR 0028).

The checks use what devices report about themselves (``Device.multicast``): the snooping
settings per bridge and network, and the services that reflect discovery or streams between
networks. Everything stays quiet where no device reports multicast, and where a network has
members that did not say whether they are the querier.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterator

from signalbox.model import (
    Client,
    Device,
    Network,
    PurposeSource,
    ReflectorKind,
    SegmentPurpose,
    ServiceReflector,
)
from signalbox.rules import Result, RuleParams, Severity, ctx, found, param, rule
from signalbox.rules._names import device_name, segment_name

#: Reflectors that carry discovery between networks (the IGMP proxy carries streams).
DISCOVERY = frozenset({ReflectorKind.MDNS, ReflectorKind.SSDP, ReflectorKind.UDP_BROADCAST_RELAY})
_KIND_NAMES = {
    ReflectorKind.MDNS: "mDNS",
    ReflectorKind.SSDP: "SSDP",
    ReflectorKind.UDP_BROADCAST_RELAY: "UDP broadcast relay",
    ReflectorKind.IGMP_PROXY: "IGMP proxy",
}


class ReflectorMissingParams(RuleParams):
    min_clients: int = param(
        1,
        unit="count",
        ge=1,
        le=100,
        description="Report an IoT network only when it has at least this many clients, and "
        "so has the network its devices would have to be found from.",
    )


def _reflectors(net: Network) -> Iterator[tuple[Device, ServiceReflector]]:
    for d in net.devices:
        for r in d.multicast.reflectors if d.multicast else []:
            if r.enabled:
                yield d, r


# --- multicast.snooping-no-querier -----------------------------------------------------------


@rule(
    "multicast.snooping-no-querier",
    "IGMP snooping without a querier",
    Severity.WARNING,
    "A bridge with IGMP snooping sends a multicast stream (IPTV, Sonos, Chromecast) only to the "
    "ports that asked for it, and learns that from the answers to a querier's queries. Without a "
    "querier the memberships time out after a few minutes and the streams stop. Reported when a "
    "network has a bridge with snooping on, every bridge that says so is not a querier, and none "
    "has seen one.",
)
def snooping_no_querier(net: Network) -> Iterator[Result]:
    by_segment: dict[str, list[tuple[Device, str, bool | None, bool]]] = defaultdict(list)
    for d in net.devices:
        for m in d.multicast.settings if d.multicast else []:
            if m.segment_id is not None and m.igmp_snooping:
                by_segment[m.segment_id].append(
                    (d, m.name, m.querier, m.observed_querier is not None)
                )
    for seg, members in sorted(by_segment.items()):
        if any(q is not False or seen for _, _, q, seen in members):
            continue
        names = ", ".join(sorted({f"{device_name(net, d.id)} {b}" for d, b, _, _ in members}))
        yield found(
            f"IGMP snooping is on in {segment_name(net, seg)} ({names}) but no device is the "
            "querier: multicast streams stop after a few minutes",
            [seg, *sorted({d.id for d, _, _, _ in members})],
            fix="Turn on the multicast querier on the router's bridge (or on one switch of the "
            "network), or turn snooping off if nothing needs it.",
            mid="multicast.snoopingNoQuerier",
            fix_id="multicast.snoopingNoQuerier.fix",
            params={"segment": segment_name(net, seg), "devices": names},
        )


# --- multicast.reflector-guest ---------------------------------------------------------------


@rule(
    "multicast.reflector-guest",
    "Discovery is reflected into a guest network",
    Severity.WARNING,
    "An mDNS repeater, SSDP or UDP broadcast relay that includes a guest network hands the names "
    "of your devices to everybody who joins it and lets guests address them. Only the reflector's "
    "settings are read, never what it carries.",
)
def reflector_guest(net: Network) -> Iterator[Result]:
    for d, r in _reflectors(net):
        if r.kind not in DISCOVERY or len(r.segments) < 2:
            continue
        guests = [
            s
            for s in r.segments
            if (seg := net.segment(s)) is not None and seg.purpose is SegmentPurpose.GUEST
        ]
        for g in guests:
            kind = _KIND_NAMES[r.kind]
            yield found(
                f"{device_name(net, d.id)} reflects {kind} between {len(r.segments)} networks "
                f"including the guest network {segment_name(net, g)}",
                [d.id, g],
                fix="Take the guest network out of the reflector's interfaces.",
                key=r.kind.value,
                mid="multicast.reflectorGuest",
                fix_id="multicast.reflectorGuest.fix",
                params={
                    "device": device_name(net, d.id),
                    "kind": kind,
                    "count": len(r.segments),
                    "segment": segment_name(net, g),
                },
            )


# --- multicast.reflector-missing -------------------------------------------------------------


def _clients_by_segment(net: Network) -> dict[str, list[Client]]:
    out: dict[str, list[Client]] = defaultdict(list)
    for c in net.clients:
        if c.segment_id is not None:
            out[c.segment_id].append(c)
    return out


@rule(
    "multicast.reflector-missing",
    "IoT devices cannot be found from the main network",
    Severity.INFO,
    "Chromecast, AirPlay, Sonos and printers announce themselves with multicast (mDNS, SSDP), "
    "which does not cross networks. With the IoT devices in their own network, the apps in the "
    "main network no longer find them. Reported for an IoT network (declared or reported, not "
    "guessed) with clients while the main network has clients too and no reflector joins them; "
    "quiet when no device reports its reflectors.",
)
def reflector_missing(net: Network) -> Iterator[Result]:
    reads = [d for d in net.devices if d.multicast is not None]
    if not reads:
        return
    reflectors = [r for _, r in _reflectors(net) if r.kind in DISCOVERY]
    if any(not r.segments for r in reflectors):
        return
    clients = _clients_by_segment(net)
    for seg in net.segments:
        if seg.purpose is not SegmentPurpose.IOT or seg.purpose_source is PurposeSource.HEURISTIC:
            continue
        p = ctx.params(ReflectorMissingParams, seg)
        if len(clients.get(seg.id, [])) < p.min_clients:
            continue
        others = [
            o
            for o in net.segments
            if o.site_id == seg.site_id
            and o.id != seg.id
            and o.purpose in (SegmentPurpose.MAIN, None)
            and len(clients.get(o.id, [])) >= p.min_clients
        ]
        if not others or any(
            seg.id in r.segments and any(o.id in r.segments for o in others) for r in reflectors
        ):
            continue
        names = ", ".join(segment_name(net, o.id) for o in others)
        yield found(
            f"{segment_name(net, seg.id)} has devices, and nothing reflects discovery "
            f"(mDNS, SSDP) between it and {names}: casting and AirPlay do not find them",
            [seg.id, *(o.id for o in others)],
            fix="If you cast or print from the main network to devices here, turn on an mDNS "
            "reflector (repeater) for the two networks, and nothing else. Ignore this when "
            "the devices are meant to stay out of sight.",
            mid="multicast.reflectorMissing",
            fix_id="multicast.reflectorMissing.fix",
            params={"segment": segment_name(net, seg.id), "others": names},
        )


# --- multicast.iptv-proxy --------------------------------------------------------------------


@rule(
    "multicast.iptv-proxy",
    "IGMP proxy upstream is not the uplink",
    Severity.INFO,
    "An IGMP proxy passes the provider's multicast streams (IPTV) from its upstream interface to "
    "the networks that ask. When the upstream is not the uplink, no stream arrives, unless the "
    "provider delivers TV in a VLAN of its own. Reported when a gateway with a known uplink has "
    "an IGMP proxy with another upstream.",
)
def iptv_proxy(net: Network) -> Iterator[Result]:
    for d, r in _reflectors(net):
        if r.kind is not ReflectorKind.IGMP_PROXY or r.upstream_interface is None:
            continue
        uplinks = net.uplinks_of(d.id)
        if not uplinks:
            continue
        names = {u.name.lower() for u in uplinks if u.name}
        for u in uplinks:
            port = net.port(u.port_id) if u.port_id else None
            if port is not None:
                names.add(port.name.lower())
        if r.upstream_interface.lower() in names:
            continue
        yield found(
            f"The IGMP proxy of {device_name(net, d.id)} takes its streams from "
            f"{r.upstream_interface}, not from the uplink ({', '.join(sorted(names))})",
            [d.id],
            fix="Set the uplink interface as the upstream of the IGMP proxy. If your provider "
            "delivers TV in a VLAN of its own, this is as intended.",
            mid="multicast.iptvProxy",
            fix_id="multicast.iptvProxy.fix",
            params={
                "device": device_name(net, d.id),
                "upstream": r.upstream_interface,
                "uplink": ", ".join(sorted(names)),
            },
        )


RULES = [snooping_no_querier, reflector_guest, reflector_missing, iptv_proxy]
