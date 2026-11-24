"""Path traces (#253): hops matched to known devices, the routed paths and who is in front.

Pure functions over the model, like :mod:`signalbox.topology`: the runner puts the stored traces
on the network with :func:`attach` (hops matched to the devices and interfaces of *that*
network), the topology page shows :func:`routed_view`, and the checks in
:mod:`signalbox.rules.traces` use :func:`tunnel_of` and :func:`gateway_target`. Running traces
is :mod:`signalbox.tracer`'s job.
"""

from __future__ import annotations

from collections.abc import Iterable
from ipaddress import IPv4Address, IPv6Network, ip_address
from typing import Any

from signalbox.model import (
    SIGNALBOX_SOURCE,
    Device,
    DeviceRole,
    IPAddress,
    NatClass,
    Network,
    PathTrace,
    TraceHop,
    address_nat_class,
)

_ULA = IPv6Network("fc00::/7")


def match(net: Network, address: IPAddress) -> tuple[str | None, str | None]:
    """The known device an address belongs to and its interface with it (subnet, uplink or
    tunnel id); (device, None) for a management address only; (None, None): not known."""
    for sub in sorted(net.subnets, key=lambda s: s.id):
        if sub.interface.ip == address:
            return sub.device_id, sub.id
    for uplink in sorted(net.uplinks, key=lambda u: u.id):
        if any(a.ip == address for a in uplink.addresses):
            return uplink.device_id, uplink.id
    for tunnel in sorted(net.tunnels, key=lambda t: t.id):
        if any(a.ip == address for a in tunnel.addresses):
            return tunnel.device_id, tunnel.id
    for dev in sorted(net.devices, key=lambda d: d.id):
        if dev.management_address and _ip(dev.management_address) == address:
            return dev.id, None
    return None, None


def _ip(text: str) -> IPAddress | None:
    try:
        return ip_address(text.strip().strip("[]"))
    except ValueError:
        return None


def attach(net: Network, traces: Iterable[PathTrace]) -> Network:
    """The network with these traces, every hop and target matched against it."""
    out = []
    for trace in sorted(traces, key=lambda t: t.id):
        hops = []
        for hop in trace.hops:
            dev, iface = match(net, hop.address) if hop.address is not None else (None, None)
            hops.append(hop.model_copy(update={"device_id": dev, "interface_id": iface}))
        target_device, _ = match(net, trace.target)
        out.append(trace.model_copy(update={"hops": hops, "target_device": target_device}))
    return net.model_copy(update={"traces": out})


def tunnel_of(net: Network, hop: TraceHop) -> str | None:
    """The read tunnel a hop lies in: the hop is a tunnel address of a device, or lies in the
    address network of a read tunnel (the other end's tunnel address)."""
    if hop.interface_id and net.tunnel(hop.interface_id) is not None:
        return hop.interface_id
    if hop.address is None:
        return None
    for tunnel in sorted(net.tunnels, key=lambda t: t.id):
        for a in tunnel.addresses:
            net_ = a.network
            if a.version == hop.address.version and net_.num_addresses > 1 and hop.address in net_:
                return tunnel.id
    return None


def hop_kind(hop: TraceHop) -> str:
    """``device`` (a known one), ``private``, ``cgnat``, ``public`` (also IPv6), ``none``."""
    if hop.device_id:
        return "device"
    if hop.address is None:
        return "none"
    if isinstance(hop.address, IPv4Address):
        nat = address_nat_class(hop.address)
        if nat is NatClass.PRIVATE:
            return "private"
        if nat is NatClass.CGNAT:
            return "cgnat"
    elif hop.address in _ULA:  # documentation prefixes count as public, as for IPv4
        return "private"
    return "public"


def gateway_target(net: Network, device: Device, source: str | None = None) -> IPAddress | None:
    """The address to trace to for a gateway: its uplink address in a network of the source
    (the source is the router in front of it), else its first IPv4 gateway subnet, else its
    management address, else any gateway subnet."""
    if source is not None:
        own = [s.interface.network for s in net.subnets if s.device_id == source]
        for uplink in sorted(net.uplinks_of(device.id), key=lambda u: u.id):
            for a in uplink.addresses:
                if any(a.version == n.version and a.ip in n for n in own):
                    return a.ip
    subs = sorted(
        (s for s in net.subnets if s.device_id == device.id and s.gateway),
        key=lambda s: (s.interface.version, s.id),
    )
    if subs and subs[0].interface.version == 4:
        return subs[0].interface.ip
    ip = _ip(device.management_address) if device.management_address else None
    if ip is not None and not ip.is_loopback:
        return ip
    return subs[0].interface.ip if subs else None


def gateways(net: Network) -> list[Device]:
    """Devices of the gateway role, in id order (also those whose integration cannot trace:
    they are targets)."""
    return sorted((d for d in net.devices if d.role is DeviceRole.GATEWAY), key=lambda d: d.id)


def source_name(net: Network, source: str) -> str:
    if source == SIGNALBOX_SOURCE:
        return "Signalbox"
    dev = net.device(source)
    return dev.name if dev else source


def complete(trace: PathTrace) -> bool:
    """The trace reached its target and every hop answered: checks may rely on it."""
    return trace.error is None and trace.reached and all(h.address for h in trace.hops)


def in_front(net: Network) -> list[dict[str, Any]]:
    """Who is in front of whom, from the traces to the internet: consecutive known routers on
    the way out (A, then B: B is in front of A), and an unknown router with a private or
    provider (CGNAT) address right after the last known one. Each pair once."""
    pairs: dict[tuple[str, str], dict[str, Any]] = {}
    for trace in net.traces:
        if trace.purpose != "internet" or trace.error:
            continue
        prev: str | None = trace.source if trace.source != SIGNALBOX_SOURCE else None
        for hop in trace.hops:
            if hop.device_id:
                if prev is not None and hop.device_id != prev:
                    key = (prev, hop.device_id)
                    entry = pairs.setdefault(
                        key,
                        {
                            "behind": prev,
                            "front": hop.device_id,
                            "address": None,
                            "kind": "device",
                            "traces": [],
                        },
                    )
                    entry["traces"].append(trace.id)
                prev = hop.device_id
                continue
            kind = hop_kind(hop)
            if prev is not None and kind in ("private", "cgnat"):
                key = (prev, str(hop.address))
                entry = pairs.setdefault(
                    key,
                    {
                        "behind": prev,
                        "front": None,
                        "address": str(hop.address),
                        "kind": kind,
                        "traces": [],
                    },
                )
                entry["traces"].append(trace.id)
            break  # past the known routers (or no answer): the rest is not ours to name
    return [pairs[k] for k in sorted(pairs)]


def routed_view(net: Network) -> dict[str, Any]:
    """The routed paths for the topology page: per trace the hops with the known device,
    the tunnel they lie in and their kind; and who is in front of whom."""
    paths = []
    for trace in net.traces:
        hops = []
        for hop in trace.hops:
            dev = net.device(hop.device_id) if hop.device_id else None
            hops.append(
                {
                    "ttl": hop.ttl,
                    "address": str(hop.address) if hop.address else None,
                    "rtt_ms": hop.rtt_ms,
                    "device_id": hop.device_id,
                    "name": dev.name if dev else None,
                    "interface_id": hop.interface_id,
                    "tunnel_id": tunnel_of(net, hop),
                    "kind": hop_kind(hop),
                }
            )
        target = net.device(trace.target_device) if trace.target_device else None
        last = next((h.rtt_ms for h in reversed(trace.hops) if h.rtt_ms is not None), None)
        paths.append(
            {
                "id": trace.id,
                "source": trace.source,
                "source_name": source_name(net, trace.source),
                "target": str(trace.target),
                "target_device": trace.target_device,
                "target_name": target.name if target else None,
                "purpose": trace.purpose,
                "started_at": trace.started_at.isoformat(),
                "reached": trace.reached,
                "error": trace.error,
                "fix": trace.fix,
                "remedy": trace.remedy,
                "message_id": trace.message_id,
                "fix_id": trace.fix_id,
                "params": trace.params,
                "rtt_ms": last if trace.reached else None,
                "tunnels": sorted({h["tunnel_id"] for h in hops if h["tunnel_id"]}),
                "hops": hops,
            }
        )
    return {"paths": paths, "in_front": in_front(net)}
