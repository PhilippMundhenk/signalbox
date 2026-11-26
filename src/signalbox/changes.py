"""Change model and planner (component "planner", issue #37).

A **change** is one typed, vendor-neutral operation on one object of one device, with the value
before (``old``, None when the object is created) and after (``new``, None when it is removed).
Its inverse swaps the two, which is how a recorded change is reverted.

The **planner** compares the desired state with the observed network and produces a
:class:`Plan`: the changes, in dependency order, the predicted network after them, and the
findings the checks report on that predicted network.

Integrations translate changes into vendor calls (``WritesConfig`` in :mod:`signalbox.adapters`);
nothing in this module knows a vendor.
"""

from __future__ import annotations

import hashlib
from collections import deque
from collections.abc import Callable, Iterable
from datetime import UTC, datetime
from enum import StrEnum
from ipaddress import IPv4Address, ip_address, ip_network
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from signalbox import firewall as reachability
from signalbox.desired import (
    DesiredState,
    EffectiveLogging,
    EndpointSpec,
    FirewallSpec,
    GatewayGroupSpec,
    SegmentRef,
    TunnelEndSpec,
    TunnelSpec,
    ZoneRef,
    effective_logging,
    firewall_key,
    seg_key,
    seg_sid,
)
from signalbox.messages import Label, plain_params
from signalbox.model import (
    DeviceRole,
    DhcpPool,
    DhcpServer,
    FastTransition,
    Firewall,
    FirewallAction,
    FirewallChain,
    FirewallMatch,
    FirewallProtocol,
    FirewallRule,
    GatewayGroup,
    GroupMode,
    IPAddress,
    IPInterface,
    IPNetwork,
    LogKind,
    LogTarget,
    LogTransport,
    Membership,
    MessageParams,
    Network,
    Pmf,
    PortForward,
    PortMembership,
    PortRange,
    Radio,
    Reservation,
    Security,
    Segment,
    ServiceKind,
    SnmpSettings,
    SnmpVersion,
    Subnet,
    Tunnel,
    TunnelKind,
    TunnelPeer,
    Verdict,
    WireGuardKey,
    Wlan,
    ZonePolicy,
    is_native_segment,
    object_id,
    passphrase_fingerprint,
    port_id,
    segment_id,
)
from signalbox.rules import Finding, Rule, RuleSettings, Severity, evaluate


class ChangeKind(StrEnum):
    ROUTER = "router"  # a segment's router interface (VLAN, name, address) on a device
    DHCP = "dhcp"  # DHCP server settings of a segment on a device
    RESERVATION = "reservation"  # one static DHCP lease
    PORT = "port"  # untagged and tagged VLANs of one port
    WLAN = "wlan"  # one SSID on one access point
    ZONE_POLICY = "zone-policy"  # default action between two firewall zones (#295)
    FIREWALL_RULE = "firewall-rule"  # one filter rule Signalbox owns
    PORT_FORWARD = "port-forward"  # one port forward (destination NAT) Signalbox owns
    LOG_TARGET = "log-target"  # one remote syslog target of a device (#327)
    SNMP_POLICY = "snmp-policy"  # the state of the SNMP agent of a device (#327)
    GATEWAY_GROUP = "gateway-group"  # tiers, weights and monitors of a gateway group (#463)
    TUNNEL = "tunnel"  # a WireGuard interface of one end of a tunnel (#152)
    TUNNEL_PEER = "tunnel-peer"  # the peer of a tunnel's end: the other end (#152)


#: Kinds that change a device's firewall: their plans are checked for lost management access.
FIREWALL_KINDS = frozenset(
    {ChangeKind.ZONE_POLICY, ChangeKind.FIREWALL_RULE, ChangeKind.PORT_FORWARD}
)


#: Kinds that change a WireGuard tunnel (#152): their plans are checked for lost management
#: access through the tunnel.
TUNNEL_KINDS = frozenset({ChangeKind.TUNNEL, ChangeKind.TUNNEL_PEER})


#: Kinds that change where a device logs to or what its SNMP agent does (#327).
LOGGING_KINDS = frozenset({ChangeKind.LOG_TARGET, ChangeKind.SNMP_POLICY})


class Value(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class RouterValue(Value):
    vlan: int | None = None
    name: str | None = None
    address: IPInterface


class DhcpValue(Value):
    enabled: bool
    pool: tuple[IPAddress, IPAddress] | None = None
    dns: list[IPAddress] | None = None
    lease_seconds: int | None = None


class ReservationValue(Value):
    mac: str
    address: IPAddress
    hostname: str | None = None


class PortValue(Value):
    #: VLAN sent untagged ("native" for the plain LAN), None for none.
    untagged: SegmentRef | None = None
    tagged: list[int] = Field(default_factory=list)


class WlanValue(Value):
    ssid: str
    security: Security
    pmf: Pmf | None = None
    segment: SegmentRef = "native"
    hidden: bool = False
    enabled: bool = True
    roaming_80211r: bool | None = None
    roaming_80211k: bool | None = None
    roaming_80211v: bool | None = None
    #: 802.11r mobility domain (four hex digits, lower case) and over-DS (#489); None: not
    #: specified or not reported (left as the device has it).
    mobility_domain: str | None = None
    ft_over_ds: bool | None = None
    #: Weakest signal a client may have (dBm), ``off`` for no limit; None: left as it is.
    min_rssi_dbm: int | Literal["off"] | None = None
    #: None: not specified (left as the device has it).
    client_isolation: bool | None = None
    #: Name of the secret holding the passphrase; resolved by the deployment, never stored here.
    passphrase_secret: str | None = None


class ZonePolicyValue(Value):
    action: FirewallAction


class FirewallRuleValue(Value):
    #: The name shown on the device (the declared name).
    name: str
    enabled: bool = True
    #: ``input``: traffic to the device itself; ``forward``: traffic it routes.
    chain: FirewallChain
    family: Literal[4, 6] | None = None
    #: Empty: every protocol.
    protocols: list[FirewallProtocol] = Field(default_factory=list)
    #: ``None``: any zone.
    source_zone: str | None = None
    source_networks: list[IPNetwork] = Field(default_factory=list)
    #: Forward rules only; ``None``: any zone.
    destination_zone: str | None = None
    destination_networks: list[IPNetwork] = Field(default_factory=list)
    destination_ports: list[PortRange] = Field(default_factory=list)
    action: FirewallAction


class PortForwardValue(Value):
    name: str
    enabled: bool = True
    protocols: list[FirewallProtocol]
    #: The zone it listens on (the internet side).
    zone: str
    external_ports: list[PortRange]
    target_address: IPAddress
    #: ``None``: the external port.
    target_port: int | None = None


class LogTargetValue(Value):
    """A remote syslog target; the key of its change is ``syslog/<address>``."""

    address: str
    port: int = 514
    transport: LogTransport = LogTransport.UDP
    #: Sent at all (a target that is configured but switched off is not enabled).
    enabled: bool = True


class GatewayMemberValue(Value):
    """One member of a gateway group: its rank, weight and monitor addresses."""

    name: str
    #: Rank among the group's tiers (1 is the first choice), renumbered without gaps.
    tier: int
    weight: int | None = None
    #: The addresses the monitor pings, sorted; empty: no monitor.
    monitor: list[IPAddress] = Field(default_factory=list)
    #: The member's next hop as the device reports it (not declared; it identifies a route).
    gateway: IPAddress | None = None


class GatewayGroupValue(Value):
    """Every member of a gateway group (the undeclared ones as the device has them); the key
    of its change is ``group/<name>``."""

    members: list[GatewayMemberValue]


class TunnelValue(Value):
    """A WireGuard interface of one end of a tunnel (#152, ADR 0034); the key of its change is
    ``tunnel/<name>``. There is no key field: the key pair is generated on the device."""

    interface: str
    #: None: not declared (the device keeps or picks its own).
    listen_port: int | None = None
    #: The end's tunnel addresses, sorted.
    addresses: list[IPInterface] = Field(default_factory=list)
    mtu: int | None = None


class TunnelPeerValue(Value):
    """The peer of one end of a tunnel: the other end (#152, ADR 0034); key ``peer/<name>``.
    Only the other end's public key; never a private or pre-shared key."""

    #: The interface the peer belongs to.
    interface: str
    public_key: WireGuardKey
    #: Where the other end is reached; None: not declared (it connects to us, or the device
    #: keeps what it has).
    endpoint_host: str | None = None
    endpoint_port: int | None = None
    #: The other end's tunnel addresses (single addresses) and its networks, sorted.
    allowed_ips: list[IPNetwork] = Field(default_factory=list)
    #: Persistent keepalive in seconds (0: off); None: not declared.
    keepalive: int | None = None


class SnmpPolicyValue(Value):
    """The state of a device's SNMP agent. Never a community or a password.

    ``on``: the agent answers (v1/v2c, or unreported versions), ``v3-only``: only SNMPv3,
    ``off``: no agent runs. The writers set ``off`` (and ``on``, to revert it)."""

    mode: Literal["on", "v3-only", "off"]


VALUE_TYPES: dict[ChangeKind, type[Value]] = {
    ChangeKind.ROUTER: RouterValue,
    ChangeKind.DHCP: DhcpValue,
    ChangeKind.RESERVATION: ReservationValue,
    ChangeKind.PORT: PortValue,
    ChangeKind.WLAN: WlanValue,
    ChangeKind.ZONE_POLICY: ZonePolicyValue,
    ChangeKind.FIREWALL_RULE: FirewallRuleValue,
    ChangeKind.PORT_FORWARD: PortForwardValue,
    ChangeKind.LOG_TARGET: LogTargetValue,
    ChangeKind.SNMP_POLICY: SnmpPolicyValue,
    ChangeKind.GATEWAY_GROUP: GatewayGroupValue,
    ChangeKind.TUNNEL: TunnelValue,
    ChangeKind.TUNNEL_PEER: TunnelPeerValue,
}
#: Order in which kinds are applied when objects are created or changed; removals run reversed.
PHASE = {
    ChangeKind.ROUTER: 0,
    ChangeKind.DHCP: 1,
    ChangeKind.RESERVATION: 2,
    ChangeKind.PORT: 3,
    ChangeKind.WLAN: 4,
    ChangeKind.ZONE_POLICY: 5,
    ChangeKind.FIREWALL_RULE: 6,
    ChangeKind.PORT_FORWARD: 7,
    ChangeKind.LOG_TARGET: 8,
    ChangeKind.SNMP_POLICY: 9,
    ChangeKind.GATEWAY_GROUP: 10,
    ChangeKind.TUNNEL: 11,
    ChangeKind.TUNNEL_PEER: 12,
}

AnyValue = (
    RouterValue
    | DhcpValue
    | ReservationValue
    | PortValue
    | WlanValue
    | ZonePolicyValue
    | FirewallRuleValue
    | PortForwardValue
    | LogTargetValue
    | SnmpPolicyValue
    | GatewayGroupValue
    | TunnelValue
    | TunnelPeerValue
)


class Change(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: ChangeKind
    device_id: str
    site_id: str
    #: Identifies the object on the device, e.g. the segment id for ROUTER and DHCP.
    key: str
    old: AnyValue | None = None
    new: AnyValue | None = None
    #: Why this change could cut a device off (shown in the review; needs a confirm timer).
    risk: str | None = None
    #: The device's own object (not created by Signalbox) this change may take over or
    #: remove: the name of an adopted rule or forward, or the zone pair of a forwarding (#295),
    #: or the address of a syslog target the device had before (#327), or the name of the
    #: device's gateway group that the desired state adopts (#463), or the interface name of
    #: a WireGuard interface the desired state adopts (#152).
    adopt: str | None = None

    @model_validator(mode="after")
    def _types(self) -> Change:
        want = VALUE_TYPES[self.kind]
        for side in (self.old, self.new):
            if side is not None and not isinstance(side, want):
                raise ValueError(f"{self.kind.value} change needs {want.__name__} values")
        if self.old is None and self.new is None:
            raise ValueError("a change needs an old or a new value")
        return self

    @property
    def id(self) -> str:
        return f"{self.device_id}:{self.kind.value}:{self.key}"

    @property
    def action(self) -> str:
        return "create" if self.old is None else "remove" if self.new is None else "update"

    def inverse(self) -> Change:
        return self.model_copy(update={"old": self.new, "new": self.old})

    def describe(self) -> str:
        def show(v: AnyValue | None) -> str:
            if v is None:
                return "nothing"
            data = v.model_dump(mode="json", exclude_none=True)
            data.pop("passphrase_secret", None)
            return ", ".join(f"{k}={_short(x)}" for k, x in data.items())

        if self.action == "create":
            return f"{self.device_id}: create {self.kind.value} {self.key} ({show(self.new)})"
        if self.action == "remove":
            return f"{self.device_id}: remove {self.kind.value} {self.key}"
        assert self.old is not None and self.new is not None
        old, new = self.old.model_dump(mode="json"), self.new.model_dump(mode="json")
        diff = [f"{k} {_short(old[k])} → {_short(new[k])}" for k in new if old.get(k) != new[k]]
        return f"{self.device_id}: {self.kind.value} {self.key}: " + "; ".join(diff)


def _short(value: Any) -> str:
    if isinstance(value, list):
        return "[" + ", ".join(str(v) for v in value) + "]"
    return str(value)


def order(changes: Iterable[Change], distance: dict[str, int] | None = None) -> list[Change]:
    """Creations and updates by phase (gateway first, then outwards); removals reversed."""
    distance = distance or {}
    far = 1 << 20
    keep = [c for c in changes if c.new is not None]
    remove = [c for c in changes if c.new is None]
    keep.sort(key=lambda c: (PHASE[c.kind], distance.get(c.device_id, far), c.device_id, c.key))
    remove.sort(key=lambda c: (-PHASE[c.kind], -distance.get(c.device_id, far), c.device_id, c.key))
    return [*keep, *remove]


def gateway_distance(net: Network, site_id: str) -> dict[str, int]:
    """Hops from the site's gateway(s) over the known links (devices without a path: absent)."""
    sites = {d.id for d in net.devices if d.site_id == site_id}
    port_dev = {p.id: p.device_id for p in net.ports}
    adj: dict[str, set[str]] = {d: set() for d in sites}
    for link in net.links:
        a, b = port_dev.get(link.a), port_dev.get(link.b)
        if a in sites and b in sites and a != b:
            adj[a].add(b)
            adj[b].add(a)
    start = [d.id for d in net.devices if d.site_id == site_id and d.role is DeviceRole.GATEWAY]
    dist = dict.fromkeys(start, 0)
    queue = deque(start)
    while queue:
        cur = queue.popleft()
        for nxt in sorted(adj[cur]):
            if nxt not in dist:
                dist[nxt] = dist[cur] + 1
                queue.append(nxt)
    return dist


# observed values ------------------------------------------------------------------------------


def _ref(net: Network, sid: str | None) -> SegmentRef:
    seg = net.segment(sid) if sid else None
    return "native" if seg is None or seg.vlan in (None, 1) else seg.vlan


def observed_router(net: Network, device_id: str, sid: str) -> RouterValue | None:
    for sub in net.subnets:
        if (
            sub.device_id == device_id
            and sub.segment_id == sid
            and isinstance(sub.interface.ip, IPv4Address)
        ):
            seg = net.segment(sid)
            return RouterValue(
                vlan=seg.vlan if seg and seg.vlan not in (None, 1) else None,
                name=seg.name if seg else None,
                address=sub.interface,
            )
    return None


def observed_dhcp(net: Network, device_id: str, sid: str) -> DhcpValue | None:
    srv = next(
        (s for s in net.dhcp_servers if s.device_id == device_id and s.segment_id == sid), None
    )
    if srv is None:
        return None
    return DhcpValue(
        enabled=srv.enabled,
        pool=(srv.pools[0].start, srv.pools[0].end) if srv.pools else None,
        dns=list(srv.dns_servers) or None,
        lease_seconds=srv.lease_seconds,
    )


def observed_port(net: Network, pid: str) -> PortValue:
    untagged: SegmentRef | None = None
    tagged: list[int] = []
    for seg in net.segments:
        for m in seg.members:
            if m.port_id != pid:
                continue
            if m.mode is Membership.UNTAGGED:
                untagged = "native" if seg.vlan in (None, 1) else seg.vlan
            elif seg.vlan not in (None, 1):
                assert seg.vlan is not None
                tagged.append(seg.vlan)
    return PortValue(untagged=untagged, tagged=sorted(tagged))


def observed_wlan(net: Network, device_id: str, ssid: str) -> WlanValue | None:
    w = next((x for x in net.wlans if x.device_id == device_id and x.ssid == ssid), None)
    if w is None:
        return None
    return WlanValue(
        ssid=w.ssid,
        security=w.security,
        pmf=w.pmf,
        segment=_ref(net, w.segment_id),
        hidden=w.hidden,
        enabled=w.enabled,
        roaming_80211r=w.roaming_80211r,
        roaming_80211k=w.roaming_80211k,
        roaming_80211v=w.roaming_80211v,
        mobility_domain=w.ft.mobility_domain if w.ft else None,
        ft_over_ds=w.ft.over_ds if w.ft else None,
        min_rssi_dbm=observed_min_rssi(w),
        client_isolation=w.client_isolation,
    )


#: SSID fields a writer sets only when the change changes them (ADR 0033).
ROAMING_DETAILS = ("mobility_domain", "ft_over_ds", "min_rssi_dbm")


def unchanged_left_alone(new: WlanValue, old: Any) -> WlanValue:
    """``new`` with the roaming details that the change does not change set to None: the
    reported value is the first radio's, so writing it would change the other radios."""
    if not isinstance(old, WlanValue):
        return new
    same = {f: None for f in ROAMING_DETAILS if getattr(old, f) == getattr(new, f)}
    return new.model_copy(update=same) if same else new


def observed_min_rssi(w: Wlan) -> int | None:
    """The minimum signal as the device reports it: ``min_rssi_dbm``, else the association
    limit (OpenWrt ``rssi_reject_assoc_rssi``); None: no limit or not reported (ADR 0033)."""
    return w.min_rssi_dbm if w.min_rssi_dbm is not None else w.assoc_rssi_dbm


# firewall (#295) ------------------------------------------------------------------------------


def policy_key(source: str, destination: str | None) -> str:
    return f"policy/{source}/{destination or 'device'}"


def _policy_pair(key: str) -> tuple[str, str | None]:
    _, source, dest = key.split("/", 2)
    return source, None if dest == "device" else dest


def observed_policy(net: Network, device_id: str, key: str) -> ZonePolicyValue | None:
    """The action the firewall applies between the two zones when no rule decides (an
    explicit zone pair policy, else the chain's fallback)."""
    fw = net.firewall_of(device_id)
    if fw is None:
        return None
    source, dest = _policy_pair(key)
    action = fw.policy(source, dest)
    if action is None:
        action = fw.input_policy if dest is None else fw.forward_policy
    return ZonePolicyValue(action=action) if action is not None else None


def _one(values: list[str], negated: bool) -> str | None:
    if negated:
        return "!" + ",".join(values)
    return ",".join(values) if values else None


def rule_value(r: FirewallRule) -> FirewallRuleValue:
    return FirewallRuleValue(
        name=r.name or "",
        enabled=r.enabled,
        chain=r.chain or FirewallChain.FORWARD,
        family=r.family,
        protocols=list(r.protocols),
        source_zone=_one(r.source.zones, r.source.zones_not),
        source_networks=list(r.source.networks),
        destination_zone=_one(r.destination.zones, r.destination.zones_not),
        destination_networks=list(r.destination.networks),
        destination_ports=list(r.destination.ports),
        action=r.action,
    )


def forward_value(f: PortForward) -> PortForwardValue:
    return PortForwardValue(
        name=f.name or "",
        enabled=f.enabled,
        protocols=list(f.protocols),
        zone=",".join(f.zones),
        external_ports=list(f.external_ports),
        target_address=f.target_address,
        target_port=f.target_port,
    )


def _owned(items: list[Any], key: str, adopt: str | None) -> Any:
    """The object tagged ``key``; without one, the device's own named ``adopt``."""
    mine = next((x for x in items if x.signalbox_key == key), None)
    if mine is None and adopt:
        mine = next((x for x in items if x.signalbox_key is None and x.name == adopt), None)
    return mine


def observed_rule(
    net: Network, device_id: str, key: str, adopt: str | None = None
) -> FirewallRuleValue | None:
    fw = net.firewall_of(device_id)
    r = _owned(fw.rules, key.partition("/")[2], adopt) if fw else None
    return rule_value(r) if r is not None else None


def observed_forward(
    net: Network, device_id: str, key: str, adopt: str | None = None
) -> PortForwardValue | None:
    fw = net.firewall_of(device_id)
    f = _owned(fw.port_forwards, key.partition("/")[2], adopt) if fw else None
    return forward_value(f) if f is not None else None


def _zone(net: Network, fw: Firewall, site_id: str, ref: ZoneRef | None, label: str) -> str | None:
    """A declared zone reference as the zone name on the device (``None``: any zone)."""
    if ref is None:
        return None
    if isinstance(ref, str):
        if fw.zone(ref) is None:
            names = ", ".join(sorted(z.name for z in fw.zones)) or Label("none", "none")
            raise PlanError(
                f"{label}: {fw.device_id} has no zone {ref!r} (zones: {names})",
                message_id="plan.noZone",
                params={"label": label, "device": fw.device_id, "zone": repr(ref), "zones": names},
            )
        return ref
    sid = seg_sid(site_id, ref.segment)
    if ref.segment in ("native", 1):  # the router's own untagged network (#205)
        sid = net.native_segment(fw.device_id) or sid
    zones = sorted(fw.zones_of(sid))
    if len(zones) != 1:
        where = "no zone" if not zones else "several zones (" + ", ".join(zones) + ")"
        raise PlanError(
            f"{label}: segment {ref.segment} is in {where} on {fw.device_id}",
            message_id="plan.segmentZones",
            params={
                "label": label,
                "segment": str(ref.segment),
                "device": fw.device_id,
                "zones": ", ".join(zones),
            },
        )
    return zones[0]


def _endpoint(
    net: Network, fw: Firewall, site_id: str, e: EndpointSpec, label: str
) -> tuple[str | None, list[IPNetwork]]:
    return _zone(net, fw, site_id, e.zone_ref(), label), list(e.network)


def firewall_changes(net: Network, site_id: str, spec: FirewallSpec) -> list[Change]:
    """The changes that make one device's firewall match its declaration."""
    _known(net, spec.device)
    fw = net.firewall_of(spec.device)
    if fw is None:
        raise PlanError(
            f"the firewall of {spec.device} has not been read",
            message_id="plan.firewallNotRead",
            params={"device": spec.device},
        )
    out: list[Change] = []

    def add(kind: ChangeKind, key: str, old: Any, new: Any, adopt: str | None = None) -> None:
        if old != new:
            out.append(
                Change(
                    kind=kind,
                    device_id=spec.device,
                    site_id=site_id,
                    key=key,
                    old=old,
                    new=new,
                    adopt=adopt,
                )
            )

    for p in spec.policies:
        label = Label(f"policy on {spec.device}", "declPolicy", spec.device)
        source = _zone(net, fw, site_id, p.from_, label)
        dest = None if p.to == "device" else _zone(net, fw, site_id, p.to, label)
        assert source is not None
        key = policy_key(source, dest)
        add(
            ChangeKind.ZONE_POLICY,
            key,
            observed_policy(net, spec.device, key),
            ZonePolicyValue(action=p.action),
            f"{source}→{dest}" if p.adopt else None,
        )
    keys: set[str] = set()
    for r in spec.rules:
        label = Label(f"rule {r.name}", "declRule", r.name)
        source, src_nets = _endpoint(net, fw, site_id, r.from_, label)
        if r.to == "device":
            dst_nets: list[IPNetwork] = []
            chain, dest = FirewallChain.INPUT, None
        else:
            chain = FirewallChain.FORWARD
            dest, dst_nets = _endpoint(net, fw, site_id, r.to, label)
        key = "rule/" + firewall_key(r.name)
        keys.add(key)
        add(
            ChangeKind.FIREWALL_RULE,
            key,
            observed_rule(net, spec.device, key, r.adopt),
            FirewallRuleValue(
                name=r.name,
                enabled=r.enabled,
                chain=chain,
                family=r.family,
                protocols=r.protocols(),
                source_zone=source,
                source_networks=src_nets,
                destination_zone=dest,
                destination_networks=dst_nets,
                destination_ports=list(r.port),
                action=r.action,
            ),
            r.adopt,
        )
    for f in spec.forwards:
        label = Label(f"forward {f.name}", "declForward", f.name)
        zone = _zone(net, fw, site_id, f.from_, label)
        if zone is None:
            wan = sorted(fw.uplink_zones())
            if len(wan) != 1:
                raise PlanError(
                    f"{label}: say which zone it listens on (`from`); {spec.device} has "
                    + (f"several internet zones ({', '.join(wan)})" if wan else "none"),
                    message_id="plan.forwardZone" if wan else "plan.forwardZoneNone",
                    params={"label": label, "device": spec.device, "zones": ", ".join(wan)},
                )
            zone = wan[0]
        key = "forward/" + firewall_key(f.name)
        keys.add(key)
        add(
            ChangeKind.PORT_FORWARD,
            key,
            observed_forward(net, spec.device, key, f.adopt),
            PortForwardValue(
                name=f.name,
                enabled=f.enabled,
                protocols=list(f.protocol),
                zone=zone,
                external_ports=list(f.port),
                target_address=f.to.address,
                target_port=f.to.port,
            ),
            f.adopt,
        )
    # what Signalbox created earlier and is no longer declared goes away
    for fr in fw.rules:
        if fr.signalbox_key and f"rule/{fr.signalbox_key}" not in keys:
            add(ChangeKind.FIREWALL_RULE, f"rule/{fr.signalbox_key}", rule_value(fr), None)
    for pf in fw.port_forwards:
        if pf.signalbox_key and f"forward/{pf.signalbox_key}" not in keys:
            add(ChangeKind.PORT_FORWARD, f"forward/{pf.signalbox_key}", forward_value(pf), None)
    return out


# logging and SNMP (#327) ----------------------------------------------------------------------

#: Where syslog goes when the declaration does not say.
LOG_PORT = 514


def _log_value(t: LogTarget) -> LogTargetValue:
    return LogTargetValue(
        address=t.address,
        port=t.port or LOG_PORT,
        transport=t.transport or LogTransport.UDP,
        enabled=t.enabled,
    )


def _syslog_of(net: Network, device_id: str) -> list[LogTarget]:
    dev = net.device(device_id)
    return [t for t in (dev.log_targets if dev else None) or [] if t.kind is LogKind.SYSLOG]


def observed_log_target(
    net: Network, device_id: str, key: str, adopt: str | None
) -> LogTargetValue | None:
    """The syslog target ``syslog/<address>`` Signalbox created, or the device's own that the
    change adopts; ``None`` for any other (the device's own are not Signalbox's to compare)."""
    address = key.partition("/")[2]
    for t in _syslog_of(net, device_id):
        if t.address == address and (t.managed or adopt == address):
            return _log_value(t)
    return None


def observed_snmp(net: Network, device_id: str) -> SnmpPolicyValue | None:
    """The agent as ``on``, ``v3-only`` or ``off`` (no agent at all is off); ``None``: the
    device's monitoring settings were not read."""
    dev = net.device(device_id)
    if dev is None or dev.log_targets is None:
        return None
    agent = next((s for s in net.services_of(device_id) if s.kind is ServiceKind.SNMP), None)
    if agent is None or not agent.enabled:
        return SnmpPolicyValue(mode="off")
    versions = agent.snmp.versions if agent.snmp else []
    return SnmpPolicyValue(mode="v3-only" if versions == [SnmpVersion.V3] else "on")


def _log_change(
    device: str,
    site_id: str,
    address: str,
    old: LogTargetValue | None,
    new: LogTargetValue | None,
    adopt: str | None,
) -> Change:
    return Change(
        kind=ChangeKind.LOG_TARGET,
        device_id=device,
        site_id=site_id,
        key=f"syslog/{address}",
        old=old,
        new=new,
        adopt=adopt,
    )


def logging_changes(net: Network, site_id: str, eff: EffectiveLogging) -> list[Change]:
    """The changes that make one device's syslog targets and SNMP agent match the declaration.

    Only targets Signalbox created (``managed``) or the declaration adopts are changed or
    removed; the device's other targets are left alone, and a declared target at an address
    where the device has its own, different one is refused until it is adopted."""
    dev = net.device(eff.device)
    if dev is None:
        raise PlanError(
            f"device {eff.device} is not configured or has not been read yet",
            message_id="plan.deviceUnknown",
            params={"device": eff.device},
        )
    if dev.log_targets is None:
        raise PlanError(
            f"the log targets and SNMP agent of {eff.device} have not been read",
            message_id="plan.logNotRead",
            params={"device": eff.device},
        )
    out: list[Change] = []
    have = _syslog_of(net, eff.device)
    if eff.syslog is not None:
        wanted = []
        for d in eff.syslog:
            new = LogTargetValue(
                address=d.address, port=d.port or LOG_PORT, transport=LogTransport(d.transport)
            )
            wanted.append(d.address)
            old_t = next((t for t in have if t.address == d.address), None)
            if old_t is None:
                out.append(_log_change(eff.device, site_id, d.address, None, new, None))
                continue
            old = _log_value(old_t)
            if old == new:
                continue
            if not old_t.managed and d.address not in eff.adopt:
                raise PlanError(
                    f"{eff.device} sends syslog to {d.address} ({old.transport.value} port "
                    f"{old.port}) and Signalbox did not set that up: list the address under "
                    "`adopt` to let a deployment change it",
                    message_id="plan.syslogForeign",
                    params={
                        "device": eff.device,
                        "address": d.address,
                        "transport": old.transport.value,
                        "port": old.port,
                    },
                )
            adopt = None if old_t.managed else d.address
            out.append(_log_change(eff.device, site_id, d.address, old, new, adopt))
        for t in have:
            if t.address not in wanted and (t.managed or t.address in eff.adopt):
                adopt = None if t.managed else t.address
                out.append(_log_change(eff.device, site_id, t.address, _log_value(t), None, adopt))
    if eff.snmp is not None:
        now = observed_snmp(net, eff.device)
        assert now is not None
        # off is stricter than v3-only: an agent that is off already satisfies both
        if now.mode != "off" and (eff.snmp == "off" or now.mode == "on"):
            out.append(
                Change(
                    kind=ChangeKind.SNMP_POLICY,
                    device_id=eff.device,
                    site_id=site_id,
                    key="snmp",
                    old=now,
                    new=SnmpPolicyValue(mode=eff.snmp),
                )
            )
    return out


def _apply_logging(net: Network, c: Change) -> Network:
    """A logging change on the predicted network."""
    if c.kind is ChangeKind.LOG_TARGET:
        address = c.key.partition("/")[2]
        dev = net.device(c.device_id)
        if dev is None or dev.log_targets is None:  # pragma: no cover - the planner refuses
            return net
        targets = [
            t
            for t in dev.log_targets
            if not (
                t.kind is LogKind.SYSLOG
                and t.address == address
                and (t.managed or c.adopt == address)
            )
        ]
        if isinstance(c.new, LogTargetValue):
            targets.append(
                LogTarget(
                    kind=LogKind.SYSLOG,
                    address=c.new.address,
                    port=c.new.port,
                    transport=c.new.transport,
                    enabled=c.new.enabled,
                    name="signalbox",
                    managed=True,
                )
            )
        devices = [
            d.model_copy(update={"log_targets": targets}) if d.id == c.device_id else d
            for d in net.devices
        ]
        return net.model_copy(update={"devices": devices})
    services = []
    for svc in net.services:
        if svc.device_id == c.device_id and svc.kind is ServiceKind.SNMP:
            mode = c.new.mode if isinstance(c.new, SnmpPolicyValue) else "off"
            update: dict[str, Any] = {"enabled": mode != "off"}
            if mode == "v3-only":
                base = svc.snmp or SnmpSettings()
                update["snmp"] = base.model_copy(
                    update={"versions": [SnmpVersion.V3], "default_community": False}
                )
            svc = svc.model_copy(update=update)
        services.append(svc)
    return net.model_copy(update={"services": services})


# gateway groups (#463) ------------------------------------------------------------------------


def _ranks(tiers: list[int]) -> list[int]:
    """The tiers renumbered 1, 2, ... in their order (1 and 5 become 1 and 2)."""
    order = sorted(set(tiers))
    return [order.index(t) + 1 for t in tiers]


def _addresses(values: Iterable[IPAddress]) -> list[IPAddress]:
    return sorted(set(values), key=lambda a: (a.version, int(a)))


def _group_of(net: Network, device_id: str, name: str) -> GatewayGroup | None:
    return next((g for g in net.gateway_groups_of(device_id) if g.name == name), None)


def _group_value(group: GatewayGroup) -> GatewayGroupValue:
    ranks = _ranks([m.tier for m in group.members])
    return GatewayGroupValue(
        members=[
            GatewayMemberValue(
                name=m.name,
                tier=rank,
                weight=m.weight,
                monitor=_addresses(m.monitor_targets),
                gateway=m.gateway,
            )
            for m, rank in zip(group.members, ranks, strict=True)
        ]
    )


def group_key(name: str) -> str:
    return f"group/{name}"


def observed_group(net: Network, device_id: str, key: str) -> GatewayGroupValue | None:
    """The gateway group ``group/<name>`` as the device reports it (None: there is none)."""
    group = _group_of(net, device_id, key.partition("/")[2])
    return _group_value(group) if group is not None else None


def gateway_group_changes(
    net: Network, site_id: str, spec: GatewayGroupSpec, *, planning: bool = True
) -> list[Change]:
    """The change that gives a group's members the declared tiers, weights and monitors.

    Signalbox never creates or removes groups or members: a declared group or member the device
    does not have is an error. Planning also needs ``adopt: true`` (every group is the device's
    own); the drift comparison does not (``planning=False``)."""
    _known(net, spec.device)
    group = _group_of(net, spec.device, spec.name)
    if group is None:
        raise PlanError(
            f"{spec.device} has no gateway group {spec.name}; Signalbox does not create groups",
            message_id="plan.groupMissing",
            params={"device": spec.device, "group": spec.name},
        )
    old = _group_value(group)
    have = {m.name for m in old.members}
    unknown = [m.name for m in spec.members if m.name not in have]
    if unknown:
        raise PlanError(
            f"Gateway group {spec.name} of {spec.device} has no member {', '.join(unknown)}; "
            "Signalbox does not add members",
            message_id="plan.groupMemberMissing",
            params={"device": spec.device, "group": spec.name, "member": ", ".join(unknown)},
        )
    declared = {m.name: m for m in spec.members}
    tiers = [
        d.tier if (d := declared.get(m.name)) is not None and d.tier is not None else m.tier
        for m in old.members
    ]
    members = []
    for m, rank in zip(old.members, _ranks(tiers), strict=True):
        d = declared.get(m.name)
        update: dict[str, Any] = {"tier": rank}
        if d is not None and d.weight is not None:
            update["weight"] = d.weight
        if d is not None and d.monitor is not None:
            update["monitor"] = _addresses(d.monitor)
        members.append(m.model_copy(update=update))
    new = GatewayGroupValue(members=members)
    if new == old:
        return []
    if planning and not spec.adopt:
        raise PlanError(
            f"Gateway group {spec.name} of {spec.device} is the device's own: add adopt: true "
            "to its entry to let a deployment change it",
            message_id="plan.groupAdopt",
            params={"device": spec.device, "group": spec.name},
        )
    return [
        Change(
            kind=ChangeKind.GATEWAY_GROUP,
            device_id=spec.device,
            site_id=site_id,
            key=group_key(spec.name),
            old=old,
            new=new,
            adopt=spec.name,
        )
    ]


def _check_monitors(changes: list[Change]) -> None:
    """A monitor belongs to a line: one line in two groups needs one set of addresses."""
    seen: dict[tuple[str, str], list[IPAddress]] = {}
    for c in changes:
        if c.kind is not ChangeKind.GATEWAY_GROUP or not isinstance(c.new, GatewayGroupValue):
            continue
        for m in c.new.members:
            other = seen.setdefault((c.device_id, m.name), m.monitor)
            if other != m.monitor:
                raise PlanError(
                    f"{c.device_id}: the line {m.name} is in several gateway groups with "
                    "different monitor addresses; its monitor is one for all its groups",
                    message_id="plan.groupMonitorConflict",
                    params={"device": c.device_id, "member": m.name},
                )


def _apply_group(net: Network, c: Change) -> Network:
    """A gateway group change on the predicted network: tiers, weights, monitors and mode."""
    if not isinstance(c.new, GatewayGroupValue):  # pragma: no cover - groups are not removed
        return net
    want = {m.name: m for m in c.new.members}
    name = c.key.partition("/")[2]
    groups = []
    for g in net.gateway_groups:
        if g.device_id == c.device_id and g.name == name:
            members = [
                m.model_copy(
                    update={"tier": w.tier, "weight": w.weight, "monitor_targets": w.monitor}
                )
                if (w := want.get(m.name)) is not None
                else m
                for m in g.members
            ]
            failover = len({m.tier for m in members}) > 1
            g = g.model_copy(
                update={
                    "members": members,
                    "mode": GroupMode.FAILOVER if failover else GroupMode.BALANCE,
                    "active": g.active if failover else None,
                }
            )
        groups.append(g)
    return net.model_copy(update={"gateway_groups": groups})


# WireGuard tunnels (#152, ADR 0034) -----------------------------------------------------------


def tunnel_key(name: str) -> str:
    return f"tunnel/{name}"


def peer_key(name: str) -> str:
    return f"peer/{name}"


def _interfaces(values: Iterable[IPInterface]) -> list[IPInterface]:
    return sorted(set(values), key=lambda a: (a.version, int(a.ip), a.network.prefixlen))


def _networks(values: Iterable[IPNetwork]) -> list[IPNetwork]:
    return sorted(set(values), key=lambda n: (n.version, int(n.network_address), n.prefixlen))


def _tunnel_on(net: Network, device_id: str, name: str, interface: str | None) -> Tunnel | None:
    """The WireGuard interface tagged ``name``; without one, the untagged one named
    ``interface`` (the device's own: for adoption and the drift comparison)."""
    found = [t for t in net.tunnels_of(device_id) if t.kind is TunnelKind.WIREGUARD]
    mine = next((t for t in found if t.signalbox_key == name), None)
    if mine is None and interface:
        mine = next((t for t in found if t.signalbox_key is None and t.name == interface), None)
    return mine


def _peer_on(t: Tunnel, name: str, public_key: str | None) -> TunnelPeer | None:
    """The peer tagged ``name``; without one, the untagged peer with the other end's key."""
    mine = next((p for p in t.peers if p.signalbox_key == name), None)
    if mine is None and public_key:
        mine = next(
            (p for p in t.peers if p.signalbox_key is None and p.public_key == public_key), None
        )
    return mine


def tunnel_value(t: Tunnel) -> TunnelValue:
    return TunnelValue(
        interface=t.name, listen_port=t.listen_port, addresses=_interfaces(t.addresses), mtu=t.mtu
    )


def peer_value(t: Tunnel, p: TunnelPeer) -> TunnelPeerValue:
    return TunnelPeerValue(
        interface=t.name,
        public_key=p.public_key,
        endpoint_host=p.endpoint_host,
        endpoint_port=p.endpoint_port if p.endpoint_host else None,
        allowed_ips=_networks(p.allowed_ips),
        keepalive=p.keepalive_seconds,
    )


def observed_tunnel(
    net: Network, device_id: str, key: str, adopt: str | None = None
) -> TunnelValue | None:
    """The interface of tunnel ``tunnel/<name>`` as the device has it (None: there is none)."""
    t = _tunnel_on(net, device_id, key.partition("/")[2], adopt)
    return tunnel_value(t) if t is not None else None


def observed_peer(net: Network, c: Change) -> TunnelPeerValue | None:
    """The peer a ``tunnel-peer`` change touches, as the device has it now."""
    name = c.key.partition("/")[2]
    values = [v for v in (c.new, c.old) if isinstance(v, TunnelPeerValue)]
    t = _tunnel_on(net, c.device_id, name, values[0].interface if values else None)
    if t is None:
        return None
    p = next((p for v in values if (p := _peer_on(t, name, v.public_key)) is not None), None)
    return peer_value(t, p) if p is not None else None


def _peer_loose(old: TunnelPeerValue | None, new: TunnelPeerValue) -> TunnelPeerValue | None:
    """``old`` without the fields ``new`` leaves to the device: without a declared endpoint
    the device reports where it last saw the peer, which is not a setting."""
    if old is None:
        return None
    update: dict[str, Any] = {}
    if new.endpoint_host is None:
        update.update(endpoint_host=None, endpoint_port=None)
    if new.keepalive is None:
        update["keepalive"] = None
    return old.model_copy(update=update)


def tunnel_changes(
    net: Network, site_id: str, spec: TunnelSpec, *, planning: bool = True
) -> tuple[list[Change], list[tuple[str, str]]]:
    """The changes that make both ends of a tunnel match the declaration, and the peers that
    wait for the other end's public key (it exists once the other end's interface does).

    Planning refuses an interface of the declared name that Signalbox did not create unless the
    end says ``adopt: true``; the drift comparison (``planning=False``) compares it anyway."""
    for end in spec.ends:
        _known(net, end.device)
    out: list[Change] = []
    pending: list[tuple[str, str]] = []
    a, b = spec.ends
    for end, other in ((a, b), (b, a)):
        t = _tunnel_on(net, end.device, spec.name, end.interface)
        ours = t is not None and t.signalbox_key == spec.name
        if planning and t is not None and not ours and not end.adopt:
            raise PlanError(
                f"{end.device} has its own interface {end.interface}: add adopt: true to this "
                f"end of tunnel {spec.name} to let a deployment change it",
                message_id="plan.tunnelAdopt",
                params={"device": end.device, "interface": end.interface, "tunnel": spec.name},
            )
        if t is not None and t.name != end.interface:
            raise PlanError(
                f"{end.device}: tunnel {spec.name} is on interface {t.name}; Signalbox does not "
                f"rename it to {end.interface}",
                message_id="plan.tunnelRename",
                params={
                    "device": end.device,
                    "tunnel": spec.name,
                    "interface": t.name,
                    "wanted": end.interface,
                },
            )
        adopt = end.interface if end.adopt and not ours else None
        old = tunnel_value(t) if t is not None else None
        new = TunnelValue(
            interface=end.interface,
            listen_port=end.listen_port
            if end.listen_port is not None
            else (old.listen_port if old else None),
            addresses=_interfaces(end.addresses)
            if end.addresses is not None
            else (old.addresses if old else []),
            mtu=end.mtu if end.mtu is not None else (old.mtu if old else None),
        )
        if old != new:
            out.append(
                Change(
                    kind=ChangeKind.TUNNEL,
                    device_id=end.device,
                    site_id=site_id,
                    key=tunnel_key(spec.name),
                    old=old,
                    new=new,
                    adopt=adopt,
                )
            )
        theirs = _tunnel_on(net, other.device, spec.name, other.interface)
        if theirs is None or theirs.public_key is None:
            pending.append(
                (
                    end.device,
                    f"{end.device}: the peer of tunnel {spec.name} waits for the public key of "
                    f"{other.interface} on {other.device}; it is read once that interface exists, "
                    "and the next deployment adds the peer",
                )
            )
            continue
        p = _peer_on(t, spec.name, theirs.public_key) if t is not None else None
        p_old = peer_value(t, p) if t is not None and p is not None else None
        p_new = _peer_value(end, other, theirs, p_old)
        if _peer_loose(p_old, p_new) != p_new:
            out.append(
                Change(
                    kind=ChangeKind.TUNNEL_PEER,
                    device_id=end.device,
                    site_id=site_id,
                    key=peer_key(spec.name),
                    old=p_old,
                    new=p_new,
                    adopt=adopt,
                )
            )
    return out, pending


def _peer_value(
    end: TunnelEndSpec, other: TunnelEndSpec, theirs: Tunnel, old: TunnelPeerValue | None
) -> TunnelPeerValue:
    """The peer ``end`` needs for ``other``: its public key (read from the device), endpoint
    and listen port, and as allowed IPs its tunnel addresses and networks."""
    assert theirs.public_key is not None
    host, port = other.endpoint_parts()
    if host is not None and port is None:
        port = theirs.listen_port
    addresses = other.addresses if other.addresses is not None else theirs.addresses
    return TunnelPeerValue(
        interface=end.interface,
        public_key=theirs.public_key,
        endpoint_host=host,
        endpoint_port=port if host else None,
        allowed_ips=_networks([*(ip_network(x.ip) for x in addresses), *other.networks]),
        keepalive=end.keepalive if end.keepalive is not None else (old.keepalive if old else None),
    )


def tunnel_removals(state: DesiredState, net: Network) -> list[Change]:
    """Tunnels and peers Signalbox created (tagged) on devices of the declared sites that no
    tunnel of the desired state names any more: they go away, like firewall rules."""
    declared = {t.name for spec in state.sites.values() for t in spec.tunnels}
    out: list[Change] = []
    for t in sorted(net.tunnels, key=lambda x: x.id):
        dev = net.device(t.device_id)
        if dev is None or dev.site_id not in state.sites or t.kind is not TunnelKind.WIREGUARD:
            continue
        for p in t.peers:
            if p.signalbox_key and p.signalbox_key not in declared:
                out.append(
                    Change(
                        kind=ChangeKind.TUNNEL_PEER,
                        device_id=t.device_id,
                        site_id=dev.site_id,
                        key=peer_key(p.signalbox_key),
                        old=peer_value(t, p),
                    )
                )
        if t.signalbox_key and t.signalbox_key not in declared:
            out.append(
                Change(
                    kind=ChangeKind.TUNNEL,
                    device_id=t.device_id,
                    site_id=dev.site_id,
                    key=tunnel_key(t.signalbox_key),
                    old=tunnel_value(t),
                )
            )
    return out


def tunnel_plan(state: DesiredState, net: Network) -> tuple[list[Change], list[str]]:
    """Every tunnel change of the desired state and the peers that wait for a public key."""
    out: list[Change] = []
    pending: list[str] = []
    for site_id, spec in state.sites.items():
        for ts in spec.tunnels:
            changes, waiting = tunnel_changes(net, site_id, ts)
            out += changes
            pending += [text for _, text in waiting]
    return [*out, *tunnel_removals(state, net)], pending


def _apply_tunnel(net: Network, c: Change) -> Network:
    """A tunnel or peer change on the predicted network (no keys: a new interface has none)."""
    name = c.key.partition("/")[2]
    tunnels = list(net.tunnels)
    if c.kind is ChangeKind.TUNNEL:
        t = _tunnel_on(net, c.device_id, name, c.adopt)
        if t is not None:
            tunnels.remove(t)
        if isinstance(c.new, TunnelValue):
            v = c.new
            update: dict[str, Any] = {
                "name": v.interface,
                "listen_port": v.listen_port,
                "addresses": list(v.addresses),
                "mtu": v.mtu,
                # an adopted interface stays the device's own: it is not tagged
                "signalbox_key": name if t is None else t.signalbox_key,
            }
            tunnels.append(
                t.model_copy(update=update)
                if t is not None
                else Tunnel(
                    id=object_id(c.device_id, "tunnel", v.interface),
                    device_id=c.device_id,
                    **update,
                )
            )
        return net.model_copy(update={"tunnels": tunnels})
    values = [x for x in (c.new, c.old) if isinstance(x, TunnelPeerValue)]
    t = next(
        (x for x in tunnels if x.device_id == c.device_id and x.name == values[0].interface), None
    )
    if t is None:
        return net
    gone = next((p for v in values if (p := _peer_on(t, name, v.public_key)) is not None), None)
    peers = [p for p in t.peers if p is not gone]
    if isinstance(c.new, TunnelPeerValue):
        n = c.new
        keep_endpoint = n.endpoint_host is None and gone is not None
        peers.append(
            TunnelPeer(
                public_key=n.public_key,
                endpoint_host=gone.endpoint_host if keep_endpoint and gone else n.endpoint_host,
                endpoint_port=gone.endpoint_port if keep_endpoint and gone else n.endpoint_port,
                allowed_ips=list(n.allowed_ips),
                keepalive_seconds=n.keepalive
                if n.keepalive is not None
                else (gone.keepalive_seconds if gone else None),
                preshared_key=gone.preshared_key if gone else None,
                signalbox_key=name if gone is None else gone.signalbox_key,
            )
        )
    tunnels[tunnels.index(t)] = t.model_copy(update={"peers": peers})
    return net.model_copy(update={"tunnels": tunnels})


def _carried(net: Network, c: Change) -> list[IPNetwork]:
    """What a tunnel change can move: the networks the touched interface or peer carries
    before and after (its tunnel networks, the allowed IPs of its peers)."""
    out: list[IPNetwork] = []
    if c.kind is ChangeKind.TUNNEL:
        t = _tunnel_on(net, c.device_id, c.key.partition("/")[2], c.adopt)
        if t is not None and c.old is not None:
            out += [a.network for a in t.addresses]
            out += [n for p in t.peers for n in p.allowed_ips]
        if isinstance(c.new, TunnelValue):
            out += [a.network for a in c.new.addresses]
        return out
    for v in (c.old, c.new):
        if isinstance(v, TunnelPeerValue):
            out += v.allowed_ips
    return out


def tunnel_cuts(
    before: Network, changes: Iterable[Change], signalbox_address: IPAddress | None = None
) -> list[str]:
    """Tunnel changes that may cut Signalbox's way to a device (#152, ADR 0034): the touched
    interface or peer carries, before or after, a configured device's management address or
    Signalbox's own address. Approved only with the explicit ``allow_lockout`` override."""
    targets: list[tuple[str, IPAddress]] = []
    for d in before.devices:
        if (ep := management_endpoint(d.management_address)) is not None:
            targets.append((d.name, ep[0]))
    if signalbox_address is not None:
        targets.append(("Signalbox", signalbox_address))
    out: list[str] = []
    for c in changes:
        if c.kind not in TUNNEL_KINDS:
            continue
        carried = _carried(before, c)
        dev = before.device(c.device_id)
        here = dev.name if dev is not None else c.device_id
        for who, address in targets:
            if any(n.version == address.version and address in n for n in carried):
                out.append(
                    f"{here}: the {c.kind.value} change of tunnel {c.key.partition('/')[2]} "
                    f"touches the way to {who} ({address}); Signalbox may lose its access"
                )
    return list(dict.fromkeys(out))


# planner --------------------------------------------------------------------------------------

SecretLookup = Callable[[str], str | None]


class PlanError(Exception):
    """The desired state cannot be planned. ``message_id`` and ``params`` translate it (#204)."""

    def __init__(
        self,
        message: str,
        *,
        message_id: str | None = None,
        params: MessageParams | None = None,
    ) -> None:
        super().__init__(message)
        self.message_id = message_id
        self.params: MessageParams = plain_params(params)


def changes_for(
    state: DesiredState, net: Network, secret: SecretLookup | None = None
) -> list[Change]:
    """Desired minus observed: the changes that make the network match the desired state."""
    out: list[Change] = []
    for site_id, spec in state.sites.items():
        gateways = [
            d.id for d in net.devices if d.site_id == site_id and d.role is DeviceRole.GATEWAY
        ]
        aps = [d.id for d in net.devices if d.site_id == site_id and d.role is DeviceRole.AP]
        for s in spec.segments:
            sid = seg_sid(site_id, s.vlan)
            vlan = seg_key(s.vlan)
            if s.gateway is not None:
                _known(net, s.gateway.device)
                old_r = observed_router(net, s.gateway.device, sid)
                new_r = RouterValue(
                    vlan=vlan,
                    name=s.name or (old_r.name if old_r else None),
                    address=s.gateway.address,
                )
                if old_r != new_r:
                    out.append(
                        Change(
                            kind=ChangeKind.ROUTER,
                            device_id=s.gateway.device,
                            site_id=site_id,
                            key=sid,
                            old=old_r,
                            new=new_r,
                        )
                    )
            if s.dhcp is not None:
                dev = s.dhcp.device or (s.gateway.device if s.gateway else None)
                if dev is None:
                    if len(gateways) != 1:
                        raise PlanError(
                            f"{sid}: DHCP needs a device (no single gateway)",
                            message_id="plan.dhcpNoDevice",
                            params={"segment": sid},
                        )
                    dev = gateways[0]
                _known(net, dev)
                old_d = observed_dhcp(net, dev, sid)
                base = old_d or DhcpValue(enabled=False)
                new_d = DhcpValue(
                    enabled=s.dhcp.enabled,
                    pool=s.dhcp.pool if s.dhcp.pool is not None else base.pool,
                    dns=s.dhcp.dns if s.dhcp.dns is not None else base.dns,
                    lease_seconds=s.dhcp.lease_seconds
                    if s.dhcp.lease_seconds is not None
                    else base.lease_seconds,
                )
                if old_d != new_d:
                    out.append(
                        Change(
                            kind=ChangeKind.DHCP,
                            device_id=dev,
                            site_id=site_id,
                            key=sid,
                            old=old_d,
                            new=new_d,
                        )
                    )
                have = {
                    r.mac: r
                    for srv in net.dhcp_servers
                    if srv.device_id == dev and srv.segment_id == sid
                    for r in srv.reservations
                }
                for r in s.reservations:
                    new_res = ReservationValue(mac=r.mac, address=r.address, hostname=r.hostname)
                    old = have.get(r.mac)
                    old_res = (
                        ReservationValue(mac=old.mac, address=old.address, hostname=old.hostname)
                        if old
                        else None
                    )
                    if old_res != new_res:
                        out.append(
                            Change(
                                kind=ChangeKind.RESERVATION,
                                device_id=dev,
                                site_id=site_id,
                                key=f"{sid}/{r.mac}",
                                old=old_res,
                                new=new_res,
                            )
                        )
        for p in spec.ports:
            _known(net, p.device)
            pid = port_id(p.device, p.port)
            if net.port(pid) is None:
                raise PlanError(
                    f"port {pid} does not exist on the device",
                    message_id="plan.noPort",
                    params={"port": pid},
                )
            old_p = observed_port(net, pid)
            new_p = PortValue(
                untagged="native" if p.untagged == 1 else p.untagged, tagged=sorted(p.tagged)
            )
            if old_p != new_p:
                out.append(
                    Change(
                        kind=ChangeKind.PORT,
                        device_id=p.device,
                        site_id=site_id,
                        key=pid,
                        old=old_p,
                        new=new_p,
                    )
                )
        for w in spec.wlans:
            if w.passphrase_secret and secret is not None and secret(w.passphrase_secret) is None:
                raise PlanError(
                    f"SSID {w.ssid}: secret {w.passphrase_secret!r} is not stored",
                    message_id="plan.secretNotStored",
                    params={"ssid": w.ssid, "name": repr(w.passphrase_secret)},
                )
            wanted: list[tuple[str, WlanValue | None, WlanValue]] = []
            before = len(out)
            for dev in w.devices if w.devices is not None else aps:
                _known(net, dev)
                old_w = observed_wlan(net, dev, w.ssid)
                new_w = WlanValue(
                    ssid=w.ssid,
                    security=w.security,
                    pmf=w.pmf if w.pmf is not None else (old_w.pmf if old_w else None),
                    segment="native" if w.segment == 1 else w.segment,
                    hidden=w.hidden,
                    enabled=w.enabled,
                    roaming_80211r=w.roaming.r
                    if w.roaming.r is not None
                    else (old_w.roaming_80211r if old_w else None),
                    roaming_80211k=w.roaming.k
                    if w.roaming.k is not None
                    else (old_w.roaming_80211k if old_w else None),
                    roaming_80211v=w.roaming.v
                    if w.roaming.v is not None
                    else (old_w.roaming_80211v if old_w else None),
                    mobility_domain=w.roaming.mobility_domain
                    if w.roaming.mobility_domain is not None
                    else (old_w.mobility_domain if old_w else None),
                    ft_over_ds=w.roaming.over_ds
                    if w.roaming.over_ds is not None
                    else (old_w.ft_over_ds if old_w else None),
                    min_rssi_dbm=_min_rssi(w.min_rssi_dbm, old_w),
                    client_isolation=w.client_isolation
                    if w.client_isolation is not None
                    else (old_w.client_isolation if old_w else None),
                    passphrase_secret=w.passphrase_secret,
                )
                if new_w.roaming_80211r is False:  # the 802.11r details mean nothing then
                    new_w = new_w.model_copy(update={"mobility_domain": None, "ft_over_ds": None})
                wanted.append((dev, old_w, new_w))
                passphrase_changes = _passphrase_differs(
                    net, dev, w.ssid, w.passphrase_secret, secret
                )
                compare_old = (
                    old_w.model_copy(update={"passphrase_secret": w.passphrase_secret})
                    if old_w
                    else None
                )
                if compare_old != new_w or passphrase_changes:
                    out.append(
                        Change(
                            kind=ChangeKind.WLAN,
                            device_id=dev,
                            site_id=site_id,
                            key=w.ssid,
                            old=old_w,
                            new=new_w,
                        )
                    )
            if any(c.kind is ChangeKind.WLAN and c.key == w.ssid for c in out[before:]):
                _check_mobility_domain(w.ssid, wanted)
        for fws in spec.firewalls:
            out += firewall_changes(net, site_id, fws)
        if spec.logging is not None:
            ids = [d.id for d in net.devices if d.site_id == site_id]
            for eff in effective_logging(spec.logging, ids):
                known = net.device(eff.device)
                if not eff.explicit and (known is None or known.log_targets is None):
                    continue  # a device whose integration does not read this: not touched
                out += logging_changes(net, site_id, eff)
        for gg in spec.gateway_groups:
            out += gateway_group_changes(net, site_id, gg)
    _check_monitors(out)
    return [*out, *tunnel_plan(state, net)[0]]


def _min_rssi(
    declared: int | Literal["off"] | None, old: WlanValue | None
) -> int | Literal["off"] | None:
    """The minimum signal to write: the declared one; ``off`` only where the device reports
    a limit (a device that reports none already has no limit, or does not say); else as it is."""
    have = old.min_rssi_dbm if old else None
    if declared is None:
        return have
    if declared == "off":
        return "off" if isinstance(have, int) else have
    return declared


def _check_mobility_domain(
    ssid: str, wanted: list[tuple[str, WlanValue | None, WlanValue]]
) -> None:
    """One 802.11r mobility domain per SSID across its access points (ADR 0033): a plan that
    changes an SSID with 802.11r on at more than one access point needs them to have, or be
    given, the same domain; one that is not reported counts as different."""
    ft = [(dev, new.mobility_domain) for dev, _, new in wanted if new.roaming_80211r]
    if len(ft) < 2 or (len({domain for _, domain in ft}) == 1 and ft[0][1] is not None):
        return
    shown = ", ".join(f"{dev} ({domain or '?'})" for dev, domain in ft)
    raise PlanError(
        f"SSID {ssid}: 802.11r is on at {shown}, but not with one mobility domain; declare "
        "roaming.mobility_domain for the SSID",
        message_id="plan.mobilityDomainSplit",
        params={"ssid": ssid, "devices": shown},
    )


def _passphrase_differs(
    net: Network, dev: str, ssid: str, name: str | None, secret: SecretLookup | None
) -> bool:
    if not name or secret is None:
        return False
    value = secret(name)
    w = next((x for x in net.wlans if x.device_id == dev and x.ssid == ssid), None)
    if value is None or w is None or w.passphrase_fingerprint is None:
        return False
    return w.passphrase_fingerprint != passphrase_fingerprint(ssid, value)


def _known(net: Network, device_id: str) -> None:
    if net.device(device_id) is None:
        raise PlanError(
            f"device {device_id} is not configured or has not been read yet",
            message_id="plan.deviceUnknown",
            params={"device": device_id},
        )


def mark_risks(changes: list[Change], net: Network) -> list[Change]:
    """Flag changes that can cut off a device Signalbox manages, or Signalbox itself.

    - a router address change on a segment that holds a device's management address
    - a port change on a port that is one end of a known link (an uplink or trunk)
    """
    linked = {p for link in net.links for p in (link.a, link.b)}
    mgmt: dict[str, list[str]] = {}
    for d in net.devices:
        if not d.management_address:
            continue
        for sub in net.subnets:
            try:
                inside = IPv4Address(d.management_address.split(":")[0]) in sub.interface.network
            except ValueError:
                inside = False
            if inside:
                mgmt.setdefault(sub.segment_id, []).append(d.id)
    out = []
    for c in changes:
        risk = None
        if c.kind is ChangeKind.ROUTER and c.old is not None and mgmt.get(c.key):
            risk = "devices are managed through this network: " + ", ".join(sorted(mgmt[c.key]))
        elif c.kind is ChangeKind.PORT and c.key in linked:
            risk = "the port is one end of a link; a mistake cuts off the devices behind it"
        out.append(c.model_copy(update={"risk": risk}) if risk else c)
    return out


# predicted network ----------------------------------------------------------------------------


def _segment(net: Network, site_id: str, vlan: int | None, name: str | None) -> Network:
    sid = segment_id(site_id, vlan)
    if net.segment(sid) is not None:
        if name:
            segs = [s.model_copy(update={"name": name}) if s.id == sid else s for s in net.segments]
            return net.model_copy(update={"segments": segs})
        return net
    seg = Segment(id=sid, site_id=site_id, vlan=vlan, name=name)
    return net.model_copy(update={"segments": [*net.segments, seg]})


def _prune(net: Network) -> Network:
    """Drop segments nothing uses any more (a removed VLAN disappears from the device)."""
    used = {m for s in net.segments if s.members for m in [s.id]}
    used |= {x.segment_id for x in net.subnets}
    used |= {x.segment_id for x in net.dhcp_servers}
    used |= {x.segment_id for x in net.wlans if x.segment_id}
    used |= {x.segment_id for x in net.clients if x.segment_id}
    segs = [s for s in net.segments if s.id in used]
    return net if len(segs) == len(net.segments) else net.model_copy(update={"segments": segs})


def apply_change(net: Network, c: Change) -> Network:
    """The network as it would be after one change (pure; used for checks before deploying)."""
    out = _apply(net, c)
    return _prune(out) if c.new is None or c.kind in (ChangeKind.PORT, ChangeKind.WLAN) else out


def _apply(net: Network, c: Change) -> Network:
    if c.kind is ChangeKind.ROUTER:
        subs = [
            s
            for s in net.subnets
            if not (
                s.device_id == c.device_id
                and s.segment_id == c.key
                and isinstance(s.interface.ip, IPv4Address)
            )
        ]
        if isinstance(c.new, RouterValue):
            net = _segment(net, c.site_id, c.new.vlan, c.new.name)
            subs.append(
                Subnet(
                    id=object_id(c.device_id, "subnet", c.key.rsplit("/", 1)[-1]),
                    segment_id=c.key,
                    interface=c.new.address,
                    device_id=c.device_id,
                    gateway=True,
                )
            )
        return net.model_copy(update={"subnets": subs})
    if c.kind is ChangeKind.DHCP:
        servers = [
            s
            for s in net.dhcp_servers
            if not (s.device_id == c.device_id and s.segment_id == c.key)
        ]
        old = next(
            (s for s in net.dhcp_servers if s.device_id == c.device_id and s.segment_id == c.key),
            None,
        )
        if isinstance(c.new, DhcpValue):
            n = c.new
            servers.append(
                DhcpServer(
                    id=old.id if old else object_id(c.device_id, "dhcp", c.key.rsplit("/", 1)[-1]),
                    device_id=c.device_id,
                    segment_id=c.key,
                    enabled=n.enabled,
                    pools=[DhcpPool(start=n.pool[0], end=n.pool[1])] if n.pool else [],
                    lease_seconds=n.lease_seconds,
                    router=old.router if old else None,
                    dns_servers=list(n.dns or []),
                    reservations=list(old.reservations) if old else [],
                )
            )
        return net.model_copy(update={"dhcp_servers": servers})
    if c.kind is ChangeKind.RESERVATION:
        sid, mac = c.key.rsplit("/", 1)
        servers = []
        for s in net.dhcp_servers:
            if s.device_id == c.device_id and s.segment_id == sid:
                res = [r for r in s.reservations if r.mac != mac]
                if isinstance(c.new, ReservationValue):
                    res.append(
                        Reservation(mac=c.new.mac, address=c.new.address, hostname=c.new.hostname)
                    )
                s = s.model_copy(update={"reservations": res})
            servers.append(s)
        return net.model_copy(update={"dhcp_servers": servers})
    if c.kind is ChangeKind.PORT:
        new = c.new if isinstance(c.new, PortValue) else PortValue()
        wanted: dict[int | None, Membership] = {}
        if new.untagged is not None:
            wanted[seg_key(new.untagged)] = Membership.UNTAGGED
        for v in new.tagged:
            wanted[seg_key(v)] = Membership.TAGGED
        # "native" is the device's own untagged network (one of several at a site, #205)
        home = net.native_segment(c.device_id) or segment_id(c.site_id, None)
        for vlan in wanted:
            net = _segment(net, c.site_id, vlan, None)
        segs = []
        for sg in net.segments:
            members = [m for m in sg.members if m.port_id != c.key]
            if sg.site_id == c.site_id:
                key = seg_key(sg.vlan) if sg.vlan is not None else None
                other_native = key is None and is_native_segment(sg.id) and sg.id != home
                if key in wanted and not other_native:
                    members.append(PortMembership(port_id=c.key, mode=wanted[key]))
            segs.append(sg.model_copy(update={"members": members}))
        # the writers set the PVID to the untagged VLAN (#156); tagged only: up to the device
        pvid = None if new.untagged is None else seg_key(new.untagged) or 1
        ports = [
            p.model_copy(update={"pvid": pvid}) if p.id == c.key and p.pvid is not None else p
            for p in net.ports
        ]
        return net.model_copy(update={"segments": segs, "ports": ports})
    if c.kind in FIREWALL_KINDS:
        return _apply_firewall(net, c)
    if c.kind in LOGGING_KINDS:
        return _apply_logging(net, c)
    if c.kind is ChangeKind.GATEWAY_GROUP:
        return _apply_group(net, c)
    if c.kind in TUNNEL_KINDS:
        return _apply_tunnel(net, c)
    # WLAN
    wl = [w for w in net.wlans if not (w.device_id == c.device_id and w.ssid == c.key)]
    if isinstance(c.new, WlanValue):
        w = c.new
        net = _segment(net, c.site_id, seg_key(w.segment), None)
        wseg = segment_id(c.site_id, seg_key(w.segment))
        if seg_key(w.segment) is None:
            wseg = net.native_segment(c.device_id) or wseg
        radios: list[Radio | None] = [r for r in net.radios if r.device_id == c.device_id]
        for i, radio in enumerate(radios or [None]):
            wl.append(
                Wlan(
                    id=object_id(c.device_id, "wlan", f"{w.ssid}-{i}"),
                    device_id=c.device_id,
                    ssid=w.ssid,
                    radio_id=radio.id if radio else object_id(c.device_id, "radio", "0"),
                    enabled=w.enabled,
                    security=w.security,
                    pmf=w.pmf,
                    segment_id=wseg,
                    hidden=w.hidden,
                    roaming_80211r=w.roaming_80211r,
                    roaming_80211k=w.roaming_80211k,
                    roaming_80211v=w.roaming_80211v,
                    ft=FastTransition(mobility_domain=w.mobility_domain, over_ds=w.ft_over_ds)
                    if w.roaming_80211r and (w.mobility_domain or w.ft_over_ds is not None)
                    else None,
                    min_rssi_dbm=w.min_rssi_dbm if isinstance(w.min_rssi_dbm, int) else None,
                    client_isolation=w.client_isolation,
                )
            )
    return net.model_copy(update={"wlans": wl})


def _match(zone: str | None, networks: list[IPNetwork], ports: list[PortRange]) -> FirewallMatch:
    negated = bool(zone and zone.startswith("!"))
    zones = [z for z in (zone or "").lstrip("!").split(",") if z]
    return FirewallMatch(zones=zones, zones_not=negated, networks=networks, ports=ports)


def _apply_firewall(net: Network, c: Change) -> Network:
    """A firewall change on the predicted network. Signalbox's rules come before the
    device's own ones (the writers put them there), in the order they were created."""
    fw = net.firewall_of(c.device_id)
    if fw is None:  # pragma: no cover - the planner refuses an unread firewall
        return net
    key = c.key.partition("/")[2]
    if c.kind is ChangeKind.ZONE_POLICY:
        source, dest = _policy_pair(c.key)
        policies = [p for p in fw.policies if (p.source, p.destination) != (source, dest)]
        if isinstance(c.new, ZonePolicyValue):
            policies.append(
                ZonePolicy(
                    source=source,
                    destination=dest,
                    action=c.new.action,
                    signalbox_key=key if dest not in (None, source) else None,
                )
            )
        fw = fw.model_copy(update={"policies": policies})
    elif c.kind is ChangeKind.FIREWALL_RULE:
        old = _owned(fw.rules, key, c.adopt)
        rules = [r for r in fw.rules if r is not old]
        if isinstance(c.new, FirewallRuleValue):
            v = c.new
            rule = FirewallRule(
                name=v.name,
                enabled=v.enabled,
                chain=v.chain,
                family=v.family,
                protocols=v.protocols,
                source=_match(v.source_zone, v.source_networks, []),
                destination=_match(v.destination_zone, v.destination_networks, v.destination_ports),
                action=v.action,
                signalbox_key=key,
            )
            if old is not None and old.signalbox_key == key:
                at = fw.rules.index(old)
            else:
                at = next((i for i, r in enumerate(rules) if r.signalbox_key is None), len(rules))
            rules.insert(at, rule)
        fw = fw.model_copy(update={"rules": rules})
    else:
        old = _owned(fw.port_forwards, key, c.adopt)
        forwards = [f for f in fw.port_forwards if f is not old]
        if isinstance(c.new, PortForwardValue):
            v2 = c.new
            forwards.append(
                PortForward(
                    name=v2.name,
                    enabled=v2.enabled,
                    protocols=v2.protocols,
                    zones=[v2.zone],
                    external_ports=v2.external_ports,
                    target_address=v2.target_address,
                    target_port=v2.target_port,
                    # the writers create forwards that pass the filter by themselves (OpenWrt)
                    passes_filter=True,
                    signalbox_key=key,
                )
            )
        fw = fw.model_copy(update={"port_forwards": forwards})
    return net.model_copy(
        update={"firewalls": [fw if f.device_id == c.device_id else f for f in net.firewalls]}
    )


def management_endpoint(address: str | None) -> tuple[IPAddress, int | None] | None:
    """``192.0.2.1``, ``192.0.2.1:8443``, ``[2001:db8::1]:443``, a URL: address and port."""
    if not address:
        return None
    text = address.split("://", 1)[-1].split("/", 1)[0]
    host, port = text, None
    if text.startswith("["):
        host, _, rest = text[1:].partition("]")
        port = rest[1:] if rest.startswith(":") else None
    elif text.count(":") == 1:
        host, port = text.split(":")
    try:
        return ip_address(host), int(port) if port else None
    except ValueError:
        return None


_RANK = {Verdict.DENIED: 0, Verdict.UNKNOWN: 1, Verdict.ALLOWED: 2}


def management_cuts(
    before: Network,
    after: Network,
    changes: Iterable[Change],
    signalbox_address: IPAddress | None = None,
) -> list[str]:
    """Devices whose management access from Signalbox the firewall changes may cut (#295).

    Simulated with :func:`signalbox.firewall.reach` before and after the plan, from
    ``signalbox_address`` (Signalbox's own address as the devices see it) or, without it, from
    the network of each device's management address. Reported when the answer gets worse:
    allowed becomes denied or unknown, unknown becomes denied.
    """
    changes = list(changes)
    if not any(c.kind in FIREWALL_KINDS for c in changes):
        return []
    sites = {c.site_id for c in changes}
    out = []
    for d in before.devices:
        target = management_endpoint(d.management_address)
        if d.site_id not in sites or target is None:
            continue
        address, port = target
        source = reachability.address_segment(before, signalbox_address or address)
        if source is None:
            continue
        was = reachability.reach(before, source, address, port, FirewallProtocol.TCP)
        now = reachability.reach(after, source, address, port, FirewallProtocol.TCP)
        if _RANK[now.verdict] < _RANK[was.verdict]:
            where = f"{address}" + (f" port {port}" if port else "")
            out.append(
                f"{d.name}: Signalbox may lose its access to {where} from {source} "
                f"({was.verdict.value} before, {now.verdict.value} after: {now.reason})"
            )
    return out


def predict(net: Network, changes: Iterable[Change]) -> Network:
    for c in changes:
        net = apply_change(net, c)
    return Network.model_validate(net.model_dump())


# plan -----------------------------------------------------------------------------------------


class Plan(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    created_at: datetime
    changes: list[Change]
    #: Findings on the predicted network that do not exist on the current one.
    new_findings: list[Finding] = Field(default_factory=list)
    #: Findings that the plan resolves.
    resolved_findings: list[Finding] = Field(default_factory=list)
    #: Devices whose management access from Signalbox the firewall changes may cut (#295):
    #: the plan is approved only with the explicit override ``allow_lockout``.
    lockouts: list[str] = Field(default_factory=list)
    #: Tunnel peers left for the next deployment: they wait for the public key of an
    #: interface that does not exist yet (#152, ADR 0034).
    pending: list[str] = Field(default_factory=list)

    @property
    def blocking(self) -> list[Finding]:
        return [f for f in self.new_findings if f.severity is Severity.ERROR and f.problem]

    def devices(self) -> list[str]:
        return list(dict.fromkeys(c.device_id for c in self.changes))

    def for_device(self, device_id: str) -> list[Change]:
        return [c for c in self.changes if c.device_id == device_id]


def make_plan(
    changes: list[Change],
    net: Network,
    rules: list[Rule],
    settings: dict[str, RuleSettings] | None = None,
    signalbox_address: IPAddress | None = None,
) -> Plan:
    """Order the changes, flag risks, and check the predicted network (and, for firewall
    changes, that Signalbox keeps its access to the devices)."""
    sites = {c.site_id for c in changes}
    dist: dict[str, int] = {}
    for site in sites:
        dist.update(gateway_distance(net, site))
    ordered = mark_risks(order(changes, dist), net)
    before = {f.id: f for f in evaluate(net, rules, settings)}
    predicted = predict(net, ordered)
    after = {f.id: f for f in evaluate(predicted, rules, settings)}
    stamp = datetime.now(UTC)
    digest = hashlib.sha256(
        "\n".join([stamp.isoformat(), *(c.model_dump_json() for c in ordered)]).encode()
    ).hexdigest()[:12]
    return Plan(
        id=f"plan-{digest}",
        created_at=stamp,
        changes=ordered,
        new_findings=[f for k, f in after.items() if k not in before],
        resolved_findings=[f for k, f in before.items() if k not in after],
        lockouts=[
            *management_cuts(net, predicted, ordered, signalbox_address),
            *tunnel_cuts(net, ordered, signalbox_address),
        ],
    )


def plan(
    state: DesiredState,
    net: Network,
    rules: list[Rule],
    settings: dict[str, RuleSettings] | None = None,
    secret: SecretLookup | None = None,
    signalbox_address: IPAddress | None = None,
) -> Plan:
    out = make_plan(changes_for(state, net, secret), net, rules, settings, signalbox_address)
    pending = tunnel_plan(state, net)[1]
    return out.model_copy(update={"pending": pending}) if pending else out


def revert_plan(
    changes: list[Change],
    net: Network,
    rules: list[Rule],
    settings: dict[str, RuleSettings] | None = None,
    signalbox_address: IPAddress | None = None,
) -> Plan:
    """A plan that undoes recorded changes (their inverses, re-ordered and checked)."""
    return make_plan([c.inverse() for c in changes], net, rules, settings, signalbox_address)
