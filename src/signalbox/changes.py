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
from ipaddress import IPv4Address
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

from signalbox.desired import DesiredState, SegmentRef, seg_key
from signalbox.model import (
    DeviceRole,
    DhcpPool,
    DhcpServer,
    IPAddress,
    IPInterface,
    Membership,
    Network,
    Pmf,
    PortMembership,
    Radio,
    Reservation,
    Security,
    Segment,
    Subnet,
    Wlan,
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
    #: None: not specified (left as the device has it).
    client_isolation: bool | None = None
    #: Name of the secret holding the passphrase; resolved by the deployment, never stored here.
    passphrase_secret: str | None = None


VALUE_TYPES: dict[ChangeKind, type[Value]] = {
    ChangeKind.ROUTER: RouterValue,
    ChangeKind.DHCP: DhcpValue,
    ChangeKind.RESERVATION: ReservationValue,
    ChangeKind.PORT: PortValue,
    ChangeKind.WLAN: WlanValue,
}
#: Order in which kinds are applied when objects are created or changed; removals run reversed.
PHASE = {
    ChangeKind.ROUTER: 0,
    ChangeKind.DHCP: 1,
    ChangeKind.RESERVATION: 2,
    ChangeKind.PORT: 3,
    ChangeKind.WLAN: 4,
}

AnyValue = RouterValue | DhcpValue | ReservationValue | PortValue | WlanValue


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
        client_isolation=w.client_isolation,
    )


# planner --------------------------------------------------------------------------------------

SecretLookup = Callable[[str], str | None]


class PlanError(Exception):
    pass


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
            sid = segment_id(site_id, seg_key(s.vlan))
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
                        raise PlanError(f"{sid}: DHCP needs a device (no single gateway)")
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
                raise PlanError(f"port {pid} does not exist on the device")
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
                raise PlanError(f"SSID {w.ssid}: secret {w.passphrase_secret!r} is not stored")
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
                    client_isolation=w.client_isolation
                    if w.client_isolation is not None
                    else (old_w.client_isolation if old_w else None),
                    passphrase_secret=w.passphrase_secret,
                )
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
    return out


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
        raise PlanError(f"device {device_id} is not configured or has not been read yet")


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
        for vlan in wanted:
            net = _segment(net, c.site_id, vlan, None)
        segs = []
        for sg in net.segments:
            members = [m for m in sg.members if m.port_id != c.key]
            if sg.site_id == c.site_id:
                key = seg_key(sg.vlan) if sg.vlan is not None else None
                if key in wanted:
                    members.append(PortMembership(port_id=c.key, mode=wanted[key]))
            segs.append(sg.model_copy(update={"members": members}))
        # the writers set the PVID to the untagged VLAN (#156); tagged only: up to the device
        pvid = None if new.untagged is None else seg_key(new.untagged) or 1
        ports = [
            p.model_copy(update={"pvid": pvid}) if p.id == c.key and p.pvid is not None else p
            for p in net.ports
        ]
        return net.model_copy(update={"segments": segs, "ports": ports})
    # WLAN
    wl = [w for w in net.wlans if not (w.device_id == c.device_id and w.ssid == c.key)]
    if isinstance(c.new, WlanValue):
        w = c.new
        net = _segment(net, c.site_id, seg_key(w.segment), None)
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
                    segment_id=segment_id(c.site_id, seg_key(w.segment)),
                    hidden=w.hidden,
                    roaming_80211r=w.roaming_80211r,
                    roaming_80211k=w.roaming_80211k,
                    roaming_80211v=w.roaming_80211v,
                    client_isolation=w.client_isolation,
                )
            )
    return net.model_copy(update={"wlans": wl})


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

    @property
    def blocking(self) -> list[Finding]:
        return [f for f in self.new_findings if f.severity is Severity.ERROR and not f.incomplete]

    def devices(self) -> list[str]:
        return list(dict.fromkeys(c.device_id for c in self.changes))

    def for_device(self, device_id: str) -> list[Change]:
        return [c for c in self.changes if c.device_id == device_id]


def make_plan(
    changes: list[Change],
    net: Network,
    rules: list[Rule],
    settings: dict[str, RuleSettings] | None = None,
) -> Plan:
    """Order the changes, flag risks, and check the predicted network."""
    sites = {c.site_id for c in changes}
    dist: dict[str, int] = {}
    for site in sites:
        dist.update(gateway_distance(net, site))
    ordered = mark_risks(order(changes, dist), net)
    before = {f.id: f for f in evaluate(net, rules, settings)}
    after = {f.id: f for f in evaluate(predict(net, ordered), rules, settings)}
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
    )


def plan(
    state: DesiredState,
    net: Network,
    rules: list[Rule],
    settings: dict[str, RuleSettings] | None = None,
    secret: SecretLookup | None = None,
) -> Plan:
    return make_plan(changes_for(state, net, secret), net, rules, settings)


def revert_plan(
    changes: list[Change],
    net: Network,
    rules: list[Rule],
    settings: dict[str, RuleSettings] | None = None,
) -> Plan:
    """A plan that undoes recorded changes (their inverses, re-ordered and checked)."""
    return make_plan([c.inverse() for c in changes], net, rules, settings)
