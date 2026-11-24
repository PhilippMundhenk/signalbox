"""Desired state: what the network should look like (component "desired state", issue #36).

The desired state is a partial description in YAML: only what is declared is managed. Files
live in ``<data>/desired/`` (one or more ``*.yaml``, merged per site); the folder may be a git
repository, then every save from the UI is a commit. Wi-Fi passphrases are never written into
the YAML: an SSID names a secret (``passphrase_secret``) kept encrypted by Signalbox.

Drift rules compare the desired state with the observed network field by field.
"""

from __future__ import annotations

import hashlib
import shutil
import subprocess
from collections.abc import Callable, Iterator, Mapping
from datetime import UTC, date, datetime
from ipaddress import IPv4Address
from pathlib import Path
from typing import Annotated, Any, Literal

import yaml
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    ValidationError,
    field_validator,
    model_validator,
)

from signalbox.model import (
    Acknowledgement,
    Annotation,
    AnnotationSource,
    DeviceRole,
    Expected,
    IPAddress,
    IPInterface,
    Membership,
    Network,
    Pmf,
    PurposeSource,
    Security,
    SegmentPurpose,
    annotation_target,
    check_expected,
    is_native_segment,
    normalise_mac,
    passphrase_fingerprint,
    port_id,
    segment_id,
)
from signalbox.rules import Result, Rule, Severity, found, incomplete

FOLDER = "desired"
SegmentRef = int | Literal["native"]


NativeKey = Annotated[str, StringConstraints(pattern=r"^native-[A-Za-z0-9._-]+$")]
"""Key of the untagged network of a further router (ADR 0005): ``native-<router id>``."""


def seg_key(ref: SegmentRef | NativeKey | None) -> int | None:
    if (
        ref is None
        or ref == "native"
        or ref == 1
        or (isinstance(ref, str) and ref.startswith("native-"))
    ):
        return None
    return int(ref)


def seg_sid(site_id: str, ref: SegmentRef | NativeKey | None) -> str:
    """Segment id of a segment entry; ``native-<router>`` names a further router's network."""
    if isinstance(ref, str) and ref.startswith("native-"):
        return f"{site_id}/segment/{ref}"
    return segment_id(site_id, seg_key(ref))


class Spec(BaseModel):
    model_config = ConfigDict(extra="forbid")


class GatewaySpec(Spec):
    device: str
    address: IPInterface = Field(description="Router address with prefix, e.g. 198.51.100.1/24")


class DhcpSpec(Spec):
    enabled: bool = True
    device: str | None = Field(None, description="DHCP server device; default: the gateway")
    pool: tuple[IPAddress, IPAddress] | None = None
    dns: list[IPAddress] | None = None
    lease_seconds: int | None = Field(None, ge=60)


class ReservationSpec(Spec):
    mac: str
    address: IPAddress
    hostname: str | None = None

    @field_validator("mac")
    @classmethod
    def _mac(cls, v: str) -> str:
        return normalise_mac(v)


class SegmentSpec(Spec):
    vlan: SegmentRef | NativeKey = Field(
        description='VLAN id, "native" for the (main) untagged LAN, or native-<router id> for '
        "the untagged LAN of a further router"
    )
    name: str | None = None
    purpose: SegmentPurpose | None = Field(
        None, description="What the network is for (main, guest, iot, management, ...)"
    )
    gateway: GatewaySpec | None = None
    dhcp: DhcpSpec | None = None
    reservations: list[ReservationSpec] = Field(default_factory=list)


class RoamingSpec(Spec):
    r: bool | None = None
    k: bool | None = None
    v: bool | None = None


class WlanSpec(Spec):
    ssid: str = Field(min_length=1, max_length=32)
    security: Security
    passphrase_secret: str | None = Field(None, description="Name of a stored secret")
    pmf: Pmf | None = None
    segment: SegmentRef = "native"
    devices: list[str] | None = Field(None, description="Access points; default: all of the site")
    hidden: bool = False
    enabled: bool = True
    roaming: RoamingSpec = RoamingSpec()
    purpose: SegmentPurpose | None = Field(
        None, description="What the SSID is for; default: the purpose of its segment"
    )
    client_isolation: bool | None = Field(
        None, description="Stations of this SSID cannot reach each other"
    )


class PortSpec(Spec):
    device: str
    port: str
    untagged: SegmentRef | None = Field(None, description='VLAN sent untagged, or "native"')
    tagged: list[int] = Field(default_factory=list)


class AnnotationSpec(Spec):
    """What the user knows about one object (#186); never written to a device."""

    target: str = Field(
        min_length=1,
        max_length=300,
        description="Device id, <device>/port/<name>, <site>/segment/<key>, a MAC address, ...",
    )
    label: str | None = Field(None, max_length=100, description="Friendly name")
    purpose: str | None = Field(None, max_length=200)
    owner: str | None = Field(None, max_length=100)
    notes: str | None = Field(None, max_length=2000)
    tags: list[Annotated[str, Field(min_length=1, max_length=40)]] = Field(
        default_factory=list, max_length=20
    )
    expected: Expected = Field(default_factory=Expected)

    @field_validator("target")
    @classmethod
    def _target(cls, v: str) -> str:
        return annotation_target(v)

    def annotation(self) -> Annotation:
        return Annotation(
            **self.model_dump(exclude={"expected"}),
            expected=self.expected,
            source=AnnotationSource.DECLARED,
        )


class AcknowledgementSpec(Spec):
    """A finding accepted on purpose (#186): one finding, or every finding of a rule that
    names the target."""

    rule: str = Field(min_length=1, max_length=100, description="Rule id, e.g. dhcp.static-in-pool")
    finding: str | None = Field(None, max_length=64, description="Finding id (one finding)")
    target: str | None = Field(None, max_length=300, description="Object the findings name")
    reason: str | None = Field(None, max_length=500)
    by: str | None = Field(None, max_length=100)
    at: date | datetime | None = Field(None, description="When it was acknowledged")
    until: date | datetime | None = Field(
        None, description="Expires then (a date: at the start of that day, UTC)"
    )
    fingerprint: str | None = Field(
        None, max_length=64, description="Lapses when the finding's message changes"
    )

    @field_validator("target")
    @classmethod
    def _target(cls, v: str | None) -> str | None:
        return annotation_target(v) if v is not None else None

    def acknowledgement(self, site_id: str) -> Acknowledgement:
        key = "\x00".join([site_id, self.rule, self.finding or "", self.target or ""])
        return Acknowledgement(
            id="declared-" + hashlib.sha256(key.encode()).hexdigest()[:12],
            rule_id=self.rule,
            finding_id=self.finding,
            target=self.target,
            reason=self.reason,
            by=self.by,
            at=_as_datetime(self.at),
            until=_as_datetime(self.until),
            fingerprint=self.fingerprint,
            source=AnnotationSource.DECLARED,
        )


def _as_datetime(value: datetime | date | None) -> datetime | None:
    if value is None or isinstance(value, datetime):
        return value
    return datetime(value.year, value.month, value.day, tzinfo=UTC)


class SiteSpec(Spec):
    segments: list[SegmentSpec] = Field(default_factory=list)
    wlans: list[WlanSpec] = Field(default_factory=list)
    ports: list[PortSpec] = Field(default_factory=list)
    #: User annotations of objects of the site (#186).
    annotations: list[AnnotationSpec] = Field(default_factory=list)
    #: Accepted findings (#186).
    acknowledgements: list[AcknowledgementSpec] = Field(default_factory=list)

    @model_validator(mode="after")
    def _scoped(self) -> SiteSpec:
        for a in self.annotations:
            check_expected(a.target, a.expected)
        for ack in self.acknowledgements:
            if ack.finding is None and ack.target is None:
                raise ValueError(f"acknowledgement of {ack.rule}: name a finding or a target")
        return self


class DesiredState(Spec):
    sites: dict[str, SiteSpec] = Field(default_factory=dict)

    def merged(self, other: DesiredState) -> DesiredState:
        sites = dict(self.sites)
        for name, spec in other.sites.items():
            old = sites.get(name)
            sites[name] = (
                spec
                if old is None
                else SiteSpec(
                    segments=[*old.segments, *spec.segments],
                    wlans=[*old.wlans, *spec.wlans],
                    ports=[*old.ports, *spec.ports],
                    annotations=[*old.annotations, *spec.annotations],
                    acknowledgements=[*old.acknowledgements, *spec.acknowledgements],
                )
            )
        return DesiredState(sites=sites)


class DesiredError(Exception):
    pass


def _validation_message(source: str, exc: ValidationError) -> str:
    parts = [f"{'.'.join(map(str, e['loc']))}: {e['msg']}" for e in exc.errors()]
    return f"{source}: " + "; ".join(parts)


def parse(text: str, source: str = "desired state") -> DesiredState:
    try:
        raw = yaml.safe_load(text) or {}
    except yaml.YAMLError as exc:
        raise DesiredError(f"{source}: not valid YAML: {exc}") from exc
    if not isinstance(raw, dict):
        raise DesiredError(f"{source}: expected a mapping with a 'sites' key")
    try:
        state = DesiredState.model_validate(raw)
    except ValidationError as exc:
        raise DesiredError(_validation_message(source, exc)) from exc
    _check_unique(state, source)
    return state


def _check_unique(state: DesiredState, source: str) -> None:
    targets = [a.target for spec in state.sites.values() for a in spec.annotations]
    dup = sorted({t for t in targets if targets.count(t) > 1})
    if dup:
        raise DesiredError(f"{source}: annotation declared twice: {', '.join(dup)}")
    for site, spec in state.sites.items():
        vlans = [seg_sid(site, s.vlan) for s in spec.segments]
        dup = sorted({v.rsplit("/", 1)[-1] for v in vlans if vlans.count(v) > 1})
        if dup:
            raise DesiredError(f"{source}: site {site}: segment declared twice: {', '.join(dup)}")
        ssids = [w.ssid for w in spec.wlans]
        dup = sorted({s for s in ssids if ssids.count(s) > 1})
        if dup:
            raise DesiredError(f"{source}: site {site}: SSID declared twice: {', '.join(dup)}")
        ports = [(p.device, p.port) for p in spec.ports]
        dup = sorted({f"{d}/{p}" for d, p in ports if ports.count((d, p)) > 1})
        if dup:
            raise DesiredError(f"{source}: site {site}: port declared twice: {', '.join(dup)}")


def load(data_dir: Path) -> DesiredState | None:
    """All YAML files of ``<data>/desired`` merged, or None when there are none."""
    folder = data_dir / FOLDER
    files = sorted(folder.glob("*.yaml")) if folder.is_dir() else []
    if not files:
        return None
    state = DesiredState()
    for f in files:
        state = state.merged(parse(f.read_text(), f.name))
    _check_unique(state, FOLDER)
    return state


def dump(state: DesiredState) -> str:
    data = state.model_dump(mode="json", exclude_defaults=True)
    return yaml.safe_dump(data, sort_keys=False, allow_unicode=True)


def save(data_dir: Path, text: str, message: str, author: str = "Signalbox") -> str | None:
    """Validate and write ``desired/network.yaml``; commit when the folder is a git repository.

    Returns the commit id, or None without git.
    """
    parse(text, "network.yaml")
    folder = data_dir / FOLDER
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "network.yaml").write_text(text)
    git = shutil.which("git")
    if git is None or not (folder / ".git").exists():
        return None

    def run(*args: str) -> str:
        return subprocess.run(
            [git, "-C", str(folder), *args], check=True, capture_output=True, text=True
        ).stdout.strip()

    run("add", "network.yaml")
    if not run("status", "--porcelain"):
        return run("rev-parse", "HEAD")
    run(
        "-c",
        f"user.name={author}",
        "-c",
        "user.email=signalbox@localhost",
        "commit",
        "-m",
        message or "Desired state changed in Signalbox",
    )
    return run("rev-parse", "HEAD")


# declared purposes --------------------------------------------------------------------------


def apply_declared(net: Network, state: DesiredState | None) -> Network:
    """The network with the purposes the desired state declares (they beat reported ones).

    A reported purpose that differs is kept in ``reported_purpose`` (the drift rules report it).
    An SSID purpose applies to that SSID on the declared devices, default: all of the site.
    """
    if state is None:
        return net
    segs: dict[str, SegmentPurpose] = {}
    ssids: dict[tuple[str, str], tuple[SegmentPurpose, list[str] | None]] = {}
    for site_id, spec in state.sites.items():
        for s in spec.segments:
            if s.purpose is not None:
                segs[seg_sid(site_id, s.vlan)] = s.purpose
        for w in spec.wlans:
            if w.purpose is not None:
                ssids[(site_id, w.ssid)] = (w.purpose, w.devices)
    if not segs and not ssids:
        return net

    def declared(obj: Any, purpose: SegmentPurpose) -> Any:
        reported = obj.purpose if obj.purpose_source is PurposeSource.REPORTED else None
        return obj.model_copy(
            update={
                "purpose": purpose,
                "purpose_source": PurposeSource.DECLARED,
                "reported_purpose": reported if reported not in (None, purpose) else None,
            }
        )

    sites = {d.id: d.site_id for d in net.devices}
    wlans = []
    for x in net.wlans:
        want = ssids.get((sites.get(x.device_id, ""), x.ssid))
        if want is not None and (want[1] is None or x.device_id in want[1]):
            x = declared(x, want[0])
        wlans.append(x)
    return net.model_copy(
        update={
            "segments": [declared(x, segs[x.id]) if x.id in segs else x for x in net.segments],
            "wlans": wlans,
        }
    )


# import from the observed network ------------------------------------------------------------


def _known_purpose(obj: Any) -> SegmentPurpose | None:
    """A purpose worth exporting: reported or declared, never a name guess."""
    return obj.purpose if obj.purpose_source is not PurposeSource.HEURISTIC else None


def from_network(net: Network, site_id: str) -> DesiredState:
    """The observed state of one site as a desired-state starting point (no passphrases)."""
    devices = {d.id: d for d in net.devices if d.site_id == site_id}
    segs: list[SegmentSpec] = []
    for seg in (s for s in net.segments if s.site_id == site_id):
        key = seg.id.rsplit("/segment/", 1)[-1]
        sub = next(
            (
                s
                for s in net.subnets
                if s.segment_id == seg.id
                and s.device_id in devices
                and (s.gateway or devices[s.device_id].role is DeviceRole.GATEWAY)
                and isinstance(s.interface.ip, IPv4Address)
            ),
            None,
        )
        dhcp = next(
            (d for d in net.dhcp_servers if d.segment_id == seg.id and d.device_id in devices),
            None,
        )
        segs.append(
            SegmentSpec(
                vlan=key
                if is_native_segment(seg.id)
                else ("native" if seg.vlan in (None, 1) else seg.vlan),
                name=seg.name,
                purpose=_known_purpose(seg),
                gateway=GatewaySpec(device=sub.device_id, address=sub.interface) if sub else None,
                dhcp=DhcpSpec(
                    enabled=dhcp.enabled,
                    device=dhcp.device_id,
                    pool=(dhcp.pools[0].start, dhcp.pools[0].end) if dhcp.pools else None,
                    dns=list(dhcp.dns_servers) or None,
                    lease_seconds=dhcp.lease_seconds,
                )
                if dhcp
                else None,
                reservations=[
                    ReservationSpec(mac=r.mac, address=r.address, hostname=r.hostname)
                    for r in (dhcp.reservations if dhcp else [])
                ],
            )
        )
    wlans: dict[str, WlanSpec] = {}
    for w in (w for w in net.wlans if w.device_id in devices):
        wseg = net.segment(w.segment_id) if w.segment_id else None
        if w.ssid in wlans:
            prev = wlans[w.ssid]
            wlans[w.ssid] = prev.model_copy(
                update={"devices": sorted({*(prev.devices or []), w.device_id})}
            )
            continue
        wlans[w.ssid] = WlanSpec(
            ssid=w.ssid,
            security=w.security,
            pmf=w.pmf,
            segment="native" if wseg is None or wseg.vlan in (None, 1) else wseg.vlan,
            devices=[w.device_id],
            hidden=w.hidden,
            enabled=w.enabled,
            roaming=RoamingSpec(r=w.roaming_80211r, k=w.roaming_80211k, v=w.roaming_80211v),
            purpose=_known_purpose(w),
            client_isolation=w.client_isolation,
        )
    ports: list[PortSpec] = []
    for p in (p for p in net.ports if p.device_id in devices):
        untagged: SegmentRef | None = None
        tagged: list[int] = []
        for seg in net.segments:
            for m in seg.members:
                if m.port_id != p.id:
                    continue
                vlan = seg.vlan if seg.vlan not in (None, 1) else None
                if m.mode is Membership.UNTAGGED:
                    untagged = "native" if vlan is None else vlan
                elif vlan is not None:
                    tagged.append(vlan)
        if untagged is not None or tagged:
            ports.append(
                PortSpec(device=p.device_id, port=p.name, untagged=untagged, tagged=sorted(tagged))
            )
    return DesiredState(
        sites={site_id: SiteSpec(segments=segs, wlans=list(wlans.values()), ports=ports)}
    )


# drift ---------------------------------------------------------------------------------------

SecretLookup = Callable[[str], str | None]


def _fmt(value: Any) -> str:
    if value is None:
        return "not set"
    if isinstance(value, list | tuple):
        return ", ".join(str(v) for v in value) or "none"
    return str(getattr(value, "value", value))


def _differ(field: str, want: Any, have: Any) -> str:
    return f"{field}: should be {_fmt(want)}, is {_fmt(have)}"


def _native_of(net: Network, device_id: str, sid: str) -> str:
    """``native`` on a port or SSID is the device's own untagged network (#205): at a site with
    several routers, the one of the router the device is behind."""
    if sid != segment_id(sid.rsplit("/segment/", 1)[0], None):
        return sid
    return net.native_segment(device_id) or sid


def drift_rules(state: DesiredState, secret: SecretLookup | None = None) -> list[Rule]:
    """Rules comparing the observed network with ``state`` (one finding per difference)."""

    def segments(net: Network) -> Iterator[Result]:
        for site_id, spec in state.sites.items():
            for s in spec.segments:
                sid = seg_sid(site_id, s.vlan)
                seg = net.segment(sid)
                if seg is None:
                    yield found(
                        f"Segment {_fmt(s.vlan)} ({s.name or 'unnamed'}) does not exist",
                        [sid],
                        key="missing",
                        fix="Deploy the desired state, or remove the segment from it.",
                    )
                    continue
                if s.name and seg.name and s.name != seg.name:
                    yield found(
                        _differ(f"Segment {_fmt(s.vlan)} name", s.name, seg.name),
                        [sid],
                        key="name",
                        severity=Severity.INFO,
                    )
                if s.purpose is not None and seg.reported_purpose is not None:
                    yield found(
                        f"Segment {_fmt(s.vlan)} is declared as {s.purpose.value}, but "
                        f"the device reports it as {seg.reported_purpose.value}",
                        [sid],
                        key="purpose",
                        severity=Severity.INFO,
                        fix="Check which is right and correct the desired state or the device.",
                    )
                if s.gateway:
                    yield from _gateway(net, sid, s.gateway)
                if s.dhcp:
                    yield from _dhcp(net, sid, s)

    def _gateway(net: Network, sid: str, g: GatewaySpec) -> Iterator[Result]:
        if net.device(g.device) is None:
            yield incomplete(f"gateway device {g.device} is not configured or not read", [sid])
            return
        subs = [x for x in net.subnets if x.segment_id == sid and x.device_id == g.device]
        if not any(x.interface == g.address for x in subs):
            have = [str(x.interface) for x in subs]
            yield found(
                _differ(f"{sid} router address on {g.device}", g.address, have),
                [sid, g.device],
                key="gateway",
            )

    def _dhcp(net: Network, sid: str, s: SegmentSpec) -> Iterator[Result]:
        d = s.dhcp
        assert d is not None
        device = d.device or (s.gateway.device if s.gateway else None)
        servers = [
            x
            for x in net.dhcp_servers
            if x.segment_id == sid and (device is None or x.device_id == device)
        ]
        if device is None and not d.enabled:
            for x in servers:
                if x.enabled:
                    yield found(
                        _differ(f"{sid} DHCP on {x.device_id}", "off", "on"), [x.id], key="enabled"
                    )
            return
        servers.sort(key=lambda x: not x.enabled)  # without a named device: the enabled one
        if not servers:
            if d.enabled:
                yield found(
                    f"{sid}: no DHCP server{f' on {device}' if device else ''}",
                    [sid],
                    key="dhcp",
                )
            return
        srv = servers[0]
        if srv.enabled != d.enabled:
            yield found(
                _differ(f"{sid} DHCP enabled", d.enabled, srv.enabled), [srv.id], key="enabled"
            )
        if d.pool is not None:
            have = (srv.pools[0].start, srv.pools[0].end) if srv.pools else None
            if have != tuple(d.pool):
                yield found(
                    _differ(f"{sid} DHCP pool", list(d.pool), list(have or [])),
                    [srv.id],
                    key="pool",
                )
        if d.dns is not None and list(srv.dns_servers) != list(d.dns):
            yield found(
                _differ(f"{sid} DHCP DNS servers", d.dns, srv.dns_servers), [srv.id], key="dns"
            )
        if d.lease_seconds is not None and srv.lease_seconds != d.lease_seconds:
            yield found(
                _differ(f"{sid} DHCP lease time", d.lease_seconds, srv.lease_seconds),
                [srv.id],
                key="lease",
                severity=Severity.INFO,
            )
        have_res = {r.mac: r.address for r in srv.reservations}
        for r in s.reservations:
            if have_res.get(r.mac) != r.address:
                yield found(
                    _differ(f"{sid} reservation {r.mac}", r.address, have_res.get(r.mac)),
                    [srv.id],
                    key=f"res-{r.mac}",
                )

    def wlans(net: Network) -> Iterator[Result]:
        for site_id, spec in state.sites.items():
            aps = [d.id for d in net.devices if d.site_id == site_id and d.role is DeviceRole.AP]
            for w in spec.wlans:
                targets = w.devices if w.devices is not None else aps
                want_seg = segment_id(site_id, seg_key(w.segment))
                fp = None
                if w.passphrase_secret and secret is not None:
                    value = secret(w.passphrase_secret)
                    if value is None:
                        yield found(
                            f"SSID {w.ssid}: secret {w.passphrase_secret!r} is not stored",
                            [f"ssid:{w.ssid}"],
                            key="secret",
                            fix="Store the passphrase under Settings, Secrets.",
                        )
                    else:
                        fp = passphrase_fingerprint(w.ssid, value)
                for dev in targets:
                    if net.device(dev) is None:
                        yield incomplete(f"SSID {w.ssid}: device {dev} not read", [dev], key=w.ssid)
                        continue
                    have = [x for x in net.wlans if x.device_id == dev and x.ssid == w.ssid]
                    if not have:
                        yield found(
                            f"SSID {w.ssid} is missing on {dev}", [dev], key=f"{w.ssid}-missing"
                        )
                        continue
                    x = have[0]
                    checks: list[tuple[str, Any, Any]] = [
                        ("security", w.security, x.security),
                        ("enabled", w.enabled, x.enabled),
                        ("hidden", w.hidden, x.hidden),
                        ("segment", _native_of(net, dev, want_seg), x.segment_id),
                    ]
                    if w.pmf is not None:
                        checks.append(("PMF", w.pmf, x.pmf))
                    for flag, want, have_v in (
                        ("802.11r", w.roaming.r, x.roaming_80211r),
                        ("802.11k", w.roaming.k, x.roaming_80211k),
                        ("802.11v", w.roaming.v, x.roaming_80211v),
                    ):
                        if want is not None:
                            checks.append((flag, want, have_v))
                    for name, want, have_v in checks:
                        if want != have_v:
                            yield found(
                                _differ(f"SSID {w.ssid} on {dev} {name}", want, have_v),
                                [x.id],
                                key=name,
                            )
                    if w.client_isolation is not None and x.client_isolation is None:
                        yield incomplete(
                            f"SSID {w.ssid} on {dev}: the device does not report client isolation",
                            [x.id],
                            key="client-isolation",
                        )
                    elif (
                        w.client_isolation is not None and x.client_isolation != w.client_isolation
                    ):
                        yield found(
                            _differ(
                                f"SSID {w.ssid} on {dev} client isolation",
                                "on" if w.client_isolation else "off",
                                "on" if x.client_isolation else "off",
                            ),
                            [x.id],
                            key="client-isolation",
                        )
                    if w.purpose is not None and x.reported_purpose is not None:
                        yield found(
                            f"SSID {w.ssid} on {dev} is declared as {w.purpose.value}, but the "
                            f"device reports it as {x.reported_purpose.value}",
                            [x.id],
                            key="purpose",
                            severity=Severity.INFO,
                        )
                    if fp is not None and x.passphrase_fingerprint not in (None, fp):
                        yield found(
                            f"SSID {w.ssid} on {dev}: passphrase differs from the stored secret",
                            [x.id],
                            key="passphrase",
                        )

    def ports(net: Network) -> Iterator[Result]:
        for site_id, spec in state.sites.items():
            for p in spec.ports:
                pid = port_id(p.device, p.port)
                if net.device(p.device) is None:
                    yield incomplete(f"port {pid}: device not read", [p.device], key=pid)
                    continue
                if net.port(pid) is None:
                    yield found(f"port {pid} does not exist", [pid], key="missing")
                    continue
                modes = {s.id: m.mode for s in net.segments for m in s.members if m.port_id == pid}
                want_u = (
                    _native_of(net, p.device, segment_id(site_id, seg_key(p.untagged)))
                    if p.untagged is not None
                    else None
                )
                have_u = [s for s, m in modes.items() if m is Membership.UNTAGGED]
                if (want_u is None and have_u) or (want_u is not None and have_u != [want_u]):
                    yield found(
                        _differ(f"port {pid} untagged", want_u, have_u), [pid], key="untagged"
                    )
                want_t = sorted(segment_id(site_id, v) for v in p.tagged)
                have_t = sorted(s for s, m in modes.items() if m is Membership.TAGGED)
                if want_t != have_t:
                    yield found(_differ(f"port {pid} tagged", want_t, have_t), [pid], key="tagged")

    explanation = (
        "The observed configuration differs from the desired state. Either deploy the desired "
        "state, or change the desired state to accept what is there."
    )
    return [
        Rule(
            "drift.segment",
            "Segment differs from the desired state",
            Severity.WARNING,
            explanation,
            segments,
        ),
        Rule(
            "drift.wlan",
            "Wi-Fi differs from the desired state",
            Severity.WARNING,
            explanation,
            wlans,
        ),
        Rule(
            "drift.port",
            "Port VLANs differ from the desired state",
            Severity.WARNING,
            explanation,
            ports,
        ),
    ]


def secret_lookup(values: Mapping[str, str]) -> SecretLookup:
    return values.get
