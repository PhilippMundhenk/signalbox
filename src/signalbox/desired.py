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
    field_serializer,
    field_validator,
    model_validator,
)

from signalbox.model import (
    Acknowledgement,
    Annotation,
    AnnotationSource,
    DeviceRole,
    DeviceStatus,
    Expected,
    Firewall,
    FirewallAction,
    FirewallChain,
    FirewallProtocol,
    IPAddress,
    IPInterface,
    IPNetwork,
    LogKind,
    LogTransport,
    Membership,
    Network,
    Pmf,
    PortRange,
    PurposeSource,
    Security,
    Segment,
    SegmentPurpose,
    ServiceKind,
    annotation_target,
    check_expected,
    is_native_segment,
    normalise_mac,
    object_id,
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
    mobility_domain: str | None = Field(
        None,
        pattern=r"^[0-9a-fA-F]{4}$",
        description="802.11r mobility domain, four hex digits; one per SSID (ADR 0033)",
    )
    over_ds: bool | None = Field(
        None, description="802.11r fast transition over the distribution system"
    )

    @field_validator("mobility_domain")
    @classmethod
    def _domain(cls, value: str | None) -> str | None:
        return value.lower() if value is not None else None

    @model_validator(mode="after")
    def _needs_r(self) -> RoamingSpec:
        if (self.mobility_domain is not None or self.over_ds is not None) and self.r is not True:
            raise ValueError("mobility_domain and over_ds need r: true")
        return self


#: Weakest signal a client may have (dBm), or ``off`` for no limit (#489, ADR 0033).
MinRssi = Annotated[int, Field(ge=-120, le=-1)] | Literal["off"]


def _off_word(value: Any) -> Any:
    """YAML 1.1 reads an unquoted ``off`` as false: that is the word the user wrote."""
    return "off" if value is False else value


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
    min_rssi_dbm: MinRssi | None = Field(
        None, description="Weakest signal a client may have (dBm, -120 to -1), or off"
    )

    _rssi_word = field_validator("min_rssi_dbm", mode="before")(_off_word)


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


# firewall (#295) ----------------------------------------------------------------------------

#: Names of declared rules and forwards: they become Signalbox's tag on the device.
FIREWALL_NAME = r"^[a-z0-9][a-z0-9_-]{0,39}$"


def firewall_key(name: str) -> str:
    """The tag of a declared rule or forward (``-`` becomes ``_``: UCI section names)."""
    return name.replace("-", "_")


def _port_ranges(value: Any) -> list[PortRange]:
    """``443``, ``"8000-8100"`` or a list of those."""
    items = value if isinstance(value, list) else [value]
    out = []
    for item in items:
        if isinstance(item, PortRange):
            out.append(item)
            continue
        if isinstance(item, dict):
            out.append(PortRange.model_validate(item))
            continue
        first, sep, last = str(item).partition("-")
        try:
            out.append(PortRange(start=int(first), end=int(last) if sep else None))
        except ValueError as exc:
            raise ValueError(f"not a port or port range: {item!r}") from exc
    return out


def _protocols(value: Any) -> list[FirewallProtocol] | None:
    if value is None:
        return None
    items = value if isinstance(value, list) else [value]
    if any(str(i) == "all" for i in items):
        return []
    return [FirewallProtocol(str(i)) for i in items]


def _show_ports(ports: list[PortRange]) -> list[int | str]:
    return [r.start if r.last == r.start else str(r) for r in ports]


class SegmentZoneSpec(Spec):
    """The firewall zone that holds a segment (on the declared device)."""

    segment: SegmentRef | NativeKey


ZoneRef = str | SegmentZoneSpec


def zone_label(ref: ZoneRef | None) -> str:
    if ref is None:
        return "any"
    return ref if isinstance(ref, str) else f"segment {ref.segment}"


class PolicySpec(Spec):
    """Default action between two zones (``to: device``: traffic to the router itself)."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    from_: ZoneRef = Field(alias="from", description="Zone name, or {segment: <vlan>}")
    to: ZoneRef = Field(description='Zone name, {segment: <vlan>}, or "device" (the router)')
    action: FirewallAction
    adopt: bool = Field(
        False,
        description="Signalbox may remove the device's own forwarding of this pair for 'reject'",
    )


class EndpointSpec(Spec):
    """Source or destination of a rule: a zone (by name or segment) and/or addresses."""

    zone: str | None = None
    segment: SegmentRef | NativeKey | None = None
    network: list[IPNetwork] = Field(
        default_factory=list, description="Addresses or prefixes (one or a list)"
    )

    @field_validator("network", mode="before")
    @classmethod
    def _one(cls, v: Any) -> Any:
        return v if isinstance(v, list) else [v]

    @model_validator(mode="after")
    def _either(self) -> EndpointSpec:
        if self.zone is not None and self.segment is not None:
            raise ValueError("give a zone or a segment, not both")
        return self

    def zone_ref(self) -> ZoneRef | None:
        if self.segment is not None:
            return SegmentZoneSpec(segment=self.segment)
        return self.zone


class RuleSpec(Spec):
    """A filter rule Signalbox owns. ``to: device``: traffic to the router itself."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    name: str = Field(pattern=FIREWALL_NAME, description="Identifies the rule (its tag)")
    from_: EndpointSpec = Field(default_factory=EndpointSpec, alias="from")
    to: Literal["device"] | EndpointSpec
    protocol: list[FirewallProtocol] | None = Field(
        None, description="tcp, udp, icmp, ... or all; default: tcp and udp with a port, else all"
    )
    port: list[PortRange] = Field(default_factory=list, description="Destination port(s)")
    family: Literal[4, 6] | None = None
    action: FirewallAction
    enabled: bool = True
    adopt: str | None = Field(
        None, description="Name of the device's own rule Signalbox takes over (import)"
    )

    _protocol = field_validator("protocol", mode="before")(
        classmethod(lambda cls, v: _protocols(v))
    )
    _port = field_validator("port", mode="before")(classmethod(lambda cls, v: _port_ranges(v)))
    _show = field_serializer("port")(lambda self, v: _show_ports(v))

    @model_validator(mode="after")
    def _ports(self) -> RuleSpec:
        tcp_udp = {FirewallProtocol.TCP, FirewallProtocol.UDP}
        if (
            self.port
            and self.protocol is not None
            and (not self.protocol or set(self.protocol) - tcp_udp)
        ):
            raise ValueError(f"rule {self.name}: ports need protocol tcp and/or udp")
        return self

    def protocols(self) -> list[FirewallProtocol]:
        if self.protocol is not None:
            return self.protocol
        return [FirewallProtocol.TCP, FirewallProtocol.UDP] if self.port else []


class ForwardTargetSpec(Spec):
    address: IPAddress
    port: int | None = Field(None, ge=1, le=65535, description="Default: the external port")


class ForwardSpec(Spec):
    """A port forward (destination NAT) Signalbox owns."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    name: str = Field(pattern=FIREWALL_NAME, description="Identifies the forward (its tag)")
    protocol: list[FirewallProtocol] = Field(
        default_factory=lambda: [FirewallProtocol.TCP, FirewallProtocol.UDP],
        description="tcp, udp or both (default)",
    )
    port: list[PortRange] = Field(min_length=1, max_length=1, description="External port(s)")
    from_: ZoneRef | None = Field(
        None, alias="from", description="Zone it listens on; default: the internet side"
    )
    to: ForwardTargetSpec
    enabled: bool = True
    adopt: str | None = Field(
        None, description="Name of the device's own forward Signalbox takes over (import)"
    )

    _protocol = field_validator("protocol", mode="before")(
        classmethod(lambda cls, v: _protocols(v) or [])
    )
    _port = field_validator("port", mode="before")(classmethod(lambda cls, v: _port_ranges(v)))
    _show = field_serializer("port")(lambda self, v: _show_ports(v))

    @model_validator(mode="after")
    def _tcp_udp(self) -> ForwardSpec:
        if not self.protocol or set(self.protocol) - {FirewallProtocol.TCP, FirewallProtocol.UDP}:
            raise ValueError(f"forward {self.name}: protocol must be tcp and/or udp")
        return self


class FirewallSpec(Spec):
    """What Signalbox manages on one device's firewall. Rules and forwards it created there
    earlier and that are no longer declared are removed; the device's own are left alone."""

    device: str
    policies: list[PolicySpec] = Field(default_factory=list)
    rules: list[RuleSpec] = Field(default_factory=list)
    forwards: list[ForwardSpec] = Field(default_factory=list)


# logging and SNMP (#327) -----------------------------------------------------------------------

SnmpPolicy = Literal["off", "v3-only"]


def _snmp_word(value: Any) -> Any:
    """YAML 1.1 reads an unquoted ``off`` as false: that is the word the user wrote."""
    return "off" if value is False else value


class SyslogSpec(Spec):
    """One remote syslog target of a device."""

    address: str = Field(description="IP address or host name of the collector")
    port: Annotated[int, Field(ge=1, le=65535)] | None = Field(None, description="Default 514")
    transport: Literal["udp", "tcp"] = "udp"

    @field_validator("address")
    @classmethod
    def _address(cls, value: str) -> str:
        value = value.strip().removeprefix("[").removesuffix("]")
        if not value:
            raise ValueError("empty address")
        return value


class DeviceLoggingSpec(Spec):
    """Logging of one device where it differs from the site's."""

    device: str
    syslog: list[SyslogSpec] | None = Field(
        None, description="Replaces the site's targets for this device; [] means none"
    )
    snmp: SnmpPolicy | None = None
    adopt: list[str] | None = Field(
        None, description="Addresses of the device's own syslog targets Signalbox may change"
    )

    _word = field_validator("snmp", mode="before")(_snmp_word)


class LoggingSpec(Spec):
    """Where the devices of a site send their logs, and what their SNMP agents may do (#327,
    ADR 0021). Only syslog targets Signalbox created (or ``adopt`` names) are changed."""

    syslog: list[SyslogSpec] | None = Field(
        None, description="Remote syslog targets of every device; [] means none"
    )
    snmp: SnmpPolicy | None = Field(
        None, description="off: the SNMP agent is switched off; v3-only: no v1/v2c (drift only)"
    )
    devices: list[str] | None = Field(
        None, description="Devices the site-wide settings apply to (default: every read device)"
    )
    adopt: list[str] = Field(
        default_factory=list,
        description="Addresses of the devices' own syslog targets Signalbox may change or remove",
    )
    overrides: list[DeviceLoggingSpec] = Field(default_factory=list)

    _word = field_validator("snmp", mode="before")(_snmp_word)


class EffectiveLogging(BaseModel):
    """What applies to one device: the site's settings with the device's override."""

    model_config = ConfigDict(frozen=True)

    device: str
    syslog: list[SyslogSpec] | None
    snmp: SnmpPolicy | None
    adopt: list[str]
    explicit: bool


def effective_logging(spec: LoggingSpec, device_ids: list[str]) -> list[EffectiveLogging]:
    """Per device: the site's settings (on ``spec.devices`` or every ``device_ids`` entry) and
    the override of the device, which replaces a setting it states."""
    names = list(dict.fromkeys([*(spec.devices if spec.devices is not None else device_ids)]))
    over = {o.device: o for o in spec.overrides}
    out = []
    for dev in dict.fromkeys([*names, *over]):
        o = over.get(dev)
        out.append(
            EffectiveLogging(
                device=dev,
                syslog=o.syslog if o is not None and o.syslog is not None else spec.syslog,
                snmp=o.snmp if o is not None and o.snmp is not None else spec.snmp,
                adopt=[*spec.adopt, *(o.adopt or [] if o else [])],
                explicit=dev in over or spec.devices is not None,
            )
        )
    return out


# gateway groups (#463) -------------------------------------------------------------------------


class GatewayMemberSpec(Spec):
    """One member of a gateway group: the fields to set, the others are left as they are."""

    name: str = Field(description="The device's name of the member (mwan3 interface, route)")
    tier: Annotated[int, Field(ge=1)] | None = Field(
        None, description="Failover tier: 1 is the first choice, higher numbers are backups"
    )
    weight: Annotated[int, Field(ge=0)] | None = Field(
        None, description="Share of the load among the members of one tier"
    )
    monitor: list[IPAddress] | None = Field(
        None, description="Addresses the gateway pings to check the line; [] means none"
    )


class GatewayGroupSpec(Spec):
    """Tiers, weights and monitors of a gateway group the device has (#463, ADR 0032).
    Signalbox never creates or removes groups or members; ``adopt: true`` lets a deployment
    change the group."""

    device: str
    name: str = Field(description="The device's name of the group (mwan3 policy; default)")
    adopt: bool = Field(False, description="Let a deployment change this group of the device")
    members: list[GatewayMemberSpec] = Field(default_factory=list)


def _as_datetime(value: datetime | date | None) -> datetime | None:
    if value is None or isinstance(value, datetime):
        return value
    return datetime(value.year, value.month, value.day, tzinfo=UTC)


class SiteSpec(Spec):
    segments: list[SegmentSpec] = Field(default_factory=list)
    wlans: list[WlanSpec] = Field(default_factory=list)
    ports: list[PortSpec] = Field(default_factory=list)
    #: Zone policies, rules and port forwards per device (#295).
    firewalls: list[FirewallSpec] = Field(default_factory=list)
    #: Syslog targets and the SNMP policy of the devices (#327).
    logging: LoggingSpec | None = None
    #: Tiers, weights and monitors of the devices' gateway groups (#463).
    gateway_groups: list[GatewayGroupSpec] = Field(default_factory=list)
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


def _merge_logging(a: LoggingSpec | None, b: LoggingSpec | None) -> LoggingSpec | None:
    """Two files declaring ``logging`` for one site: the later one's settings win, overrides
    and adopted addresses add up."""
    if a is None or b is None:
        return a or b
    return LoggingSpec(
        syslog=b.syslog if b.syslog is not None else a.syslog,
        snmp=b.snmp or a.snmp,
        devices=b.devices if b.devices is not None else a.devices,
        adopt=[*a.adopt, *b.adopt],
        overrides=[*a.overrides, *b.overrides],
    )


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
                    firewalls=[*old.firewalls, *spec.firewalls],
                    logging=_merge_logging(old.logging, spec.logging),
                    gateway_groups=[*old.gateway_groups, *spec.gateway_groups],
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
        devs = [f.device for f in spec.firewalls]
        dup = sorted({d for d in devs if devs.count(d) > 1})
        if dup:
            raise DesiredError(
                f"{source}: site {site}: firewall of {', '.join(dup)} declared twice"
            )
        if spec.logging is not None:
            _check_logging(spec.logging, source, site)
        _check_groups(spec.gateway_groups, source, site)
        for fw in spec.firewalls:
            for what, names in (
                ("rule", [firewall_key(r.name) for r in fw.rules]),
                ("forward", [firewall_key(f.name) for f in fw.forwards]),
            ):
                dup = sorted({n for n in names if names.count(n) > 1})
                if dup:
                    raise DesiredError(
                        f"{source}: firewall of {fw.device}: {what} declared twice: "
                        + ", ".join(dup)
                    )
            pairs = [(zone_label(p.from_), zone_label(p.to)) for p in fw.policies]
            dup = sorted({f"{a} to {b}" for a, b in pairs if pairs.count((a, b)) > 1})
            if dup:
                raise DesiredError(
                    f"{source}: firewall of {fw.device}: policy declared twice: {', '.join(dup)}"
                )


def _check_logging(spec: LoggingSpec, source: str, site: str) -> None:
    devs = [o.device for o in spec.overrides]
    dup = sorted({d for d in devs if devs.count(d) > 1})
    if dup:
        raise DesiredError(f"{source}: site {site}: logging of {', '.join(dup)} declared twice")
    lists = [("site", spec.syslog or [])] + [(o.device, o.syslog or []) for o in spec.overrides]
    for who, targets in lists:
        addresses = [t.address for t in targets]
        dup = sorted({a for a in addresses if addresses.count(a) > 1})
        if dup:
            raise DesiredError(
                f"{source}: site {site}: logging of {who}: syslog target declared twice: "
                + ", ".join(dup)
            )


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
    data = state.model_dump(mode="json", exclude_defaults=True, by_alias=True)
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


def _declared_segment(
    seg: Segment,
    purposes: dict[str, SegmentPurpose],
    names: dict[str, str],
    declared: Any,
) -> Segment:
    """``seg`` with its declared purpose and name (the name goes to ``declared_name`` only)."""
    if seg.id in purposes:
        seg = declared(seg, purposes[seg.id])
    if seg.id in names:
        seg = seg.model_copy(update={"declared_name": names[seg.id]})
    return seg


def apply_declared(net: Network, state: DesiredState | None) -> Network:
    """The network with the purposes the desired state declares (they beat reported ones).

    A reported purpose that differs is kept in ``reported_purpose`` (the drift rules report it).
    An SSID purpose applies to that SSID on the declared devices, default: all of the site.
    """
    if state is None:
        return net
    segs: dict[str, SegmentPurpose] = {}
    seg_names: dict[str, str] = {}
    ssids: dict[tuple[str, str], tuple[SegmentPurpose, list[str] | None]] = {}
    for site_id, spec in state.sites.items():
        for s in spec.segments:
            if s.purpose is not None:
                segs[seg_sid(site_id, s.vlan)] = s.purpose
            if s.name and s.name.strip():
                seg_names[seg_sid(site_id, s.vlan)] = s.name.strip()
        for w in spec.wlans:
            if w.purpose is not None:
                ssids[(site_id, w.ssid)] = (w.purpose, w.devices)
    if not segs and not ssids and not seg_names:
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
            "segments": [_declared_segment(x, segs, seg_names, declared) for x in net.segments],
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
    # 802.11r details and the minimum signal apply to every access point of the SSID: exported
    # only where all of them report the same value (ADR 0033)
    shared: dict[tuple[str, str], set[Any]] = {}
    for w in (w for w in net.wlans if w.device_id in devices):
        ft = w.ft if w.roaming_80211r is True else None
        shared.setdefault((w.ssid, "domain"), set()).add(ft.mobility_domain if ft else None)
        shared.setdefault((w.ssid, "over_ds"), set()).add(ft.over_ds if ft else None)
        rssi = w.min_rssi_dbm if w.min_rssi_dbm is not None else w.assoc_rssi_dbm
        shared.setdefault((w.ssid, "rssi"), set()).add(rssi)

    def one(ssid: str, what: str) -> Any:
        values = shared[(ssid, what)]
        return next(iter(values)) if len(values) == 1 else None

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
            roaming=RoamingSpec(
                r=w.roaming_80211r,
                k=w.roaming_80211k,
                v=w.roaming_80211v,
                mobility_domain=one(w.ssid, "domain") if w.roaming_80211r else None,
                over_ds=one(w.ssid, "over_ds") if w.roaming_80211r else None,
            ),
            purpose=_known_purpose(w),
            client_isolation=w.client_isolation,
            min_rssi_dbm=one(w.ssid, "rssi"),
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
    firewalls = [
        spec
        for fw in net.firewalls
        if fw.device_id in devices and (spec := _firewall_spec(fw)) is not None
    ]
    return DesiredState(
        sites={
            site_id: SiteSpec(
                segments=segs,
                wlans=list(wlans.values()),
                ports=ports,
                firewalls=firewalls,
                logging=_logging_spec(net, list(devices)),
                gateway_groups=_group_specs(net, list(devices)),
            )
        }
    )


def _group_specs(net: Network, device_ids: list[str]) -> list[GatewayGroupSpec]:
    """Every gateway group with all its members as the device reports them, not adopted:
    adopting is the user's decision (ADR 0032)."""
    return [
        GatewayGroupSpec(
            device=g.device_id,
            name=g.name,
            members=[
                GatewayMemberSpec(
                    name=m.name, tier=m.tier, weight=m.weight, monitor=list(m.monitor_targets)
                )
                for m in g.members
            ],
        )
        for dev in device_ids
        for g in net.gateway_groups_of(dev)
    ]


def _logging_spec(net: Network, device_ids: list[str]) -> LoggingSpec | None:
    """The syslog targets the devices send to (all of them are adopted: the device's own
    targets become declared ones) and an agent that is off. Per device, so that a site-wide
    default is a decision for the user."""
    out = []
    for dev in (net.device(i) for i in device_ids):
        if dev is None or dev.log_targets is None:
            continue
        targets = [
            t
            for t in dev.log_targets
            if t.kind is LogKind.SYSLOG and t.enabled and t.transport is not LogTransport.TLS
        ]
        agent = next((s for s in net.services_of(dev.id) if s.kind is ServiceKind.SNMP), None)
        snmp: SnmpPolicy | None = "off" if agent is not None and not agent.enabled else None
        if not targets and snmp is None:
            continue
        out.append(
            DeviceLoggingSpec(
                device=dev.id,
                syslog=[
                    SyslogSpec(
                        address=t.address,
                        port=t.port,
                        transport="tcp" if t.transport is LogTransport.TCP else "udp",
                    )
                    for t in targets
                ],
                snmp=snmp,
                adopt=[t.address for t in targets if not t.managed],
            )
        )
    return LoggingSpec(devices=[], overrides=out) if out else None


def _export_name(name: str | None, key: str) -> str:
    import re

    if name and re.match(FIREWALL_NAME, name) and firewall_key(name) == key:
        return name
    return key


def _firewall_spec(fw: Firewall) -> FirewallSpec | None:
    """The zone policies a firewall states and the rules and forwards Signalbox created
    there (the device's own rules are not exported: declaring them would duplicate them)."""
    policies = [
        PolicySpec(from_=p.source, to=p.destination or "device", action=p.action)
        for p in fw.policies
    ]
    rules = []
    for r in fw.rules:
        if not r.signalbox_key or r.chain not in (FirewallChain.INPUT, FirewallChain.FORWARD):
            continue
        to: Literal["device"] | EndpointSpec = (
            "device"
            if r.chain is FirewallChain.INPUT
            else EndpointSpec(
                zone=r.destination.zones[0] if r.destination.zones else None,
                network=list(r.destination.networks),
            )
        )
        rules.append(
            RuleSpec(
                name=_export_name(r.name, r.signalbox_key),
                from_=EndpointSpec(
                    zone=r.source.zones[0] if r.source.zones else None,
                    network=list(r.source.networks),
                ),
                to=to,
                protocol=list(r.protocols),
                port=list(r.destination.ports),
                family=r.family,
                action=r.action,
                enabled=r.enabled,
            )
        )
    forwards = [
        ForwardSpec(
            name=_export_name(f.name, f.signalbox_key),
            protocol=list(f.protocols),
            port=list(f.external_ports),
            from_=f.zones[0] if f.zones else None,
            to=ForwardTargetSpec(address=f.target_address, port=f.target_port),
            enabled=f.enabled,
        )
        for f in fw.port_forwards
        if f.signalbox_key and f.external_ports and f.protocols
    ]
    if not (policies or rules or forwards):
        return None
    return FirewallSpec(device=fw.device_id, policies=policies, rules=rules, forwards=forwards)


# drift ---------------------------------------------------------------------------------------

SecretLookup = Callable[[str], str | None]


def _check_groups(groups: list[GatewayGroupSpec], source: str, site: str) -> None:
    keys = [(g.device, g.name) for g in groups]
    dup = sorted({f"{d}/{n}" for d, n in keys if keys.count((d, n)) > 1})
    if dup:
        raise DesiredError(f"{source}: site {site}: gateway group declared twice: {', '.join(dup)}")
    for g in groups:
        names = [m.name for m in g.members]
        dup = sorted({n for n in names if names.count(n) > 1})
        if dup:
            raise DesiredError(
                f"{source}: site {site}: gateway group {g.device}/{g.name}: member declared "
                "twice: " + ", ".join(dup)
            )


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
                domains: dict[str, list[str]] = {}
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
                    if x.roaming_80211r and x.ft is not None and x.ft.mobility_domain:
                        domains.setdefault(x.ft.mobility_domain, []).append(dev)
                    if w.roaming.mobility_domain is not None:
                        checks.append(
                            (
                                "mobility domain",
                                w.roaming.mobility_domain,
                                x.ft.mobility_domain if x.ft else None,
                            )
                        )
                    if w.roaming.over_ds is not None:
                        checks.append(
                            ("802.11r over DS", w.roaming.over_ds, x.ft.over_ds if x.ft else None)
                        )
                    have_rssi = x.min_rssi_dbm if x.min_rssi_dbm is not None else x.assoc_rssi_dbm
                    if isinstance(w.min_rssi_dbm, int) or (
                        w.min_rssi_dbm == "off" and have_rssi is not None
                    ):
                        checks.append(
                            (
                                "minimum signal",
                                w.min_rssi_dbm,
                                have_rssi if have_rssi is not None else "none reported",
                            )
                        )
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
                if w.roaming.mobility_domain is None and len(domains) > 1:
                    shown = "; ".join(f"{d}: {', '.join(v)}" for d, v in sorted(domains.items()))
                    yield found(
                        f"SSID {w.ssid}: 802.11r uses more than one mobility domain ({shown}), so "
                        "clients cannot fast roam between these access points",
                        [f"ssid:{w.ssid}"],
                        key="mobility-domain-split",
                        fix="Declare roaming.mobility_domain for the SSID and deploy it.",
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

    def firewalls(net: Network) -> Iterator[Result]:
        # the planner resolves zone references; imported here (it imports this module)
        from signalbox.changes import PlanError, firewall_changes

        for site_id, spec in state.sites.items():
            for fw in spec.firewalls:
                if net.device(fw.device) is None or net.firewall_of(fw.device) is None:
                    yield incomplete(
                        f"firewall of {fw.device}: not read", [fw.device], key=fw.device
                    )
                    continue
                target = net.firewall_of(fw.device)
                assert target is not None
                try:
                    found_changes = firewall_changes(net, site_id, fw)
                except PlanError as exc:
                    yield found(
                        f"Firewall of {fw.device} cannot be compared: {exc}",
                        [target.id],
                        key="invalid",
                        fix="Correct the desired state (zone names, segments).",
                    )
                    continue
                for c in found_changes:
                    what = c.kind.value.replace("-", " ")
                    name = c.key.partition("/")[2]
                    if c.old is None:
                        message = f"Firewall of {fw.device}: {what} {name} is missing"
                    elif c.new is None:
                        message = (
                            f"Firewall of {fw.device}: {what} {name} was created by Signalbox "
                            "and is no longer declared (a deployment removes it)"
                        )
                    else:
                        old = c.old.model_dump(mode="json")
                        new = c.new.model_dump(mode="json")
                        diffs = [
                            _differ(k, new[k], old.get(k)) for k in new if old.get(k) != new[k]
                        ]
                        message = f"Firewall of {fw.device}: {what} {name}: " + "; ".join(diffs)
                    yield found(message, [target.id], key=c.key)

    def logging(net: Network) -> Iterator[Result]:
        from signalbox.changes import PlanError, logging_changes

        for site_id, spec in state.sites.items():
            if spec.logging is None:
                continue
            ids = [d.id for d in net.devices if d.site_id == site_id]
            for eff in effective_logging(spec.logging, ids):
                dev = net.device(eff.device)
                if dev is None or dev.log_targets is None:
                    if eff.explicit:
                        yield incomplete(
                            f"logging of {eff.device}: not read", [eff.device], key=eff.device
                        )
                    continue
                try:
                    found_changes = logging_changes(net, site_id, eff)
                except PlanError as exc:
                    yield found(
                        f"Logging of {eff.device} cannot be compared: {exc}",
                        [eff.device],
                        key=f"invalid/{eff.device}",
                        fix="Correct the desired state, or adopt the device's own target.",
                    )
                    continue
                for c in found_changes:
                    what = "syslog target" if c.kind.value == "log-target" else "SNMP agent"
                    name = c.key.partition("/")[2] or "policy"
                    if c.old is None:
                        message = f"Logging of {eff.device}: {what} {name} is missing"
                    elif c.new is None:
                        message = (
                            f"Logging of {eff.device}: {what} {name} is not declared "
                            "(a deployment removes it)"
                        )
                    else:
                        old = c.old.model_dump(mode="json")
                        new = c.new.model_dump(mode="json")
                        diffs = [
                            _differ(k, new[k], old.get(k)) for k in new if old.get(k) != new[k]
                        ]
                        message = f"Logging of {eff.device}: {what} {name}: " + "; ".join(diffs)
                    yield found(message, [eff.device], key=f"{eff.device}/{c.key}")

    def groups(net: Network) -> Iterator[Result]:
        from signalbox.changes import GatewayGroupValue, PlanError, gateway_group_changes
        from signalbox.sightings import ANSWERED

        for site_id, spec in state.sites.items():
            for gg in spec.gateway_groups:
                subject = f"Gateway group {gg.name} of {gg.device}"
                if (
                    net.device(gg.device) is None
                    or net.statuses.get(gg.device, DeviceStatus.OK) not in ANSWERED
                ):
                    yield incomplete(
                        f"{subject}: not read", [gg.device], key=f"{gg.device}/{gg.name}"
                    )
                    continue
                try:
                    found_changes = gateway_group_changes(net, site_id, gg, planning=False)
                except PlanError as exc:
                    yield found(
                        f"{subject}: {exc}",
                        [gg.device],
                        key=f"{gg.device}/{gg.name}",
                        fix="Correct the desired state: Signalbox changes the members of the "
                        "device's groups, it does not create groups or members.",
                    )
                    continue
                target = object_id(gg.device, "gateway-group", gg.name)
                for c in found_changes:
                    assert isinstance(c.old, GatewayGroupValue)
                    assert isinstance(c.new, GatewayGroupValue)
                    have = {m.name: m.model_dump(mode="json") for m in c.old.members}
                    for m in c.new.members:
                        want, now = m.model_dump(mode="json"), have[m.name]
                        diffs = [
                            _differ(k, want[k], now.get(k))
                            for k in ("tier", "weight", "monitor")
                            if now.get(k) != want[k]
                        ]
                        if diffs:
                            yield found(
                                f"{subject}: member {m.name}: " + "; ".join(diffs),
                                [target],
                                key=f"{gg.device}/{gg.name}/{m.name}",
                            )

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
        Rule(
            "drift.firewall",
            "Firewall differs from the desired state",
            Severity.WARNING,
            explanation
            + " Only zone policies and the rules and port forwards Signalbox created are "
            "compared; the device's own rules are left alone.",
            firewalls,
        ),
        Rule(
            "drift.logging",
            "Logging or SNMP differs from the desired state",
            Severity.WARNING,
            explanation
            + " Only the syslog targets Signalbox created or was told to adopt are compared "
            "with a change; the SNMP policy is compared by the state of the agent.",
            logging,
        ),
        Rule(
            "drift.gateway-group",
            "Gateway group differs from the desired state",
            Severity.WARNING,
            explanation
            + " Tiers are compared by their order, monitor addresses as a set; only the "
            "declared fields of the declared members are compared.",
            groups,
        ),
    ]


def secret_lookup(values: Mapping[str, str]) -> SecretLookup:
    return values.get
