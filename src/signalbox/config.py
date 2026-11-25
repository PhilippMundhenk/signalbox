"""Configuration: ``<data>/signalbox.yaml`` plus ``SIGNALBOX_*`` environment overrides.

On the first start the file is written with every key and a comment. Every key can be
overridden by an environment variable: the dotted path in upper case with underscores, for
example ``server.port`` → ``SIGNALBOX_SERVER_PORT``. Environment wins over the file.
"""

from __future__ import annotations

import logging
import os
import re
from collections.abc import Mapping
from datetime import time as dtime
from enum import StrEnum
from ipaddress import IPv4Address, IPv6Address, ip_address
from pathlib import Path
from typing import Any, Literal, get_args

import yaml
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    SecretStr,
    ValidationError,
    field_validator,
    model_validator,
)

from signalbox.rules import RuleSettings, Severity

ENV_PREFIX = "SIGNALBOX_"
FILE_NAME = "signalbox.yaml"

log = logging.getLogger(__name__)


class Section(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ServerConfig(Section):
    host: str = Field("0.0.0.0", description="Address the web interface listens on.")
    port: int = Field(8080, ge=1, le=65535, description="Port of the web interface.")
    base_url: str = Field(
        "", description="Public URL when behind a reverse proxy (used in links), e.g. https://..."
    )


class AuthConfig(Section):
    password: SecretStr | None = Field(
        None,
        description="Web interface password. Empty: generated on the first start and printed once.",
    )
    session_hours: int = Field(168, ge=1, description="How long a login stays valid.")


class ObserveConfig(Section):
    interval_seconds: int = Field(300, ge=10, description="How often every device is read.")
    timeout_seconds: float = Field(10, gt=0, description="Timeout of one device request.")
    concurrency: int = Field(4, ge=1, description="Devices read at the same time.")


class MqttConfig(Section):
    enabled: bool = Field(False, description="Publish findings and devices to Home Assistant.")
    host: str = Field("", description="MQTT broker host.")
    port: int = Field(1883, ge=1, le=65535, description="MQTT broker port.")
    username: str = Field("", description="MQTT user name, empty for none.")
    password: SecretStr | None = Field(None, description="MQTT password.")
    tls: bool = Field(False, description="Connect with TLS (and verify the certificate).")
    topic_prefix: str = Field("signalbox", description="Prefix of the state topics.")
    discovery_prefix: str = Field("homeassistant", description="Home Assistant discovery prefix.")


class ExportsConfig(Section):
    identity: bool = Field(
        False,
        description="Include device serial numbers and base MAC addresses in what leaves "
        "Signalbox (MQTT / Home Assistant discovery and exporter plugins). Off: they stay on "
        "the device page.",
    )
    wifi_clients: bool = Field(
        False,
        description="Publish the Wi-Fi association of each client (SSID, band, signal, standard, "
        "capabilities) per access point over MQTT. Off: only the number of clients. Client MAC "
        "addresses are included only if exports.identity is on as well.",
    )


class DeployConfig(Section):
    enabled: bool = Field(
        False,
        description="Allow deploying changes at all (devices also need 'allow changes').",
    )
    confirm_seconds: int = Field(
        120,
        ge=30,
        le=900,
        description="Devices that support it roll back by themselves unless confirmed in time.",
    )
    signalbox_address: IPv4Address | IPv6Address | None = Field(
        None,
        description="Signalbox's own address as the devices see it. Firewall changes are "
        "checked against it so they do not cut Signalbox off; default: each device is reached "
        "from the network of its management address.",
    )


class HistoryConfig(Section):
    days: int = Field(
        30,
        ge=1,
        le=3650,
        description="Days the observation history (first/last seen, status and link changes) "
        "is kept. Client sightings are a presence log: keep this short.",
    )


class CountersConfig(Section):
    error_ratio: float = Field(
        0.001,
        ge=0,
        le=1,
        description="Deprecated, use rules.port.errors.params.error_ratio (#441). Port error "
        "check (port.errors): report a port when the errors between two reads are at least this "
        "share of its packets (0.001: one in a thousand).",
    )
    crc_ratio: float = Field(
        0.0001,
        ge=0,
        le=1,
        description="Deprecated, use rules.port.errors.params.crc_ratio. Report a warning when "
        "the CRC/FCS errors received between two reads are at least this share of the "
        "packets received (0.0001: one in ten thousand).",
    )
    min_packets: int = Field(
        1000,
        ge=1,
        description="Deprecated, use rules.port.errors.params.min_packets. Reads with fewer "
        "packets "
        "than this on a port are too small to judge.",
    )
    min_errors: int = Field(
        5,
        ge=1,
        description="Deprecated, use rules.port.errors.params.min_errors. Fewer errors than this "
        "between two reads are never reported (a single bad frame).",
    )


class CertificatesConfig(Section):
    warn_days: int = Field(
        30,
        ge=1,
        le=3650,
        description="Deprecated, use rules.<id>.params.warn_days of security.certificate-expiry, "
        "cert.vpn-expiring and cert.ca-expiring (#441). Days before a certificate expires when "
        "Signalbox warns.",
    )
    urgent_days: int = Field(
        7,
        ge=0,
        le=3650,
        description="Deprecated, use rules.<id>.params.urgent_days of the same rules. Days "
        "before it expires when the warning becomes an error (an expired certificate is always "
        "an error).",
    )


class DiscoveryConfig(Section):
    enabled: bool = Field(
        True,
        description="Allow 'Find devices' on the devices page (started by you only, never in "
        "the background; see docs/DISCOVERY.md). false: no probe is ever sent.",
    )
    timeout_seconds: float = Field(
        2, gt=0, le=30, description="Timeout of one probe request, in seconds."
    )
    concurrency: int = Field(16, ge=1, le=128, description="Addresses probed at the same time.")
    rate_per_second: float = Field(
        30, gt=0, le=1000, description="At most this many probe requests per second."
    )
    sweep_prefix: int = Field(
        24,
        ge=16,
        le=32,
        description="Gateway subnets with this prefix length or longer are probed completely; "
        "of larger ones only the gateway and known clients.",
    )
    max_hosts: int = Field(
        1024, ge=1, le=65536, description="At most this many addresses in one run."
    )


class SetupConfig(Section):
    enabled: bool = Field(
        True,
        description="Offer 'Set up automatically' in the device form: with the admin login you "
        "give once, Signalbox creates its own least-privilege login on that device (only when "
        "you start it and confirm the plan; docs/adr/0009). false: the API refuses it and the "
        "form does not show it; the manual setup guides always work.",
    )
    fixes: bool = Field(
        True,
        description="Offer 'Fix it' next to a read problem Signalbox's own setup can repair "
        "(a missing package or permission it reads through; no 'Allow changes' needed for these), "
        "with the admin login, only when you start it and confirm the plan (docs/adr/0012). "
        "Never changes network settings. Off when this or setup.enabled is false.",
    )


class TracesConfig(Section):
    enabled: bool = Field(
        False,
        description="Path traces (docs/adr/0014): let the routers Signalbox reads (and its own "
        "host) run traceroutes to each other and to one internet address, to show the routed "
        "path. Off by default; needs an extra permission on some devices (docs/TRACES.md).",
    )
    interval_hours: int = Field(
        0,
        ge=0,
        le=720,
        description="Run all traces every this many hours; 0: only when you press Trace now.",
    )
    internet_target: str = Field(
        "1.1.1.1",
        description="The internet address every gateway traces to (an IP address); empty: none.",
    )
    from_signalbox: bool = Field(
        True,
        description="Also trace from Signalbox's own host (unprivileged UDP, no root needed).",
    )
    max_hops: int = Field(16, ge=2, le=30, description="Hops per trace at most.")
    wait_seconds: float = Field(
        1, gt=0, le=5, description="How long a hop may take to answer, in seconds."
    )
    timeout_seconds: float = Field(
        40, ge=5, le=120, description="Timeout of one whole trace, in seconds."
    )
    concurrency: int = Field(2, ge=1, le=8, description="Traces running at the same time.")
    min_gap_seconds: int = Field(
        60, ge=0, le=3600, description="Trace now is refused this soon after the last run."
    )
    max_pairs: int = Field(64, ge=1, le=512, description="At most this many traces in one run.")

    @field_validator("internet_target")
    @classmethod
    def _address(cls, value: str) -> str:
        text = value.strip()
        if text:
            ip_address(text)  # ValueError: not an IP address
        return text


class ProbesConfig(Section):
    enabled: bool = Field(
        False,
        description="Foreign DHCP servers and routers (docs/adr/0015): let Signalbox's own host "
        "send one DHCPDISCOVER (never a REQUEST: no lease is taken) and one IPv6 router "
        "solicitation on each of its networks and list who answers. Off by default; needs "
        "host networking and UDP port 68, router solicitations need CAP_NET_RAW "
        "(docs/PROBES.md).",
    )
    interval_hours: int = Field(
        0,
        ge=0,
        le=720,
        description="Probe every this many hours; 0: only when you press Probe now.",
    )
    dhcp: bool = Field(True, description="Send a DHCPDISCOVER (needs UDP port 68).")
    router_solicitation: bool = Field(
        True, description="Send an IPv6 router solicitation (needs CAP_NET_RAW)."
    )
    interfaces: list[str] = Field(
        default_factory=list,
        description="Probe only these interfaces of Signalbox's host (eth0, eth0.20); empty: "
        "every interface whose network Signalbox knows.",
    )
    wait_seconds: float = Field(
        3, ge=1, le=10, description="How long to listen for answers per interface, in seconds."
    )
    min_gap_seconds: int = Field(
        300, ge=0, le=86400, description="Probe now is refused this soon after the last run."
    )


Kind = Literal["email", "ntfy", "matrix", "telegram", "gotify", "webhook", "browser", "apprise"]


KINDS_LIST: tuple[str, ...] = get_args(Kind)


class EventKind(StrEnum):
    FINDING = "finding"  # a new or a resolved finding
    DEVICE = "device"  # a device cannot be reached or only partly read, or is back
    DRIFT = "drift"  # the network differs from the desired state
    DEPLOY = "deploy"  # the result of a deployment
    CERTIFICATE = "certificate"  # a certificate is about to expire or has expired (new only)
    ROGUE_SSID = "rogue_ssid"  # a foreign access point uses one of your Wi-Fi names (new only)


def parse_clock(text: str) -> dtime:
    match = re.fullmatch(r"([01]?\d|2[0-3]):([0-5]\d)", text)
    if match is None:
        raise ValueError("a time looks like 22:30")
    return dtime(int(match.group(1)), int(match.group(2)))


class ChannelSpec(BaseModel):
    """One notification channel (#367). ``secret`` is the token, the password or (Apprise) the
    URL: encrypted when set in the web interface, write-only there."""

    model_config = ConfigDict(extra="forbid")

    kind: Kind
    enabled: bool = Field(False, description="Send to this channel.")
    min_severity: Severity = Field(Severity.WARNING, description="Lowest severity to send.")
    events: list[EventKind] = Field(
        default_factory=lambda: list(EventKind), description="Event kinds to send."
    )
    quiet_start: str = Field("", description="Quiet hours start (HH:MM, server local time).")
    quiet_end: str = Field("", description="Quiet hours end; events wait until then.")
    language: str = Field("", description="Message language; empty: notifications.language.")
    url: str = Field("", description="Server URL (ntfy, Matrix, Gotify, Telegram API, webhook).")
    topic: str = Field("", description="ntfy topic.")
    room_id: str = Field("", description="Matrix room id.")
    chat_id: str = Field("", description="Telegram chat id.")
    host: str = Field("", description="SMTP host.")
    port: int = Field(0, ge=0, le=65535, description="SMTP port; 0: 587, 465 or 25 by security.")
    security: Literal["starttls", "ssl", "none"] = "starttls"
    verify_tls: bool = True
    username: str = ""
    sender: str = Field("", description="From address of e-mails.")
    recipients: list[str] = Field(default_factory=list)
    secret: SecretStr | None = None

    @field_validator("quiet_start", "quiet_end")
    @classmethod
    def _clock(cls, value: str) -> str:
        value = value.strip()
        if value:
            parse_clock(value)
        return value

    @field_validator("url")
    @classmethod
    def _url(cls, value: str) -> str:
        value = value.strip()
        if value and not value.startswith(("http://", "https://")):
            raise ValueError("the URL must start with http:// or https://")
        return value

    @property
    def quiet(self) -> bool:
        return bool(self.quiet_start and self.quiet_end)


class NotificationsConfig(Section):
    language: str = Field(
        "en", description="Language of notification texts (a code of the UI languages, e.g. de)."
    )
    timeout_seconds: float = Field(
        10, gt=0, le=60, description="Timeout of one delivery attempt, in seconds."
    )
    retries: int = Field(2, ge=0, le=5, description="Retries after a failed delivery (bounded).")
    channels: dict[str, ChannelSpec] = Field(
        default_factory=dict,
        description="Channels set in the file (docs/NOTIFICATIONS.md); more can be added in the "
        "web interface. Every channel is off until enabled: true.",
    )

    @field_validator("channels")
    @classmethod
    def _names(cls, value: dict[str, ChannelSpec]) -> dict[str, ChannelSpec]:
        for name in value:
            if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,39}", name):
                raise ValueError(f"channel name {name!r}: use lower case letters, digits, - and _")
        return value


class PluginsConfig(Section):
    remote_adapters: dict[str, list[str]] = Field(
        default_factory=dict,
        description="Adapters that run as separate programs: id -> command (see docs/PLUGINS.md).",
    )


class Config(Section):
    server: ServerConfig = ServerConfig()
    auth: AuthConfig = AuthConfig()
    observe: ObserveConfig = ObserveConfig()
    mqtt: MqttConfig = MqttConfig()
    exports: ExportsConfig = ExportsConfig()
    deploy: DeployConfig = DeployConfig()
    history: HistoryConfig = HistoryConfig()
    counters: CountersConfig = CountersConfig()
    certificates: CertificatesConfig = CertificatesConfig()
    discovery: DiscoveryConfig = DiscoveryConfig()
    setup: SetupConfig = SetupConfig()
    traces: TracesConfig = TracesConfig()
    probes: ProbesConfig = ProbesConfig()
    notifications: NotificationsConfig = NotificationsConfig()
    plugins: PluginsConfig = PluginsConfig()
    rules: dict[str, RuleSettings] = Field(
        default_factory=dict,
        description="Per rule: enabled (true/false), severity (info/warning/error), params "
        "and scopes (docs/RULES.md#parameters).",
    )

    @model_validator(mode="after")
    def _deprecated_thresholds(self) -> Config:
        """``counters.*`` and ``certificates.*`` became rule parameters (#441): a value other
        than the default still counts, as the rule-wide parameter unless ``rules`` sets it."""
        for section, rule_ids in LEGACY_THRESHOLDS:
            old = getattr(self, section)
            for key, ids in rule_ids.items():
                value = getattr(old, key)
                if value == type(old).model_fields[key].default:
                    continue
                for rule_id in ids:
                    settings = self.rules.setdefault(rule_id, RuleSettings())
                    settings.params.setdefault(key, value)
                log.warning(
                    "%s.%s is deprecated: set rules.%s.params.%s instead (docs/RULES.md)",
                    section,
                    key,
                    ids[0],
                    key,
                )
        return self


#: Settings that became rule parameters: section -> key -> the rules that take them over.
_CERTIFICATE_RULES = ["security.certificate-expiry", "cert.vpn-expiring", "cert.ca-expiring"]
LEGACY_THRESHOLDS: list[tuple[str, dict[str, list[str]]]] = [
    (
        "counters",
        {k: ["port.errors"] for k in ("error_ratio", "crc_ratio", "min_packets", "min_errors")},
    ),
    ("certificates", dict.fromkeys(("warn_days", "urgent_days"), _CERTIFICATE_RULES)),
]


class ConfigError(Exception):
    pass


TEMPLATE = """\
# Signalbox configuration. Every key can also be set by an environment variable:
# the path in upper case with underscores, e.g. server.port -> SIGNALBOX_SERVER_PORT.
# Devices, sites and links are managed in the web interface, not here.

server:
  # Address and port of the web interface.
  host: 0.0.0.0
  port: 8080
  # Public URL when Signalbox runs behind a reverse proxy, e.g. https://signalbox.example.org
  base_url: ""

auth:
  # Web interface password. Leave empty to have one generated on the first start;
  # it is printed once in the log. `signalbox reset-password` makes a new one.
  password:
  # Hours a login stays valid.
  session_hours: 168

observe:
  # How often every device is read, in seconds.
  interval_seconds: 300
  # Timeout of one request to a device, in seconds.
  timeout_seconds: 10
  # How many devices are read at the same time.
  concurrency: 4

mqtt:
  # Publish findings and device status to Home Assistant (MQTT discovery).
  enabled: false
  host: ""
  port: 1883
  username: ""
  password:
  tls: false
  topic_prefix: signalbox
  discovery_prefix: homeassistant

exports:
  # Serial numbers and base MAC addresses identify a device: they stay out of MQTT and exporter
  # plugins unless you set this to true.
  identity: false
  # Publish each client's Wi-Fi association (SSID, band, signal) per access point over MQTT.
  # Shows who is where and how well, so it is off by default; without identity: true no
  # MAC addresses are included.
  wifi_clients: false

deploy:
  # Allow deploying changes to devices at all. Each device must also allow changes
  # (device settings). Off by default: Signalbox only reads.
  enabled: false
  # Devices that can roll back by themselves (OpenWrt) do so unless confirmed in time.
  confirm_seconds: 120

# Deprecated: the certificate thresholds are parameters of the rules security.certificate-expiry,
# cert.vpn-expiring and cert.ca-expiring (warn_days, urgent_days; see `rules` below). A
# `certificates:` section with other values than 30 and 7 still works and is applied to all three.

history:
  # Days the observation history is kept: when devices, clients and ports were first and
  # last seen, device status and link changes. Some checks use it (stale reservations,
  # clients that change networks, long outages). Client sightings show who was at home:
  # they are never exported and are deleted after this many days.
  days: 30

# Deprecated: the port error thresholds are parameters of the rule port.errors (error_ratio,
# crc_ratio, min_packets, min_errors; see `rules` below). A `counters:` section with other
# values than the defaults still works.


discovery:
  # "Find devices" on the devices page probes the networks Signalbox knows (and ranges you
  # enter) for supported devices, without credentials. Only when you start it; false turns
  # it off completely. What is sent: docs/DISCOVERY.md.
  enabled: true
  # Timeout of one probe request, in seconds.
  timeout_seconds: 2
  # Addresses probed at the same time, and probe requests per second at most.
  concurrency: 16
  rate_per_second: 30
  # Gateway subnets of /24 or smaller are probed completely; of larger ones only the
  # gateway and known clients.
  sweep_prefix: 24
  # At most this many addresses in one run.
  max_hosts: 1024

setup:
  # "Set up automatically" in the device form: you give a device's admin login once and
  # Signalbox creates its own least-privilege login there, after you confirmed the plan.
  # Never in the background; the admin login is not stored. false turns it off completely
  # (the manual setup guides always work). Details: docs/adr/0009.
  enabled: true
  # "Fix it" next to a read problem the setup can repair (a missing package or permission
  # Signalbox reads through), (no "Allow changes" needed for these), with the admin login and only
  # after you confirmed the plan. Never changes network settings. Details: docs/adr/0012.
  fixes: true

traces:
  # Path traces: the routers Signalbox reads (OPNsense, MikroTik, Linux) and Signalbox's own
  # host run traceroutes to each other and to one internet address; the topology page shows
  # the routed path (which router is in front of which, paths through VPN tunnels). Off by
  # default. Some devices need an extra permission for it (docs/TRACES.md); the automatic
  # setup and Fix it add it only while this is on. Details: docs/adr/0014.
  enabled: false
  # Run every trace every this many hours; 0: only when you press "Trace now".
  interval_hours: 0
  # The internet address every gateway traces to; empty: none.
  internet_target: 1.1.1.1
  # Also trace from Signalbox's own host (unprivileged UDP, no root or raw sockets).
  from_signalbox: true
  # Hops per trace, seconds per hop and per trace, traces at the same time.
  max_hops: 16
  wait_seconds: 1
  timeout_seconds: 40
  concurrency: 2
  # "Trace now" is refused this soon after the last run, and one run has at most this many
  # traces.
  min_gap_seconds: 60
  max_pairs: 64

probes:
  # Foreign DHCP servers and routers: Signalbox's own host sends one DHCPDISCOVER (never a
  # REQUEST, so no lease is taken) and one IPv6 router solicitation on each network it is
  # attached to and lists who answers. Off by default. Needs host networking and UDP port 68;
  # router solicitations need CAP_NET_RAW (docs/PROBES.md). Details: docs/adr/0015.
  enabled: false
  # Probe every this many hours; 0: only when you press "Probe now".
  interval_hours: 0
  dhcp: true
  router_solicitation: true
  # Only these interfaces of Signalbox's host; empty: every one on a network Signalbox knows.
  interfaces: []
  # Seconds to listen per interface; "Probe now" is refused this soon after the last run.
  wait_seconds: 3
  min_gap_seconds: 300

notifications:
  # Send findings and events to e-mail, ntfy, Matrix, Telegram, Gotify, a webhook, the browser or
  # Apprise (docs/NOTIFICATIONS.md). Off by default and outbound only; channels are added here or
  # in Settings. One message per observation round and channel. Tokens set in this file are
  # stored as written: prefer the web interface, which encrypts them.
  language: en
  timeout_seconds: 10
  retries: 2
  # Example (all channels are off until enabled: true):
  #   channels:
  #     phone:
  #       kind: ntfy
  #       enabled: true
  #       url: https://ntfy.example.org
  #       topic: signalbox
  #       min_severity: warning
  #       events: [finding, device, drift, deploy]
  #       quiet_start: "22:00"
  #       quiet_end: "07:00"
  channels: {}

plugins:
  # Adapters that run as separate programs, each with only the settings of its device:
  #   remote_adapters:
  #     myrouter: ["/opt/signalbox-myrouter/bin/myrouter-adapter"]
  remote_adapters: {}

# Per-rule settings, for example:
# rules:
#   wifi.channel-overlap: {enabled: false}
#   dhcp.one-server: {severity: warning}
#   health.storage-full:
#     params: {warn_pct: 80}
#     scopes:
#       - match: {site: lab}
#         params: {warn_pct: 95}
# Parameters with their defaults and units: docs/RULES.md#parameters.
rules: {}
"""


def _env_overrides(env: Mapping[str, str]) -> dict[str, Any]:
    """Map SIGNALBOX_SECTION_KEY variables onto the nested config structure."""
    out: dict[str, Any] = {}
    for name, value in env.items():
        if not name.startswith(ENV_PREFIX) or name in {"SIGNALBOX_SECRET_KEY", "SIGNALBOX_DATA"}:
            continue
        rest = name[len(ENV_PREFIX) :].lower()
        for section, field_info in Config.model_fields.items():
            sub = field_info.annotation
            if not (isinstance(sub, type) and issubclass(sub, Section)):
                continue
            prefix = f"{section}_"
            if rest.startswith(prefix) and rest[len(prefix) :] in sub.model_fields:
                out.setdefault(section, {})[rest[len(prefix) :]] = value
                break
        else:
            raise ConfigError(f"unknown setting {name}")
    return out


def _deep_merge(base: dict[str, Any], top: Mapping[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for key, value in top.items():
        if isinstance(value, Mapping) and isinstance(merged.get(key), Mapping):
            merged[key] = _deep_merge(dict(merged[key]), value)
        else:
            merged[key] = value
    return merged


def load(data_dir: Path, env: Mapping[str, str] | None = None) -> Config:
    """Read (and on first start write) the configuration file, then apply the environment."""
    env = os.environ if env is None else env
    path = data_dir / FILE_NAME
    if not path.exists():
        data_dir.mkdir(parents=True, exist_ok=True)
        path.write_text(TEMPLATE)
    try:
        raw = yaml.safe_load(path.read_text()) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"{path}: not valid YAML: {exc}") from exc
    if not isinstance(raw, dict):
        raise ConfigError(f"{path}: expected a mapping at the top level")
    merged = _deep_merge(raw, _env_overrides(env))
    try:
        return Config.model_validate(merged)
    except ValidationError as exc:
        lines = [f"{'.'.join(map(str, e['loc']))}: {e['msg']}" for e in exc.errors()]
        raise ConfigError(f"{path}: " + "; ".join(lines)) from exc
