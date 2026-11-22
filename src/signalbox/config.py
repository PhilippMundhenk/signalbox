"""Configuration: ``<data>/signalbox.yaml`` plus ``SIGNALBOX_*`` environment overrides.

On the first start the file is written with every key and a comment. Every key can be
overridden by an environment variable: the dotted path in upper case with underscores, for
example ``server.port`` → ``SIGNALBOX_SERVER_PORT``. Environment wins over the file.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, SecretStr, ValidationError

from signalbox.rules import RuleSettings

ENV_PREFIX = "SIGNALBOX_"
FILE_NAME = "signalbox.yaml"


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
    deploy: DeployConfig = DeployConfig()
    plugins: PluginsConfig = PluginsConfig()
    rules: dict[str, RuleSettings] = Field(
        default_factory=dict,
        description="Per rule: enabled (true/false) and severity (info/warning/error).",
    )


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

deploy:
  # Allow deploying changes to devices at all. Each device must also allow changes
  # (device settings). Off by default: Signalbox only reads.
  enabled: false
  # Devices that can roll back by themselves (OpenWrt) do so unless confirmed in time.
  confirm_seconds: 120

plugins:
  # Adapters that run as separate programs, each with only the settings of its device:
  #   remote_adapters:
  #     myrouter: ["/opt/signalbox-myrouter/bin/myrouter-adapter"]
  remote_adapters: {}

# Per-rule settings, for example:
# rules:
#   wifi.channel-overlap: {enabled: false}
#   dhcp.one-server: {severity: warning}
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
