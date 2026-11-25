"""Publish findings and device status to MQTT, with Home Assistant discovery.

Active when ``mqtt.enabled`` is true. Every observation round publishes:

- ``<prefix>/status``: ``online`` / ``offline`` (last will), availability of everything
- ``<prefix>/site/<site>/state``: findings per severity for one site; acknowledged findings
  (#186) are counted apart and never switch the problem sensor on
- ``<prefix>/device/<device>/state``: status, firmware, clients and findings of one device, and
  its health (uptime, CPU, memory, temperature) where the device reports it, and for a
  gateway with uplinks whether it is online and its NAT class (never its addresses), and the
  totals of its port counters (bytes, errors, drops over all jacks; no port names, #434)

Discovery messages make each site and each device a Home Assistant device with sensors.
"""

from __future__ import annotations

import contextlib
import json
import logging
import re
import ssl
import threading
import time
from collections import Counter
from collections.abc import Callable
from typing import Any

import paho.mqtt.client as paho
from paho.mqtt.enums import CallbackAPIVersion

from signalbox import __version__
from signalbox.config import MqttConfig
from signalbox.counters import CounterRecord
from signalbox.model import Device, DeviceStatus, NatClass, Network, PortKind, PortRole
from signalbox.rules import Finding, Severity

log = logging.getLogger(__name__)
SUPPORT_URL = "https://github.com/PhilippMundhenk/signalbox"
STATUSES = [s.value for s in DeviceStatus]


def node_id(text: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_-]", "_", text)


def site_state(net: Network, findings: list[Finding], site_id: str) -> dict[str, Any]:
    devices = {d.id for d in net.devices if d.site_id == site_id}
    mine = [
        f for f in findings if not f.objects or any(o.split("/")[0] in devices for o in f.objects)
    ]
    sev = Counter(f.severity.value for f in mine if f.problem)
    return {
        "errors": sev.get(Severity.ERROR.value, 0),
        "warnings": sev.get(Severity.WARNING.value, 0),
        "info": sev.get(Severity.INFO.value, 0),
        "incomplete": sum(1 for f in mine if f.incomplete and f.acknowledged is None),
        "acknowledged": sum(1 for f in mine if f.acknowledged is not None),
        "problem": "ON" if sev.get(Severity.ERROR.value, 0) else "OFF",
        "devices": len(devices),
        "unreachable": sum(
            1 for d in devices if net.statuses.get(d) not in (DeviceStatus.OK, DeviceStatus.PARTIAL)
        ),
    }


#: Health values published per device: key, name, unit, device class, icon.
HEALTH_SENSORS: list[tuple[str, str, str, str | None, str]] = [
    ("uptime", "Uptime", "s", "duration", "mdi:timer-outline"),
    ("cpu_load", "CPU load", "%", None, "mdi:cpu-64-bit"),
    ("memory_used", "Memory used", "%", None, "mdi:memory"),
    ("temperature", "Temperature", "°C", "temperature", "mdi:thermometer"),
]


def health_values(dev: Device | None) -> dict[str, float | int | None]:
    h = dev.health if dev else None
    if h is None:
        return {}
    mem = h.memory_used_pct()
    return {
        "uptime": h.uptime_seconds,
        "cpu_load": h.cpu_load_pct,
        "memory_used": round(mem, 1) if mem is not None else None,
        "temperature": h.max_temperature_c(),
    }


#: Traffic counters published per device (#434): key, name, unit, icon. Sums over the device's
#: physical ports, as the device counts them (they start again from zero when it restarts).
COUNTER_SENSORS: list[tuple[str, str, str | None, str]] = [
    ("rx_bytes", "Received", "B", "mdi:download-network"),
    ("tx_bytes", "Sent", "B", "mdi:upload-network"),
    ("port_errors", "Port errors", None, "mdi:alert-circle-outline"),
    ("port_drops", "Port drops", None, "mdi:package-down"),
]


def counter_values(
    net: Network, device_id: str, counters: dict[str, CounterRecord]
) -> dict[str, int]:
    """Totals of the last counter reads over the device's jacks (never per port: port names
    can carry what is plugged in). Only counters the device reports are in the result."""
    sums: dict[str, int] = {}
    for port in net.ports_of(device_id):
        if port.kind is not PortKind.ETHERNET or port.role not in (None, PortRole.JACK):
            continue
        record = counters.get(port.id)
        if record is None:
            continue
        last = record.last
        parts = {
            "rx_bytes": last.rx_bytes,
            "tx_bytes": last.tx_bytes,
            "port_errors": sum(v for v in (last.rx_errors, last.tx_errors) if v is not None)
            if (last.rx_errors is not None or last.tx_errors is not None)
            else None,
            "port_drops": sum(v for v in (last.rx_drops, last.tx_drops) if v is not None)
            if (last.rx_drops is not None or last.tx_drops is not None)
            else None,
        }
        for key, value in parts.items():
            if value is not None:
                sums[key] = sums.get(key, 0) + value
    return sums


NAT_CLASSES = [c.value for c in NatClass]


def uplink_values(net: Network, device_id: str) -> dict[str, str]:
    """Internet connectivity and NAT class of a gateway's uplinks (#148).

    Online when any uplink is up; the NAT class of the first one that is up (or the first).
    Addresses and prefixes identify the household and are never published.
    """
    uplinks = net.uplinks_of(device_id)
    out: dict[str, str] = {}
    states = [u.up for u in uplinks if u.up is not None]
    if states:
        out["internet"] = "ON" if any(states) else "OFF"
    ordered = sorted(uplinks, key=lambda u: u.up is not True)
    nat = next((c for c in (u.nat_class() for u in ordered) if c is not None), None)
    if nat is not None:
        out["nat"] = nat.value
    return out


def device_state(
    net: Network,
    findings: list[Finding],
    device_id: str,
    counters: dict[str, CounterRecord] | None = None,
) -> dict[str, Any]:
    dev = net.device(device_id)
    status = net.statuses.get(device_id, DeviceStatus.UNREACHABLE)
    prefix = f"{device_id}/"
    mine = [
        f
        for f in findings
        if f.problem and any(o == device_id or o.startswith(prefix) for o in f.objects)
    ]
    clients = [c for c in net.clients if (c.seen_on or "").startswith(prefix)]
    return {
        "status": status.value,
        "reachable": "ON" if status in (DeviceStatus.OK, DeviceStatus.PARTIAL) else "OFF",
        "firmware": (dev.firmware.current if dev and dev.firmware else None) or "unknown",
        "clients": len(clients),
        "findings": len(mine),
        **{k: v for k, v in health_values(dev).items() if v is not None},
        **uplink_values(net, device_id),
        **counter_values(net, device_id, counters or {}),
    }


class Discovery:
    def __init__(self, cfg: MqttConfig, base_url: str = "", identity: bool = False) -> None:
        #: Serial numbers and base MACs go into the discovery only with ``exports.identity``.
        self.identity = identity
        self.prefix = cfg.topic_prefix.strip("/") or "signalbox"
        self.discovery = cfg.discovery_prefix.strip("/") or "homeassistant"
        self.base_url = base_url
        #: The last counter reads by port id (#434), set by the bridge before each publish.
        self.counters: dict[str, CounterRecord] = {}

    @property
    def status_topic(self) -> str:
        return f"{self.prefix}/status"

    def site_topic(self, site_id: str) -> str:
        return f"{self.prefix}/site/{node_id(site_id)}/state"

    def device_topic(self, device_id: str) -> str:
        return f"{self.prefix}/device/{node_id(device_id)}/state"

    def _entity(
        self,
        node: str,
        object_id: str,
        name: str,
        state_topic: str,
        device: dict[str, Any],
        **kw: Any,
    ) -> dict[str, Any]:
        entity: dict[str, Any] = {
            "name": name,
            "unique_id": f"signalbox_{node}_{object_id}",
            "object_id": f"signalbox_{node}_{object_id}",
            "state_topic": state_topic,
            "availability_topic": self.status_topic,
            "device": device,
            "origin": {"name": "Signalbox", "sw_version": __version__, "support_url": SUPPORT_URL},
        }
        entity.update(kw)
        return entity

    def configs(self, net: Network) -> dict[str, dict[str, Any]]:
        """Discovery topic -> config, for every site and device of the network."""
        out: dict[str, dict[str, Any]] = {}
        for site in net.sites:
            node = f"site_{node_id(site.id)}"
            device: dict[str, Any] = {
                "identifiers": [f"signalbox_{node}"],
                "name": f"Signalbox {site.name}",
                "manufacturer": "Signalbox",
                "model": "Network site",
                "sw_version": __version__,
            }
            if self.base_url:
                device["configuration_url"] = self.base_url
            topic = self.site_topic(site.id)
            for key, name in (
                ("errors", "Errors"),
                ("warnings", "Warnings"),
                ("incomplete", "Not checked"),
                ("acknowledged", "Acknowledged"),
            ):
                out[f"{self.discovery}/sensor/{node}/{key}/config"] = self._entity(
                    node,
                    key,
                    name,
                    topic,
                    device,
                    value_template=f"{{{{ value_json.{key} }}}}",
                    state_class="measurement",
                    icon="mdi:alert-circle-outline",
                )
            out[f"{self.discovery}/binary_sensor/{node}/problem/config"] = self._entity(
                node,
                "problem",
                "Network problem",
                topic,
                device,
                value_template="{{ value_json.problem }}",
                device_class="problem",
            )
            out[f"{self.discovery}/sensor/{node}/unreachable/config"] = self._entity(
                node,
                "unreachable",
                "Unreachable devices",
                topic,
                device,
                value_template="{{ value_json.unreachable }}",
                state_class="measurement",
                icon="mdi:lan-disconnect",
            )
        for dev in net.devices:
            node = f"device_{node_id(dev.id)}"
            device = {
                "identifiers": [f"signalbox_{node}"],
                "name": dev.name,
                "manufacturer": dev.vendor or "Unknown",
                "model": dev.model or dev.role.value,
                "via_device": f"signalbox_site_{node_id(dev.site_id)}",
            }
            if dev.firmware and dev.firmware.current:
                device["sw_version"] = dev.firmware.current
            if self.identity:  # opt-in (#427): identifying data
                if dev.serial:
                    device["serial_number"] = dev.serial
                if dev.mac:
                    device["connections"] = [["mac", dev.mac]]
            topic = self.device_topic(dev.id)
            out[f"{self.discovery}/binary_sensor/{node}/reachable/config"] = self._entity(
                node,
                "reachable",
                "Reachable",
                topic,
                device,
                value_template="{{ value_json.reachable }}",
                device_class="connectivity",
            )
            out[f"{self.discovery}/sensor/{node}/status/config"] = self._entity(
                node,
                "status",
                "Status",
                topic,
                device,
                value_template="{{ value_json.status }}",
                device_class="enum",
                options=STATUSES,
            )
            out[f"{self.discovery}/sensor/{node}/firmware/config"] = self._entity(
                node,
                "firmware",
                "Firmware",
                topic,
                device,
                value_template="{{ value_json.firmware }}",
                entity_category="diagnostic",
                icon="mdi:chip",
            )
            for key, name, icon in (
                ("clients", "Clients", "mdi:devices"),
                ("findings", "Findings", "mdi:alert-outline"),
            ):
                out[f"{self.discovery}/sensor/{node}/{key}/config"] = self._entity(
                    node,
                    key,
                    name,
                    topic,
                    device,
                    value_template=f"{{{{ value_json.{key} }}}}",
                    state_class="measurement",
                    icon=icon,
                )
            for key, name, unit, device_class, icon in HEALTH_SENSORS:
                if health_values(dev).get(key) is None:
                    continue
                extra: dict[str, Any] = {"device_class": device_class} if device_class else {}
                out[f"{self.discovery}/sensor/{node}/{key}/config"] = self._entity(
                    node,
                    key,
                    name,
                    topic,
                    device,
                    value_template=f"{{{{ value_json.{key} }}}}",
                    unit_of_measurement=unit,
                    state_class="measurement",
                    entity_category="diagnostic",
                    icon=icon,
                    **extra,
                )
            totals = counter_values(net, dev.id, self.counters)
            for key, name, count_unit, icon in COUNTER_SENSORS:
                if key not in totals:
                    continue
                counter_extra: dict[str, Any] = {}
                if count_unit:
                    counter_extra["unit_of_measurement"] = count_unit
                out[f"{self.discovery}/sensor/{node}/{key}/config"] = self._entity(
                    node,
                    key,
                    name,
                    topic,
                    device,
                    value_template=f"{{{{ value_json.{key} }}}}",
                    state_class="total_increasing",
                    entity_category="diagnostic",
                    icon=icon,
                    **counter_extra,
                )
            wan = uplink_values(net, dev.id)
            if "internet" in wan:
                out[f"{self.discovery}/binary_sensor/{node}/internet/config"] = self._entity(
                    node,
                    "internet",
                    "Internet",
                    topic,
                    device,
                    value_template="{{ value_json.internet }}",
                    device_class="connectivity",
                )
            if "nat" in wan:
                out[f"{self.discovery}/sensor/{node}/nat/config"] = self._entity(
                    node,
                    "nat",
                    "Internet NAT",
                    topic,
                    device,
                    value_template="{{ value_json.nat }}",
                    device_class="enum",
                    options=NAT_CLASSES,
                    entity_category="diagnostic",
                    icon="mdi:router-network",
                )
        return out

    def states(self, net: Network, findings: list[Finding]) -> dict[str, dict[str, Any]]:
        out = {self.site_topic(s.id): site_state(net, findings, s.id) for s in net.sites}
        out.update(
            {
                self.device_topic(d.id): device_state(net, findings, d.id, self.counters)
                for d in net.devices
            }
        )
        return out


ClientFactory = Callable[[], Any]


def _default_client() -> Any:
    return paho.Client(CallbackAPIVersion.VERSION2, client_id="signalbox")


class MqttBridge:
    """Runner listener that publishes discovery and state; reconnects in the background."""

    def __init__(
        self,
        cfg: MqttConfig,
        base_url: str = "",
        client_factory: ClientFactory = _default_client,
        identity: bool = False,
    ) -> None:
        self.cfg = cfg
        self.discovery = Discovery(cfg, base_url, identity)
        self.client_factory = client_factory
        self.client: Any = None
        self.connected = threading.Event()
        self.sent_configs: set[str] = set()
        self.last: tuple[Network, list[Finding]] | None = None
        #: Where the last counter reads come from (the runner's history), None: no counters.
        self.counters_source: Callable[[], dict[str, CounterRecord]] | None = None
        self.status: dict[str, Any] = {"state": "off", "error": None, "published": 0}

    @property
    def enabled(self) -> bool:
        return self.cfg.enabled and bool(self.cfg.host)

    def start(self) -> None:
        if not self.enabled:
            if self.cfg.enabled:
                log.warning("mqtt.enabled is set but mqtt.host is empty: not publishing")
            return
        client = self.client_factory()
        if self.cfg.username:
            password = self.cfg.password.get_secret_value() if self.cfg.password else None
            client.username_pw_set(self.cfg.username, password)
        if self.cfg.tls:
            client.tls_set(cert_reqs=ssl.CERT_REQUIRED)
        client.will_set(self.discovery.status_topic, "offline", qos=1, retain=True)
        client.on_connect = self._on_connect
        client.on_disconnect = self._on_disconnect
        client.reconnect_delay_set(1, 60)
        self.client = client
        self.status["state"] = "connecting"
        client.connect_async(self.cfg.host, self.cfg.port, keepalive=60)
        client.loop_start()

    def stop(self) -> None:
        if self.client is None:
            return
        try:
            info = self.client.publish(self.discovery.status_topic, "offline", qos=1, retain=True)
            if self.connected.is_set():
                # a clean disconnect does not fire the last will: make sure the broker has it
                with contextlib.suppress(Exception):
                    info.wait_for_publish(3)
                time.sleep(0.3)
            self.client.disconnect()
        finally:
            self.client.loop_stop()
            self.client = None
            self.connected.clear()
            self.status["state"] = "off"

    def _on_connect(
        self, client: Any, userdata: Any, flags: Any, reason: Any, props: Any = None
    ) -> None:
        if getattr(reason, "is_failure", False):
            self.status.update(state="error", error=f"the broker refused the connection: {reason}")
            log.warning("MQTT: %s", self.status["error"])
            return
        self.status.update(state="connected", error=None)
        self.connected.set()
        client.publish(self.discovery.status_topic, "online", qos=1, retain=True)
        self.sent_configs.clear()  # the broker may have lost retained configs
        if self.last is not None:
            self.publish(*self.last)

    def _on_disconnect(
        self, client: Any, userdata: Any, flags: Any, reason: Any, props: Any = None
    ) -> None:
        self.connected.clear()
        if self.status["state"] != "off":
            self.status.update(state="connecting", error=f"connection lost: {reason}")

    def _send(self, topic: str, payload: dict[str, Any] | str) -> None:
        text = payload if isinstance(payload, str) else json.dumps(payload, separators=(",", ":"))
        self.client.publish(topic, text, qos=1, retain=True)
        self.status["published"] += 1

    def publish(self, net: Network, findings: list[Finding]) -> None:
        """Runner listener: publish discovery (new entities, removed ones) and all states."""
        self.last = (net, findings)
        if self.client is None or not self.connected.is_set():
            return
        if self.counters_source is not None:
            try:
                self.discovery.counters = self.counters_source()
            except Exception:  # the counters are an extra: never block the other values
                log.exception("counters for the MQTT export")
        configs = self.discovery.configs(net)
        for topic in sorted(self.sent_configs - set(configs)):
            self._send(topic, "")  # an empty retained config removes the entity
        for topic, config in configs.items():
            if topic not in self.sent_configs:
                self._send(topic, config)
        self.sent_configs = set(configs)
        for topic, state in self.discovery.states(net, findings).items():
            self._send(topic, state)
