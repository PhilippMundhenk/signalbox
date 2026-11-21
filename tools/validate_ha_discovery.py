"""Check Signalbox's MQTT discovery messages with Home Assistant's own schemas.

Run with a Python that has Home Assistant installed (it is not a Signalbox dependency):

    python tools/validate_ha_discovery.py

Builds the discovery messages for a sample network, validates each with the DISCOVERY_SCHEMA of
the matching Home Assistant MQTT platform, and renders every value template against the state
message published on its topic.
"""

from __future__ import annotations

import asyncio
import importlib
import json
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from homeassistant.const import __version__ as ha_version  # noqa: E402
from jinja2 import Environment  # noqa: E402

from signalbox.config import MqttConfig  # noqa: E402
from signalbox.merge import merge  # noqa: E402
from signalbox.model import Device, DeviceRole, Firmware, Site, Snapshot  # noqa: E402
from signalbox.mqtt import Discovery  # noqa: E402
from signalbox.rules import Finding, Severity  # noqa: E402

T0 = datetime(2026, 1, 15, 12, 0, tzinfo=UTC)


def sample():  # type: ignore[no-untyped-def]
    devs = [
        Device(
            id="gw",
            site_id="home",
            name="Gateway",
            role=DeviceRole.GATEWAY,
            adapter="x",
            firmware=Firmware(current="1.0"),
        ),
        Device(id="ap", site_id="home", name="AP", role=DeviceRole.AP, adapter="x"),
    ]
    net = merge([Site(id="home", name="Home")], [Snapshot(device=d, observed_at=T0) for d in devs])
    findings = [
        Finding(
            id="1", rule_id="r", severity=Severity.ERROR, title="t", message="m", objects=["gw"]
        )
    ]
    return net, findings


async def validate() -> int:
    from homeassistant.core import HomeAssistant

    hass = HomeAssistant(tempfile.mkdtemp())
    env = Environment()
    net, findings = sample()
    d = Discovery(MqttConfig(), "http://signalbox.example:8080")
    states = json.loads(json.dumps(d.states(net, findings)))
    errors = checked = 0
    for topic, payload in d.configs(net).items():
        component = topic.split("/")[1]
        schema = importlib.import_module(
            f"homeassistant.components.mqtt.{component}"
        ).DISCOVERY_SCHEMA
        payload = json.loads(json.dumps(payload))
        payload["platform"] = "mqtt"
        try:
            schema(payload)
        except Exception as exc:
            errors += 1
            print(f"INVALID {topic}: {exc}")
            continue
        rendered = env.from_string(payload["value_template"]).render(
            value_json=states[payload["state_topic"]]
        )
        if rendered in ("", "None"):
            errors += 1
            print(f"EMPTY {topic}: {payload['value_template']!r}")
        checked += 1
    print(f"Home Assistant {ha_version}: {checked} discovery messages valid, {errors} problem(s)")
    await hass.async_stop(force=True)
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(validate()))
