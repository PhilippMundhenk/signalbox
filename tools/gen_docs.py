"""Generate the parts of the documentation that come from the code.

    python tools/gen_docs.py

- docs/CONFIGURATION.md: every setting with its environment variable, default and meaning
- docs/MATURITY.md: what every adapter can read, and what is confirmed on real devices

Tests fail when the committed files differ from what this writes.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from pydantic.fields import FieldInfo

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from signalbox.adapters import Capability, load_adapters  # noqa: E402
from signalbox.changes import ChangeKind  # noqa: E402
from signalbox.config import Config, Section  # noqa: E402

REPORTS = ROOT / "docs" / "hardware-reports.json"


def _default(info: FieldInfo) -> str:
    if info.default_factory is not None:
        return "-"
    value = info.default
    if value is None or value == "":
        return "empty"
    if isinstance(value, bool):
        return "true" if value else "false"
    return f"`{value}`"


def configuration() -> str:
    lines = [
        "# Configuration",
        "",
        "Signalbox writes `signalbox.yaml` into its data folder (`/data` in the container) on the",
        "first start, with every setting and a comment. Every setting can also be given as an",
        "environment variable, which wins over the file. Devices, sites and cables are managed in",
        "the web interface, not here.",
        "",
        "Two more environment variables: `SIGNALBOX_DATA` (the data folder, default `/data`) and",
        "`SIGNALBOX_SECRET_KEY` (the key that encrypts device credentials; without it the key is",
        "generated into `secret.key` in the data folder — back it up together with the database).",
        "",
        "Generated from the code by `tools/gen_docs.py`.",
        "",
    ]
    for section, field in Config.model_fields.items():
        sub = field.annotation
        if not (isinstance(sub, type) and issubclass(sub, Section)):
            continue
        lines += [f"## `{section}`", "", "| Setting | Environment variable | Default | Meaning |"]
        lines.append("| --- | --- | --- | --- |")
        for name, info in sub.model_fields.items():
            env = f"SIGNALBOX_{section.upper()}_{name.upper()}"
            lines.append(
                f"| `{section}.{name}` | `{env}` | {_default(info)} | {info.description or ''} |"
            )
        lines.append("")
    lines += [
        "## `rules`",
        "",
        "Per rule (ids in [RULES.md](RULES.md)): `enabled` (true/false) and `severity`",
        "(info/warning/error). Only in the file:",
        "",
        "```yaml",
        "rules:",
        "  wifi.channel-overlap: {enabled: false}",
        "  dhcp.one-server: {severity: warning}",
        "```",
        "",
    ]
    return "\n".join(lines)


#: Adapters verified against the real software by the integration tests (#136).
EMULATED = {
    "openwrt": "OpenWrt: 24.10.8 and 25.12.6, official x86-64 images in QEMU "
    "([details](adapters/openwrt.md#verified-against-the-real-openwrt))",
    "opnsense": "OPNsense: 26.7.9, official nano image in QEMU "
    "([details](adapters/opnsense.md#integration-tests))",
}


def maturity() -> str:
    reports: dict[str, Any] = json.loads(REPORTS.read_text()) if REPORTS.exists() else {}
    adapters = load_adapters()
    caps = list(Capability)
    lines = [
        "# Maturity",
        "",
        "What every adapter reads, and how well that is tested. *Simulator* means the adapter",
        "passes the contract checks against its built-in simulator in CI; the API shapes the",
        "simulator answers with come from the vendors' documentation. *Confirmed* means a user",
        "reported it working on a real device (`docs/hardware-reports.json`). Please report your",
        "device in [#21](https://github.com/PhilippMundhenk/signalbox/issues/21).",
        "",
        "*writes* lists the kinds of change an adapter can deploy ([CHANGES.md](CHANGES.md));",
        "they are tested against the simulators.",
        "",
        "*Emulated*: verified against the real device software in CI, reads and writes",
        "([TESTING.md](TESTING.md)):",
        "",
        *[f"- {what}" for _, what in sorted(EMULATED.items())],
        "",
        "Generated from the adapter manifests by `tools/gen_docs.py`.",
        "",
        "| Adapter | " + " | ".join(c.value for c in caps) + " | writes | Confirmed on |",
        "| --- | " + " | ".join("---" for _ in caps) + " | --- | --- |",
    ]
    for key in sorted(adapters):
        m = adapters[key].manifest
        confirmed = reports.get(m.id, {})
        cells = []
        for c in caps:
            if c not in m.capabilities:
                cells.append("-")
            elif c.value in confirmed.get("capabilities", []):
                cells.append("confirmed")
            else:
                cells.append("simulator")
        devices = ", ".join(confirmed.get("devices", [])) or "nothing yet"
        writes = ", ".join(k.value for k in ChangeKind if k in m.writes) or "-"
        lines.append(f"| {m.name} (`{m.id}`) | " + " | ".join(cells) + f" | {writes} | {devices} |")
    return "\n".join(lines) + "\n"


OUTPUTS = {"CONFIGURATION.md": configuration, "MATURITY.md": maturity}

if __name__ == "__main__":
    for name, fn in OUTPUTS.items():
        (ROOT / "docs" / name).write_text(fn())
        print(f"wrote docs/{name}")
