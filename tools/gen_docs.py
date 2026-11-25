"""Generate the parts of the documentation that come from the code.

    python tools/gen_docs.py

- docs/CONFIGURATION.md: every setting with its environment variable, default and meaning
- docs/MATURITY.md: what every adapter can read, and what is confirmed on real devices
- docs/RULES.md: the rule groups in docs/rules/ and every rule parameter (#187)
- docs/rules-schema.json: JSON Schema of the rules: section with every rule's parameters

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
from signalbox.rules import load_rules, rules_schema  # noqa: E402
from signalbox.rules._params import unit_of  # noqa: E402

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
        "Per rule (ids in [RULES.md](RULES.md)): `enabled` (true/false), `severity`",
        "(info/warning/error), `params` (the rule's parameters, listed with default and unit in",
        "[RULES.md](RULES.md#parameters)) and `scopes`: settings for some objects only. `enabled`",
        "and `severity` are set in the file; `params` and `scopes` also on the settings page:",
        "",
        "```yaml",
        "rules:",
        "  wifi.channel-overlap: {enabled: false}",
        "  dhcp.one-server: {severity: warning}",
        "  health.storage-full:",
        "    params: {warn_pct: 80, error_pct: 95}",
        "    scopes:",
        "      - match: {site: lab}",
        "        params: {warn_pct: 95}",
        "      - match: {segment_purpose: guest}",
        "        enabled: false",
        "```",
        "",
        "A scope's `match` takes `site`, `device` (id or name), `device_role`, `segment` (id, name",
        "or VLAN id), `segment_purpose` and `tag` (a tag of the object's annotation); every",
        "selector given must match. A finding belongs to its first affected object: a port or",
        "server counts for its device and network. When several scopes match, the most specific",
        "wins (device, then network, tag, role or purpose, site; more selectors before fewer),",
        "and among equally specific ones the first listed. A scope changes only what it sets.",
        "Parameters are checked at start: an unknown name or a value out of range stops",
        "Signalbox with the setting's path. The JSON Schema of the whole section is",
        "[rules-schema.json](rules-schema.json)",
        "([ADR 0027](adr/0027-rule-parameters-and-scopes.md)).",
        "",
        "The settings page edits `params` and `scopes` too (an admin, after login). They are saved",
        "in the data store, not in `signalbox.yaml`, and apply at once without a restart. The",
        "layers are: defaults, then the page, then the file, then the environment. A parameter the",
        "file or the environment sets is shown with its source and cannot be changed on the page;",
        "scopes of the file stay as they are and the page's scopes are listed after them. Reset to",
        "default removes the page's value.",
        "",
    ]
    return "\n".join(lines)


#: Adapters verified against the real software by the integration tests (#136).
EMULATED = {
    "mikrotik": "MikroTik: RouterOS 7.25.1, official CHR image in QEMU, without Wi-Fi "
    "([details](adapters/mikrotik.md#integration-tests))",
    "linux": "Linux gateway: Debian 11, 12 and 13 in containers (sshd, iproute2, dnsmasq, chrony, "
    "WireGuard), read only ([details](adapters/linux.md#integration-tests))",
    "omada": "TP-Link Omada: Software Controller 6.3.0.111, official Linux package in Docker, "
    "without managed devices ([details](adapters/omada.md#integration-tests))",
    "openwrt": "OpenWrt: 23.05.6, 24.10.8 and 25.12.6, official x86-64 images in QEMU "
    "([details](adapters/openwrt.md#verified-against-the-real-openwrt))",
    "opnsense": "OPNsense: 26.7.9 and 25.1, official nano images in QEMU (25.1 read only) "
    "([details](adapters/opnsense.md#versions-390))",
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


RULES_INTRO = """# Rules

The consistency rules that ship with Signalbox: what each one checks and how to fix a finding.

Each rule can be turned off or given another severity in the configuration
(`rules: {dhcp.dns-option: {enabled: false}}`). When a rule cannot check something because a
device did not report the data, it reports an *incomplete* finding (severity info) instead of
staying silent.

Each group is documented next to the others in [rules/](rules/), one file per rule module
(`docs/rules/<module>.md` for `src/signalbox/rules/<module>.py`), so that new rules do not
touch a shared file. This index is generated (`python tools/gen_docs.py`).

"""


def rules_index() -> str:
    """docs/RULES.md: the groups in docs/rules/ with their rule ids."""
    import re

    lines = [RULES_INTRO]
    for path in sorted((ROOT / "docs" / "rules").glob("*.md")):
        text = path.read_text()
        title = re.search(r"^# (.+)$", text, re.M)
        ids = re.findall(r"^## `([^`]+)`", text, re.M)
        lines.append(f"## [{title.group(1) if title else path.stem}](rules/{path.name})\n\n")
        lines.extend(f"- [`{i}`](rules/{path.name}#{re.sub(r'[^a-z0-9-]', '', i)})\n" for i in ids)
        lines.append("\n")
    lines.append(PARAMS_INTRO)
    for r in load_rules():
        if r.params is None:
            continue
        lines.append(f"### `{r.id}`\n\n| Parameter | Default | Unit | Meaning |\n")
        lines.append("| --- | --- | --- | --- |\n")
        for name, info in r.params.model_fields.items():
            unit = unit_of(r.params, name)
            default = info.default
            if isinstance(default, float) and default.is_integer():
                default = int(default)
            if isinstance(default, bool):
                default = str(default).lower()
            lines.append(f"| `{name}` | `{default}` | {unit} | {info.description} |\n")
        lines.append("\n")
    return "".join(lines).rstrip("\n") + "\n"


PARAMS_INTRO = """## Parameters

The thresholds of these rules can be changed in the configuration, for all objects
(`rules.<id>.params`) or for some sites, devices or networks (`rules.<id>.scopes`, see
[CONFIGURATION.md](CONFIGURATION.md#rules)). A finding lists the values it was judged with and
where each came from. The defaults are the values the rules used before they had parameters.

"""


def rules_schema_json() -> str:
    return json.dumps(rules_schema(load_rules()), indent=2, ensure_ascii=False) + "\n"


OUTPUTS = {
    "CONFIGURATION.md": configuration,
    "MATURITY.md": maturity,
    "RULES.md": rules_index,
    "rules-schema.json": rules_schema_json,
}

if __name__ == "__main__":
    for name, fn in OUTPUTS.items():
        (ROOT / "docs" / name).write_text(fn())
        print(f"wrote docs/{name}")
