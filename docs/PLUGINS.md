# Plugins

Signalbox can be extended without changing it: integrations (adapters), rules and exporters are
plugins. Installed Python packages register them through entry points; integrations can also
run as separate programs.

## Integrations

- **As a package**: see [ADAPTERS.md](ADAPTERS.md). Register the class under the entry point
  group `signalbox.adapters`.
- **As a separate program** (out of process): the program gets only the settings of the device it
  reads, an empty environment (only `PATH`) and a temporary working folder, so a third-party
  integration never sees the credentials of other devices or Signalbox's own secrets. Configure
  it in `signalbox.yaml`:

  ```yaml
  plugins:
    remote_adapters:
      myrouter: ["/opt/signalbox-myrouter/bin/myrouter-adapter"]
  ```

  Signalbox starts the program for each request and writes one line of JSON to its stdin; the
  program answers with one line on stdout:

  | Request | Answer |
  | --- | --- |
  | `{"method": "manifest"}` | `{"result": {"id", "name", "version", "api_version", "vendor", "roles", "capabilities", "description", "config_schema"}}` |
  | `{"method": "observe", "context": {"site_id", "device_id", "device_name", "role", "config", "pinned_fingerprint", "timeout"}}` | `{"result": <Snapshot>}` or `{"error": {"kind": "unreachable" \| "auth" \| "untrusted" \| "error", "message", "fingerprint"}}` |

  `config_schema` is a flat JSON Schema object (string, integer, number, boolean properties;
  `"format": "password"` for secrets). The snapshot follows [schema.json](schema.json) and is
  validated before use; it must be for the device it was asked about. An adapter written in
  Python with the normal API runs as a program with one line:

  ```python
  from signalbox.adapters.remote import serve

  raise SystemExit(serve(MyAdapter))
  ```

  Out-of-process integrations read only; writing needs an in-process integration for now.
  They do not take part in *Find devices* either: discovery probes are class methods of
  in-process integrations ([ADAPTERS.md](ADAPTERS.md#discovery)).

## Rules

A rule is a function over the network model, see the top of `signalbox.rules`:

```python
from signalbox.rules import Severity, found, rule


@rule("acme.no-open-wifi", "No open Wi-Fi", Severity.ERROR, "Open networks are not allowed here.")
def no_open_wifi(net):
    for w in net.wlans:
        if w.security.value == "open":
            yield found(f"{w.ssid} on {w.device_id} is open", [w.id], fix="Use WPA2 or WPA3.")
```

A rule that needs the past uses `history_rule` and gets the read-only observation history
(`signalbox.sightings.History`: first/last seen and changes per device, client and port) as a
second argument. On the desired or predicted state the history is empty: stay silent then.

```python
from datetime import timedelta

from signalbox.rules import Severity, found, history_rule


@history_rule("acme.new-device", "New device", Severity.INFO, "A MAC seen for the first time.")
def new_device(net, history):
    if history.now is None or not history.covers(timedelta(days=7)):
        return
    for c in net.clients:
        seen = history.clients.get(c.mac)
        if seen and history.now - seen.first_seen < timedelta(hours=1):
            yield found(f"{c.mac} is new", [c.id])
```

Register a rule or a list of rules under the entry point group `signalbox.rules`. They appear on
the Settings page and can be turned off or re-rated in the configuration like built-in rules.

## Exporters

An exporter is a callable `(network, findings) -> None`, called after every observation round
(the Home Assistant export works this way). Register it under `signalbox.exporters`. An
exporter that raises is logged and does not stop the others.
