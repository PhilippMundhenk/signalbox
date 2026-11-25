# Configuration

Signalbox writes `signalbox.yaml` into its data folder (`/data` in the container) on the
first start, with every setting and a comment. Every setting can also be given as an
environment variable, which wins over the file. Devices, sites and cables are managed in
the web interface, not here.

Two more environment variables: `SIGNALBOX_DATA` (the data folder, default `/data`) and
`SIGNALBOX_SECRET_KEY` (the key that encrypts device credentials; without it the key is
generated into `secret.key` in the data folder — back it up together with the database).

Generated from the code by `tools/gen_docs.py`.

## `server`

| Setting | Environment variable | Default | Meaning |
| --- | --- | --- | --- |
| `server.host` | `SIGNALBOX_SERVER_HOST` | `0.0.0.0` | Address the web interface listens on. |
| `server.port` | `SIGNALBOX_SERVER_PORT` | `8080` | Port of the web interface. |
| `server.base_url` | `SIGNALBOX_SERVER_BASE_URL` | empty | Public URL when behind a reverse proxy (used in links), e.g. https://... |

## `auth`

| Setting | Environment variable | Default | Meaning |
| --- | --- | --- | --- |
| `auth.password` | `SIGNALBOX_AUTH_PASSWORD` | empty | Web interface password. Empty: generated on the first start and printed once. |
| `auth.session_hours` | `SIGNALBOX_AUTH_SESSION_HOURS` | `168` | How long a login stays valid. |

## `observe`

| Setting | Environment variable | Default | Meaning |
| --- | --- | --- | --- |
| `observe.interval_seconds` | `SIGNALBOX_OBSERVE_INTERVAL_SECONDS` | `300` | How often every device is read. |
| `observe.timeout_seconds` | `SIGNALBOX_OBSERVE_TIMEOUT_SECONDS` | `10` | Timeout of one device request. |
| `observe.concurrency` | `SIGNALBOX_OBSERVE_CONCURRENCY` | `4` | Devices read at the same time. |

## `mqtt`

| Setting | Environment variable | Default | Meaning |
| --- | --- | --- | --- |
| `mqtt.enabled` | `SIGNALBOX_MQTT_ENABLED` | false | Publish findings and devices to Home Assistant. |
| `mqtt.host` | `SIGNALBOX_MQTT_HOST` | empty | MQTT broker host. |
| `mqtt.port` | `SIGNALBOX_MQTT_PORT` | `1883` | MQTT broker port. |
| `mqtt.username` | `SIGNALBOX_MQTT_USERNAME` | empty | MQTT user name, empty for none. |
| `mqtt.password` | `SIGNALBOX_MQTT_PASSWORD` | empty | MQTT password. |
| `mqtt.tls` | `SIGNALBOX_MQTT_TLS` | false | Connect with TLS (and verify the certificate). |
| `mqtt.topic_prefix` | `SIGNALBOX_MQTT_TOPIC_PREFIX` | `signalbox` | Prefix of the state topics. |
| `mqtt.discovery_prefix` | `SIGNALBOX_MQTT_DISCOVERY_PREFIX` | `homeassistant` | Home Assistant discovery prefix. |

## `deploy`

| Setting | Environment variable | Default | Meaning |
| --- | --- | --- | --- |
| `deploy.enabled` | `SIGNALBOX_DEPLOY_ENABLED` | false | Allow deploying changes at all (devices also need 'allow changes'). |
| `deploy.confirm_seconds` | `SIGNALBOX_DEPLOY_CONFIRM_SECONDS` | `120` | Devices that support it roll back by themselves unless confirmed in time. |
| `deploy.signalbox_address` | `SIGNALBOX_DEPLOY_SIGNALBOX_ADDRESS` | empty | Signalbox's own address as the devices see it. Firewall changes are checked against it so they do not cut Signalbox off; default: each device is reached from the network of its management address. |

## `history`

| Setting | Environment variable | Default | Meaning |
| --- | --- | --- | --- |
| `history.days` | `SIGNALBOX_HISTORY_DAYS` | `30` | Days the observation history (first/last seen, status and link changes) is kept. Client sightings are a presence log: keep this short. |

## `counters`

| Setting | Environment variable | Default | Meaning |
| --- | --- | --- | --- |
| `counters.error_ratio` | `SIGNALBOX_COUNTERS_ERROR_RATIO` | `0.001` | Port error check (port.errors): report a port when the errors between two reads are at least this share of its packets (0.001: one in a thousand). |
| `counters.crc_ratio` | `SIGNALBOX_COUNTERS_CRC_RATIO` | `0.0001` | Report a warning when the CRC/FCS errors received between two reads are at least this share of the packets received (0.0001: one in ten thousand). |
| `counters.min_packets` | `SIGNALBOX_COUNTERS_MIN_PACKETS` | `1000` | Reads with fewer packets than this on a port are too small to judge. |
| `counters.min_errors` | `SIGNALBOX_COUNTERS_MIN_ERRORS` | `5` | Fewer errors than this between two reads are never reported (a single bad frame). |

## `certificates`

| Setting | Environment variable | Default | Meaning |
| --- | --- | --- | --- |
| `certificates.warn_days` | `SIGNALBOX_CERTIFICATES_WARN_DAYS` | `30` | Days before a device's HTTPS certificate expires when Signalbox warns. |
| `certificates.urgent_days` | `SIGNALBOX_CERTIFICATES_URGENT_DAYS` | `7` | Days before it expires when the warning becomes an error (an expired certificate is always an error). |

## `discovery`

| Setting | Environment variable | Default | Meaning |
| --- | --- | --- | --- |
| `discovery.enabled` | `SIGNALBOX_DISCOVERY_ENABLED` | true | Allow 'Find devices' on the devices page (started by you only, never in the background; see docs/DISCOVERY.md). false: no probe is ever sent. |
| `discovery.timeout_seconds` | `SIGNALBOX_DISCOVERY_TIMEOUT_SECONDS` | `2` | Timeout of one probe request, in seconds. |
| `discovery.concurrency` | `SIGNALBOX_DISCOVERY_CONCURRENCY` | `16` | Addresses probed at the same time. |
| `discovery.rate_per_second` | `SIGNALBOX_DISCOVERY_RATE_PER_SECOND` | `30` | At most this many probe requests per second. |
| `discovery.sweep_prefix` | `SIGNALBOX_DISCOVERY_SWEEP_PREFIX` | `24` | Gateway subnets with this prefix length or longer are probed completely; of larger ones only the gateway and known clients. |
| `discovery.max_hosts` | `SIGNALBOX_DISCOVERY_MAX_HOSTS` | `1024` | At most this many addresses in one run. |

## `setup`

| Setting | Environment variable | Default | Meaning |
| --- | --- | --- | --- |
| `setup.enabled` | `SIGNALBOX_SETUP_ENABLED` | true | Offer 'Set up automatically' in the device form: with the admin login you give once, Signalbox creates its own least-privilege login on that device (only when you start it and confirm the plan; docs/adr/0009). false: the API refuses it and the form does not show it; the manual setup guides always work. |
| `setup.fixes` | `SIGNALBOX_SETUP_FIXES` | true | Offer 'Fix it' next to a read problem Signalbox's own setup can repair (a missing package or permission it reads through; no 'Allow changes' needed for these), with the admin login, only when you start it and confirm the plan (docs/adr/0012). Never changes network settings. Off when this or setup.enabled is false. |

## `traces`

| Setting | Environment variable | Default | Meaning |
| --- | --- | --- | --- |
| `traces.enabled` | `SIGNALBOX_TRACES_ENABLED` | false | Path traces (docs/adr/0014): let the routers Signalbox reads (and its own host) run traceroutes to each other and to one internet address, to show the routed path. Off by default; needs an extra permission on some devices (docs/TRACES.md). |
| `traces.interval_hours` | `SIGNALBOX_TRACES_INTERVAL_HOURS` | `0` | Run all traces every this many hours; 0: only when you press Trace now. |
| `traces.internet_target` | `SIGNALBOX_TRACES_INTERNET_TARGET` | `1.1.1.1` | The internet address every gateway traces to (an IP address); empty: none. |
| `traces.from_signalbox` | `SIGNALBOX_TRACES_FROM_SIGNALBOX` | true | Also trace from Signalbox's own host (unprivileged UDP, no root needed). |
| `traces.max_hops` | `SIGNALBOX_TRACES_MAX_HOPS` | `16` | Hops per trace at most. |
| `traces.wait_seconds` | `SIGNALBOX_TRACES_WAIT_SECONDS` | `1` | How long a hop may take to answer, in seconds. |
| `traces.timeout_seconds` | `SIGNALBOX_TRACES_TIMEOUT_SECONDS` | `40` | Timeout of one whole trace, in seconds. |
| `traces.concurrency` | `SIGNALBOX_TRACES_CONCURRENCY` | `2` | Traces running at the same time. |
| `traces.min_gap_seconds` | `SIGNALBOX_TRACES_MIN_GAP_SECONDS` | `60` | Trace now is refused this soon after the last run. |
| `traces.max_pairs` | `SIGNALBOX_TRACES_MAX_PAIRS` | `64` | At most this many traces in one run. |

## `probes`

| Setting | Environment variable | Default | Meaning |
| --- | --- | --- | --- |
| `probes.enabled` | `SIGNALBOX_PROBES_ENABLED` | false | Foreign DHCP servers and routers (docs/adr/0015): let Signalbox's own host send one DHCPDISCOVER (never a REQUEST: no lease is taken) and one IPv6 router solicitation on each of its networks and list who answers. Off by default; needs host networking and UDP port 68, router solicitations need CAP_NET_RAW (docs/PROBES.md). |
| `probes.interval_hours` | `SIGNALBOX_PROBES_INTERVAL_HOURS` | `0` | Probe every this many hours; 0: only when you press Probe now. |
| `probes.dhcp` | `SIGNALBOX_PROBES_DHCP` | true | Send a DHCPDISCOVER (needs UDP port 68). |
| `probes.router_solicitation` | `SIGNALBOX_PROBES_ROUTER_SOLICITATION` | true | Send an IPv6 router solicitation (needs CAP_NET_RAW). |
| `probes.interfaces` | `SIGNALBOX_PROBES_INTERFACES` | - | Probe only these interfaces of Signalbox's host (eth0, eth0.20); empty: every interface whose network Signalbox knows. |
| `probes.wait_seconds` | `SIGNALBOX_PROBES_WAIT_SECONDS` | `3` | How long to listen for answers per interface, in seconds. |
| `probes.min_gap_seconds` | `SIGNALBOX_PROBES_MIN_GAP_SECONDS` | `300` | Probe now is refused this soon after the last run. |

## `notifications`

| Setting | Environment variable | Default | Meaning |
| --- | --- | --- | --- |
| `notifications.language` | `SIGNALBOX_NOTIFICATIONS_LANGUAGE` | `en` | Language of notification texts (a code of the UI languages, e.g. de). |
| `notifications.timeout_seconds` | `SIGNALBOX_NOTIFICATIONS_TIMEOUT_SECONDS` | `10` | Timeout of one delivery attempt, in seconds. |
| `notifications.retries` | `SIGNALBOX_NOTIFICATIONS_RETRIES` | `2` | Retries after a failed delivery (bounded). |
| `notifications.channels` | `SIGNALBOX_NOTIFICATIONS_CHANNELS` | - | Channels set in the file (docs/NOTIFICATIONS.md); more can be added in the web interface. Every channel is off until enabled: true. |

## `plugins`

| Setting | Environment variable | Default | Meaning |
| --- | --- | --- | --- |
| `plugins.remote_adapters` | `SIGNALBOX_PLUGINS_REMOTE_ADAPTERS` | - | Adapters that run as separate programs: id -> command (see docs/PLUGINS.md). |

## `rules`

Per rule (ids in [RULES.md](RULES.md)): `enabled` (true/false), `severity`
(info/warning/error), `params` (the rule's parameters, listed with default and unit in
[RULES.md](RULES.md#parameters)) and `scopes`: settings for some objects only. Only in
the file:

```yaml
rules:
  wifi.channel-overlap: {enabled: false}
  dhcp.one-server: {severity: warning}
  health.storage-full:
    params: {warn_pct: 80, error_pct: 95}
    scopes:
      - match: {site: lab}
        params: {warn_pct: 95}
      - match: {segment_purpose: guest}
        enabled: false
```

A scope's `match` takes `site`, `device` (id or name), `device_role`, `segment` (id, name
or VLAN id), `segment_purpose` and `tag` (a tag of the object's annotation); every
selector given must match. A finding belongs to its first affected object: a port or
server counts for its device and network. When several scopes match, the most specific
wins (device, then network, tag, role or purpose, site; more selectors before fewer),
and among equally specific ones the first listed. A scope changes only what it sets.
Parameters are checked at start: an unknown name or a value out of range stops
Signalbox with the setting's path. The JSON Schema of the whole section is
[rules-schema.json](rules-schema.json)
([ADR 0027](adr/0027-rule-parameters-and-scopes.md)).
