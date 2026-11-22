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

## `rules`

Per rule (ids in [RULES.md](RULES.md)): `enabled` (true/false) and `severity`
(info/warning/error). Only in the file:

```yaml
rules:
  wifi.channel-overlap: {enabled: false}
  dhcp.one-server: {severity: warning}
```
