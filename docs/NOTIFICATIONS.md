# Notifications

Signalbox can send findings and events to the services you already use. Everything is **off by
default** and **outbound only**: Signalbox never listens for anything on behalf of a channel.

## What is sent

After every observation round Signalbox compares the network with the round before. Each channel
gets **one message per round** (a digest) with the events it asked for:

| Kind | Event |
| --- | --- |
| `finding` | A new finding, or one that is resolved (acknowledged and incomplete findings do not count). |
| `device` | A device cannot be reached, was only read in part, or is reachable again. |
| `drift` | The network differs from the desired state, or matches it again. |
| `deploy` | A change was applied, rolled back or failed. |

The first round after the first start is only a baseline, and so is the first round after the state
was lost: nothing is sent for what already existed. The state is kept in the database, so a restart
does not repeat old events.

Per channel you set: **enabled**, the **minimum severity** (info, warning, error; devices that
cannot be reached count as errors, partly read ones as warnings, a deployment that failed as an
error), the **event kinds**, **quiet hours** and the **language**. Events during the quiet hours are
held (in memory) and sent together with the first message after they end. *Send test* in Settings
sends a test message at once, also while the channel is disabled.

Texts are the UI's message catalogues (all languages; `notifications.language` is the default, a
channel may set its own). When `server.base_url` is set, a message links back to the findings page.

## Where to configure

- **Settings > Notifications** in the web interface. Tokens and passwords are stored **encrypted**
  (like device credentials), are never shown again (leave the field empty to keep the stored one)
  and are never written to a log, an export or MQTT.
- **`signalbox.yaml`**, section `notifications.channels` (shown read-only in Settings, the test
  button works). A secret written there is stored as you wrote it, like `mqtt.password`: prefer the
  web interface for tokens.

```yaml
notifications:
  language: en
  timeout_seconds: 10   # per delivery attempt
  retries: 2            # then the message is dropped and the error shown in Settings
  channels:
    phone:
      kind: ntfy
      enabled: true
      url: https://ntfy.example.org
      topic: signalbox
      min_severity: warning
      events: [finding, device, drift, deploy]
      quiet_start: "22:00"
      quiet_end: "07:00"
```

Timeouts and retries are bounded, deliveries run on a worker thread, and a channel that fails
(unreachable server, wrong token) only shows its last error in Settings: it never delays a read of
your devices and never stops the other channels.

## E-mail

`kind: email`. Settings: `host`, `port` (0: 587 for `starttls`, 465 for `ssl`, 25 for `none`),
`security` (`starttls`, `ssl`, `none`), `username` and `secret` (the password), `sender`,
`recipients`. Certificates are verified (`verify_tls: false` turns that off, for a server with a
self-signed certificate on a trusted network).

## ntfy

`kind: ntfy`. `url` of your server or `https://ntfy.sh`, `topic`, and a `secret` (access token)
for protected topics. Messages are published as JSON, so every language works in the title.

## Matrix

`kind: matrix`. `url` of the homeserver, `room_id` (`!abc:example.org`, the internal id, not the
alias) and `secret` (the access token of the account that is in the room). Signalbox calls
`PUT /_matrix/client/v3/rooms/{room}/send/m.room.message/{txn}`; a retry reuses the transaction id,
so a message is never doubled.

## Telegram

`kind: telegram`. `secret` is the bot token from BotFather, `chat_id` the chat (write to the bot
once first). `url` is only for a self-hosted Bot API server; empty: `https://api.telegram.org`.

## Gotify

`kind: gotify`. `url` of the server and `secret` (the application token). The token is sent in a
header, not in the URL.

## Webhook (JSON)

`kind: webhook`. `url` receives a `POST` with

```json
{"version": 1, "id": "…", "subject": "…", "text": "…", "severity": "error",
 "language": "en", "events": [{"kind": "finding", "severity": "error", "text": "…", "url": "…"}]}
```

An optional `secret` is sent as `Authorization: Bearer …`. Any 2xx answer counts as delivered.

## Browser

`kind: browser`. While the web interface is open in a browser tab, messages appear as notifications
of that browser (Notification API). Press *Allow notifications* in Settings once: the browser asks
for permission only then. Nothing is sent when no page is open; there is no Web Push service
(a follow-up, see the issue tracker).

## Apprise (optional)

`kind: apprise`. Needs the optional extra: `pip install "signalbox-net[apprise]"` (it is not in the
default image). The `secret` is an [Apprise URL](https://github.com/caronc/apprise/wiki), for
example `mailto://…` or `discord://…`; it usually contains a credential, which is why it is stored
like any other secret.
