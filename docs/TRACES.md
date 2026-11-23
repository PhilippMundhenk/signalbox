# Path traces

*Routed paths* on the topology page show the layer-3 path between your routers and from each
router to the internet, as the routers themselves trace it (#253): which router is in front
of which (double NAT, the firewall behind the provider's box), which traffic goes through a
VPN tunnel to the other site, and how long each path takes. Switches and access points do not
appear: they do not route. Decision and details: [ADR 0014](adr/0014-path-traces.md).

## Turning it on

Off by default. In `signalbox.yaml` (or with `SIGNALBOX_TRACES_ENABLED=true`):

```yaml
traces:
  enabled: true
  interval_hours: 0        # 0: only when you press "Trace now"; 24: once a day
  internet_target: 1.1.1.1 # every gateway also traces to this address; "" for none
  from_signalbox: true     # also trace from Signalbox's own host
```

Then press **Trace now** on the topology page. By default every gateway that can trace (and
Signalbox's host) traces to every other gateway and to the internet target; *From* and *To*
pick one source or one destination (a device or an IP address). Further settings (hops, waits,
traces at once, how soon *Trace now* may run again) are in [CONFIGURATION.md](CONFIGURATION.md).

## What each device needs

| Integration | How | Permission |
| --- | --- | --- |
| OPNsense | `POST /api/diagnostics/traceroute/set` (the web interface's *Interfaces: Diagnostics: Trace Route*), ICMP | privilege **Diagnostics: Traceroute** (`page-diagnostics-traceroute`) for the API user |
| MikroTik RouterOS | `POST /rest/tool/traceroute`, one probe per hop, no DNS | policy **test** for the user's group |
| Linux gateway | `tracepath -n` (package `iputils-tracepath`), else `traceroute -n`, as the SSH read user | none: both send unprivileged UDP, no sudo, no root |
| Signalbox's host | UDP probes with `IP_RECVERR`, like `tracepath` | none: no root, no raw sockets, nothing installed in the container |
| OpenWrt | not supported: rpcd has no traceroute method; LuCI's diagnostics run `/usr/bin/traceroute` through an exec right, which Signalbox does not ask for | – |
| Fritz!Box, Omada, ProSAFE / Easy Smart switches | not supported (no traceroute in their APIs) | – |

Devices that cannot trace are still destinations: a Fritz!Box in front of the firewall shows up
as the router in front.

Give the permission by hand:

- **OPNsense:** System > Access > Users > the API user (`signalbox`) > Effective privileges:
  add *Diagnostics: Traceroute*. Or the **Fix it** (`privileges`) next to the refused trace
  on the device page adds it (with the admin login, after you
  confirm the plan), but only while `traces.enabled` is on.
- **MikroTik:** `/user group set signalbox-read policy=read,api,rest-api,test` (the policies of
  the setup guide plus `test`; `signalbox-write` likewise). Or, while `traces.enabled` is on,
  **Fix it** (`policies`) next to the refused trace on the device page, or **Set up
  automatically** again: both then give the group `test`.
- **Linux:** `apt install iputils-tracepath` if `tracepath` is missing.

The automatic setup (ADR 0009) adds these permissions only while path traces are on; with the
feature off a new login gets none of them.

## What is sent

One probe per hop, at most `traces.max_hops` hops, `traces.wait_seconds` per hop and
`traces.timeout_seconds` per trace; at most `traces.concurrency` traces at once and
`traces.max_pairs` per run. No device looks up names (numeric output). The internet target is
the only address outside your networks that is traced to; leave `internet_target` empty to
trace only between your own routers.

## What is kept

The latest trace per source and destination, in Signalbox's database (not in the device
snapshots), for `history.days`; removing a device removes its traces, and *DELETE
/api/traces* forgets them all. The provider's routers on the way out identify your connection
like an uplink address: they are shown in the UI and never exported (MQTT).

## Checks

`trace.not-via-tunnel` and `trace.extra-nat` ([rules/traces.md](rules/traces.md)), both
information only and only on complete traces.
