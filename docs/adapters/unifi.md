# Ubiquiti UniFi adapter

Reads one site of the **UniFi Network application**, read only: the gateway, switches and access
points it manages with their ports (VLAN profiles, PoE, link aggregation, LLDP, MAC tables),
networks and DHCP, the gateway's WAN, radios and Wi-Fi networks, clients and the uplinks of
access points and switches as neighbours (the same pattern as [Omada](omada.md)). Nothing is
changed on the controller (writes are a later step, issue #403).

| | |
| --- | --- |
| Adapter id | `unifi` |
| Roles | `other` (recommended: the application), `ap`, `switch`, `gateway` |
| Capabilities | interfaces, DHCP, wireless, clients, neighbours, health, time |
| Writes | none |
| Simulator | `signalbox.sim.unifi` (`uvicorn --factory signalbox.sim.unifi:create_app`) |

> **Not yet confirmed on a real console or controller** ([#21](https://github.com/PhilippMundhenk/signalbox/issues/21)).
> Paths and fields follow what the application's web API is known to answer; they are tested
> against the simulator and a recording replay only. Parts that are guesses are marked
> *(guess)* below. Parsing is tolerant: a missing field stays empty, unknown fields are ignored,
> an answer of the wrong shape becomes a readable "could not read" finding.

## Installations and versions

Both kinds are told apart automatically (setting `kind`, advanced, to force one):

| | UniFi OS console (UDM, UDR, Cloud Gateway, Cloud Key Gen2+) | Self-hosted controller (Linux package, Docker) |
| --- | --- | --- |
| Detection | `GET /` answers 200 | `GET /` redirects |
| Login | `POST /api/auth/login`, cookie | `POST /api/login`, cookie |
| API | `/proxy/network/api/s/<site>/...` | `/api/s/<site>/...` |
| Integration API | `/proxy/network/integration/v1/...` | `/integration/v1/...` *(guess)* |
| Port | 443 | 8443 |

If the guessed kind answers 404 at the login, the other is tried once.

Supported: the current Network application major version **10** and the two before it, **9** and
**8** (#389). Other versions are read the same way and reported with an optional finding. Where
a field changed between them both spellings are read:

| What | 8 | 9 and 10 |
| --- | --- | --- |
| Wi-Fi bands of a network | `wlan_band` (`both`, `2g`, `5g`) | `wlan_bands` (list, with `6g`) |
| Custom port profile | every network except `excluded_networkconf_ids` is tagged | `tagged_networkconf_ids` *(guess: which minor release switched)* |
| LLDP | per port (`port_table[].lldp_table`) | per device (`lldp_table` with `local_port_idx`) *(guess)* |
| WPA3 | `wpa3_support`, `wpa3_transition` | same |
| API key | not available | Network 9.0.108 and later |

## Setup

Use **an API key or a local account**. Both are stored encrypted and never sent back to the UI.

1. *Local account* (works on every supported version, full read): *Settings > Admins & Users*,
   add a **local** user (not a Ubiquiti cloud account, no two-factor login) with a read-only role
   (*Network: View Only*; on a self-hosted controller the role *Read-only*), restricted to the
   local network.
   *API key* (Network 9.0.108 and later): *Settings > Control Plane > Integrations*, create a key.
   The official Integration API is small (devices, networks, clients). Whether the key also opens
   the classic API Signalbox reads ports, radios and uplinks from is **not confirmed**
   *(guess)*: if the application refuses it there, Signalbox reads the Integration API only and
   says so ("accepts this API key for the Integration API only"). Use the local account for the
   full read.
2. In Signalbox add a device with adapter `unifi`, role `other`:

```yaml
adapter: unifi
url: https://192.0.2.1            # console; self-hosted: https://192.0.2.10:8443
site: default                     # internal name, or the name shown in the UI
username: signalbox               # local account ...
password: "..."                   # ... or instead:
api_key: "..."
```

| Key | Default | Meaning |
| --- | --- | --- |
| `url` | | address with port, `https://host[:port]` |
| `site` | `default` | site, by internal name or shown name (case-insensitive) |
| `username`, `password` | | local account with a read-only role |
| `api_key` | | API key (`X-API-KEY`); used instead of the account when set |
| `kind` | `auto` | `unifi_os`, `controller` or detected |
| `allow_insecure_http` | `false` | plain `http://` (simulator only: the login crosses the network in clear text) |

The device is trusted by its pinned certificate (*Test connection*, then trust the shown
fingerprint), as for every HTTPS integration.

## What is read

The Signalbox device stands for the **site**; the gateway, switches and access points are
reported as devices of their own with ids `<device>/<type>-<mac>` (`gateway`, `switch`, `uap`),
as for Omada ([ADR 0004](../adr/0004-controllers-report-several-devices.md)). Devices that are
not adopted are left out.

| Capability | Source | What |
| --- | --- | --- |
| system | `stat/sysinfo`, `api/self/sites` | application version, site, time zone |
| interfaces | `stat/device` (`port_table`), `rest/portconf`, `rest/networkconf` | ports with link, speed, duplex, PoE (`port_poe`, `poe_enable`), admin state, profile name, PVID; segments with the untagged and tagged members of each port by its profile (`forward` all / native / customize / disabled); link aggregation (`aggregated_by`, `op_mode` aggregate) as `lag` ports; subnets of the networks; WAN (`wan1`, `wan2`: address, gateway, DNS; kind from the WAN network's `wan_type`) |
| dhcp | `rest/networkconf` | pool, lease time, DNS, router, domain per network |
| wireless | `radio_table`, `radio_table_stats`, `vap_table`, `rest/wlanconf` | per AP radio (band, channel, width, power, utilisation, clients) and the Wi-Fi networks it broadcasts (security, WPA3 mode, ciphers, PMF, hidden, guest, VLAN or network, isolation, passphrase fingerprint, never the passphrase) |
| clients | `stat/sta`, `port_table[].mac_table` | wired and wireless clients with address, network and where they were seen; the switch MAC tables where the device lists them |
| neighbours | `uplink` of every device, `lldp_table` | an AP's switch port, mesh uplinks between APs, switch-to-gateway links; LLDP neighbours (name, port, description) |
| health, time | `stat/device`, `Date` header | uptime, CPU, load, memory, temperature, storage per device; clock and time zone |

PoE (#159): per port `poe_enable`, `poe_mode` (`auto`, `pasv24`, `passthrough`, `off`), the delivered
`poe_power` (W), `poe_good` and `poe_class` (`Class 4`); per switch `total_max_power` (W) as the
budget and the sum of the port power as used. A Network version without a field leaves it out
(*guess: the field names are from the classic API of Network 7 and 8, not checked on a real switch*);
the integration API (`/integration/v1`) has no ports, so no PoE. `stat/device` also answers with STP
state, SFP data and more; they are not read yet. Firewall, VPN and routes are not read.

## Findings you may see

| Finding | Meaning |
| --- | --- |
| the application refused the login | wrong account, or a cloud / two-factor account; use a local one |
| accepts this API key for the Integration API only | see Setup; ports, radios, Wi-Fi and uplinks are missing |
| is version N; Signalbox is written for ... | a version outside 8 to 10; optional |
| port profiles / networks / Wi-Fi networks: not read | an endpoint the role or version does not answer; optional |

## Guesses that need a real device (#21)

- `/integration/v1` without `/proxy/network` on a self-hosted controller, and that an API key is
  accepted by the classic `/api/s/<site>/...` paths.
- `uplink.uplink_remote_port` / `port_idx` as the two ends of an uplink; `last_uplink` of an
  offline device; the LLDP field names (`chassis_name`, `chassis_descr`, `port_id`).
- `aggregated_by` and `op_mode: aggregate` for link aggregation (the mode is not reported).
- `wpa_enc: auto` meaning TKIP and CCMP; `owe_enabled`; `group_rekey` as the key rotation.
- Which release moved a field between the spellings in the table above.
- The Integration API's `features` list (`switching`, `accessPoint`) and device statistics.

## Integration tests

A self-hosted Network application in Docker would be the natural CI target (the issue names
`linuxserver/unifi-network-application` with MongoDB). See the section at the end of this page
for what the CI job does, or why there is none.

## WAN failover and dynamic DNS (#150, #154)

`rest/networkconf` rows with `purpose` `wan` give each WAN connection its `wan_failover_priority`
(1 first), `wan_load_balance_type` (`failover-only` or `weighted`) and `wan_load_balance_weight`;
the gateway's `wan1`/`wan2` give `up`, `latency` and `is_uplink` (the connection in use). Two or
more connections form the group `WAN`. UniFi has no readable monitor target. Field spellings of
the controller 8, 9 and 10 are the same in the simulator; on older controllers a missing field
leaves the value empty *(guess, #21)*. `rest/dynamicdns` (`host_name`, `service`, `interface`)
gives the DDNS entries; `login` and `x_password` are never read, the result is unknown, and a
controller without the list gives none.

### Firmware upgrade flag (#181)

The classic device list's `upgradable` and `upgrade_to_firmware` give `Firmware.upgradable` and
`available` of the managed device; the Integration API has neither (unknown). The auto-upgrade
schedule is not read yet.
