# Pi-hole adapter (v6 and v5)

Reads a Pi-hole **v6** DNS filter through its REST API (`/api/...`): the DNS service and its
port, the upstream servers, local DNS records, and the DHCP server with its leases and
reservations if it is enabled, and the network table as clients. **Read only**: besides the login and logout, Signalbox sends GET
requests only. The DNS and DHCP checks then see Pi-hole's real settings instead of "an unread
DNS service" ([#241](https://github.com/PhilippMundhenk/signalbox/issues/241)). AdGuard Home
is the sibling integration ([adguardhome.md](adguardhome.md)); both map to the model the same
way.

| | |
| --- | --- |
| Adapter id | `pihole` |
| Roles | `other` |
| Capabilities | dns, dhcp, clients |
| Writes | none |
| Simulator | `signalbox.sim.dnsfilter.PiholeSim` |

**Pi-hole v5** (the legacy `/admin/api.php`, API token) is read too, with less: see
[Pi-hole v5](#pi-hole-v5) ([#385](https://github.com/PhilippMundhenk/signalbox/issues/385)).
It is one device type: Signalbox detects the version itself. Everything above and below this
section is about v6.

> **Based on the public API documentation, not on a real device.** Parts marked *(guess)* are
> not certain. Please report your device in
> [#21](https://github.com/PhilippMundhenk/signalbox/issues/21).

## Setup

No automatic setup: Signalbox never changes Pi-hole.

1. Pi-hole v6 (`pihole -up`, or the v6 container image).
2. Web interface: *Settings > Web interface / API > Configure app password > Enable app
   password*. Copy the password it shows once. An app password works with two-factor
   authentication on. Pi-hole has **no read-only login**: the app password has the rights of
   the web interface (Signalbox only reads) and you can disable it again at any time.
3. In Signalbox add a device of kind *Pi-hole*: the address (https on port 443 by default; the
   certificate is self-signed, trust it after comparing the fingerprint) and the app password.
   For Pi-hole v5 enter the API token instead, see below.

## Sessions and secrets

`POST /api/auth` with `{"password": "<app password>"}` returns a session id (`session.sid`).
Signalbox sends it in the `sid` header of each request *(guess: header name, per the API
documentation)* and ends the session with `DELETE /api/auth` when the observation is over, also
after a failed read. The session id is kept in memory only for that observation and is never
stored, logged or part of an error or a recording. A refused login (HTTP 401, or `valid:
false` for a second factor) is *authentication failed* with the fix "use an app password";
HTTP 429 (too many failed logins or API sessions, `webserver.api.max_sessions`) is reported
with a fix.

## What is read

| Request | Used for |
| --- | --- |
| `POST /api/auth`, `DELETE /api/auth` | login and logout |
| `GET /api/info/version` | firmware (`version.ftl.local.version`, newer release from `.remote`); v6 check |
| `GET /api/config` | `config.dns` (`upstreams`, `port`, `hosts`, `revServers`, `blocking.active`, `domain.name`, `interface`, `listeningMode`) and `config.dhcp` (`active`, `start`, `end`, `router`, `leaseTime`, `hosts`) and `misc.dnsmasq_lines` |
| `GET /api/network/devices` | clients (#314): `devices[]` with `hwaddr`, `ips[]` (`ip`, `name`, `lastSeen`), `lastQuery` |
| `GET /api/dhcp/leases` | `leases[]`: `ip`, `hwaddr`, `name`, `expires` (epoch, 0: does not end), `clientid` |

Mapping to the model:

- **DNS service** `<device>/dns/pihole` on `dns.port`. Pi-hole does not list the addresses it
  listens on, so the device's management address is used. Whether blocking is on is
  `vendor_extra.filtering_enabled`.
- **Forwarders**: `dns.upstreams` (`192.0.2.1`, `203.0.113.53#5353`, `2001:db8::1`).
  Conditional forwarding (`dns.revServers`, enabled entries) is
  `vendor_extra.domain_forwards`, not a forwarder. Local DNS records (`dns.hosts`,
  `192.0.2.10 printer.lan`) are host records.
- **DHCP** (only when `dhcp.active`): `<device>/dhcp/pihole` with the range, lease time
  (`24h`, `90m`, `7d`, seconds), router, domain, the reservations (`dhcp.hosts`, dnsmasq
  `dhcp-host` lines with a MAC and an IPv4 address) and the lease table (entries without a MAC
  and client id are dropped). Reported on the site's native segment (see AdGuard Home).
  **DNS servers handed out** (`dns_servers`, #314): Pi-hole itself, that is the address
  Signalbox reaches it at (a host name tells no address: then empty), unless
  `misc.dnsmasq_lines` has a `dhcp-option=6,...` or `dhcp-option=option:dns-server,...` line
  (`0.0.0.0` stands for Pi-hole itself; lines scoped to a `tag:` are skipped) *(guess: v6 has
  no field for it in `config.dhcp`, and dnsmasq's own default is the server itself; needs a
  real device)*.
- **Clients** (#314): the network table `/api/network/devices`, one client per MAC address
  with the addresses and the first name Pi-hole knows, `last_seen` from the newest `lastSeen`
  or `lastQuery`. A row without a real MAC (Pi-hole names address-only devices `ip-<address>`)
  is not listed: the model keys a client by MAC. `/api/clients` is not read: it is the list
  of group-management entries (MAC, IP, network or name), not a table of hosts.
- **Not read**: query statistics, blocklists, the group settings.

## Discovery (#314)

*Find devices* ([DISCOVERY.md](../DISCOVERY.md)) sends `GET /api/info/login` (public in v6)
to `https` port 443, then `http` port 80: JSON with a boolean `dns` is Pi-hole v6. Otherwise
`GET /admin/` (v5 and v6): `Pi-hole` in the page makes a candidate whose note says Signalbox
needs v6. The candidate's address is always `https` (with `https_port` if the plain answer
names one). *(Guess: the exact fields of `/api/info/login`, and that it needs no session;
needs a real device, #21.)* Passive, only when you press *Search now*, and not at all with
`discovery.enabled: false`.

## Gaps

- The lease table could not be read (`/api/dhcp/leases` failed): the DHCP server is reported
  without leases ("not read", not "no leases") and the device as partly read, with a fix.
- The network table could not be read: the device is partly read, with a fix (no clients).
- A device that is neither v6 nor v5, an old v6 beta, a missing `dns.upstreams`: an error naming
  the request.

## Simulator and tests

`signalbox.sim.dnsfilter.PiholeSim` answers the requests above (`192.0.2.54` forwarding to
AdGuard Home at `192.0.2.53`, DHCP range `192.0.2.150-199`) and checks the session id;
switches for v5, other servers, second factor, session limit and failures.
`tests/test_dnsfilter.py` covers the contract (http and pinned TLS), that every session is
ended, that no password is sent to an untrusted certificate, the gaps, and the DNS loop and
one-DHCP-server checks over both simulators; `tests/test_recordings.py` records and replays it.

## Pi-hole v5

Pi-hole v5 (for example Pi-hole 5.17, FTL 5.23, web interface 5.21) has no REST API, only the
legacy API of the web interface (`api.php`, `api_FTL.php`, `api_db.php`). Signalbox reads it
with the **API token** and **read only** (GET requests only, no login, no session).

**Detection.** With an app password Signalbox first tries v6 (`POST /api/auth`). v5 answers 404
there, then `GET /admin/api.php?versions` names the box as v5 and the v5 reader takes over. With
only an API token, v6 is not tried. The same device type and the same address field serve both;
the *API token (v5)* field is next to the app password. Give the token only (v5) or the app
password only (v6); with both, v6 is tried first. A v5 box without a token is reported as *this
is Pi-hole v5: Signalbox needs its API token* with the fix to copy it from **Settings > API >
Show API token** (a long hexadecimal string, not the web password; it changes when the web
password changes).

**What is read** (`?versions`, `?status` need no token):

| Request | Used for |
| --- | --- |
| `GET /admin/api.php?versions` | firmware (`core_current`, `core_latest`, `core_update`), `web_current` and `FTL_current` as `vendor_extra` |
| `GET /admin/api.php?status` | `{"status": "enabled"}`: `vendor_extra.filtering_enabled` |
| `GET /admin/api.php?getForwardDestinations&auth=<token>` | upstream servers: `forward_destinations` keys `name\|address` (`router.lan\|192.0.2.1`, address may be `ip#port`); `blocklist`, `cache` and `other` are no servers; mapped through the shared DNS mapping like v6 |
| `GET /admin/api_db.php?network&auth=<token>` | clients: `network[]` with `hwaddr`, `ip[]`, `name[]`, `lastQuery` |

- **DNS**: the DNS service `<device>/dns/pihole`, the port is 53 (v5 does not say), no listen
  addresses and no local DNS records. v5 lists the servers it *forwarded queries to*, not the
  configured ones: a server that did not get a query yet is missing, and one that did but is no
  longer configured can still show up *(guess, #21)*.
- **Clients**: one per MAC address with the addresses and the first name. A row without a real
  MAC (`ip-192.0.2.99`) is not listed, as for v6. `topClients` / `getQuerySources` are not
  read: they give names and addresses but no MAC, and the model keys a client by MAC. Without
  the token's rights or with the query database off, the network table is a gap (*the network
  table was not read*) and no client is listed.
- **DHCP**: v5 has no API for DHCP settings or leases. Reported as an **optional gap** (the
  device stays "ok") with the fix *upgrade to Pi-hole v6*.

**The token is a secret.** It is stored encrypted like the app password, is write-only in the
settings, and is never logged: it is removed from every error message and parameter, it is
not part of any snapshot, and recordings replace it. **But v5 takes the token in the query
string** (`?...&auth=<token>`): anything that sees the URL sees the token, that is a proxy or
reverse proxy that logs requests (access logs), not the TLS connection itself. Use `https`
(Pi-hole v5 has no HTTPS of its own unless you put one in front or set up lighttpd; the
certificate is pinned like the others and the token is not sent to a certificate that was
not trusted), and prefer a network where nobody else reads the Pi-hole's access log. The
token gives access to the web interface API (the same rights as the web password for the
API); Signalbox only sends GET requests. Plain `http://` needs the explicit
`allow_insecure_http` and sends the token in the clear.

**Guesses for [#21](https://github.com/PhilippMundhenk/signalbox/issues/21)** (from the public
API description and the web interface source, not from a real v5 box):

- the `auth` query parameter name and that `?versions` and `?status` work without it;
- a wrong or missing token is answered with an empty list `[]` (not an HTTP error);
- the `forward_destinations` key format `name|address[#port]` and the names of the entries
  that are no server;
- `api_db.php?network`: the field names, that `ip` and `name` are lists (a plain string is
  accepted), and that `lastQuery` is a Unix time;
- `core_current` as the version (`v5.17`) and `core_update` / `core_latest` for the newer
  release;
- whether the network table needs the token at all.

**Simulator**: `PiholeSim(version="v5")` answers the four requests (token
`signalbox.sim.dnsfilter.PH_TOKEN`, made at run time) and records every query in
`PiholeSim.queries`; `tests/test_dnsfilter.py` has the contract test, detection (also the
errors without a token and with only a token on a v6 box), the wrong token, the gaps, pinned
TLS and the check that the token is removed from errors; `tests/test_recordings.py` records
and replays it (`SIGNALBOX_RECORD_API_TOKEN`).

## DNS transport, DNSSEC and block lists (#182, #80)

Pi-hole itself does not encrypt upstream traffic (DoT and DoH need `cloudflared` or `stubby`),
so `dns.forwarder-encrypted` stays silent for it. v6: `dns.dnssec` becomes `dnssec` and
`/api/lists` (type `block`) the block lists (host of the address only). v5: neither is read (the
legacy API has no setting for them; it is in `setupVars.conf`).
