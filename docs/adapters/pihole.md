# Pi-hole adapter (v6)

Reads a Pi-hole **v6** DNS filter through its REST API (`/api/...`): the DNS service and its
port, the upstream servers, local DNS records, and the DHCP server with its leases and
reservations if it is enabled. **Read only**: besides the login and logout, Signalbox sends GET
requests only. The DNS and DHCP checks then see Pi-hole's real settings instead of "an unread
DNS service" ([#241](https://github.com/PhilippMundhenk/signalbox/issues/241)). AdGuard Home
is the sibling integration ([adguardhome.md](adguardhome.md)); both map to the model the same
way.

| | |
| --- | --- |
| Adapter id | `pihole` |
| Roles | `other` |
| Capabilities | dns, dhcp |
| Writes | none |
| Simulator | `signalbox.sim.dnsfilter.PiholeSim` |

**Pi-hole v5 is not supported** (it has no REST API). A v5 device is reported as *this is
Pi-hole v5: Signalbox needs the v6 REST API* with the fix "update Pi-hole to v6".

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
| `GET /api/config` | `config.dns` (`upstreams`, `port`, `hosts`, `revServers`, `blocking.active`, `domain.name`, `interface`, `listeningMode`) and `config.dhcp` (`active`, `start`, `end`, `router`, `leaseTime`, `hosts`) |
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
  `dns_servers` stays empty *(guess: Pi-hole hands out itself)*.
- **Not read**: query statistics, blocklists, clients (`/api/network/devices`), the group
  settings.

## Gaps

- The lease table could not be read (`/api/dhcp/leases` failed): the DHCP server is reported
  without leases ("not read", not "no leases") and the device as partly read, with a fix.
- A v5 or non-Pi-hole device, an old v6 beta, a missing `dns.upstreams`: an error naming the
  request.

## Simulator and tests

`signalbox.sim.dnsfilter.PiholeSim` answers the requests above (`192.0.2.54` forwarding to
AdGuard Home at `192.0.2.53`, DHCP range `192.0.2.150-199`) and checks the session id;
switches for v5, other servers, second factor, session limit and failures.
`tests/test_dnsfilter.py` covers the contract (http and pinned TLS), that every session is
ended, that no password is sent to an untrusted certificate, the gaps, and the DNS loop and
one-DHCP-server checks over both simulators; `tests/test_recordings.py` records and replays it.
