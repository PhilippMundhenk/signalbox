# AdGuard Home adapter

Reads an AdGuard Home DNS filter through its REST API (`/control/...`): the DNS service and its
port, the upstream servers, whether filtering is on, the DHCP server if it is enabled (range,
leases, static leases) and the configured clients. **Read only**: Signalbox sends GET requests
only. The DNS checks (forwarder loops, a missing resolver, a single upstream) and the DHCP
checks (one server per network, foreign servers) then see AdGuard Home's real settings instead
of "an unread DNS service" ([#241](https://github.com/PhilippMundhenk/signalbox/issues/241)).
Pi-hole is the sibling integration ([pihole.md](pihole.md)); both map to the model the same way.

| | |
| --- | --- |
| Adapter id | `adguardhome` |
| Roles | `other` |
| Capabilities | dns, dhcp, clients |
| Writes | none |
| Simulator | `signalbox.sim.dnsfilter.AdGuardSim` |

> **Based on the public API description, not on a real device.** The endpoints and answer
> shapes below come from AdGuard Home's OpenAPI description. Parts marked *(guess)* are not
> certain. Please report your device in
> [#21](https://github.com/PhilippMundhenk/signalbox/issues/21).

## Setup

No automatic setup: Signalbox never changes AdGuard Home.

1. AdGuard Home has **no read-only user**; every user is an administrator. Create a user for
   Signalbox of its own so that you can remove it later: under `users:` in `AdGuardHome.yaml`
   add `- name: signalbox` and `password: <bcrypt hash>` (for example
   `htpasswd -B -n -b signalbox '<password>'`, take what follows the colon), then restart
   AdGuard Home. (Or use an existing user.)
2. In Signalbox add a device of kind *AdGuard Home*: the address of the web interface (the
   port is the one you gave in the first-run wizard, 3000 or 80 by default), the user and the
   password.
3. AdGuard Home serves **plain http** unless Settings > Encryption is configured. With plain
   http tick *Allow plain http*; the password then travels unencrypted (HTTP basic auth), so
   use it only on a network you trust. The device is shown as read over an unencrypted
   connection. With HTTPS, Signalbox pins the certificate on first use like for other devices.

## Settings

| Key | Meaning |
| --- | --- |
| `url` | address of the web interface, `192.0.2.53:3000`, `http://192.0.2.53` (no scheme: https) |
| `username`, `password` | the login (the password is stored encrypted and never sent back) |
| `allow_insecure_http` | allow plain `http://` (see above) |

## What is read

| Request | Used for |
| --- | --- |
| `GET /control/status` | version (`version`), listen addresses (`dns_addresses`), DNS port (`dns_port`), `protection_enabled`, `running` |
| `GET /control/dns_info` | upstream servers (`upstream_dns`, `upstream_dns_file`), `bootstrap_dns`, `upstream_mode` |
| `GET /control/dhcp/status` | `enabled`, `interface_name`, `v4` (`gateway_ip`, `range_start`, `range_end`, `lease_duration`), `v6.range_start`, `leases` (`mac`, `ip`, `hostname`, `expires`), `static_leases` |
| `GET /control/clients` | configured clients: `name`, `ids` |
| `GET /control/rewrite/list` | DNS rewrites as host records (`domain`, `answer`) *(not in the original brief; read-only, a failure is a gap)* |

Mapping to the model:

- **DNS service** `<device>/dns/adguardhome`: port from `dns_port`, listen addresses from
  `dns_addresses` without loopback, unspecified and link-local ones (empty: the device's
  management address is used). `running: false` marks it disabled.
- **Forwarders**: each upstream with an IP address (`192.0.2.1`, `192.0.2.1:5353`,
  `tls://203.0.113.53` = port 853, `https://203.0.113.2/dns-query` = port 443, `udp://`,
  `tcp://`, `quic://`, `h3://`) is a forwarder with its port. Upstreams given by **name** are
  listed in `vendor_extra.named_upstreams` as `scheme://host` (never the path, it can hold a
  token) and `sdns://` stamps as `sdns://`; Signalbox cannot match them with a device.
  `[/example.lan/]192.0.2.1` (one domain only) is `vendor_extra.domain_forwards`, not a
  forwarder. Whether filtering is on is `vendor_extra.filtering_enabled`.
- **Host records**: DNS rewrites whose answer is an IP address (wildcards and CNAME answers
  are skipped).
- **DHCP** (only when `enabled`): one server `<device>/dhcp/adguardhome` with the IPv4 range,
  lease time, router (`gateway_ip`), the reservations (`static_leases`) and the lease table:
  dynamic leases as active (with the expiry), static ones as `reserved` entries. AdGuard Home
  does not say which VLAN it is in: the server is reported on the site's native segment and
  core moves it to the segment of the router it shares a network with. DHCPv6 ranges are only
  kept as `vendor_extra.v6_range_start`. The DNS server AdGuard Home hands out is not shown
  by the API *(guess: its own address)*, so `dns_servers` stays empty.
- **Clients**: configured clients that have a **MAC address** among their identifiers
  (the model keys a client by MAC); clients that are only an IP address or a network, and
  AdGuard Home's automatically found clients, are not listed.

## Gaps (reported as partly read, with a fix)

- `upstream_dns_file` is set: the API does not show the file, so the service is reported as
  not read (`config_read: false`), not as "resolves by itself"; the fix says to enter the
  upstreams in the settings.
- The rewrite list could not be read (an older AdGuard Home without it, or a refusal): the
  rest is kept.
- HTTP 401 is *authentication failed* (check user and password); other errors name the request.

## Simulator and tests

`signalbox.sim.dnsfilter.AdGuardSim` answers the requests above with documentation addresses
only (`192.0.2.53`, upstreams `192.0.2.1` and `203.0.113.53`, DHCP range `192.0.2.100-199`).
`tests/test_dnsfilter.py` runs the contract checks against it (plain http and pinned TLS), the
gaps and failures, and the DNS and DHCP rules over merged snapshots;
`tests/test_recordings.py` records and replays it.
