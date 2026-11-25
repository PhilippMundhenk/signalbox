<!-- rules of src/signalbox/rules/dns.py; part of the rules documentation (docs/RULES.md lists all) -->

# DNS

Only enabled DNS services count. Host records are compared per site. An address is *used* if it
is an interface address or management address of a known device, a listen address of a DNS
service, or an address of a client seen in this run. A device may run several DNS services
(AdGuard Home on port 53 next to Unbound on another port); each has its own port, and a
forwarder is an address and a port (53 unless given). Checks that rely on "no client uses this
address" only run for a site and IP version for which clients were reported (IPv4 when a device
reads clients; IPv6 only when IPv6 client addresses were seen), and stay silent otherwise.

## `dns.host-record-reservation`

- **Severity:** warning; info for a record with another name on a reserved address
- **Checks:** a host record whose name without the domain (`nas` for `nas.home.example`,
  case-insensitive) equals the hostname of a DHCP reservation at the same site points to the
  same addresses (several records of one name, round robin, are compared as a set; IPv4 and IPv6
  separately). A record whose address is reserved for a device with a different hostname is
  reported as info; it may be an intended second name. Reservations without a hostname are
  skipped.
- **Fix:** update the DNS record (or the reservation) so that both use the same address.

## `dns.host-record-stale`

- **Severity:** info for an unused address in a network of the site (the device may be off),
  warning for a private address outside every network Signalbox knows
- **Checks:** a host record does not point to an address in a network of the site that no
  device, client or DHCP reservation uses, nor to a non-public address that lies in no known
  network (a typo or an old network). Public addresses (intended overrides), `0.0.0.0` and
  loopback (blocking entries) and link-local addresses are not reported.
- **Fix:** remove the record, or correct the address.

## `dns.host-record-dynamic`

- **Severity:** warning
- **Checks:** a host record does not point to an address inside the pool of an enabled DHCP
  server at the same site unless that server has a reservation for the address. Records are
  treated as static: names the DNS service registers from DHCP leases are not reported as host
  records by the integrations.
- **Fix:** add a DHCP reservation for the device at that address, or move the record (and the
  device) to an address outside the pool.

## `dns.forwarder-loop`

- **Severity:** error
- **Checks:** DNS services do not forward in a circle. A forwarder leads to a known DNS service
  only if address **and** port match (its listen addresses, or all addresses of its device if
  none are reported; a loopback address is the forwarding device itself); a cycle, including a
  service that forwards to itself, is one finding that names each step. Domain-specific
  (conditional) forwards are not counted. A forward to a service whose settings are not read
  (`config_read: false`), or to a device that runs a known DNS service on a port none of its
  services listens on (another DNS server, such as AdGuard Home), cannot be followed: it is
  reported as incomplete (info), never as a loop (#241).
- **Fix:** let one of them forward to an upstream resolver, or resolve recursively.

## `dns.forwarder-missing`

- **Severity:** error when it is the only forwarder or DNS server, warning when others exist
- **Checks:** a forwarder of a DNS service, or a DNS server handed out by an enabled DHCP
  server, that lies in a known network is used by a known device, DNS service or client.
  Addresses outside every known network are not checked.
- **Fix:** point the setting to an existing resolver, or bring the resolver back.

## `dns.single-forwarder`

- **Severity:** info
- **Checks:** a DNS service with forwarders has more than one upstream: two forwarders that
  belong to the same known device count as one. If the single upstream is a known DNS service,
  the chain is followed: it is fine when that service has several upstreams or resolves itself.
  A service without forwarders is treated as resolving recursively and is not reported; loops
  are left to `dns.forwarder-loop`. A chain that reaches a service whose settings are not read
  is not reported (its upstreams are unknown).
- **Fix:** add a second upstream resolver, or let the resolver resolve recursively.

## `dns.forwarder-encrypted`

- **Severity:** info
- **Checks:** a DNS service that can forward over TLS or HTTPS (`supports_encrypted_dns`: OPNsense
  Unbound, RouterOS 7, AdGuard Home, OpenWrt with `https-dns-proxy` or `stubby`) has a forwarder
  with plain transport to a public address. Local networks (RFC 1918, CGNAT, ULA, link-local,
  loopback) and addresses of known devices are not public; the documentation ranges count as
  public. Services that cannot encrypt (Pi-hole, plain dnsmasq) or were not read are silent.
- **Fix:** enable DNS over TLS (or HTTPS) to that provider, with its server name.
- **Data:** `DnsForwarder.transport` / `tls_name` (OPNsense `dots` type and `verify`, MikroTik
  `use-doh-server`, AdGuard Home and Pi-hole `tls://`, `https://`, `quic://` upstreams).

## `dns.conflicting-records`

- **Severity:** warning
- **Checks:** a name has the same addresses on every DNS service of a site that has a record for
  it. Names are compared case-insensitively and without a local domain (the domain a DHCP server
  of the site hands out), so `nas` and `nas.home.example` are the same name when `home.example`
  is a DHCP domain. IPv4 and IPv6 records are compared separately; identical round-robin sets
  are fine, and several addresses of one name on a single service (round robin) are not
  reported.
- **Fix:** use the same record on every resolver, or use a single resolver.
