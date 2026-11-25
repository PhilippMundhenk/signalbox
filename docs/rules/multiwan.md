<!-- rules of src/signalbox/rules/multiwan.py; part of the rules documentation (docs/RULES.md lists all) -->

# Multi-WAN and dynamic DNS

These rules read gateway groups (failover and load balancing, #150) and dynamic DNS clients
(#154) that a gateway reported. They stay quiet where the state of a member or the announced
address is not known.

## `wan.group-member-down`

- **Severity:** warning
- **Checks:** a member of a gateway group that the monitor reports down, while at least two
  other members work.
- **Stays quiet** when the state of any member is not known, and when the group would have
  only one line left (`wan.group-last-member` reports that).
- **Fix:** check the cable, modem or mobile signal of the line and the address the gateway
  pings; turn the rule off for a line that is down on purpose.

## `wan.group-last-member`

- **Severity:** warning
- **Checks:** a group where all members but one are down: nothing is left to fail over to.
- **Stays quiet** when all members are down (`wan.down` reports it) or a state is unknown.
- **Fix:** bring the other lines back.

## `wan.monitor-local`

- **Severity:** info
- **Checks:** a member of a group whose monitor target is its own next hop (the modem or the
  provider's router): a dead provider network is never detected.
- **Stays quiet** when the target or the member's gateway is not known.
- **Fix:** ping an address on the internet through that line instead.

## `wan.on-backup`

- **Severity:** warning
- **Checks:** a failover group whose active member is on a later tier than its first choice:
  the traffic runs over the backup line (often slower, metered or behind carrier-grade NAT).
- **Stays quiet** when the gateway does not say which member is active, for load balancing
  groups, and when the active member is on the first tier.
- **Fix:** find out why the first choice was left; the group goes back by itself.

## `wan.flapping`

- **Severity:** warning
- **Checks:** a failover group whose active member changed `count` or more times (4 by
  default) in the last `hours` hours (24 by default), counted from the observation history
  (#463). Each change breaks connections; the usual causes are a first line that drops out now
  and then, or a monitor address that does not always answer.
- **Stays quiet** without an observation history, and for groups whose gateway does not say
  which member is active (load balancing). Switches between two observation rounds are not seen.
- **Parameters:** `count` (2 to 1000), `hours` (1 to 720).
- **Fix:** check the first line and the group's monitor; raise the parameters if it is
  expected.

## `wan.failover-same-path`

- **Severity:** warning
- **Checks:** two members of a failover group on different tiers that use the same port of the
  gateway or the same public next hop: one cable, modem or provider failure takes both down.
- **Stays quiet** for private, shared (carrier-grade NAT) and link-local next hops (modems
  often share such an address), for load balancing groups, and where the port and the next
  hop are not known.
- **Fix:** connect the backup through another port, modem and, if possible, provider or
  technology.

## `wan.monitor-missing`

- **Severity:** warning
- **Checks:** a member of a group that has no monitor address while another member of the same
  group has one: its failure is never noticed, so the group does not switch.
- **Stays quiet** when no member has a monitor (the gateway may not report it) and for groups with one member.
- **Fix:** let the gateway ping an address on the internet through that line.

## `wan.degraded`

- **Severity:** warning
- **Checks:** an uplink (or a group member without an uplink) that the gateway's monitor calls
  degraded, or whose packet loss or latency reaches the parameters `loss_pct` (5 % by default)
  and `latency_ms` (300 ms by default; set per site or device in the rule's scopes).
- **Stays quiet** for lines that are down (`wan.down` reports those) and when the gateway
  reports neither a state nor figures. OpenWrt (mwan3), OPNsense and Omada report latency and
  loss; UniFi and MikroTik only the state.
- **Fix:** check the line, modem and signal; raise the parameters if the line is always like that.

## `ddns.mismatch`

- **Severity:** warning
- **Checks:** an enabled dynamic DNS client whose announced IPv4 address differs from the
  public IPv4 address of its internet connection.
- **Stays quiet** when the address announced is not known, when the line is down or has no
  public address of its own (carrier-grade NAT, double NAT), and for IPv6.
- **Name resolution (optional, #450):** with `ddns.resolve: true` in the configuration, Signalbox
  resolves the host name itself and compares what the name answers today with the connection's
  address, also when the device does not say what it announced. Off by default: it sends a DNS
  query for each name from the host Signalbox runs on, to the resolver that host uses.
- **Fix:** run an update and check the client uses this connection.

## `ddns.update-failed`

- **Severity:** warning
- **Checks:** an enabled dynamic DNS client whose last update failed.
- **Fix:** check the account, password or token and the provider's status.

## `ddns.private-address`

- **Severity:** warning
- **Checks:** an enabled dynamic DNS client that announces a private, shared (carrier-grade
  NAT), loopback or link-local address, or, where the gateway does not say what it announced,
  whose internet connection has a shared address.
- **Stays quiet** when neither address is known, when the client is off or the line is down.
- **Fix:** announce the public address of the connection; behind carrier-grade NAT, ask the
  provider for a public address or use a VPN that connects outwards.

## `ddns.plain-http`

- **Severity:** warning
- **Checks:** an enabled dynamic DNS client that sends its updates over plain HTTP (FRITZ!Box
  and OpenWrt say it: the scheme of the update address, or `use_https`).
- **Stays quiet** when the gateway does not say (OPNsense, MikroTik), and for clients that are
  off. The update address itself is never read beyond its scheme.
- **Fix:** turn on HTTPS and change the password or token.

## `ddns.vpn-endpoint`

- **Severity:** warning
- **Checks:** a VPN peer whose endpoint is the name of a dynamic DNS client that is turned off
  or whose last update failed.
- **Stays quiet** when no client of a known device carries that name (it may be kept by
  another device that Signalbox does not read) and for peers that are off.
- **Fix:** turn the client on and fix its updates.

## `ddns.stale`

- **Severity:** info
- **Checks:** an enabled dynamic DNS client whose last update is older than the parameter
  `days` (30 by default; set per site or device in the rule's scopes).
- **Stays quiet** when the gateway does not say when it last updated (OPNsense, FRITZ!Box,
  MikroTik) and without the observation clock.
- **Fix:** start an update and check that the client still runs.
