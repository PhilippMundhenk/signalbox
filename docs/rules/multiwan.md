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

## `ddns.mismatch`

- **Severity:** warning
- **Checks:** an enabled dynamic DNS client whose announced IPv4 address differs from the
  public IPv4 address of its internet connection.
- **Stays quiet** when the address announced is not known, when the line is down or has no
  public address of its own (carrier-grade NAT, double NAT), and for IPv6.
- **Fix:** run an update and check the client uses this connection.

## `ddns.update-failed`

- **Severity:** warning
- **Checks:** an enabled dynamic DNS client whose last update failed.
- **Fix:** check the account, password or token and the provider's status.
