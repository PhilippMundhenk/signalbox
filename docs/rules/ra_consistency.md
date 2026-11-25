<!-- rules of src/signalbox/rules/ra_consistency.py; part of the rules documentation (docs/RULES.md lists all) -->

# IPv6 router advertisements and DHCPv6

This check compares the router advertisement (RA) settings of the routers with the DHCPv6
servers of each network (#72, #151). The data comes from the integrations that read them
(`Network.router_adverts`, `Network.dhcp6_servers`: OpenWrt, OPNsense, MikroTik, Linux with
radvd or dnsmasq, FRITZ!Box where it offers them). The answers of Signalbox's own probe
([PROBES.md](../PROBES.md), `probes.enabled`) complete them: a DHCPv6 server seen on the wire
counts as a server, and a known router that no integration reports settings for is compared by
the prefixes it was heard to announce. Without any device that reports RA settings the check is
silent.

## `ipv6.ra-consistent`

- **Severity:** warning
- **Checks**, per network:
  - the managed (M) or other-config (O) flag is set, but no DHCPv6 server runs on the network
    (none read, none seen by the probe, no DHCP relay);
  - a DHCPv6 server runs, but no router advertisement sets the flag clients need to ask it
    (managed for a stateful server, managed or other-config for a stateless one), or no router
    sends advertisements at all (DHCPv6 gives no default route);
  - the DNS servers in the advertisements (RDNSS) differ from the ones the DHCPv6 server hands out;
  - an RDNSS address that is no known device (or is a provider resolver) while the IPv4 DHCP
    server hands out only local resolvers: IPv6 clients bypass local filtering and names;
  - two routers advertise different prefixes (the ones with the A flag, or the router's own
    IPv6 networks) or different flags on one network.
- **Quiet when:** no device reported its RA settings for the network, a prefix list or flags
  are not known, or a DHCP relay exists.
- **Fix:** the finding says which flag, prefix or DNS server to align.
