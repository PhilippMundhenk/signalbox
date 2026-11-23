<!-- rules of src/signalbox/rules/vpn.py; part of the rules documentation (docs/RULES.md lists all) -->

# VPN tunnels

These rules read the WireGuard tunnels and peers that integrations report (OPNsense, OpenWrt,
MikroTik; [ADR 0011](../adr/0011-vpn-tunnels-and-site-links.md)). They stay quiet where a
device did not report what a rule needs. The findings name the tunnel and the peer, never its
public address (endpoints are household data). "Now" is the time the device was read.

## `vpn.handshake-stale`

- **Severity:** warning for a peer with a persistent keepalive; info for a peer that only has
  an endpoint
- **Checks:** a peer that should be connected (a persistent keepalive is set, or it has an
  endpoint this device connects to) whose last handshake is older than five minutes, or that
  never completed one since the tunnel came up (when the device reports the transfer counters).
  With a keepalive WireGuard handshakes about every two minutes; without one an idle tunnel
  is quiet by design, which is why that case is only info.
- **Stays quiet** for peers that connect to this device (no endpoint, no keepalive: phones and
  laptops), disabled peers, a tunnel that is down or disabled, a device that did not report
  the running state (no handshake and no counters) and a handshake in the future (clock skew).
- **Fix:** check that the other end runs and is reachable (public address or name, port,
  firewall) and that both ends have the other's public key.

## `vpn.allowed-ips-overlap`

- **Severity:** warning
- **Checks:** two enabled peers of one tunnel that route the same network (host addresses are
  left out: the tunnel addresses of peers), and a network a peer routes that overlaps a
  network of the site the device belongs to (a subnet of any device of that site).
- **Stays quiet** when one network lies inside another on different peers (the more specific
  route wins; that is how an exit peer next to site peers works), for a full tunnel
  (`0.0.0.0/0`, `::/0`), for the tunnel's own transit addresses, and for networks of other sites.
- **Fix:** give each peer its own networks; use different address ranges at the two ends of a
  site link (two sites with the same network cannot route to each other).

## `vpn.allowed-ips-unrouted`

- **Severity:** warning
- **Checks:** a network in a peer's allowed IPs (not a host address, not the tunnel's own
  network) that the device's configuration does not route into the tunnel. Only for integrations
  that read routes: OpenWrt (static `route`/`route6` sections of the interface and peers with
  *route allowed IPs*). OPNsense and MikroTik do not report routes yet, so they are not checked.
- **Stays quiet** when the routes are not known, for a tunnel that is down and for disabled
  peers. A route added by a script or a routing daemon is not seen: acknowledge the finding then.
- **Fix:** let the device add the routes of the allowed IPs, or add a static route for the
  network through the tunnel interface.

## `vpn.keepalive-behind-nat`

- **Severity:** warning
- **Checks:** a tunnel on a device whose internet connections are all behind NAT (private or
  carrier-grade NAT address, see `wan.cgnat`) and that has an endpoint for a peer but a
  persistent keepalive of 0. The NAT entry of an idle tunnel expires, and the other end can no
  longer reach this one.
- **Stays quiet** when the device has no uplinks reported, when any connected uplink has a
  public IPv4 address or an unknown class, when the keepalive is not known, and for peers
  without an endpoint (they connect to this device; a keepalive here would not help).
- **Fix:** set the persistent keepalive of the peer to 25 seconds.

## `vpn.ends-disagree`

- **Severity:** warning
- **Checks:** for a peer whose public key belongs to another read tunnel: that tunnel does not
  list this one as an enabled peer (the link is one-way and cannot work), or this tunnel routes
  a network to it that does not overlap any network of the site at the other end.
- **Stays quiet** when the other end is not read (a remote site Signalbox does not manage), when
  this tunnel's own public key is not known, when the other site's networks are not known, for
  full tunnels and for disabled tunnels and peers. The networks the other end routes back are
  checked when that tunnel is evaluated.
- **Fix:** add this tunnel's public key as a peer on the other end, or remove the peer here;
  correct the allowed IPs to the networks that really lie behind the other end.
