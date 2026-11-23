# 0008. VPN tunnels and site links

Date: 2026-11-22 · Status: accepted

## Context

Two sites connected by a site-to-site WireGuard tunnel (#239: an OPNsense firewall at one
site, a Raspberry Pi doing the gateway's job at the other) showed up as two unrelated sites.
Nothing in the model could say that a device has a tunnel, who is at its other end, whether
the tunnel is alive, or which networks it carries. A tunnel is not a cable: its ends are not
ports with MAC addresses or LLDP, and the other end may be a site Signalbox does not manage.
WireGuard keys make it worse: the configuration of a tunnel holds a private key and often a
pre-shared key, and several device APIs return them next to the public data.

## Decision

- **A tunnel is an object of its device** (`Tunnel`, `<device>/tunnel/<interface>`): kind
  (`wireguard`), interface name, description, port, up, listen port, its own public key,
  addresses, MTU and its peers. A **peer** (`TunnelPeer`) is a value on the tunnel: public key,
  name, endpoint (host and port), allowed IPs, last handshake, transfer counters, keepalive,
  whether a pre-shared key is set, enabled. Tunnels are read with a new capability `vpn`, which
  needs **adapter API 1.3**: a missing privilege becomes a read error of that capability alone.
- **No secrets.** The model has no field for a private or pre-shared key. The contract checks
  (`signalbox.testing.secret_problems`) refuse a `vendor_extra` field named like a private or
  pre-shared key and any WireGuard-shaped key in `vendor_extra` that is not a public key of the
  snapshot. Recordings replace every WireGuard key by a placeholder key (the same for the same
  key, so the two ends of a recorded tunnel still match). Integrations read the running state
  where it leaves the keys out (OPNsense: `wireguard/service/show`, not the configuration
  grids) and accept that a disabled tunnel is then not seen.
- **Site links come from the keys.** Two read tunnels whose peers name each other's public
  keys are the two ends of one link (`Network.tunnel_end`): `topology.tunnel_links` yields a
  `Link` of kind `vpn`, origin `tunnel`, whose ends are the tunnel ids, not ports. It works
  within a site and across sites. A peer that names a key no read tunnel has, or a tunnel that
  does not name us back, gives no link.
- **An unmanaged remote site** is a site peer whose other end is not read
  (`Network.remote_sites`). A site peer routes networks of its own: allowed IPs that are more than one
  address and lie outside the tunnel's own address networks (`Tunnel.remote_networks`; a device
  may report its tunnel address as /128, so single addresses never count); a peer with only its tunnel address
  is a client (a phone, a laptop), not a site. The topology view shows a remote site as a box
  of its own with those networks; it is not a `Site`, has no devices and no id in the
  inventory.
- **Endpoints are household data**, like an uplink's public address: shown behind a click,
  never exported.

## Consequences

- One reading of one end is enough to see that a site is connected somewhere, and which
  networks lie behind the tunnel; reading both ends turns that into a link between two known
  sites with both ends' handshakes.
- Link rules keep working on ports: they look ports up and skip ends that are none, so a `vpn`
  link raises no cable or VLAN finding (tested with every built-in rule).
- Every integration that can see WireGuard fills the same objects: OPNsense now; OpenWrt, MikroTik
  and the generic Linux gateway (#240) next (docs/ADAPTERS.md lists the fields). IPsec and
  OpenVPN (#153) get further `TunnelKind` values with the same peers, keyed by their own
  identities instead of public keys.
- Checks on tunnels (handshake age, overlapping or unrouted allowed IPs, keepalive behind NAT,
  ends that disagree) build on `tunnel_end`, `tunnel_with_key`, `remote_networks` and the
  handshake time; they are not part of this decision.
- Deploying a tunnel from the desired state (#152) needs the private keys after all: they will
  be generated and kept in the vault as secrets, never in the observed model.
