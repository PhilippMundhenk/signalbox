# 0034. WireGuard tunnels in the desired state: keys stay on the devices

Date: 2026-11-26 · Status: accepted

## Context

WireGuard interfaces and their peers are read since #152 and #261 (`Tunnel`, `TunnelPeer`:
OpenWrt UCI and `luci.wireguard`, MikroTik `/interface/wireguard`, OPNsense, Linux), and the
`vpn.*` checks compare the two ends of a site link. #152 also asks to set up a site-to-site
tunnel between two devices Signalbox manages, through the existing transaction of
[DESIRED.md](../DESIRED.md) and [DESIGN.md](../DESIGN.md#changing-configuration): explicit start,
plan, approval per device, *Changes allowed*, lock and re-read, backup, apply, verify, confirm or
roll back, as [ADR 0032](0032-gateway-group-desired-state.md) and
[ADR 0033](0033-wifi-roaming-desired-state.md) did for gateway groups and Wi-Fi roaming.

This is the most sensitive write so far:

- A tunnel is two halves on two devices, and each half needs a key of the other: its peer is
  the other end's **public** key, which only exists once the other end has a key pair.
- Whoever holds a private key can impersonate the site. Signalbox keeps plans, change records,
  backups, logs and API answers; none of them may ever hold a private or pre-shared key, and
  the readers already drop both the moment a device answers (#152).
- A tunnel can carry Signalbox's own way to a remote device: a wrong allowed IP, a removed peer
  or a changed port can cut Signalbox off from the other site, with nobody there to fix it.
- The existing OpenWrt backup is the raw `uci get network`, which holds the `private_key` of
  every WireGuard interface, and the RouterOS backup keeps an `/export` text.

## Decision

- **Syntax** (docs/DESIRED.md, `tunnels:` of a site): one entry per tunnel with `name` (the
  tunnel's key, `tunnel/<name>`), optionally `mtu`, and exactly two `ends`. An end has `device`
  (any managed device, also one of another site), `interface` (the device's interface name,
  `wg_office`), `listen_port`, `addresses` (the end's tunnel addresses with prefix),
  `endpoint` (how the other end reaches this one: a host name or address, optionally `:port`;
  omitted for an end behind NAT that only connects out), `networks` (the networks behind this
  end), `keepalive` (seconds this end sends keepalives to the other; for an end behind NAT) and
  `adopt`. Each end's peer is derived, not declared: the other end's public key, its endpoint
  and listen port, and as allowed IPs the other end's tunnel addresses (as single addresses)
  plus its `networks`. A tunnel name, and one interface per device, may be declared once; the
  two ends must be different devices. Only what is written is compared, like every other field.
- **Keys never pass through Signalbox.** There is no field for a private or pre-shared key in
  the desired state, the change values, the model or the API, and nothing reads one:
  - A new end's key pair is generated **on the device**. RouterOS generates it when
    `/interface/wireguard` is added without `private-key`. On OpenWrt a small helper script
    that the write setup installs (`/usr/libexec/signalbox-wg-key`, run through rpcd
    `file exec`, only for interfaces Signalbox created) runs `wg genkey` into the interface's
    `private_key` with its own UCI save directory and prints nothing; `luci.wireguard
    generateKeyPair` is never called, as it returns the private key to the caller. Without the
    helper, creating a tunnel on OpenWrt is refused with the reason; changing an adopted one
    still works.
  - Only public keys travel: the readers report each end's public key after the interface
    exists, and the planner puts that key into the other end's peer.
  - **Pre-shared keys stay out.** A PSK would have to be the same on both ends, and Signalbox
    cannot carry it from one to the other without seeing it. Signalbox therefore never sets,
    changes or removes a pre-shared key; an adopted peer keeps the one it has (the readers only
    report that one is set). A PSK for a tunnel Signalbox created is set by the owner on both
    devices; doing it without Signalbox seeing it is a leftover of #152.
  - Backups and restores leave keys out: the OpenWrt backup drops `private_key` and
    `preshared_key` like the readers do, and a restore neither sets nor deletes them; the
    RouterOS backup drops `private-key` and `preshared-key` from the rows and from the export
    text. Restoring a backup that brings back a removed tunnel therefore gives it a new key pair
    (RouterOS) or none (OpenWrt), and its peers need the next deployment.
  - The tests seed the simulators with keys marked `do-not-leak` and check that no plan,
    change record, backup, log line or API answer contains them.
- **Two steps for a new tunnel.** A plan is fully known when it is approved (the vendor calls
  are prepared before anything is written), and the public key of an end that does not exist
  yet is not. So the first deployment creates the missing interfaces (and the peers whose other
  end already has a key), the next observation reads the new public keys, and the next plan adds
  the remaining peers; the plan names the peers that wait for a key (`pending`), and
  `drift.tunnel` shows them until then. Where both ends exist (adopted, or created earlier), one
  deployment sets both peers.
- **Ownership**: Signalbox changes only tunnels and peers it created, tagged on the device
  (OpenWrt: option `signalbox` with the key on the interface and the peer section; RouterOS:
  the comment `signalbox:<key>`), or ends whose entry says `adopt: true`. On an adopted
  interface Signalbox writes only the declared fields and the peer of the other end (found by
  its tag, else by the other end's public key); every other peer (road warriors, other sites)
  is left as it is. Only what Signalbox creates is tagged; an adopted interface or peer stays
  the device's own (found by its name or the other end's public key), so it is never removed
  when the tunnel is no longer declared. A declared end on an interface that exists but is neither tagged nor
  adopted refuses the plan with that hint. A tagged tunnel or peer that is no longer declared
  anywhere in the desired state is removed, like firewall rules Signalbox created.
- **Change kinds** `tunnel` (key `tunnel/<name>`: interface name, listen port, addresses, MTU)
  and `tunnel-peer` (key `peer/<name>`: public key, endpoint, allowed IPs, keepalive), applied
  after the gateway groups; peers after their interface, removals reversed. The verification
  re-reads the tunnel and compares the declared fields; the endpoint of a peer is compared only
  where it is declared, as a device reports the address a peer was last seen at for one without.
- **Lockout protection** reuses the firewall deploys' check (#295): `Plan.lockouts`, and the
  approval needs the explicit `allow_lockout` override. A tunnel change is listed there when a
  configured device's management address (or Signalbox's own address) lies in what the tunnel
  carries, before or after: its tunnel addresses or the allowed IPs of its peers, and the change
  changes or removes the interface or a peer (a new peer whose allowed IPs take the way to a
  managed device away from another path counts too).
- **Drift** (`drift.tunnel`) is the planner's comparison, so drift and plan agree; a device
  that was not read gives an incomplete finding, a peer waiting for a key is reported as such.
  *Import* writes no tunnels: which interfaces form a tunnel, and which networks are behind an
  end, is the owner's decision.
- **Writers** (each documented in the integration's page):
  - **OpenWrt** (network UCI through rpcd, inside the existing `uci apply` with its confirm
    timer): the `proto wireguard` interface (`listen_port`, `addresses`, `mtu`) and a
    `wireguard_<interface>` peer section (`public_key`, `endpoint_host`, `endpoint_port`,
    `allowed_ips`, `route_allowed_ips '1'`, `persistent_keepalive`). The key helper runs after
    the apply and before the confirmation, so a rollback also takes the key away. Reading the
    new public key needs luci-proto-wireguard (`getWgInstances`), as it does for the checks.
  - **MikroTik** (REST): `/interface/wireguard` (`listen-port`, `mtu`), `/ip/address` for the
    tunnel addresses, `/interface/wireguard/peers` (`public-key`, `endpoint-address`,
    `endpoint-port`, `allowed-address`, `persistent-keepalive`), armed by the scheduler revert of
    the firewall changes; routes for the other end's networks are a static route per network
    through the interface, tagged like the rest.
  - **OPNsense** and the other integrations refuse a plan with tunnel changes for now: the
    OPNsense WireGuard API (`/api/wireguard/server/...`, `/api/wireguard/client/...`) can
    generate a key pair on the firewall, but its answers carry the private key back, and the
    privilege and row layout are not confirmed on a device (#21); this stays a leftover.

## Consequences

- No key leaves a device through Signalbox: a stolen database, backup or log does not expose a
  tunnel.
- A new tunnel needs two deployments; the second one is a plan of public keys only and shows
  what waits.
- A tunnel that carries Signalbox's way to a remote device is only changed with an explicit
  override, as for firewall changes; the override is recorded in the change log.
- Undoing a deployment that created a tunnel removes it; undoing the removal of one creates a
  new interface with a new key pair, whose peer on the other end follows with the next plan.
- The OpenWrt helper's UCI handling, `getWgInstances` on older releases and the RouterOS
  property spellings in a write are guesses until a real device confirms them (#21).
