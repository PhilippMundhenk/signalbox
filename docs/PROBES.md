# Foreign DHCP servers and routers

A second DHCP server on a network (a forgotten travel router, the provider's box in router
mode, an access point left in router mode) hands out the wrong gateway and DNS servers: some
clients lose the internet, others bypass the firewall. No device configuration shows it.
Signalbox finds such servers two ways (#184, #61); decision and details:
[ADR 0015](adr/0015-foreign-dhcp-servers-and-routers.md).

The segments page lists every DHCP server and IPv6 router seen answering, *known* (a device
Signalbox reads) or *foreign*; foreign ones are findings (`dhcp.foreign-server`,
`ra.foreign-router`, [rules/foreign.md](rules/foreign.md)), each acknowledgeable.

## Without a probe: what the devices report

Always on, nothing is sent:

- **MikroTik**: the built-in rogue DHCP detector. Add an alert per network, listing your real
  server's MAC as valid: `/ip dhcp-server alert add interface=bridge valid-server=<MAC>`.
  RouterOS then lists the MACs of other servers it saw in `unknown-server`, and Signalbox
  reads them.
- **A device that gets its own address by DHCP** (a MikroTik switch or access point with a
  DHCP client on its LAN): the server it got the lease from. Its provider's server on the WAN
  is not judged.

Other integrations report no answering servers (OpenWrt, OPNsense, Fritz!Box, Omada, the
switches: no rogue-server detector in their APIs that Signalbox reads).

## The probe: asking each network who answers

Off by default. In `signalbox.yaml` (or with `SIGNALBOX_PROBES_ENABLED=true`):

```yaml
probes:
  enabled: true
  interval_hours: 0          # 0: only when you press "Probe now"; 24: once a day
  dhcp: true                 # DHCPDISCOVER, needs UDP port 68
  router_solicitation: true  # IPv6 router solicitation, needs CAP_NET_RAW
  interfaces: []             # only these host interfaces; empty: all on known networks
  wait_seconds: 3
  min_gap_seconds: 300
```

Then press **Probe now** on the segments page. On each interface of Signalbox's host that is
up and has an address in a network Signalbox knows (a subnet of a device it reads), it sends:

- **one DHCPDISCOVER** from a random, locally administered client MAC (`x2:…`) with the
  broadcast flag, and listens `wait_seconds` for OFFERs. It never sends a REQUEST, so no server
  hands out a lease; a server only holds the offered address back for its offer timeout (a few
  seconds to a minute). Each OFFER gives the server's identifier, the gateway, DNS servers,
  domain and the relay it came through. The server's MAC comes from the host's ARP table if it
  is there (nothing is sent for it), else from a client of a device Signalbox reads with that
  address.
- **one IPv6 router solicitation** to ff02::2 and listens for router advertisements: the
  router's link-local address and MAC, its router lifetime, prefixes, routes and DNS servers.

That is all: no other packets, one probe per interface per run, *Probe now* refused within
`min_gap_seconds` of the last one.

### What it needs

**Only the networks Signalbox's host is attached to can be probed.** With Docker's default
bridge network the container sees only Docker's own network: nothing is probed (the interface is
not on a known network). You need:

1. **Host networking** (`network_mode: host`), so the container uses the host's interfaces; to
   probe further VLANs give the host a VLAN interface on each (for example `eth0.20`), or run
   Signalbox on a host in that network.
2. **UDP port 68** (the DHCP client port; OFFERs are broadcast to it). Ports below 1024 need
   `CAP_NET_BIND_SERVICE`. The container runs as a non-root user, for which Docker's `cap_add`
   does not take effect; choose one:
   - on the host, allow unprivileged processes from port 67 on:
     `sysctl -w net.ipv4.ip_unprivileged_port_start=67` (persist it in `/etc/sysctl.d/`). With
     host networking this is the host's setting and lets every local user bind ports 67–1023;
   - or run the container as root with only the needed capabilities:
     `user: "0:0"`, `cap_drop: [ALL]`, `cap_add: [NET_BIND_SERVICE, NET_RAW]` *(not tested in
     CI, #21)*.

   Signalbox binds with `SO_REUSEADDR` and chooses the interface per packet with
   `IP_PKTINFO`; no raw socket and no `SO_BINDTODEVICE`. If a DHCP client on the host holds
   port 68 the leg reports that.
3. **`CAP_NET_RAW` for router solicitations only**: ICMPv6 other than ping needs a raw socket.
   Without it the IPv6 leg reports "router solicitations need a raw ICMPv6 socket" and the DHCP
   leg still runs; set `router_solicitation: false` to skip it. Nothing is installed in the
   container.

Example (`docker-compose.yml`):

```yaml
services:
  signalbox:
    image: ghcr.io/philippmundhenk/signalbox:latest
    network_mode: host
    environment:
      SIGNALBOX_PROBES_ENABLED: "true"
      SIGNALBOX_PROBES_ROUTER_SOLICITATION: "false"   # no CAP_NET_RAW
```

and on the host `sysctl -w net.ipv4.ip_unprivileged_port_start=67`.

## What is kept

The latest answer per server and network, in Signalbox's database (not in the device
snapshots), with when it was first and last seen; an answer the same interface did not hear in
the next run is forgotten, everything after `history.days`. *DELETE /api/probes* forgets them
all. While `probes.enabled` is off the stored answers are not used. Offers can contain
third-party addresses (a provider's DNS): they are shown in the UI and the findings, and no
MQTT entity of their own is published.

## Checks

- `dhcp.foreign-server` (error): a DHCP server that is no device Signalbox reads, no known
  relay and not the server a known relay forwards to.
- `ra.foreign-router` (error): an unknown router that advertises itself as a default router or
  a prefix for addresses. Routers that only announce routes (lifetime 0: Thread border routers
  such as smart speakers) are listed but not reported.

The finding says where the server's MAC is (a port of a switch or access point Signalbox reads,
from MAC tables and client lists) and what to do: turn off that device's DHCP server or put it
into bridge / access point mode.
