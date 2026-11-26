# Desired state

The desired state says what your network *should* look like. Signalbox compares it with what the
devices report and shows every difference as a finding ("drift"). In a later version the same
file drives changes to the devices (plan, review, deploy, roll back; see [DESIGN.md](DESIGN.md)).

Edit it under *Desired state* in the web interface, or as YAML files in `<data>/desired/`
(every `*.yaml` there is read and merged). Declare only what Signalbox should manage; everything
else is left alone. *Import what the devices report* fills the editor with the current state of
a site as a starting point.

If `<data>/desired/` is a git repository (`git init`), every save from the web interface is a
commit with your change note, so the history is reviewable and can be reverted.

## Format

```yaml
sites:
  home:                         # site id (Settings, Sites)
    segments:
      - vlan: native            # the untagged LAN (VLAN 1 is the same)
        name: LAN
        gateway: {device: gateway, address: 192.0.2.1/24}
        dhcp:
          enabled: true          # on the gateway unless `device` names another one
          pool: [192.0.2.100, 192.0.2.199]
          dns: [192.0.2.1]
          lease_seconds: 43200
        reservations:
          - {mac: "00:00:5e:00:53:10", address: 192.0.2.10, hostname: printer}
      - vlan: 20
        name: IoT
        purpose: iot             # what the network is for, see below
        gateway: {device: gateway, address: 198.51.100.1/24}
      - vlan: 30
        purpose: guest
    wlans:
      - ssid: Example
        security: wpa2-wpa3      # open, owe, wpa2-psk, wpa3-sae, wpa2-wpa3, ...
        passphrase_secret: main-wifi   # name of a secret stored under Desired state, Secrets
        pmf: optional            # disabled, optional, required
        segment: native
        devices: [ap-1, ap-2]    # default: every access point of the site
        roaming: {r: true, mobility_domain: a1b2, over_ds: false}   # one domain per SSID
        min_rssi_dbm: -75        # weaker clients cannot associate; off: no limit
      - ssid: Example-IoT
        security: wpa2-psk
        passphrase_secret: iot-wifi
        segment: 20
      - ssid: Example-Guest
        security: wpa2-psk
        passphrase_secret: guest-wifi
        segment: 30
        purpose: guest           # default: the purpose of its segment
        client_isolation: true   # guests cannot reach each other
    ports:
      - {device: ap-1, port: lan1, untagged: native, tagged: [20]}
```

Every field except the identifying ones (`vlan`, `ssid`, `device` + `port`) is optional; only
what is written is compared.

`native` is the untagged network. A site with two routers in a row (a firewall behind the
internet provider's router) has two of them: on a port or an SSID, `native` is the device's own
untagged network (the one of the router it is behind); a `vlan: native` segment is the main one
(see [DESIGN.md](DESIGN.md#untagged-networks-of-several-routers)). The LAN of a further router
has its own key, `vlan: native-<router id>` (for example `native-isp`); an import writes one
entry per untagged network, and each key may appear once per site.

## Firewall

Zone policies, filter rules and port forwards of a router (#295,
[ADR 0017](adr/0017-firewall-desired-state-and-deployments.md)). Deployed on OpenWrt, OPNsense and MikroTik (tagged
objects, no rollback timer on OPNsense 26.7, a scheduler revert on MikroTik, [details](adapters/opnsense.md#firewall-changes-295),
where a rule has one destination zone or destination addresses, one port, one protocol set);
other integrations refuse a plan with firewall changes for now.

```yaml
sites:
  home:
    firewalls:
      - device: gateway              # the router whose firewall this is
        policies:                    # what applies when no rule decides
          - {from: iot, to: lan, action: reject}           # zone names of the device ...
          - {from: {segment: 30}, to: device, action: drop} # ... or the zone of a segment
          - {from: guest, to: wan, action: accept}
        rules:                       # Signalbox's own rules, checked before the device's own
          - name: iot-printer        # identifies the rule: a-z, 0-9, - and _
            from: {segment: 20}
            to: {zone: lan, network: 192.0.2.10}           # one address/prefix or a list
            protocol: tcp            # tcp, udp, icmp, esp, gre, a list, or all
            port: 631                # destination port(s): 631, 8000-8100 or a list
            action: accept           # accept, drop or reject
          - name: no-ssh-from-iot
            from: {zone: iot}
            to: device               # the router itself
            port: 22
            action: reject
        forwards:                    # port forwards from the internet
          - name: web
            protocol: tcp            # default: tcp and udp
            port: 443                # external port (or one range)
            to: {address: 192.0.2.20, port: 8443}          # port: default the external one
```

- **Zones** are the device's own (`lan`, `wan`, `iot` on OpenWrt); `{segment: <vlan>}` (or
  `native`) is the one zone that holds that segment on the device. `to: device` is traffic to
  the router itself (its web interface, SSH, DNS). A forward listens on the device's internet
  zone unless `from` names one; `family: 4` or `6` limits a rule to one IP version; `enabled:
  false` keeps a rule or forward but switches it off.
- **Without `protocol`** a rule with a port matches TCP and UDP, one without a port every
  protocol.
- **Signalbox only changes what it created.** Each rule and forward is tagged on the device
  with its name; a declared firewall owns its device's tagged rules and forwards, so one you
  delete from the desired state is removed by the next deployment. The device's own rules,
  forwards and forwardings (vendor defaults, rules made in LuCI) are never changed or removed:
  - `adopt: <name>` on a rule or forward takes over the device's object of that name: it is
    taken over as Signalbox's tagged one (that is how you *import* an existing rule). Every
    property of the object that the desired state does not model (`log`, a rate limit, a
    state type, a category ...) is kept and listed in the plan; where it cannot be kept the
    adoption is refused with the list. Never dropped silently.
  - `adopt: true` on a policy lets a deployment remove the device's own forwarding between the
    two zones for `reject`; without it the plan is refused with that hint.
  - A policy to the device or inside one zone sets that zone's own setting (OpenWrt `input`,
    `forward`). Zones are never created or removed.
- **Order**: Signalbox's rules come before the device's own ones, in the order they were
  created.
- **Lost access**: a plan with firewall changes is checked for Signalbox's own access to every
  device of the site ([CHANGES.md](CHANGES.md#firewall-changes-and-management-access)).
- *Import what the devices report* exports the zone policies the devices state explicitly and
  the rules and forwards Signalbox created, not the device's own rules.

## Logging and SNMP

Where the devices of a site send their syslog, and whether their SNMP agent runs (#327,
[ADR 0021](adr/0021-logging-and-snmp-desired-state.md)). Written on OpenWrt and MikroTik;
other integrations refuse a plan with logging changes for now. Off like every write: it needs
`deploy.enabled`, *Allow changes* on the device and the per-plan approval.

```yaml
sites:
  home:
    logging:
      syslog:                       # every device named below (or every read device) sends here
        - {address: 192.0.2.5, port: 514, transport: udp}   # port default 514; udp or tcp
      snmp: off                     # off, or v3-only (see below)
      devices: [gateway, ap-1]      # default: every device of the site whose log targets are read
      adopt: [192.0.2.9]            # the devices' own targets Signalbox may change or remove
      overrides:
        - device: ap-1              # replaces a setting for one device ([] means none)
          syslog: [{address: 198.51.100.7, transport: tcp}]
          snmp: off
```

- **Ownership**: Signalbox changes or removes only a target it created (OpenWrt: the option
  `signalbox_syslog` in the `system` section; MikroTik: an action named `signalbox<address>`
  with its logging rules) and a target of the device's own whose address is under `adopt`. A
  declared target at an address where the device has its own, different one is refused with the
  hint (`adopt`); a device's other targets are never touched. `syslog: []` removes the targets
  Signalbox created (and adopted ones); leaving `syslog` out manages nothing.
- **One target per address**; OpenWrt's logd has one slot, so there at most one target can be
  declared. `transport` is `udp` or `tcp`; syslog over TLS is read but not written.
- **`snmp: off`** switches the agent off (`snmpd` on OpenWrt, `/snmp` on MikroTik); the revert
  switches it on again. **`snmp: v3-only`** is compared (an agent that answers v1 or v2c is
  drift) but not written: creating SNMPv3 users needs secrets Signalbox does not handle; the
  plan is refused with that reason. An agent that is off satisfies both. Communities and
  passwords are never read into the model, shown, or stored.
- *Import what the devices report* exports each device's syslog targets under `overrides`
  (all of them listed under `adopt`, so they can be edited) and `snmp: off` for an agent that
  is switched off. `devices: []` keeps the site-wide settings from applying to anything until
  you write some.

## Gateway groups

Tiers, weights and monitor addresses of the members of a multi-WAN gateway group (#463,
[ADR 0032](adr/0032-gateway-group-desired-state.md)). Written on OpenWrt (mwan3,
[details](adapters/openwrt.md#what-each-change-does-in-uci)) and MikroTik (the default routes,
[details](adapters/mikrotik.md#gateway-group-463)); other integrations refuse a plan with gateway
group changes for now. Off like every write: it needs `deploy.enabled`, *Allow changes* on the
device and the per-plan approval.

```yaml
sites:
  home:
    gateway_groups:
      - device: gateway           # the router that has the group
        name: failover            # the device's name of the group (mwan3 policy, MikroTik: default)
        adopt: true               # lets a deployment change it (needed for a plan)
        members:                  # the device's names of the members, as the device page shows them
          - name: wan
            tier: 1               # 1 is the first choice, higher numbers are backups
            weight: 3             # share of the load among the members of one tier
            monitor: [192.0.2.53, 198.51.100.53]   # what the gateway pings; [] means none
          - {name: wanb, tier: 2}
```

- **Signalbox never creates or removes groups or members.** It changes the tier, weight and
  monitor of members the group has; a declared group or member the device does not have is
  reported as drift and refuses the plan.
- **Adopt**: every group is the device's own, so a plan changes it only with `adopt: true`;
  without it the plan is refused with that hint, and the drift is still shown. Groups that are
  not declared, and members that are not listed, are left as they are.
- **Tiers** are an order: they are compared and written renumbered 1, 2, ... (tiers 1 and 5 are
  the same as 1 and 2), together with the tiers of the members that are not listed. In a group
  with tiers 1, 2 and 3, `tier: 2` for the first member puts it next to the second one, and as
  tier 1 is then empty, all move up (1, 1, 2). Members on one tier share the load; several tiers
  are a failover.
- **Monitor** addresses are compared as a set. A monitor belongs to the line, so a line that is
  in several groups has one monitor for all of them; different declarations are refused.
- *Import what the devices report* exports every group with all its members, without `adopt`.

## WireGuard tunnels

A site-to-site WireGuard tunnel between two devices Signalbox manages (#152,
[ADR 0034](adr/0034-wireguard-tunnels-desired-state.md)). Written on OpenWrt
([details](adapters/openwrt.md#what-each-change-does-in-uci); a new interface needs the
[key helper](adapters/openwrt.md#wireguard-key-helper)) and MikroTik
([details](adapters/mikrotik.md#wireguard-tunnels-152)); other integrations refuse a plan with
tunnel changes.
Off like every write: it needs `deploy.enabled`, *Allow changes* on both devices and the
per-plan approval.

```yaml
sites:
  home:
    tunnels:
      - name: office              # tags what Signalbox creates on both devices
        ends:
          - device: home-gw
            interface: wg_office  # the device's interface name
            listen_port: 51820
            addresses: [203.0.113.253/30]   # this end's tunnel address(es)
            endpoint: 203.0.113.10          # how the other end reaches this one (host[:port])
            networks: [192.0.2.0/25]        # networks behind this end
          - device: office-gw
            interface: wg_home
            listen_port: 51821
            addresses: [203.0.113.254/30]
            networks: [198.51.100.0/25]
            keepalive: 25         # this end is behind NAT and keeps the way open
            # no endpoint: this end only connects out
```

- **No keys in the file, none through Signalbox.** Each device generates its own key pair when
  the interface is created; Signalbox reads only the public keys and gives each end's peer the
  other end's public key. Private keys are never read, stored, logged or shown, and backups
  leave them out. Pre-shared keys are not supported: Signalbox would have to carry the same key
  to both ends; a peer that has one keeps it.
- **Two steps for a new tunnel.** The first deployment creates the missing interfaces; once the
  devices have been read again, the next plan adds the peers with the public keys. The plan
  lists the peers that wait (`pending`), and `drift.tunnel` reports them until then. Where both
  interfaces exist, one deployment sets both peers.
- **The peer of each end is derived**: the other end's public key, its `endpoint` with its
  `listen_port` (or the port in the endpoint), and as allowed IPs the other end's tunnel
  addresses (single addresses) and its `networks`. An endpoint that is not declared is not
  compared: devices report where they last saw a peer.
- **Ownership**: Signalbox changes interfaces and peers it created (tagged with the tunnel name)
  and an interface of the device's own only when its end says `adopt: true`; on an adopted
  interface only the declared fields and the peer of the other end are written, other peers
  (phones, other sites) are left as they are. Tagged tunnels and peers that no tunnel of the
  desired state names any more are removed. Signalbox does not rename an interface.
- **Lockout protection**: a change of an interface or peer that carries the management address
  of a configured device or Signalbox's own address (tunnel addresses, allowed IPs, before or
  after) is listed under *may cut Signalbox off* and needs the explicit override, as for
  firewall changes.
- *Import what the devices report* writes no tunnels: which interfaces form a tunnel is your
  decision.

## UPnP, NAT-PMP and PCP

Whether a gateway lets clients open ports to the internet, and for whom (#513,
[ADR 0035](adr/0035-upnp-desired-state.md)). Written on OpenWrt (miniupnpd,
[details](adapters/openwrt.md#what-each-change-does-in-uci)), MikroTik
([details](adapters/mikrotik.md#upnp-513)) and the FRITZ!Box (on or off only); other integrations
refuse a plan with UPnP changes for now. Off like every write: it needs `deploy.enabled`,
*Allow changes* on the device and the per-plan approval.

```yaml
sites:
  home:
    upnp:
      - device: gateway           # the router that offers UPnP IGD, NAT-PMP or PCP
        enabled: false            # off; true turns it on (only when written here)
      - device: office-gw
        secure_mode: true         # a client may only open ports to itself
        networks: [native]        # the networks it answers in
        allow:                    # the clients that may open ports; everything else is denied
          - {network: 192.0.2.0/25, ports: 1024-65535}   # ports: default 1024-65535
```

- **Only what is written** is compared and changed; devices without an entry are never touched.
  `enabled` covers every protocol the device answers (UPnP IGD, NAT-PMP, PCP).
- **Never opened up by accident.** Turning UPnP on, secure mode off, adding a network or letting
  more clients map only happens when the entry says exactly that; the plan marks such a change
  as *widens UPnP*. Other fields keep what the device has, and a service that is off stays off
  while its secure mode, networks or rules are written.
- **`allow` is the whole list**: one rule per entry, then one that denies everything else; the
  device's other permission rules are replaced (the backup keeps them).
- **Open mappings are not removed** by Signalbox: they end with their lease, and the device may
  drop them itself when the service stops. The `upnp.*` checks keep showing the ones that are
  still open.
- A device without UPnP satisfies `enabled: false`; any other field for it refuses the plan.
  RouterOS has no secure mode and no permission rules, the FRITZ!Box only the switch: those
  fields are refused there.
- *Import what the devices report* writes `enabled` and, where reported, `secure_mode`.

## Network purposes

`purpose` says what a segment or SSID is for: `main`, `guest`, `iot`, `management`, `servers`,
`lab`, `voice`, `cameras`, `transit` or `other`. Most devices do not know it, so it is mainly
declared here; the guest and IoT checks ([rules/networks.md](rules/networks.md)) depend on it.

- A declared purpose is applied to the observed network every time Signalbox builds it (before
  the checks run and in every view), and beats what a device reports (Fritz!Box guest network,
  Omada guest network) and the guess from the name ("Guest", "IoT"). The UI marks the source:
  declared, reported, or a guess with a "?".
- An SSID's purpose applies to that SSID on its `devices` (default: every device of the site).
  An SSID without one inherits the purpose of its segment.
- A purpose is not written to devices. When a device reports a different purpose, `drift.segment`
  or `drift.wlan` reports it (info).
- *Import what the devices report* exports reported purposes, never guesses.

`client_isolation` is a device setting and compared like the others (`drift.wlan`). Where a
device does not report it the finding is incomplete. Deployments write it on OpenWrt
(`option isolate`); the Omada, MikroTik and Fritz!Box integrations refuse a plan that changes it.

### Wi-Fi roaming

`roaming` switches 802.11r (`r`), 802.11k (`k`) and 802.11v (`v`); with `r: true` it also takes
`mobility_domain` (four hex digits) and `over_ds` (fast transition over the distribution system
instead of over the air). `min_rssi_dbm` (-120 to -1, or `off`) is the weakest signal a client
may have ([ADR 0033](adr/0033-wifi-roaming-desired-state.md)).

- **One mobility domain per SSID**: the declared domain applies to all access points of the
  SSID. Without one, a plan that leaves 802.11r on for an SSID on several access points needs
  them to report the same domain; otherwise it is refused with the hint to declare it.
- These fields never change security, PMF or the passphrase.
- Written on OpenWrt (`ieee80211r`, `mobility_domain`, `ft_over_ds`, and `rssi_reject_assoc_rssi`
  from OpenWrt 22.03) and MikroTik (`security.ft`, `ft-mobility-domain`, `ft-over-ds`; a minimum
  signal is refused there for now). Omada refuses a plan that changes them.

## Drift findings

| Rule | Compares |
| --- | --- |
| `drift.segment` | segment exists, name, purpose against a reported one, router address, DHCP on/off, pool, DNS servers, lease time, reservations |
| `drift.wlan` | SSID present on each access point, security, PMF, VLAN, hidden, on/off, 802.11r/k/v, mobility domain, over-DS and minimum signal, one mobility domain per SSID, client isolation, purpose against a reported one, passphrase (by fingerprint against the stored secret) |
| `drift.port` | untagged and tagged VLANs of each declared port |
| `drift.logging` | the declared syslog targets of each device (address, port, transport, sent at all), targets Signalbox created or was told to adopt that are no longer declared, and the SNMP agent (off, or v3-only) |
| `drift.firewall` | every declared zone policy (the action the device applies), rule and port forward Signalbox created (all fields), and tagged ones that are no longer declared; a reference to a zone or segment that does not resolve |
| `drift.gateway-group` | the declared tier (as an order), weight and monitor addresses of each declared member of a declared gateway group; a group or member the device does not have |
| `drift.tunnel` | both ends of each declared tunnel: the interface (listen port, addresses, MTU) and the peer of the other end (public key, endpoint where declared, allowed IPs, keepalive); a missing interface or a peer that waits for the other end's public key |
| `drift.upnp` | the declared state of the UPnP service of each declared gateway: on or off, secure mode, the networks it answers in and the permission rules; a declaration for a device without UPnP |

A device that was not read gives an "incomplete" finding instead. An unreadable desired-state
file gives the error finding `desired.invalid` with the reason.

## Annotations and acknowledgements

Your own knowledge about objects, and findings you accept on purpose (#186,
[ADR 0007](adr/0007-annotations-and-acknowledgements.md)). They are never written to a device and
never cause drift; they are applied to the observed network every time Signalbox builds it, like
declared purposes.

```yaml
sites:
  home:
    annotations:
      - target: 02:00:00:00:00:44          # a MAC address: a client (or a foreign access point)
        label: office printer
        owner: Example Owner
        notes: fixed address set on the printer itself
        tags: [office]
        expected: {static_address: true, category: printer}
      - target: sw-attic/port/5
        purpose: lab bench, slow on purpose
        expected: {neighbour: lab-switch}
      - target: ap-garden
        expected: {may_be_unreachable: true}   # off in winter
    acknowledgements:
      - rule: wifi.pmf                      # every finding of this rule that names the target
        target: ap-garden/wlan/cafe
        reason: the old garden camera cannot do PMF
        until: 2027-06-30                   # counts as a problem again from that day
      - rule: dhcp.one-server
        finding: 0123456789abcdef           # exactly one finding (its id, see the API)
        fingerprint: 5d41402abc4b2a76       # optional: lapses when the message changes
```

- **Targets** are model ids: a device id, `<device>/port/<name>`, `<site>/segment/<vlan or
  native>`, `<device>/subnet/<name>`, other `<device>/<kind>/<name>` objects, or a MAC address
  (stored as `client/<mac>`). One annotation per target across all files.
- **Expectations** (`expected`) are typed and refused where they do not fit: clients
  `segment`, `static_address`, `category` (`computer`, `phone`, `tablet`, `iot`, `camera`,
  `printer`, `media`, `server`, `network`, `other`), `known_neighbour`; ports `neighbour`,
  `uplink`; devices `role`; devices and clients `may_be_unreachable`. Checks use them to stay
  silent where you said what is intended.
- **Acknowledged findings** are still checked and shown under *Acknowledged* on the start page,
  but they are not problems: not in the error and warning counts, not in Home Assistant's
  problem sensor, and an acknowledged error does not block a plan. `until` (a date or a time)
  ends an acknowledgement (`ack.expired` says so); `fingerprint` ends it when the finding's
  details change.
- **In the UI** the *Acknowledge* button on a finding and the notes on a device or client page
  store the same things in the database. Declared entries win per target and are read-only in
  the UI. `GET /api/annotations/export` gives the stored ones as YAML to paste here.
- Objects that no longer exist (a renamed port, a removed device, a client not seen for the
  history period) are reported by `annotations.stale`. Labels, owners and notes are personal
  data: they stay in Signalbox and are not sent to MQTT.

## Secrets

Wi-Fi passphrases are not written into the YAML. Store them under *Desired state*, *Secrets*
(encrypted with the same key as the device credentials); the SSID names the secret. Signalbox
compares a passphrase only through its fingerprint and never shows a stored value again.
