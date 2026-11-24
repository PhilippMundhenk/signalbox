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
        roaming: {r: true}
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

## Drift findings

| Rule | Compares |
| --- | --- |
| `drift.segment` | segment exists, name, purpose against a reported one, router address, DHCP on/off, pool, DNS servers, lease time, reservations |
| `drift.wlan` | SSID present on each access point, security, PMF, VLAN, hidden, on/off, 802.11r/k/v, client isolation, purpose against a reported one, passphrase (by fingerprint against the stored secret) |
| `drift.port` | untagged and tagged VLANs of each declared port |
| `drift.firewall` | every declared zone policy (the action the device applies), rule and port forward Signalbox created (all fields), and tagged ones that are no longer declared; a reference to a zone or segment that does not resolve |

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
