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
(see [DESIGN.md](DESIGN.md#untagged-networks-of-several-routers)). The provider router's LAN is
left out when the state is imported from the network and cannot be declared yet.

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

A device that was not read gives an "incomplete" finding instead. An unreadable desired-state
file gives the error finding `desired.invalid` with the reason.

## Secrets

Wi-Fi passphrases are not written into the YAML. Store them under *Desired state*, *Secrets*
(encrypted with the same key as the device credentials); the SSID names the secret. Signalbox
compares a passphrase only through its fingerprint and never shows a stored value again.
