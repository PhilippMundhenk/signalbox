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
          - {mac: "02:00:00:00:00:10", address: 192.0.2.10, hostname: printer}
      - vlan: 20
        name: IoT
        gateway: {device: gateway, address: 198.51.100.1/24}
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
    ports:
      - {device: ap-1, port: lan1, untagged: native, tagged: [20]}
```

Every field except the identifying ones (`vlan`, `ssid`, `device` + `port`) is optional; only
what is written is compared.

## Drift findings

| Rule | Compares |
| --- | --- |
| `drift.segment` | segment exists, name, router address, DHCP on/off, pool, DNS servers, lease time, reservations |
| `drift.wlan` | SSID present on each access point, security, PMF, VLAN, hidden, on/off, 802.11r/k/v, passphrase (by fingerprint against the stored secret) |
| `drift.port` | untagged and tagged VLANs of each declared port |

A device that was not read gives an "incomplete" finding instead. An unreadable desired-state
file gives the error finding `desired.invalid` with the reason.

## Secrets

Wi-Fi passphrases are not written into the YAML. Store them under *Desired state*, *Secrets*
(encrypted with the same key as the device credentials); the SSID names the secret. Signalbox
compares a passphrase only through its fingerprint and never shows a stored value again.
