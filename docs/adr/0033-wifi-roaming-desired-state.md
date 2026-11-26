# 0033. Wi-Fi roaming in the desired state: 802.11r details and the minimum signal

Date: 2026-11-26 · Status: accepted

## Context

The roaming settings of an SSID are read since #168 and #469: `roaming_80211r/k/v`, the
802.11r details (`ft`: mobility domain, over the distribution system, key holder) and the
weakest signal a client may have (`min_rssi_dbm`, and `assoc_rssi_dbm` for the association
limit of OpenWrt's hostapd). The desired state already declares `roaming: {r, k, v}` per SSID,
and OpenWrt and MikroTik write these switches. #489 asks for the rest of the write side: the
mobility domain, fast transition over the DS and the minimum signal, through the existing
transaction of [DESIRED.md](../DESIRED.md) and [DESIGN.md](../DESIGN.md#changing-configuration),
as [ADR 0032](0032-gateway-group-desired-state.md) did for gateway groups.

What makes these fields different from the other SSID fields:

- 802.11r only works between access points that share the SSID **and** the mobility domain.
  Two access points with different domains do not break the network, but clients cannot fast
  roam between them, and a client that tries over the DS can drop. The domain must therefore be
  one value per SSID across all its access points, whatever integration each one uses.
- The defaults differ: OpenWrt derives the domain from the MD5 sum of the SSID when
  `mobility_domain` is not set, RouterOS has its own default, and a controller (Omada) picks
  one for all its access points. Turning 802.11r on without naming a domain can therefore give
  a site two domains.
- The minimum signal has no single write target: OpenWrt rejects weak associations through
  hostapd's `rssi_reject_assoc_rssi` (read as `assoc_rssi_dbm`), RouterOS refuses clients
  outside the `signal-range` of an access-list entry, Omada has an `rssiSetting` per SSID that
  is a guess until a real controller confirms it (#21).

## Decision

- **Syntax** (docs/DESIRED.md, `wlans:` of a site): `roaming` gains `mobility_domain` (four hex
  digits, `a1b2`) and `over_ds` (true or false) next to `r`, `k` and `v`; the SSID gains
  `min_rssi_dbm` (-120 to -1, or `off` for no limit). Only what is written is compared and
  changed, like every other field. Declaring `mobility_domain` or `over_ds` with `r: false` is
  an error of the file (the details mean nothing without 802.11r). The key holder and the
  reassociation deadline stay read-only.
- **One mobility domain per SSID.** The declared domain applies to every access point of the
  SSID. When a plan leaves 802.11r on (or turns it on) for an SSID on more than one access
  point and no domain is declared, the planner takes each access point's reported domain; if
  one does not report it (802.11r off so far, or the integration does not say) or two differ,
  the plan is refused with the hint to declare `mobility_domain`. `drift.wlan` reports
  different domains of one SSID even without a declaration.
- **Minimum signal** is compared against what the device reports, `min_rssi_dbm`, or on
  OpenWrt `assoc_rssi_dbm` (a client below it cannot associate; already associated clients are
  not kicked, which the integration page says). `off` means no limit.
- **Safety**: nothing changes the way other desired-state writes do not: a deployment is
  started explicitly, the plan is approved per device, the device needs "Changes allowed", and
  each device goes plan, backup, apply, verify, then commit or roll back (the devices already
  changed are rolled back when a later one fails). Only SSIDs declared in the file are touched.
  The roaming fields never change security, PMF or the passphrase: a writer that would need
  that to turn on 802.11r refuses with the reason instead. The verification re-reads the SSID
  and compares the new fields too.
- **Writers** (each documented in the integration's page):
  - **OpenWrt** (wireless UCI, inside the existing `uci apply` with its confirm timer):
    `ieee80211r`, `mobility_domain`, `ft_over_ds` of the `wifi-iface`; the minimum signal is
    `rssi_reject_assoc_rssi` (`off` deletes the option). The option is understood by netifd's
    hostapd script since OpenWrt 22.03 (hostapd 2.10); on an older release the plan is refused
    with that reason, and the other fields are still written.
  - **MikroTik** (RouterOS 7 `wifi` package, REST): `security.ft`,
    `security.ft-mobility-domain` (written as the number RouterOS shows) and
    `security.ft-over-ds` of the interface. The minimum signal lives in the access list, which
    also holds the owner's MAC rules, so a plan that changes it is refused for now (follow-up).
  - **Omada** keeps refusing a plan that changes 802.11r or the new fields: `enable11r` is
    read, but the write body and the `rssiSetting` fields are not confirmed on a controller
    (#21); they stay a leftover of #489.
  - Other integrations refuse a plan with these fields, as they refuse other SSID changes.

## Consequences

- An SSID has one mobility domain on every access point once a deployment wrote it, and a plan
  that would split it is refused before anything is written.
- Turning 802.11r on for an SSID on several access points needs one extra line in the file (the
  domain) unless they already agree; this is deliberate, a guessed default would be the most
  likely cause of a split.
- An undo of a deployment writes back the old values that were reported; a minimum signal that
  was not reported (`None`) is left as it is, restoring the backup puts back the exact
  configuration.
- The OpenWrt release limit for `rssi_reject_assoc_rssi` and the RouterOS spelling of
  `ft-mobility-domain` in a write are guesses until a real device confirms them (#21).
