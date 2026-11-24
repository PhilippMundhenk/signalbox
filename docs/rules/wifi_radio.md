<!-- rules of src/signalbox/rules/wifi_radio.py; part of the rules documentation (docs/RULES.md lists all) -->

# Wi-Fi radio state

These rules use what a radio reports about itself (#172): what it supports and its state at
the last read (utilisation, radar, standard). Radios that do not report a value are skipped,
so on devices without that data the rules stay quiet. Disabled radios are skipped.

## `wifi.channel-busy`

- **Severity:** info from 60 % channel utilisation, warning from 80 %
- **Checks:** the share of time the radio's channel was busy at the last read (its own
  clients, neighbouring networks and other radio sources). Where the radio also reports the
  share used by others (neighbours and interference), the message names it. One read is a
  snapshot: a short peak can trigger it; a channel that is busy at every read needs action.
- **Fix:** when others use most of the air time (at least half of the busy time): move to a
  less busy channel or turn on automatic channel selection; if automatic selection already
  picked the channel, the band is crowded: use a narrower channel or move clients to another
  band. Otherwise: spread the clients over more access points or bands, or move to a less busy
  channel.

## `wifi.radar-hit`

- **Severity:** info
- **Checks:** a 5 GHz radio reports radar detected within the last 24 hours, or that it left
  its channel because of radar (DFS state *radar detected*). The access point then may not use
  the channel for half an hour and its clients lose the network for a moment. Without a reading
  time (desired or predicted state) only the DFS state counts.
- **Fix:** if it repeats, use a channel outside 52-144: the ones the radio supports where it
  reports its channels, else 36-48 or 149-165.

## `wifi.legacy-standard`

- **Severity:** warning for 802.11a, b and g; info for newer standards
- **Checks:** the standard a radio is set to (the newest one it may use) is older than the
  newest standard it supports, counted up to 802.11ax (Wi-Fi 6): a radio set to 802.11ax that
  supports 802.11be (Wi-Fi 7) is not reported, as many clients cannot use Wi-Fi 7 yet. 802.11a
  and g count as one generation.
- **Fix:** set the radio's mode to the newest standard it supports (up to 802.11ax); older
  clients keep working.
