<!-- rules of src/signalbox/rules/wifi_regulatory.py; part of the rules documentation (docs/RULES.md lists all) -->

# Wi-Fi regulatory limits

Each country allows only some Wi-Fi channels and a maximum transmit power. These rules compare
the channel, the channel width and the transmit power of a radio with the country code it is
set to (#96). Disabled radios are skipped.

**The table is a guide, not legal advice.** It is a small subset of public regulatory data
(below) and does not replace the national regulator. Rules change, many countries add
conditions, and an access point's firmware is what really decides what it may do. Do not treat a
quiet result as a permission or a finding as a legal ruling.

## `wifi.regulatory`

- **Severity:** error for a channel (or a part of a wide channel) that is not allowed, and for a
  band that does not exist in the country (6 GHz); warning for a transmit power above the limit;
  info for a missing country code
- **Checks:**
  - the channel, and every 20 MHz channel its width covers (on 2.4 GHz the secondary channel), is
    inside an allowed range of the radio's country; an example is channel 13 with country US, or
    a 40 MHz channel at 140 in the EU, whose second half (144) is above the EU limit
  - 6 GHz is only used in a country that has an allocation (not CN in this table)
  - the transmit power the radio reports is not above the table's limit for its channel (the
    lowest limit of the channels it covers); where the table knows no limit (Brazil on 6 GHz) the
    power is not checked
  - a radio without a country code is reported for information: radios then fall back to the
    most restrictive world domain, and Signalbox cannot check the channel. `wifi.country` reports
    the same gap as a warning for radios at a site.
- **Device data wins:** where a radio reports the channels it supports (#172), that list is used
  instead of the table for the channel check, as the firmware knows its regulatory database
  better than this table. The power limit always comes from the table.
- **Quiet:** disabled radios, radios without a channel, and countries that are not in the table
  (their code is not checked at all, unless the device reports its channels).
- **Fix:** set the correct country code, or use one of the allowed channels (listed), a narrower
  channel, or a lower power. For 6 GHz without an allocation: turn the radio off or correct the
  country.
- **Unit of the power:** limits are maximum EIRP, which includes the antenna gain. Devices
  report their power as the radio's output (conducted) or as EIRP, and Signalbox cannot tell
  which, so only a reported power above the limit is flagged.

## The regulatory table

The table is the module `src/signalbox/regdomains.py` and nothing else: one data structure, one
place to correct or extend it. Each domain lists, per band, frequency ranges in MHz with the
maximum EIRP in dBm and the conditions (DFS = radar detection required, indoor = indoor use
only). A channel is allowed when its whole 20 MHz span lies inside one range. The EU/ETSI group
is one entry for the EU and EEA countries; GB and CH have their own, AU and NZ are separate
entries.

| Domain | 2.4 GHz (MHz: max EIRP) | 5 GHz | 6 GHz |
| --- | --- | --- | --- |
| EU/ETSI (EU and EEA) | 2400-2483.5: 20 dBm | 5150-5250: 23 dBm, indoor<br>5250-5350: 20 dBm, DFS, indoor<br>5470-5725: 27 dBm, DFS<br>5725-5875: 14 dBm (short-range devices) | 5945-6425: 23 dBm, indoor (LPI) |
| United Kingdom (GB) | 2400-2483.5: 20 dBm | 5150-5250: 23 dBm, indoor<br>5250-5350: 20 dBm, DFS, indoor<br>5470-5730: 27 dBm, DFS<br>5725-5850: 23 dBm, indoor | 5925-6425: 24 dBm, indoor (LPI) |
| Switzerland (CH) | 2400-2483.5: 20 dBm | 5150-5250: 23 dBm, indoor<br>5250-5350: 20 dBm, DFS, indoor<br>5470-5725: 27 dBm, DFS<br>5725-5875: 14 dBm | 5945-6425: 23 dBm, indoor (LPI) |
| United States (US, FCC) | 2400-2472: 30 dBm | 5150-5250: 23 dBm<br>5250-5350: 24 dBm, DFS<br>5470-5730: 24 dBm, DFS<br>5730-5850: 30 dBm | 5925-7125: 30 dBm, indoor (LPI) |
| Canada (CA) | 2400-2483.5: 36 dBm | 5150-5250: 23 dBm, indoor<br>5250-5350: 27 dBm, DFS<br>5470-5730: 27 dBm, DFS<br>5730-5850: 36 dBm | 5925-7125: 30 dBm, indoor (LPI) |
| Japan (JP) | 2402-2482: 20 dBm<br>2474-2494: 20 dBm (channel 14, 802.11b only) | 5170-5250: 20 dBm, indoor<br>5250-5330: 20 dBm, DFS, indoor<br>5490-5730: 23 dBm, DFS | 5925-6425: 23 dBm, indoor (LPI) |
| Australia (AU) | 2400-2483.5: 36 dBm | 5150-5250: 23 dBm, indoor<br>5250-5350: 20 dBm, DFS, indoor<br>5470-5600 and 5650-5730: 27 dBm, DFS<br>5730-5850: 36 dBm | 5925-6585: 24 dBm, indoor (LPI) |
| New Zealand (NZ) | 2400-2483.5: 36 dBm | 5150-5250: 30 dBm<br>5250-5350: 27 dBm, DFS<br>5470-5730: 27 dBm, DFS<br>5725-5875: 36 dBm | 5925-6425: 24 dBm, indoor (LPI) |
| China (CN) | 2400-2483.5: 20 dBm | 5150-5250: 23 dBm, indoor<br>5250-5350: 20 dBm, DFS, indoor<br>5725-5850: 33 dBm | none |
| South Korea (KR) | 2400-2483.5: 23 dBm | 5150-5230: 23 dBm<br>5230-5250: 17 dBm<br>5250-5350: 20 dBm, DFS<br>5470-5725: 20 dBm, DFS<br>5725-5850: 23 dBm | 5925-6425: 18 dBm, indoor<br>6425-7125: 15 dBm, indoor |
| India (IN) | 2402-2482: 30 dBm | 5150-5250: 30 dBm<br>5250-5350: 24 dBm, DFS<br>5470-5725: 24 dBm, DFS<br>5725-5875: 30 dBm | 5925-6425: 24 dBm, indoor (LPI) |
| Brazil (BR) | 2400-2483.5: 30 dBm | 5150-5250: 27 dBm, indoor<br>5250-5350: 27 dBm, DFS, indoor<br>5470-5725: 27 dBm, DFS<br>5725-5850: 30 dBm | 5925-7125: limit not known, indoor (LPI) |

EU and EEA countries in the first row: AT, BE, BG, HR, CY, CZ, DK, EE, FI, FR, DE, GR, HU, IE,
IT, LV, LT, LU, MT, NL, PL, PT, RO, SK, SI, ES, SE, IS, LI, NO. Other countries are not in the
table and are not checked.

Notes:

- On 5 GHz, the DFS ranges (5250-5350 and 5470-5725 MHz, channels 52-64 and 100-144) require
  radar detection and avoidance; see `wifi.dfs` and `wifi.radar-hit`. Several countries allow
  these and the lower ranges indoors only, and the EU allows 5725-5875 MHz only at low power
  (short-range device rules).
- 6 GHz: the table assumes low-power indoor (LPI) access points. Standard-power and very-low-power
  operation (outdoors, automated frequency coordination) have other limits and are not covered.
  For the US and Canada the table uses the LPI limit (30 dBm) where the regdb lists the generic
  12 dBm client limit; for Brazil it has no limit.
- Ranges that the regdb marks NO-IR (the device may not start transmitting on its own, for
  example 5850-5895 MHz in the US) are not in the table, so those channels count as not allowed.
- The EU row follows the German entry of the regdb; a few EU countries restrict single ranges
  further.

### Sources

- Linux wireless regulatory database, `db.txt` (public, ISC licence):
  <https://git.kernel.org/pub/scm/linux/kernel/git/wens/wireless-regdb.git/tree/db.txt>, read in
  November 2026. The ranges and limits come from its entries for DE (as the EU/ETSI reference),
  GB, CH, US, CA, JP, AU, NZ, CN, KR, IN and BR; mW values are converted to dBm.
- 6 GHz LPI limits of the US and Canada: FCC 47 CFR 15.407 and ISED RSS-248 (30 dBm EIRP for
  low-power indoor access points).
- ETSI EN 301 893 (5 GHz) and EN 303 687 (6 GHz) for the EU/ETSI ranges and DFS.

This is a guide, not legal advice. Corrections are welcome as an issue or pull request that
changes `regdomains.py` and this table.
