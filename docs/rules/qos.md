<!-- rules of src/signalbox/rules/qos.py; part of the rules documentation (docs/RULES.md lists all) -->

# Traffic shaping and smart queues

These checks read the shapers a gateway reports (OpenWrt sqm-scripts, OPNsense traffic shaper
pipes, MikroTik queues, UniFi Smart Queues) together with the line rates of the internet
connections (the modem's sync rate, where the device knows it). A rate or a line rate that is
not reported is never judged. The FRITZ!Box prioritisation is not available through TR-064 and
is not read.

## `qos.shaper-above-line`

- **Severity:** warning
- **Parameters:** `tolerance_pct` (default 5 %)
- **Checks:** the download or upload rate of an enabled shaper is not higher than the line rate
  of its internet connection plus the tolerance. Above the line, the line stays the bottleneck
  and the queue in front of the modem fills up: the shaper does nothing.
- **Fix:** set the shaper to about 90 to 95 % of the real line speed.

## `qos.shaper-far-below-line`

- **Severity:** info
- **Parameters:** `below_pct` (default 50 %)
- **Checks:** the rate of an enabled shaper is not below that share of the line rate. A much
  lower value is usually one that was not updated after a speed upgrade.
- **Fix:** raise the rate to about 90 to 95 % of the line speed.

## `qos.shaper-on-down-uplink`

- **Severity:** info
- **Checks:** an enabled shaper does not belong to an internet connection that is down. Such a
  shaper does nothing until the line is back and may be a leftover.
- **Fix:** bring the connection up, or disable or remove the shaper.

## `qos.no-shaper`

- **Severity:** info
- **Checks:** a connection that is up and prone to bufferbloat (LTE, PPPoE, or a modem rate
  below 1 Gbit/s: DSL, cable) has a smart queue or any enabled shaper on it. Only gateways whose
  integration reads shapers (OpenWrt, OPNsense, MikroTik, UniFi) are checked; a gateway with an
  enabled shaper that is not tied to a connection is not reported, as it may cover it.
- **Fix:** set up SQM (cake) or Smart Queues at about 90 to 95 % of the line speed.
