<!-- rules of src/signalbox/rules/wifi_security.py; part of the rules documentation (docs/RULES.md lists all) -->

# Wi-Fi security

These rules use the security details of a Wi-Fi network (ciphers, WPS, SAE, passphrase digest,
radio capabilities). A detail a device did not report is never guessed: the rule stays quiet.
Disabled SSIDs are skipped. See also `wifi.6ghz-security` and `wifi.pmf` under *Wi-Fi hygiene*.

## `wifi.weak-security`

- **Severity:** error for WEP, WPA (version 1), TKIP or WEP as the only cipher and an open
  network that is not a guest network; warning for an open guest network, WPA/WPA2 mixed mode,
  WPA Enterprise (version 1), and TKIP offered next to AES or used as the broadcast cipher.
- **Checks:** per SSID and access point. A guest network is one whose purpose (own or of its
  network) is guest. Enhanced Open (OWE) is fine.
- **Fix:** use WPA2/WPA3 with AES (CCMP) only, or OWE for an open guest network.

## `wifi.wpa3-available`

- **Severity:** info
- **Checks:** an SSID with WPA2-PSK only, on a radio that reports WPA3 or WPA2/WPA3 among its
  supported security modes. Quiet when the radio did not report them.
- **Fix:** switch to WPA2/WPA3 transition mode (protected management frames optional).

## `wifi.passphrase-reuse`

- **Severity:** warning
- **Checks:** different SSIDs of one site with the same passphrase, compared by a keyed digest
  that is never shown. Reported when one of them is a guest network, or when they put clients
  into different networks. The same SSID on several radios or access points, and SSIDs of one
  network (one SSID per band), are not reported.
- **Fix:** give the guest network (or each network) its own passphrase.

## `wifi.wps`

- **Severity:** warning for the PIN method, info for the push button, NFC or an unknown method
- **Checks:** WPS is enabled on an SSID.
- **Fix:** turn WPS off; join devices with the passphrase or a QR code.

## `wifi.6ghz-h2e`

- **Severity:** error
- **Checks:** a WPA3-only SSID on a 6 GHz radio whose SAE password element is only
  hunting-and-pecking. Quiet when the method is not reported or both are allowed.
- **Fix:** set the SAE password element to hash-to-element (H2E).
