# Troubleshooting

Every problem reading a device shows up as a finding on the start page and as the device's
status under *Devices*. *Test connection* on a device reads it at once and shows the errors.

| Status | Meaning | What to do |
| --- | --- | --- |
| `unreachable` | no answer, connection refused, or the request timed out | check the URL (scheme, host, port, `/ubus` for OpenWrt), that the device's web interface is on, and that the Signalbox host can reach it |
| `auth-failed` | the device refused the login | check user and password / API key and secret; a new key means editing the device |
| `untrusted-certificate` | the device presented a certificate that is not trusted yet, or a different one than before | compare the fingerprint shown in Signalbox with the device's certificate and trust it; if you did not change the certificate, find out why it changed before you trust it |
| `partial` | the device answered, but some parts could not be read | the finding names the part and the reason, usually a missing permission (OPNsense privilege, OpenWrt rpcd ACL entry) |

## The password of the web interface is lost

`docker compose run --rm signalbox reset-password` prints a new one; restart Signalbox. With
`SIGNALBOX_AUTH_PASSWORD` set, that value is the password and cannot be changed in the UI.

## "stored credentials cannot be decrypted"

The secret key changed: `secret.key` was lost or `SIGNALBOX_SECRET_KEY` differs from the one used
before. Restore the old key, or enter the device credentials again.

## Findings look wrong

- A device shows "could not check": it did not report what the rule needs (see the finding).
- VLAN findings through an unmanaged switch are reported as incomplete: Signalbox cannot see
  inside it. Enter the cables on the *Topology* page so the path is known.
- A rule that does not fit your network can be turned off or given another severity, see
  [CONFIGURATION.md](CONFIGURATION.md#rules).

If a finding is plainly wrong for your device, please open an issue with the device model,
firmware version and the finding text (leave out addresses and names).

## Home Assistant shows nothing

Check `/health`: `"mqtt": "connected"`. `connecting` means the broker cannot be reached or refused
the login (the log says why). Discovery uses the prefix `homeassistant` unless
`SIGNALBOX_MQTT_DISCOVERY_PREFIX` says otherwise.
