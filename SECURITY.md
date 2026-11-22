# Security

## Reporting a vulnerability

Please do not open a public issue for security problems. Use GitHub's private vulnerability
reporting on this repository ("Security" tab, "Report a vulnerability"). You should get a first
response within a week.

## Deployment notes

- Signalbox holds credentials for your routers, switches and access points. Treat its data
  directory like a password store: back it up encrypted and keep it readable only by the
  container user.
- Device credentials are encrypted with a key kept outside the database (`/data/secret.key`, or
  `SIGNALBOX_SECRET_KEY`). Anyone with both the database and the key can read them.
- Wi-Fi passphrases read from devices are never stored, only compared: a fingerprint salted
  with the SSID, and a digest keyed with a key derived from the secret key (so a passphrase
  cannot be tested against the database alone). Neither is shown in the UI or API, nor exported.
- Give Signalbox its own least-privilege, read-only user on every device. Writing is off by
  default and enabled per site and adapter.
- The web interface asks for a password. Run it on your LAN or behind a reverse proxy with
  TLS; do not expose it to the internet.
- Device certificates are pinned on first contact. A changed certificate is refused until you
  confirm the new fingerprint.
