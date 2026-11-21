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
- Give Signalbox its own least-privilege, read-only user on every device. Writing is off by
  default and enabled per site and adapter.
- The web interface asks for a password. Run it on your LAN or behind a reverse proxy with
  TLS; do not expose it to the internet.
- Device certificates are pinned on first contact. A changed certificate is refused until you
  confirm the new fingerprint.
