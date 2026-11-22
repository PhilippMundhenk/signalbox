# Deployment

## Container

The image `ghcr.io/philippmundhenk/signalbox` is built for amd64 and arm64. Tags: `latest`
(newest release), `X.Y.Z` and `X.Y` (releases), `main` (development). It runs as user 10001,
keeps everything in `/data`, listens on port 8080 and has a healthcheck on `/health`.

Signalbox only makes outgoing HTTPS connections to your devices, so the normal bridged network
of Docker is enough; no host networking is needed.

[docker-compose.yml](../docker-compose.yml) is the recommended setup, with the common settings
commented. All settings: [CONFIGURATION.md](CONFIGURATION.md).

## Data folder

`/data` holds:

| File | What |
| --- | --- |
| `signalbox.yaml` | the configuration, written with comments on the first start |
| `signalbox.sqlite` | sites, devices, cables, the last reading of every device, findings history |
| `secret.key` | the key that encrypts device credentials in the database (unless `SIGNALBOX_SECRET_KEY` is set) |

The container user must be able to write the folder. For a bind mount either give it to user
10001 (`mkdir -p data && sudo chown 10001:10001 data`) or run the container as your own user
(`user: "1000:1000"` in the compose file).

## Backups

Back up the whole data folder. The database alone is not enough: without `secret.key` (or the
`SIGNALBOX_SECRET_KEY` you set) the stored device credentials cannot be decrypted, and you have
to enter them again. Keep the backup encrypted; it gives access to your network devices.

## Reverse proxy and TLS

Signalbox serves plain HTTP. On a LAN that is acceptable for a first look; for daily use put it
behind a reverse proxy with TLS (Traefik, Caddy, nginx) and set `SIGNALBOX_SERVER_BASE_URL` to
the public URL. The session cookie is marked `Secure` when the request arrives over HTTPS. Do not
expose Signalbox to the internet.

## Device accounts

Give Signalbox its own read-only account on every device, so a leaked Signalbox credential
cannot change anything:

- OPNsense: an API user with read privileges only, see [adapters/opnsense.md](adapters/opnsense.md)
- OpenWrt: an rpcd login with a read-only ACL, see [adapters/openwrt.md](adapters/openwrt.md)
- Fritz!Box: a user of its own with only the right "FRITZ!Box settings" (TR-064 has no
  read-only right), see [adapters/fritzbox.md](adapters/fritzbox.md)

## Updates

Pull the new image and restart. The database is upgraded automatically on start; an older
Signalbox refuses to open a database written by a newer one, so restore a backup if you go back.

## Without Docker

Python 3.11 or newer: `pip install .`, then `signalbox --data /path/to/data serve`. Run it as an
unprivileged user, for example as a systemd service.
