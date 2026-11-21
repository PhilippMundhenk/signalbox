# Branding

Product name **Signalbox**, code name `signalbox` (package `signalbox`, PyPI `signalbox-net`, CLI,
image, `SIGNALBOX_` prefix). Plain, calm, tool-like. No marketing.

Disclaimer, used in the README, the web footer and here: *Signalbox is an independent
open-source project, not affiliated with, endorsed or supported by any of the vendors whose
devices it works with. Product names are used only to say what it works with.*

Signalbox is a sibling of [Switchyard](https://github.com/PhilippMundhenk/switchyard): the same
layout and components, a different accent colour (green instead of blue) and its own icon.

## Tokens

Defined as CSS custom properties in `src/signalbox/web/static/style.css`.

| Token | Light | Dark |
| --- | --- | --- |
| `--bg` | `#f4f6fa` | `#0f1522` |
| `--surface` | `#ffffff` | `#182032` |
| `--text` | `#17202e` | `#e6ebf5` |
| `--muted` | `#5d6a82` | `#96a3bd` |
| `--accent` | `#1e7f5c` | `#3fbf8a` |
| `--ok` / `--warn` / `--danger` | `#1f9d55` / `#b7791f` / `#d64545` | `#3ecf8e` / `#e3b341` / `#ff6b6b` |

Severity colours: error = `--danger`, warning = `--warn`, info and "could not check" = `--muted`.

Type: the system font stack; monospace for MAC addresses, fingerprints and port names.
Radius 10 px.

## Components

Cards with a thin border; one primary button per view; findings as cards with a severity stripe,
the fix in its own line; devices with a status badge; links in the topology drawn as lines
between port jacks, VLANs as coloured overlays.

## Tone

Short sentences, plain words. A finding says what is wrong, where, and what to do about it.
Say what will happen before a destructive action.

## Icon

A railway signal: a signal head with three lamps on a post. It stands for the signal box that
watches a whole line and shows when something is wrong. White shapes on a rounded square in the
accent green `#1e7f5c`, 64 x 64 viewBox, readable at 16 px. Source: `docs/assets/icon.svg`.
`python tools/make_icons.py` derives `favicon.svg`, `apple-touch-icon.png`, `icon-192.png`,
`icon-512.png`, `site.webmanifest` (web static folder) and `docs/assets/social-preview.png`
(1280 x 640, upload it in the repository *Settings*, *Social preview*). The web interface shows
the same SVG as its brand mark.
