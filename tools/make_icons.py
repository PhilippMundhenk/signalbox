"""Derive the icon files from docs/assets/icon.svg (Playwright + Chromium).

Writes favicon.svg, apple-touch-icon.png, icon-192.png, icon-512.png and
site.webmanifest into the web static folder, and docs/assets/social-preview.png.
Set SIGNALBOX_CHROMIUM to use another Chromium binary.
"""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parent.parent
SVG = (ROOT / "docs/assets/icon.svg").read_text()
STATIC = ROOT / "src/signalbox/web/static"


def png(page, html: str, path: Path, size: tuple[int, int], transparent: bool = True) -> None:
    page.set_viewport_size({"width": size[0], "height": size[1]})
    page.set_content(f"<body style='margin:0;background:transparent'>{html}</body>")
    page.screenshot(path=str(path), omit_background=transparent)


def main() -> None:
    STATIC.mkdir(parents=True, exist_ok=True)
    shutil.copy(ROOT / "docs/assets/icon.svg", STATIC / "favicon.svg")
    with sync_playwright() as p:
        browser = p.chromium.launch(
            executable_path=os.environ.get("SIGNALBOX_CHROMIUM"),
            args=["--no-sandbox", "--disable-gpu"],
        )
        page = browser.new_page()
        for name, size in (
            ("apple-touch-icon.png", 180),
            ("icon-192.png", 192),
            ("icon-512.png", 512),
        ):
            html = SVG.replace(
                "<svg ", f'<svg width="{size}" height="{size}" style="display:block" ', 1
            )
            png(page, html, STATIC / name, (size, size))
        card = f"""
        <div style="width:1280px;height:640px;background:#1e7f5c;display:flex;align-items:center;
                    justify-content:center;gap:48px;font-family:system-ui,'DejaVu Sans',sans-serif">
          <div style="width:220px;height:220px">{
            SVG.replace("<svg ", '<svg width="220" height="220" ', 1).replace(
                'fill="#1e7f5c"', 'fill="#155c42"', 1
            )
        }</div>
          <div style="color:#fff"><div style="font-size:96px;font-weight:700;line-height:1">Signalbox</div>
          <div style="font-size:30px;margin-top:16px;opacity:.9">One place to see and check every device of your network</div></div>
        </div>"""
        png(page, card, ROOT / "docs/assets/social-preview.png", (1280, 640), transparent=False)
        browser.close()
    manifest = {
        "name": "Signalbox",
        "short_name": "Signalbox",
        "start_url": "/",
        "display": "standalone",
        "background_color": "#f4f6fa",
        "theme_color": "#1e7f5c",
        "icons": [
            {"src": "icon-192.png", "sizes": "192x192", "type": "image/png"},
            {"src": "icon-512.png", "sizes": "512x512", "type": "image/png"},
            {"src": "favicon.svg", "sizes": "any", "type": "image/svg+xml"},
        ],
    }
    (STATIC / "site.webmanifest").write_text(json.dumps(manifest, indent=2) + "\n")
    print("icons written")


if __name__ == "__main__":
    main()
