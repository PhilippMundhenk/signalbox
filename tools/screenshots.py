"""Documentation screenshots from the demo (simulated devices), with Playwright + Chromium.

    python tools/screenshots.py

Writes docs/screenshots/*.png (light, desktop and phone; one dark). Set SIGNALBOX_CHROMIUM to use
another Chromium binary.
"""

from __future__ import annotations

import asyncio
import os
import sys
import tempfile
from pathlib import Path

from playwright.sync_api import Page, sync_playwright

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from signalbox.demo import demo_devices  # noqa: E402
from signalbox.service import build  # noqa: E402
from signalbox.sim.server import serve  # noqa: E402
from signalbox.web.app import create_app  # noqa: E402

OUT = ROOT / "docs" / "screenshots"
PASSWORD = "screenshot-password"
DESKTOP = [
    ("findings", "#/"),
    ("devices", "#/devices"),
    ("topology", "#/topology"),
    ("wireless", "#/wireless"),
    ("segments", "#/segments"),
]
PHONE = [("phone-findings", "#/"), ("phone-devices", "#/devices")]


def shoot(page: Page, base: str, name: str, route: str) -> None:
    page.goto(f"{base}/{route}")
    page.wait_for_load_state("networkidle")
    page.wait_for_timeout(400)
    page.screenshot(path=str(OUT / f"{name}.png"), full_page=False)


def login(page: Page, base: str) -> None:
    page.goto(base)
    page.get_by_test_id("login-password").fill(PASSWORD)
    page.get_by_test_id("login-submit").click()
    page.wait_for_load_state("networkidle")


def main() -> None:
    os.environ.setdefault("NO_PROXY", "127.0.0.1,localhost")
    OUT.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        svc = build(Path(tmp), env={"SIGNALBOX_AUTH_PASSWORD": PASSWORD})
        try:
            with demo_devices(svc):
                asyncio.run(svc.runner.observe_all())
                with serve(create_app(svc, run_background=False)) as base, sync_playwright() as p:
                    browser = p.chromium.launch(
                        executable_path=os.environ.get("SIGNALBOX_CHROMIUM") or None
                    )
                    page = browser.new_page(
                        viewport={"width": 1280, "height": 800}, device_scale_factor=2
                    )
                    login(page, base)
                    for name, route in DESKTOP:
                        shoot(page, base, name, route)
                    page.evaluate("localStorage.setItem('theme', 'dark')")
                    page.reload()
                    shoot(page, base, "findings-dark", "#/")
                    page.evaluate("localStorage.removeItem('theme')")
                    phone = browser.new_page(**p.devices["Pixel 7"])
                    login(phone, base)
                    for name, route in PHONE:
                        shoot(phone, base, name, route)
                    phone.get_by_test_id("nav-menu").click()
                    phone.wait_for_timeout(400)
                    phone.screenshot(path=str(OUT / "phone-menu.png"), full_page=False)
                    browser.close()
        finally:
            svc.close()
    print(f"screenshots written to {OUT}")


if __name__ == "__main__":
    main()
