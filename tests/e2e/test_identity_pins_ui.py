"""Setup reuses the certificate pin and pins every SSH host key type, in the browser (#535).

OPNsense over HTTPS: a firewall set up before needs no certificate prompt; with a new
certificate the setup shows the distinct warning with the old and the new fingerprint, nothing
reaches the firewall's API, and it goes on only after the new certificate is trusted by name.
OpenWrt over SSH: the prompt lists the other key types the router offers, the device page shows
them as confirmed with the key.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any

import asyncssh
import pytest
from playwright.sync_api import expect

from signalbox.adapters.openwrt import OpenWrtAdapter
from signalbox.adapters.opnsense import OpnsenseAdapter
from signalbox.adapters.ssh import host_key_fingerprint
from signalbox.sim.openwrt import OpenWrtSim, create_app
from signalbox.sim.openwrt_ssh import ROOT_PASSWORD, OpenWrtSsh, serve_ssh_in_thread
from signalbox.sim.opnsense import KEY, SECRET, OpnsenseSimulator
from signalbox.sim.server import self_signed_certificate, serve

from .conftest import LiveServer, add_site, api

pytestmark = pytest.mark.e2e


@pytest.fixture
def server(tmp_path: Path) -> Iterator[LiveServer]:
    srv = LiveServer(
        tmp_path / "data", adapters={"opnsense": OpnsenseAdapter, "openwrt": OpenWrtAdapter}
    )
    yield srv
    srv.stop()


def grouped(hex_digest: str) -> str:
    """A certificate fingerprint as the UI shows it (AB:CD:...)."""
    text = hex_digest.upper()
    return ":".join(text[i : i + 2] for i in range(0, len(text), 2))


def firewall_body(url: str, trust: str) -> dict[str, Any]:
    return {
        "device": {
            "name": "Firewall",
            "site_id": "home",
            "role": "gateway",
            "adapter": "opnsense",
            "config": {"url": url, "api_key": "", "api_secret": ""},
        },
        "admin": {"user": KEY, "secret": SECRET},
        "trust": trust,
    }


def to_identity(app: Any, device_id: str, port: int | None = None) -> None:
    """The stored device's setup box, up to the identity (no password asked yet)."""
    app.goto(app.server.url + f"/#/device/{device_id}/settings")
    app.reload()  # the same address again renders the page afresh
    expect(app.get_by_test_id("auto-setup")).to_be_visible()
    app.get_by_test_id("auto-setup").locator("summary").click()
    if port is not None:
        app.get_by_test_id("setup-admin-port").fill(str(port))
    app.get_by_test_id("setup-plan").click()
    app.get_by_test_id("setup-continue").click()


def test_known_certificate_needs_no_prompt_and_a_changed_one_warns(
    app: Any, server: LiveServer, tmp_path: Path
) -> None:
    sim = OpnsenseSimulator()
    tls = self_signed_certificate(tmp_path / "tls")
    add_site(app)
    with serve(sim.app(), tls=tls) as url:
        assert api(app, "POST", "/devices/setup/apply", firewall_body(url, tls.fingerprint))["ok"]
        # the stored firewall again: straight to the login, the steps say it was trusted
        to_identity(app, "firewall")
        expect(app.get_by_test_id("setup-admin-secret")).to_be_visible()
        expect(app.get_by_test_id("setup-trust")).to_have_count(0)
        known = app.get_by_test_id("setup-host-key-known")
        expect(known).to_contain_text("Certificate as trusted on")
        expect(known).to_contain_text(grouped(tls.fingerprint))

    # the firewall is reinstalled: a new certificate, here at another port
    other = self_signed_certificate(tmp_path / "other")
    with serve(sim.app(), tls=other) as url2:
        store = server.services.store
        rec = store.device("firewall")
        assert rec is not None
        cfg = store.adapter_config("firewall", OpnsenseAdapter.manifest.config)
        values = {
            **cfg.model_dump(mode="json"),
            "url": url2,
            "api_key": cfg.api_key.get_secret_value(),  # type: ignore[attr-defined]
            "api_secret": cfg.api_secret.get_secret_value(),  # type: ignore[attr-defined]
        }
        store.put_device(rec, values, OpnsenseAdapter.manifest.config)
        sim.requests.clear()
        to_identity(app, "firewall")
        warning = app.get_by_test_id("setup-host-key-changed")
        expect(warning).to_be_visible()
        expect(warning).to_contain_text("The certificate of Firewall has changed")
        expect(warning.get_by_test_id("setup-host-key-changed-old")).to_have_text(
            grouped(tls.fingerprint)
        )
        expect(warning.get_by_test_id("setup-host-key-changed-new")).to_have_text(
            grouped(other.fingerprint)
        )
        assert "error" in (warning.get_attribute("class") or "")
        # no way to a password and no plain "trust": only the button naming the new one
        expect(app.get_by_test_id("setup-admin-secret")).to_have_count(0)
        expect(app.get_by_test_id("setup-trust")).to_have_count(0)
        retrust = warning.get_by_test_id("setup-host-key-changed-retrust")
        expect(retrust).to_contain_text(grouped(other.fingerprint))
        assert sim.requests == []  # nothing reached the API: no key, no password

        # trusting the new certificate by name: the setup goes on without a prompt
        retrust.click()
        expect(app.get_by_test_id("setup-admin-secret")).to_be_visible()
        expect(app.get_by_test_id("setup-host-key-known")).to_contain_text(
            grouped(other.fingerprint)
        )
        assert sim.requests == []
        app.get_by_test_id("setup-admin-user").fill(KEY)
        app.get_by_test_id("setup-admin-secret").fill(SECRET)
        app.get_by_test_id("setup-apply").click()
        expect(app.get_by_test_id("toast").first).to_contain_text("Firewall set up.")
        device = next(d for d in api(app, "GET", "/devices") if d["id"] == "firewall")
        assert [p["fingerprint"] for p in device["certificate_history"]] == [tls.fingerprint]
        assert SECRET not in app.content()


def test_the_prompt_lists_the_other_key_types(app: Any, tmp_path: Path) -> None:
    tls = self_signed_certificate(tmp_path / "router-tls")
    http = OpenWrtSim()
    keys = [
        asyncssh.generate_private_key("ssh-ed25519"),
        asyncssh.generate_private_key("ecdsa-sha2-nistp256"),
    ]
    device = OpenWrtSsh(http=http, certificate=tls.cert.read_bytes(), host_keys=keys)
    ed, ecdsa = (host_key_fingerprint(k) for k in keys)
    add_site(app)
    with serve(create_app(http), tls=tls) as url, serve_ssh_in_thread(device) as (port, _):
        app.goto(app.server.url + "/#/devices/new")
        app.get_by_test_id("device-name").fill("Access point")
        app.get_by_test_id("device-adapter").select_option("openwrt")
        app.get_by_test_id("cfg-url").fill(url)
        app.get_by_test_id("auto-setup").locator("summary").click()
        app.get_by_test_id("setup-admin-port").fill(str(port))
        app.get_by_test_id("setup-plan").click()
        app.get_by_test_id("setup-continue").click()
        expect(app.get_by_test_id("setup-fingerprint")).to_contain_text(ed)
        offered = app.get_by_test_id("setup-offered")
        expect(offered).to_contain_text("also offers these SSH host key types")
        expect(offered.get_by_test_id("setup-offered-key")).to_have_count(1)
        expect(offered).to_contain_text(ecdsa)
        app.get_by_test_id("setup-trust").click()
        app.get_by_test_id("setup-admin-secret").fill(ROOT_PASSWORD)
        app.get_by_test_id("setup-apply").click()
        expect(app.get_by_test_id("toast").first).to_contain_text("Access point set up.")
    app.goto(app.server.url + "/#/device/access-point")
    expect(app.get_by_test_id("device-host-key")).to_have_text(ed)
    expect(app.get_by_test_id("device-host-key-also")).to_have_text(ecdsa)
