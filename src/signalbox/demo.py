"""Demo mode: simulated devices on local ports, already added and trusted.

``signalbox demo`` starts an OPNsense gateway and two OpenWrt access points from the built-in
simulators (TLS with generated certificates), adds them to a "Home (demo)" site with their
certificates pinned, and serves the web interface. Nothing on the real network is touched.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import ExitStack, contextmanager
from pathlib import Path

from signalbox.model import DeviceRole, Link, LinkOrigin, Site
from signalbox.service import Services
from signalbox.sim import openwrt as openwrt_sim
from signalbox.sim import opnsense as opnsense_sim
from signalbox.sim.server import TlsFiles, self_signed_certificate, serve
from signalbox.store import DeviceRecord

SITE = Site(id="home", name="Home (demo)")


def _certificate(directory: Path, name: str) -> TlsFiles:
    """Reuse the certificate of an earlier demo run, so the stored pin stays valid."""
    cert, key, fp = (
        directory / f"{name}.crt",
        directory / f"{name}.key",
        directory / f"{name}.sha256",
    )
    if cert.exists() and key.exists() and fp.exists():
        return TlsFiles(cert=cert, key=key, fingerprint=fp.read_text().strip())
    files = self_signed_certificate(directory, name)
    fp.write_text(files.fingerprint)
    return files


def _put(services: Services, rec: DeviceRecord, values: dict[str, object]) -> None:
    cls = services.adapters[rec.adapter]
    old = services.store.device(rec.id)
    if old is not None:
        rec = rec.model_copy(update={"pinned_fingerprint": old.pinned_fingerprint})
    services.store.put_device(rec, values, cls.manifest.config)


@contextmanager
def demo_devices(services: Services) -> Iterator[dict[str, str]]:
    """Run the simulators and register them; yields device id -> URL."""
    certs = services.data_dir / "demo-certificates"
    certs.mkdir(parents=True, exist_ok=True)
    with ExitStack() as stack:
        store = services.store
        store.put_site(SITE)
        urls: dict[str, str] = {}

        gw_tls = _certificate(certs, "gateway")
        gw = stack.enter_context(serve(opnsense_sim.OpnsenseSimulator().app(), tls=gw_tls))
        urls["gateway"] = gw
        _put(
            services,
            DeviceRecord(
                id="gateway",
                site_id=SITE.id,
                name="Gateway",
                role=DeviceRole.GATEWAY,
                adapter="opnsense",
                pinned_fingerprint=gw_tls.fingerprint,
            ),
            {"url": gw, "api_key": opnsense_sim.KEY, "api_secret": opnsense_sim.SECRET},
        )
        for n in (1, 2):
            tls = _certificate(certs, f"ap{n}")
            sim = openwrt_sim.OpenWrtSim()
            url = stack.enter_context(serve(openwrt_sim.create_app(sim), tls=tls)) + "/ubus"
            urls[f"ap-{n}"] = url
            _put(
                services,
                DeviceRecord(
                    id=f"ap-{n}",
                    site_id=SITE.id,
                    name=f"Access point {n}",
                    role=DeviceRole.AP,
                    adapter="openwrt",
                    pinned_fingerprint=tls.fingerprint,
                ),
                {"url": url, "username": sim.username, "password": sim.password},
            )
        if not store.links():
            store.put_link(
                Link(
                    id="demo-uplink",
                    a="ap-1/port/lan1",
                    b="gateway/port/igb0",
                    origin=LinkOrigin.MANUAL,
                )
            )
        yield urls
