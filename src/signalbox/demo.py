"""Demo mode: simulated devices on local ports, already added and trusted.

``signalbox demo`` starts about a dozen devices over two sites from the built-in simulators
(OPNsense, OpenWrt, Linux, Omada, AdGuard Home, Pi-hole and, when Switchyard is installed, a
NETGEAR and a TP-Link switch), adds them with their certificates or host keys pinned, draws the
cables between them and serves the web interface. Nothing on the real network is touched.

Site "site-a" has the OPNsense gateway, a core switch, an access switch, two access points, the
Omada controller and the two DNS filters. "site-b" is a small branch with a Linux gateway (the
other end of the WireGuard site-to-site link), a router, a switch and an access point. The
branch router is only partly readable: its user may not read the firewall.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import threading
from collections.abc import Callable, Iterator, Mapping
from contextlib import ExitStack, contextmanager
from pathlib import Path
from typing import Any

import asyncssh

from signalbox.adapters.linux.setup import SUDOERS_PATH, sudoers
from signalbox.adapters.ssh import sha256_hex
from signalbox.model import DeviceRole, Link, LinkOrigin, Site
from signalbox.rules import RuleSettings
from signalbox.service import Services
from signalbox.sim import dnsfilter as dns_sim
from signalbox.sim import linux as linux_sim
from signalbox.sim import omada as omada_sim
from signalbox.sim import openwrt as openwrt_sim
from signalbox.sim import opnsense as opnsense_sim
from signalbox.sim.server import TlsFiles, self_signed_certificate, serve
from signalbox.store import DeviceRecord

SITE_A = Site(id="site-a", name="Site A (demo)")
SITE_B = Site(id="site-b", name="Site B (demo)")
COMPACT_SITE = Site(id="home", name="Home (demo)")

#: Cables between the devices (port ids); two between the switches form a LAG (#157).
CABLES: list[tuple[str, str]] = [
    ("gateway-a/port/igb0", "core-switch/port/lan1"),
    # two parallel cables between the switches: a LAG, drawn as one bundle
    ("core-switch/port/lan2", "access-switch/port/1"),
    ("core-switch/port/lan3", "access-switch/port/2"),
    ("access-switch/port/3", "ap-2/port/lan1"),
    ("access-switch/port/4", "omada/switch-020000000b01/port/1"),
    ("omada/switch-020000000b01/port/4", "ap-1/port/lan1"),
    ("gateway-b/port/eth1", "switch-b/port/1"),
    ("switch-b/port/2", "router-b/port/lan1"),
    ("switch-b/port/3", "ap-b/port/lan1"),
]

#: The checks the demo shows. The simulators were written one by one, so together they trip many
#: more rules (the same client in several lists, DHCP servers of several devices): the rest
#: is switched off here (in memory), which keeps the findings page readable.
SHOWN_RULES = {
    "security.service-exposure",
    "vlan.native-mismatch",
    "wifi.channel-overlap",
    "wifi.weak-security",
    "link.speed-duplex",
    "firmware.update-available",
    "signalbox.read",
    "dns.forwarder-loop",
    "time.offset",
    "segment.purpose-missing",
}


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


def _put(
    services: Services, rec: DeviceRecord, values: Mapping[str, object], keep_pin: bool = True
) -> None:
    cls = services.adapters[rec.adapter]
    old = services.store.device(rec.id)
    if old is not None and keep_pin:
        rec = rec.model_copy(update={"pinned_fingerprint": old.pinned_fingerprint})
    services.store.put_device(rec, dict(values), cls.manifest.config)
    if not keep_pin and rec.pinned_fingerprint:  # a host key that is new at every start
        services.store.set_pending_fingerprint(rec.id, rec.pinned_fingerprint)
        services.store.trust_fingerprint(rec.id, rec.pinned_fingerprint)


@contextmanager
def _in_thread(
    start: Callable[[], Any], stop: Callable[[Any], None] | None = None
) -> Iterator[Any]:
    """Run ``await start()`` on an event loop of its own thread (the simulators of the switches
    are asyncio datagram servers); yields its result, ``stop(result)`` runs on shutdown."""
    loop = asyncio.new_event_loop()
    ready: concurrent.futures.Future[Any] = concurrent.futures.Future()
    done = asyncio.Event()

    async def main() -> None:
        try:
            value = await start()
        except BaseException as exc:  # pragma: no cover
            ready.set_exception(exc)
            return
        ready.set_result(value)
        await done.wait()
        if stop is not None:
            stop(value)

    thread = threading.Thread(target=loop.run_until_complete, args=(main(),), daemon=True)
    thread.start()
    try:
        yield ready.result(timeout=15)
    finally:
        loop.call_soon_threadsafe(done.set)
        thread.join(timeout=10)
        loop.close()


def _renumber(value: Any, old: str, new: str) -> Any:
    """``value`` with the prefix ``old`` replaced by ``new`` in every string (a second site
    needs networks of its own)."""
    if isinstance(value, str):
        return value.replace(old, new)
    if isinstance(value, list):
        return [_renumber(v, old, new) for v in value]
    if isinstance(value, dict):
        return {k: _renumber(v, old, new) for k, v in value.items()}
    return value


def _openwrt(
    n: int, address: str, ip6: str, hostname: str, prefix: str = "192.0.2.", **options: Any
) -> openwrt_sim.OpenWrtSim:
    """An OpenWrt simulator with an address and a name of its own."""
    sim = openwrt_sim.OpenWrtSim(mac_base=n, **options)
    if prefix != "192.0.2.":
        sim.configs = {k: _renumber(v, "192.0.2.", prefix) for k, v in sim.state.items()}
    lan = sim.state["network"]["lan"]
    lan["ipaddr"] = f"{address}/24"
    lan["ip6addr"] = f"{ip6}/64"
    for section in sim.state["system"].values():
        if section.get(".type") == "system":
            section["hostname"] = hostname
    return sim


@contextmanager
def _compact_devices(services: Services) -> Iterator[dict[str, str]]:
    """The small network of tests: an OPNsense gateway and two OpenWrt access points in one
    site, every rule on. Starts in a fraction of a second and reads the same every time."""
    certs = services.data_dir / "demo-certificates"
    certs.mkdir(parents=True, exist_ok=True)
    with ExitStack() as stack:
        store = services.store
        store.put_site(COMPACT_SITE)
        urls: dict[str, str] = {}
        tls = _certificate(certs, "gateway")
        url = stack.enter_context(serve(opnsense_sim.OpnsenseSimulator().app(), tls=tls))
        urls["gateway"] = url
        opn = {"url": url, "api_key": opnsense_sim.KEY, "api_secret": opnsense_sim.SECRET}
        rec = DeviceRecord(
            id="gateway",
            site_id=COMPACT_SITE.id,
            name="Gateway",
            role=DeviceRole.GATEWAY,
            adapter="opnsense",
            pinned_fingerprint=tls.fingerprint,
        )
        _put(services, rec, opn)
        for n in (1, 2):
            tls = _certificate(certs, f"ap{n}")
            sim = openwrt_sim.OpenWrtSim(mac_base=n)
            url = stack.enter_context(serve(openwrt_sim.create_app(sim), tls=tls)) + "/ubus"
            urls[f"ap-{n}"] = url
            rec = DeviceRecord(
                id=f"ap-{n}",
                site_id=COMPACT_SITE.id,
                name=f"Access point {n}",
                role=DeviceRole.AP,
                adapter="openwrt",
                pinned_fingerprint=tls.fingerprint,
            )
            _put(services, rec, {"url": url, "username": sim.username, "password": sim.password})
        if not store.links():
            link = Link(
                id="demo-uplink",
                a="ap-1/port/lan1",
                b="gateway/port/igb0",
                origin=LinkOrigin.MANUAL,
            )
            store.put_link(link)
        yield urls


@contextmanager
def demo_devices(services: Services, *, compact: bool = False) -> Iterator[dict[str, str]]:
    """Run the simulators and register them; yields device id -> URL.

    ``compact``: only the three devices of one site that tests use (every rule on)."""
    if compact:
        with _compact_devices(services) as small:
            yield small
        return
    certs = services.data_dir / "demo-certificates"
    certs.mkdir(parents=True, exist_ok=True)
    for rule in services.rules:
        if rule.id not in SHOWN_RULES:
            services.runner.config.rules[rule.id] = RuleSettings(enabled=False)
    with ExitStack() as stack:
        store = services.store
        store.put_site(SITE_A)
        store.put_site(SITE_B)
        urls: dict[str, str] = {}

        def add(
            dev: str,
            site: Site,
            name: str,
            role: DeviceRole,
            adapter: str,
            values: Mapping[str, object],
            url: str,
            pin: str | None = None,
            keep_pin: bool = True,
        ) -> None:
            urls[dev] = url
            rec = DeviceRecord(
                id=dev,
                site_id=site.id,
                name=name,
                role=role,
                adapter=adapter,
                pinned_fingerprint=pin,
            )
            _put(services, rec, values, keep_pin)

        def https(dev: str, app: Any) -> tuple[str, TlsFiles]:
            tls = _certificate(certs, dev)
            return stack.enter_context(serve(app, tls=tls)), tls

        def openwrt(dev: str, site: Site, name: str, role: DeviceRole, sim: Any) -> None:
            url, tls = https(dev, openwrt_sim.create_app(sim))
            url += "/ubus"
            values = {"url": url, "username": sim.username, "password": sim.password}
            add(dev, site, name, role, "openwrt", values, url, tls.fingerprint)

        # site A -------------------------------------------------------------------------
        url, tls = https("gateway-a", opnsense_sim.OpnsenseSimulator().app())
        opn = {"url": url, "api_key": opnsense_sim.KEY, "api_secret": opnsense_sim.SECRET}
        add(
            "gateway-a",
            SITE_A,
            "Gateway A",
            DeviceRole.GATEWAY,
            "opnsense",
            opn,
            url,
            tls.fingerprint,
        )

        sw, ap, router = DeviceRole.SWITCH, DeviceRole.AP, DeviceRole.GATEWAY
        # lan2 and lan3 form a static bond towards the access switch (#157)
        core = _openwrt(
            3,
            "192.0.2.3",
            "2001:db8::3",
            "core-switch",
            no_wireless_object=True,
            bond="balance-xor",
        )
        openwrt("core-switch", SITE_A, "Core switch", sw, core)
        openwrt("ap-1", SITE_A, "Office AP", ap, _openwrt(1, "192.0.2.2", "2001:db8::2", "ap-1"))
        openwrt("ap-2", SITE_A, "Hall AP", ap, _openwrt(2, "192.0.2.4", "2001:db8::4", "ap-2"))

        omada = omada_sim.OmadaSimulator()
        # the controller's own gateway is left out: the OPNsense gateway is the site's router
        devices = f"{omada_sim.SITE}/devices"
        omada.data[devices] = [d for d in omada.data[devices] if d["type"] != "gateway"]
        url, tls = https("omada", omada.app())
        values: dict[str, object] = {
            "url": url,
            "omadac_id": omada_sim.OMADAC_ID,
            "client_id": omada_sim.CLIENT_ID,
            "client_secret": omada_sim.CLIENT_SECRET,
        }
        add(
            "omada",
            SITE_A,
            "Omada controller",
            DeviceRole.OTHER,
            "omada",
            values,
            url,
            tls.fingerprint,
        )

        adguard = dns_sim.AdGuardSim()
        url, tls = https("adguard", adguard.app())
        values = {"url": url, "username": adguard.username, "password": adguard.password}
        add(
            "adguard",
            SITE_A,
            "AdGuard Home",
            DeviceRole.OTHER,
            "adguardhome",
            values,
            url,
            tls.fingerprint,
        )
        pihole = dns_sim.PiholeSim()
        url, tls = https("pihole", pihole.app())
        add(
            "pihole",
            SITE_A,
            "Pi-hole",
            DeviceRole.OTHER,
            "pihole",
            {"url": url, "password": pihole.password},
            url,
            tls.fingerprint,
        )

        # site B -------------------------------------------------------------------------
        key = asyncssh.generate_private_key("ssh-ed25519")
        box = linux_sim.LinuxSim()
        # the branch has networks of its own; its WAN is in 203.0.113.0/24
        box.sections = {
            k: v.replace("198.51.100.", "203.0.113.").replace("192.0.2.", "198.51.100.")
            for k, v in box.sections.items()
        }
        # the other end of the tunnel of the OPNsense gateway
        box.wireguard = {
            k: v.replace(linux_sim.GW_KEY, opnsense_sim.WG_SITE_B)
            .replace(linux_sim.PEER_KEY, opnsense_sim.WG_KEY)
            .replace("198.51.100.128/25", "192.0.2.0/24")
            for k, v in box.wireguard.items()
        }
        box.users["signalbox"] = linux_sim.User(
            keys=[key.export_public_key("openssh").decode().strip()], system=True
        )
        box.sudoers_files[SUDOERS_PATH] = sudoers("signalbox")
        port, fingerprint = stack.enter_context(linux_sim.serve_ssh_in_thread(box))
        values = {
            "host": "127.0.0.1",
            "port": port,
            "username": "signalbox",
            "private_key": key.export_private_key().decode(),
        }
        add(
            "gateway-b",
            SITE_B,
            "Gateway B",
            router,
            "linux",
            values,
            f"ssh://127.0.0.1:{port}",
            sha256_hex(fingerprint),
            keep_pin=False,
        )

        openwrt(
            "router-b",
            SITE_B,
            "Router B",
            router,
            _openwrt(
                5,
                "198.51.100.65",
                "2001:db8:b::2",
                "router-b",
                "198.51.100.",
                router=True,
                denied={"uci:firewall"},
            ),
        )
        openwrt(
            "ap-b",
            SITE_B,
            "Branch AP",
            ap,
            _openwrt(6, "198.51.100.66", "2001:db8:b::3", "ap-b", "198.51.100."),
        )

        # the switches of Switchyard (optional): NETGEAR Plus (UDP) and TP-Link Easy Smart
        try:
            from switchyard.easysmart.sim import SIM_MODULUS, EasySmartSimulator, SimEasySmart
            from switchyard.sim import SimSwitch, Simulator
        except ImportError:  # pragma: no cover
            pass
        else:
            ng = SimSwitch("02:00:00:00:10:01", ip="192.0.2.10", name="access-switch")
            ng.lags[1] = (True, [1, 2])  # the other end of the core switch's bond (#157)
            ngsim = Simulator([ng])
            ng_port = stack.enter_context(_in_thread(ngsim.start, lambda _: ngsim.stop()))
            tp = SimEasySmart("02:00:00:00:20:01", ip="192.0.2.70", name="switch-b")
            tpsim = EasySmartSimulator([tp])
            tp_port = stack.enter_context(_in_thread(tpsim.start, lambda _: tpsim.stop()))
            services.runner.context_extra["access-switch"] = {
                "client_port": 0,
                "device_port": ng_port,
                "timeout": 2.0,
            }
            services.runner.context_extra["switch-b"] = {
                "client_port": 0,
                "device_port": tp_port,
                "timeout": 2.0,
                "rsa_modulus": SIM_MODULUS,
            }
            add(
                "access-switch",
                SITE_A,
                "Access switch",
                sw,
                "prosafe",
                {"address": "127.0.0.1", "password": ng.password},
                f"udp://127.0.0.1:{ng_port}",
            )
            add(
                "switch-b",
                SITE_B,
                "Switch B",
                sw,
                "easysmart",
                {"address": "127.0.0.1", "username": tp.username, "password": tp.password},
                f"udp://127.0.0.1:{tp_port}",
            )

        if not store.links():
            for n, (a, b) in enumerate(CABLES, start=1):
                store.put_link(Link(id=f"demo-cable-{n}", a=a, b=b, origin=LinkOrigin.MANUAL))
        yield urls
