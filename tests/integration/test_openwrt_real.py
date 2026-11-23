"""OpenWrt adapter against the real OpenWrt (x86-64 in QEMU, #137).

The target is built by tools/integration/openwrt/ (see docs/TESTING.md):

    IT_OPENWRT_URL             https://127.0.0.1:8443/ubus
    IT_OPENWRT_USER            signalbox          (read-only ACL from docs/adapters/openwrt.md)
    IT_OPENWRT_PASSWORD
    IT_OPENWRT_WRITE_USER      signalbox-write    (write ACL from the same document)
    IT_OPENWRT_WRITE_PASSWORD
    IT_OPENWRT_VERSION         the release the image was built from (optional, checked)

The device: br-lan (VLAN filtering) over eth1 and eth2, VLAN 1 "lan" 192.0.2.1/24 with dnsmasq
DHCP .100-.149 untagged on both, VLAN 20 "iot" 198.51.100.1/24 tagged on eth2; SSID
"Example-IT" (WPA2) on radio0 (2.4 GHz) and radio1 (5 GHz); radio2 is a station associated to
it. Every test leaves the device as it found it (and checks that it did).
"""

from __future__ import annotations

import asyncio
import copy
import time
from collections.abc import AsyncIterator, Callable, Iterator
from ipaddress import ip_address, ip_interface, ip_network
from pathlib import Path
from typing import Any

import pytest
from pydantic import SecretStr

from signalbox.adapters import AdapterContext, AdapterError
from signalbox.adapters.openwrt import OpenWrtAdapter, OpenWrtConfig
from signalbox.adapters.openwrt.ubus import AccessDenied
from signalbox.changes import Change, ChangeKind, ReservationValue
from signalbox.history import ChangeStatus
from signalbox.history import DeviceStatus as DeployStatus
from signalbox.model import (
    Band,
    Cipher,
    DeviceRole,
    DeviceStatus,
    Membership,
    NatClass,
    Security,
    Site,
    Snapshot,
    UplinkKind,
    passphrase_digest,
)
from signalbox.store import DeviceRecord
from signalbox.testing import assert_contract, passphrase_digest_key

from .conftest import Target, certificate_fingerprint
from .lab import Lab

SITE = "lab"
DEV = "openwrt"
NATIVE = f"{SITE}/segment/native"
SSID = "Example-IT"
PSK = "example-it-passphrase"
SECRETS = {"it-guest": "integration guest passphrase"}
CONFIGS = ("network", "wireless", "dhcp")

pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def ow(target: Callable[[str], Target]) -> Target:
    return target("openwrt")


@pytest.fixture(scope="module")
def pin(ow: Target) -> str:
    return ow.fingerprint()


def context(
    t: Target,
    pin: str | None,
    *,
    write: bool = False,
    password: str | None = None,
    timeout: float = 20.0,
) -> AdapterContext:
    user = (t.write_username or "signalbox-write") if write else (t.username or "signalbox")
    secret = (t.write_password if write else t.password) or ""
    return AdapterContext(
        site_id=SITE,
        device_id=DEV,
        device_name="OpenWrt (QEMU)",
        role=DeviceRole.GATEWAY,
        config=OpenWrtConfig(url=t.url, username=user, password=SecretStr(password or secret)),
        pinned_fingerprint=pin,
        timeout=timeout,
    )


async def observe(ctx: AdapterContext) -> Snapshot:
    adapter = OpenWrtAdapter(ctx)
    try:
        return await adapter.observe()
    finally:
        await adapter.close()


async def uci(t: Target, pin: str) -> dict[str, Any]:
    """The committed UCI configs as rpcd's ``uci get`` answers them (fresh session)."""
    adapter = OpenWrtAdapter(context(t, pin))
    try:
        return {
            c: (await adapter.ubus.call("uci", "get", {"config": c}))["values"] for c in CONFIGS
        }
    finally:
        await adapter.close()


@pytest.fixture
async def unchanged(ow: Target, pin: str) -> AsyncIterator[dict[str, Any]]:
    """The UCI state before the test; after it, the device must be back to exactly that."""
    before = await uci(ow, pin)
    yield copy.deepcopy(before)
    after = await uci(ow, pin)
    assert after == before, "the test left the device changed"


@pytest.fixture
def lab(ow: Target, pin: str, tmp_path: Path) -> Iterator[Lab]:
    record = DeviceRecord(
        id=DEV,
        site_id=SITE,
        name="OpenWrt (QEMU)",
        role=DeviceRole.GATEWAY,
        adapter="openwrt",
        pinned_fingerprint=pin,
        allow_writes=True,
    )
    values = {
        "url": ow.url,
        "username": ow.write_username or "signalbox-write",
        "password": ow.write_password or "",
    }
    lab = Lab(
        tmp_path,
        OpenWrtAdapter,
        record,
        values,
        OpenWrtConfig,
        site=Site(id=SITE, name="Lab"),
        secrets=SECRETS,
        # long enough for netifd and hostapd to reload before Signalbox verifies and confirms
        env={"SIGNALBOX_DEPLOY_CONFIRM_SECONDS": "120"},
    )
    yield lab
    lab.close()


# --- reading ----------------------------------------------------------------------------------


async def test_certificate_is_pinned(ow: Target) -> None:
    real = certificate_fingerprint(ow.host, ow.port)
    unpinned = await observe(context(ow, None))
    assert unpinned.status is DeviceStatus.UNTRUSTED
    assert real in unpinned.errors[0].message
    wrong = await observe(context(ow, "00" * 32))
    assert wrong.status is DeviceStatus.UNTRUSTED
    colons = ":".join(real[i : i + 2] for i in range(0, 64, 2)).upper()
    assert (await observe(context(ow, colons))).status is DeviceStatus.OK
    if ow.pin:
        assert ow.pin.replace(":", "").lower() == real


async def test_wrong_password_is_refused(ow: Target, pin: str) -> None:
    snap = await observe(context(ow, pin, password="not-the-password"))
    assert snap.status is DeviceStatus.AUTH_FAILED, snap.errors
    assert "refused" in snap.errors[0].message


async def test_read_contract(ow: Target, pin: str) -> None:
    adapter = OpenWrtAdapter(context(ow, pin))
    try:
        snap = await assert_contract(adapter)
    finally:
        await adapter.close()
    assert snap.device.firmware is not None
    if "VERSION" in ow.extra:
        assert snap.device.firmware.current == ow.extra["VERSION"]
    assert snap.device.model


async def test_wifi_security_details(ow: Target, pin: str) -> None:
    """#167: the lab SSID is ``psk2`` without suffix or WPS options; wpad-mbedtls and rpcd-mod-luci
    are in the image, so ``luci getFeatures`` answers. Confirms the ``getFeatures`` shape (the
    ``hostapd`` flag names are from LuCI's sources)."""
    with passphrase_digest_key():
        snap = await observe(context(ow, pin))
        expected = passphrase_digest(PSK)
    assert snap.status is DeviceStatus.OK, snap.errors
    assert expected is not None
    wlans = [w for w in snap.wlans if w.ssid == SSID]
    assert wlans
    for w in wlans:
        assert w.ciphers == [Cipher.CCMP] and w.group_cipher is Cipher.CCMP
        assert w.sae is None
        assert w.wps is not None and w.wps.enabled is False
        assert w.passphrase_digest == expected
    assert len({w.passphrase_digest for w in wlans}) == 1
    for r in snap.radios:
        sup = r.supported_security
        assert sup is not None and Security.WPA2 in sup and Security.WPA3 in sup, sup


async def test_mapping_of_the_lab_device(ow: Target, pin: str) -> None:
    snap = await observe(context(ow, pin))
    assert snap.status is DeviceStatus.OK, snap.errors
    ports = {p.name: p for p in snap.ports}
    assert {"eth0", "eth1", "eth2", "br-lan"} <= set(ports), sorted(ports)
    assert ports["eth1"].up and ports["eth1"].mac == "02:00:00:00:a0:01"
    # port details (#156): netifd's MTU, the bridge ports up, primary VLAN 1 (``eth1:u*``)
    for name in ("eth1", "eth2"):
        p = ports[name]
        assert (p.mtu, p.admin_up, p.pvid) == (1500, True, 1), p
        assert p.max_speed_mbps is None or p.speed_mbps is None or p.speed_mbps <= p.max_speed_mbps
    segments = {s.id: s for s in snap.segments}
    assert set(segments) == {NATIVE, f"{SITE}/segment/20"}, sorted(segments)
    native = {m.port_id: m.mode for m in segments[NATIVE].members}
    untagged = Membership.UNTAGGED
    assert native == {f"{DEV}/port/eth1": untagged, f"{DEV}/port/eth2": untagged}
    iot = {m.port_id: m.mode for m in segments[f"{SITE}/segment/20"].members}
    assert iot == {f"{DEV}/port/eth2": Membership.TAGGED}
    assert segments[NATIVE].name == "lan" and segments[f"{SITE}/segment/20"].name == "iot"
    subnets = {str(s.interface): s for s in snap.subnets}
    assert {"192.0.2.1/24", "198.51.100.1/24"} <= set(subnets), sorted(subnets)
    assert subnets["192.0.2.1/24"].gateway and subnets["192.0.2.1/24"].segment_id == NATIVE

    radios = {r.name: r for r in snap.radios}
    assert radios["radio0"].band is Band.GHZ_2_4 and radios["radio0"].enabled
    assert radios["radio1"].band is Band.GHZ_5 and radios["radio1"].enabled
    assert radios["radio0"].channel == 1 and radios["radio1"].channel == 36
    wlans = [w for w in snap.wlans if w.ssid == SSID]
    assert sorted(w.radio_id for w in wlans) == [radios["radio0"].id, radios["radio1"].id]
    for w in wlans:
        assert w.enabled and w.security is Security.WPA2 and w.segment_id == NATIVE
        assert w.roaming_80211k and w.roaming_80211v and not w.roaming_80211r

    [dhcp] = [d for d in snap.dhcp_servers if d.segment_id == NATIVE]
    assert dhcp.enabled and dhcp.lease_seconds == 12 * 3600
    [pool] = dhcp.pools
    assert (pool.start, pool.end) == (ip_address("192.0.2.100"), ip_address("192.0.2.149"))
    assert dhcp.router == ip_address("192.0.2.1")
    assert dhcp.ntp_servers == [ip_address("192.0.2.1")]
    assert dhcp.leases is not None  # #183: luci-rpc or /tmp/dhcp.leases read (maybe empty)
    assert dhcp.authoritative is True  # the stock dnsmasq section has authoritative 1 (guess)


async def test_health_and_time(ow: Target, pin: str) -> None:
    """``system info``, the thermal zones (none in QEMU: no temperatures, no error) and
    ``uci get system`` (Europe/Berlin, NTP server on lan) as the read-only login sees them."""
    adapter = OpenWrtAdapter(context(ow, pin))
    try:
        info = await adapter.ubus.call("system", "info")
        snap = await adapter.observe()
    finally:
        await adapter.close()
    # the shape docs/adapters/openwrt.md describes: KiB for root/tmp, load times 65536
    assert {"localtime", "uptime", "load", "memory", "root", "tmp"} <= set(info), info
    assert {"total", "free", "available"} <= set(info["memory"]), info
    assert {"total", "used"} <= set(info["root"]) and len(info["load"]) == 3, info
    assert snap.status is DeviceStatus.OK, snap.errors
    h = snap.device.health
    assert h is not None and h.uptime_seconds and h.uptime_seconds > 0, h
    assert h.load_average is not None and h.memory_total_bytes, h
    assert h.memory_used_bytes and 0 < h.memory_used_bytes < h.memory_total_bytes, h
    kinds = {s.name: s.kind.value for s in h.storage}
    assert kinds == {"/": "system", "/tmp": "temporary"}, h.storage
    root = next(s for s in h.storage if s.name == "/")
    assert root.total_bytes and root.total_bytes > 1024 * 1024, root  # KiB, not bytes
    t = snap.device.time
    assert t is not None and t.clock is not None, t
    offset = t.offset_seconds()
    assert offset is not None and abs(offset) < 600, t  # QEMU starts with the host's clock
    assert t.timezone == "Europe/Berlin" and t.utc_offset_minutes in (60, 120), t
    assert t.ntp_client is not None and t.ntp_client.enabled and t.ntp_client.servers, t
    assert t.ntp_server is not None and t.ntp_server.enabled, t
    assert t.ntp_server.segments == [NATIVE], t


async def test_management_services(ow: Target, pin: str) -> None:
    """dropbear (SSH) and uhttpd (LuCI, HTTPS with the image's certificate) from ``uci get`` as
    the read-only login sees them (#173; needs ``dropbear`` and ``uhttpd`` in the ACL)."""
    adapter = OpenWrtAdapter(context(ow, pin))
    try:
        snap = await adapter.observe()
    finally:
        await adapter.close()
    assert snap.status is DeviceStatus.OK, snap.errors
    by = {s.kind.value: s for s in snap.services}
    assert {"ssh", "http", "https"} <= set(by), snap.services
    ssh = by["ssh"]
    assert ssh.enabled and ssh.port == 22 and ssh.encrypted is True, ssh
    # OpenWrt defaults: password login for everyone, root included
    assert ssh.password_login and ssh.root_login and ssh.root_password_login, ssh
    assert by["http"].enabled and by["http"].port == 80, by["http"]
    assert by["https"].enabled and by["https"].port == 443, by["https"]
    assert by["http"].redirects_to_https is False, by["http"]
    assert snap.device.transport_encrypted is True


async def test_the_management_interface_is_the_uplink(ow: Target, pin: str) -> None:
    """The lab has no ``wan``: ``mgmt`` (static 10.0.2.15/24 on eth0, default route via QEMU's
    10.0.2.2) leads upstream and is no network of the site; ``wwan`` has no default route."""
    snap = await observe(context(ow, pin))
    uplinks = {u.name: u for u in snap.uplinks}
    assert "wwan" not in uplinks and "lan" not in uplinks, sorted(uplinks)
    mgmt = uplinks.get("mgmt")
    assert mgmt is not None, snap.uplinks
    assert (mgmt.id, mgmt.port_id, mgmt.kind) == (
        f"{DEV}/uplink/mgmt",
        f"{DEV}/port/eth0",
        UplinkKind.STATIC,
    )
    assert mgmt.up is True and mgmt.since is not None
    assert ip_interface("10.0.2.15/24") in mgmt.addresses, mgmt.addresses
    assert mgmt.upstream_gateway == ip_address("10.0.2.2")
    assert mgmt.nat_class() is NatClass.PRIVATE  # QEMU's user network is a NAT in front


async def test_the_station_is_a_client(ow: Target, pin: str) -> None:
    """radio2 is associated to the SSID (on radio0 or radio1: the station scans both bands):
    hostapd lists it, dnsmasq leased it."""
    lan = ip_network("192.0.2.0/24")
    aps = {f"{DEV}/wlan/default_radio0", f"{DEV}/wlan/default_radio1"}
    for _ in range(30):
        snap = await observe(context(ow, pin))
        wireless = [c for c in snap.clients if c.seen_on in aps]
        if wireless and any(a in lan for c in wireless for a in c.addresses):
            break
        await asyncio.sleep(2)
    assert wireless, snap.clients
    [station] = wireless
    assert station.segment_id == NATIVE
    assert any(a in lan for a in station.addresses), station


# --- writing through the Deployer: APPLIED, then the revert gives the same UCI state ----------

PORT = f"""
sites:
  {SITE}:
    ports:
      - {{device: {DEV}, port: eth1, untagged: native, tagged: [30]}}
"""
WLAN = f"""
sites:
  {SITE}:
    wlans:
      - ssid: Example-IT-Guest
        security: wpa2-psk
        passphrase_secret: it-guest
        devices: [{DEV}]
        roaming: {{k: true, v: true}}
"""
DHCP = f"""
sites:
  {SITE}:
    segments:
      - vlan: 20
        dhcp:
          device: {DEV}
          pool: [198.51.100.100, 198.51.100.149]
          lease_seconds: 3600
"""
RESERVATION = f"""
sites:
  {SITE}:
    segments:
      - vlan: native
        dhcp: {{device: {DEV}}}
        reservations:
          - {{mac: "02:00:00:00:10:01", address: 192.0.2.50, hostname: printer}}
"""


@pytest.mark.parametrize(
    ("desired", "kind"),
    [
        (PORT, ChangeKind.PORT),
        (WLAN, ChangeKind.WLAN),
        (DHCP, ChangeKind.DHCP),
        (RESERVATION, ChangeKind.RESERVATION),
    ],
    ids=["port", "wlan", "dhcp", "reservation"],
)
async def test_deploy_and_revert(
    lab: Lab, unchanged: dict[str, Any], desired: str, kind: ChangeKind
) -> None:
    rec = await lab.deploy(desired)
    assert [c.kind for c in rec.plan.changes] == [kind]
    assert rec.status is ChangeStatus.APPLIED, [(r.status, r.error) for r in rec.devices]
    assert rec.devices[0].status is DeployStatus.CONFIRMED
    assert (await lab.plan(desired)).changes == []  # the device now reports what was wanted
    back = await lab.revert(rec)
    assert back.status is ChangeStatus.APPLIED, [(r.status, r.error) for r in back.devices]
    # the fixture compares the UCI state with the one before


async def test_restore_of_the_backup(lab: Lab, ow: Target, pin: str, unchanged: Any) -> None:
    rec = await lab.deploy(RESERVATION)
    assert rec.status is ChangeStatus.APPLIED, [(r.status, r.error) for r in rec.devices]
    backup = rec.devices[0].backup_id
    assert backup is not None
    restore = await lab.run(await lab.deployer.restore_backup(backup, "integration", "it"))
    assert restore.status is ChangeStatus.APPLIED, [(r.status, r.error) for r in restore.devices]


# --- the transaction on the device: rollback timer, ACL --------------------------------------


def reservation(mac: str = "02:00:00:00:10:02") -> Change:
    value = ReservationValue(mac=mac, address=ip_address("192.0.2.51"), hostname="rollback")
    return Change(
        kind=ChangeKind.RESERVATION,
        device_id=DEV,
        site_id=SITE,
        key=f"{NATIVE}/{mac}",
        old=None,
        new=value,
    )


def hosts(state: dict[str, Any]) -> set[str]:
    return {str(s.get("mac")) for s in state["dhcp"].values() if s.get(".type") == "host"}


async def wait_for(check: Callable[[], Any], seconds: float) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if await check():
            return True
        await asyncio.sleep(1)
    return False


async def test_without_confirm_the_device_rolls_back(
    ow: Target, pin: str, unchanged: dict[str, Any]
) -> None:
    adapter = OpenWrtAdapter(context(ow, pin, write=True))
    try:
        result = await adapter.apply([reservation()], {}, 10)
        assert result.confirm_deadline is not None
        assert "02:00:00:00:10:02" in hosts(await uci(ow, pin))  # applied, not confirmed

        async def back() -> bool:
            return await uci(ow, pin) == unchanged

        assert await wait_for(back, 60), "rpcd did not roll back after the timeout"
        with pytest.raises(AdapterError, match="rolled the change back"):
            await adapter.confirm()
        # rpcd put the rolled back change into the session again (as LuCI's unsaved changes);
        # the next transaction must not commit it
        staged = await adapter.ubus.call("uci", "changes", {}, keep_session=True)
        assert staged["changes"].get("dhcp"), staged
        other = reservation("02:00:00:00:10:03")
        await adapter.apply([other], {}, 60)
        await adapter.confirm()
        assert hosts(await uci(ow, pin)) - hosts(unchanged) == {"02:00:00:00:10:03"}
        undo = other.inverse()
        await adapter.apply([undo], {}, 60)
        await adapter.confirm()
    finally:
        await adapter.close()


async def test_read_only_login_cannot_change_anything(
    ow: Target, pin: str, unchanged: dict[str, Any]
) -> None:
    adapter = OpenWrtAdapter(context(ow, pin))
    try:
        with pytest.raises(AccessDenied, match=r"access denied for uci\.(add|set) \(dhcp\)"):
            await adapter.apply([reservation()], {}, 30)
    finally:
        await adapter.close()


async def test_a_second_apply_waits_for_the_first(
    ow: Target, pin: str, unchanged: dict[str, Any]
) -> None:
    """rpcd gives a new login of the same user the session of a pending apply; the second
    client's change lands in that session, its apply and revert are refused."""
    first = OpenWrtAdapter(context(ow, pin, write=True))
    second = OpenWrtAdapter(context(ow, pin, write=True))
    try:
        await first.apply([reservation()], {}, 60)
        with pytest.raises(AdapterError, match="waits for its confirmation"):
            await second.apply([reservation("02:00:00:00:10:03")], {}, 60)
        assert second.ubus.session == first.ubus.session  # reclaimed
        await first.confirm()
        assert hosts(await uci(ow, pin)) - hosts(unchanged) == {"02:00:00:00:10:02"}
        # the next transaction drops what the second client left staged in the session
        await first.apply([reservation().inverse()], {}, 60)
        await first.confirm()
    finally:
        await first.close()
        await second.close()
