from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest

from factories import SITE, ip
from signalbox.changes import (
    Change,
    ChangeKind,
    DhcpValue,
    Plan,
    WlanValue,
    make_plan,
    observed_dhcp,
    observed_wlan,
    plan,
)
from signalbox.deploy import Deployer, DeployError, matches
from signalbox.desired import parse
from signalbox.history import ChangeStatus, DeviceStatus
from signalbox.model import DeviceRole, Link, LinkOrigin, Pmf, Security, passphrase_fingerprint
from signalbox.rules.builtin import RULES
from signalbox.service import Services, build
from signalbox.store import DeviceRecord
from writable import WConfig, Writable, initial, snapshot_json

ENV = {"SIGNALBOX_AUTH_PASSWORD": "x" * 12, "SIGNALBOX_DEPLOY_ENABLED": "true"}

WANT = """
sites:
  home:
    segments:
      - vlan: 20
        name: IoT
        gateway: {device: gw, address: 198.51.100.1/24}
        dhcp: {enabled: true, pool: [198.51.100.100, 198.51.100.199]}
    wlans:
      - {ssid: Example, security: wpa2-wpa3, segment: native, passphrase_secret: psk, devices: [ap]}
    ports:
      - {device: gw, port: lan, untagged: native, tagged: [20]}
      - {device: ap, port: lan, untagged: native, tagged: [20]}
"""


@pytest.fixture
def svc(tmp_path: Path) -> Iterator[Services]:
    Writable.reset()
    s = build(tmp_path, env=ENV, adapters={"w": Writable}, rules=RULES, link_sources=[])
    s.store.put_site(SITE)
    for dev, role in (("gw", DeviceRole.GATEWAY), ("ap", DeviceRole.AP)):
        rec = DeviceRecord(
            id=dev, site_id="home", name=dev, role=role, adapter="w", allow_writes=True
        )
        s.store.put_device(rec, {"host": "192.0.2.9", "password": "pw"}, WConfig)
    s.store.put_link(Link(id="up", a="gw/port/lan", b="ap/port/lan", origin=LinkOrigin.MANUAL))
    s.store.set_secret("psk", "the new passphrase")
    yield s
    s.close()


async def planned(svc: Services, text: str = WANT) -> tuple[Deployer, str]:
    await svc.runner.observe_all()
    p = plan(parse(text), svc.runner.network(), RULES, secret=svc.store.get_secret)
    d = Deployer(svc.runner)
    rec = await d.prepare(p, "add the IoT network", "tester")
    return d, rec.id


async def deployed(svc: Services, d: Deployer, cid: str) -> ChangeStatus:
    d.approve(cid, "tester")
    return (await d.deploy(cid)).status


async def test_happy_path_applies_verifies_confirms_and_records(svc: Services) -> None:
    d, cid = await planned(svc)
    rec = svc.store.change(cid)
    assert rec is not None and rec.status is ChangeStatus.PLANNED
    assert [r.device_id for r in rec.devices] == ["gw", "ap"]
    assert all(r.calls for r in rec.devices)
    assert await deployed(svc, d, cid) is ChangeStatus.APPLIED
    rec = svc.store.change(cid)
    assert rec is not None
    assert [r.status for r in rec.devices] == [DeviceStatus.CONFIRMED, DeviceStatus.CONFIRMED]
    assert all(r.backup_id for r in rec.devices)
    assert Writable.secrets_seen == ["the new passphrase"]
    assert "the new passphrase" not in rec.model_dump_json()
    events = [(e.device_id, e.event) for e in svc.store.events(cid)]
    assert events[0] == (None, "planned") and events[-1] == (None, "applied")
    assert ("gw", "backed-up") in events and ("ap", "confirmed") in events
    # the network now matches the desired state: a new plan is empty
    net = svc.runner.network()
    assert plan(parse(WANT), net, RULES, secret=svc.store.get_secret).changes == []
    # backups are stored encrypted and listed
    infos = svc.store.backups("gw")
    assert len(infos) == 1 and infos[0].change_id == cid
    raw = svc.store._one("SELECT content FROM backups")
    assert raw is not None and "192.0.2.1" not in raw["content"]


async def test_refusals(svc: Services, tmp_path: Path) -> None:
    d, cid = await planned(svc)
    with pytest.raises(DeployError, match="must be approved"):
        await d.deploy(cid)
    with pytest.raises(DeployError, match="no such change"):
        d.approve("nope", "t")
    d.approve(cid, "t")
    with pytest.raises(DeployError, match="approved, not planned"):
        d.approve(cid, "t")
    svc.runner.config.deploy.enabled = False
    with pytest.raises(DeployError, match="turned off"):
        await d.deploy(cid)
    svc.runner.config.deploy.enabled = True
    rec = svc.store.device("ap")
    assert rec is not None
    svc.store.put_device(
        rec.model_copy(update={"allow_writes": False}), {"host": "x", "password": ""}, WConfig
    )
    with pytest.raises(DeployError, match="changes are not allowed on this device"):
        await d.deploy(cid)
    assert d.reject(cid, "t").status is ChangeStatus.REJECTED
    with pytest.raises(DeployError, match="rejected"):
        d.reject(cid, "t")
    p = plan(parse(WANT), svc.runner.network(), RULES, secret=svc.store.get_secret)
    with pytest.raises(DeployError, match="not allowed"):
        await d.prepare(p, "again", "t")
    with pytest.raises(DeployError, match="say why"):
        await d.prepare(p, "  ", "t")
    empty = p.model_copy(update={"changes": []})
    with pytest.raises(DeployError, match="no changes"):
        await d.prepare(empty, "x", "t")
    svc.store.delete_secret("psk")
    with pytest.raises(DeployError, match="secret 'psk' is not stored"):
        await d.prepare(p, "x", "t")


async def test_integration_must_support_the_kind(svc: Services) -> None:
    class ReadOnlyish(Writable):
        manifest = Writable.manifest.model_copy(update={"writes": frozenset({"wlan"})})

    svc.runner.adapters = {"w": ReadOnlyish}  # type: ignore[misc]
    await svc.runner.observe_all()
    p = plan(parse(WANT), svc.runner.network(), RULES, secret=svc.store.get_secret)
    with pytest.raises(DeployError, match="cannot change dhcp, port, router"):
        await Deployer(svc.runner).prepare(p, "x", "t")


async def test_device_changed_since_the_plan(svc: Services) -> None:
    d, cid = await planned(svc)
    from factories import iface
    from signalbox.model import Subnet

    by_hand = Subnet(
        id="gw/subnet/x",
        segment_id="home/segment/20",
        interface=iface("198.51.100.254/24"),
        device_id="gw",
    )
    gw = Writable.state["gw"]
    Writable.state["gw"] = gw.model_copy(update={"subnets": [*gw.subnets, by_hand]})
    assert await deployed(svc, d, cid) is ChangeStatus.ROLLED_BACK
    rec = svc.store.change(cid)
    assert rec is not None
    gw, ap = rec.devices
    assert gw.status is DeviceStatus.FAILED and "changed since the plan" in (gw.error or "")
    assert ap.status is DeviceStatus.SKIPPED
    assert "apply" not in Writable.log.get("gw", [])


@pytest.mark.parametrize(
    ("switch", "error"),
    [
        ("apply", "apply failed"),
        ("noop", "not applied as planned"),
        ("down-after", "does not answer after the change"),
    ],
)
async def test_second_device_fails_everything_rolled_back(
    svc: Services, switch: str, error: str
) -> None:
    before = {d: snapshot_json(d) for d in ("gw", "ap")}
    d, cid = await planned(svc)
    Writable.fail["ap"] = {switch}
    assert await deployed(svc, d, cid) is ChangeStatus.ROLLED_BACK
    rec = svc.store.change(cid)
    assert rec is not None
    gw, ap = rec.devices
    assert error in (ap.error or "")
    assert ap.status is DeviceStatus.ROLLED_BACK and gw.status is DeviceStatus.ROLLED_BACK
    assert snapshot_json("gw") == before["gw"] and snapshot_json("ap") == before["ap"]
    assert Writable.log["gw"].count("apply") == 2  # change, then its inverse
    assert "restore" not in Writable.log["gw"]


async def test_inverse_fails_then_backup_restored(svc: Services) -> None:
    before = snapshot_json("gw")
    d, cid = await planned(svc)
    Writable.fail["gw"] = {"inverse"}
    Writable.fail["ap"] = {"apply"}
    assert await deployed(svc, d, cid) is ChangeStatus.ROLLED_BACK
    assert "restore" in Writable.log["gw"] and snapshot_json("gw") == before
    events = [e.event for e in svc.store.events(cid) if e.device_id == "gw"]
    assert "inverse-failed" in events and "rolled-back" in events


async def test_rollback_impossible_is_reported_as_failed(svc: Services) -> None:
    d, cid = await planned(svc)
    Writable.fail["gw"] = {"inverse", "restore"}
    Writable.fail["ap"] = {"apply"}
    assert await deployed(svc, d, cid) is ChangeStatus.FAILED
    rec = svc.store.change(cid)
    assert rec is not None and rec.devices[0].status is DeviceStatus.ROLLBACK_FAILED


async def test_backup_failure_changes_nothing(svc: Services) -> None:
    d, cid = await planned(svc)
    Writable.fail["gw"] = {"backup"}
    assert await deployed(svc, d, cid) is ChangeStatus.ROLLED_BACK
    rec = svc.store.change(cid)
    assert rec is not None and "backup failed" in (rec.devices[0].error or "")
    assert "apply" not in Writable.log.get("gw", [])


async def test_unreadable_device_is_not_touched(svc: Services) -> None:
    d, cid = await planned(svc)
    Writable.fail["gw"] = {"down"}
    assert await deployed(svc, d, cid) is ChangeStatus.ROLLED_BACK
    rec = svc.store.change(cid)
    assert rec is not None and "could not be read" in (rec.devices[0].error or "")


async def test_restore_without_backup_and_restore_that_fails(svc: Services) -> None:
    d, cid = await planned(svc)
    Writable.fail["ap"] = {"noop", "restore"}
    assert await deployed(svc, d, cid) is ChangeStatus.FAILED
    rec = svc.store.change(cid)
    assert rec is not None and rec.devices[1].status is DeviceStatus.ROLLBACK_FAILED


async def test_confirm_timer_is_confirmed(svc: Services) -> None:
    d, cid = await planned(svc)
    Writable.fail["gw"] = {"timer"}
    assert await deployed(svc, d, cid) is ChangeStatus.APPLIED
    assert "confirm" in Writable.log["gw"] and "confirm" not in Writable.log["ap"]


async def test_revert_brings_the_network_back(svc: Services) -> None:
    before = {d: snapshot_json(d) for d in ("gw", "ap")}
    d, cid = await planned(svc)
    assert await deployed(svc, d, cid) is ChangeStatus.APPLIED
    back = await d.revert(cid, "IoT network not needed", "tester")
    assert back.reverts == cid
    assert await deployed(svc, d, back.id) is ChangeStatus.APPLIED
    assert snapshot_json("gw") == before["gw"]
    original = svc.store.change(cid)
    assert original is not None and original.reverted_by == back.id
    with pytest.raises(DeployError, match="already reverted"):
        await d.revert(cid, "again", "t")
    planned_only = await d.revert(back.id, "undo the undo", "t")
    with pytest.raises(DeployError, match="only an applied change"):
        await d.revert(planned_only.id, "x", "t")


async def test_revert_refused_when_devices_changed_since(svc: Services) -> None:
    d, cid = await planned(svc)
    await deployed(svc, d, cid)
    Writable.state["gw"] = initial("gw", DeviceRole.GATEWAY)  # reset by hand
    await svc.runner.observe_all()
    with pytest.raises(DeployError, match="changed since"):
        await d.revert(cid, "undo", "t")


async def test_restore_a_backup(svc: Services) -> None:
    before = snapshot_json("gw")
    d, cid = await planned(svc)
    await deployed(svc, d, cid)
    backup_id = next(b.id for b in svc.store.backups("gw") if b.change_id == cid)
    rec = await d.restore_backup(backup_id, "back to the old gateway config", "tester")
    assert [r.device_id for r in rec.devices] == ["gw"]
    assert await deployed(svc, d, rec.id) is ChangeStatus.APPLIED
    assert snapshot_json("gw") == before
    with pytest.raises(DeployError, match="cannot be reverted"):
        await d.revert(rec.id, "x", "t")
    with pytest.raises(DeployError, match="no such backup"):
        await d.restore_backup("nope", "x", "t")


async def test_blocking_findings_need_an_override(svc: Services) -> None:
    text = "sites: {home: {segments: [{vlan: native, dhcp: {device: ap, enabled: true}}]}}"
    d, cid = await planned(svc, text)
    rec = svc.store.change(cid)
    assert rec is not None and rec.plan.blocking
    with pytest.raises(DeployError, match="override"):
        d.approve(cid, "t")
    assert d.approve(cid, "t", override="lab test").override == "lab test"


async def test_matches_handles_wlan_passphrase_and_missing_port(svc: Services) -> None:
    _, cid = await planned(svc)
    rec = svc.store.change(cid)
    assert rec is not None
    net = svc.runner.network()
    wlan = next(c for c in rec.plan.changes if c.kind.value == "wlan")
    assert matches(net, wlan, wlan.old, {})
    assert not matches(net, wlan, wlan.new, {"psk": "the new passphrase"})
    port = next(c for c in rec.plan.changes if c.kind.value == "port")
    assert not matches(net, port, None, {})


async def test_changes_on_a_managed_device_go_through_its_controller(svc: Services) -> None:
    await svc.runner.observe_all()
    d = Deployer(svc.runner)
    assert d.owner("gw") == "gw" and d.owner("unknown") == "unknown"
    from signalbox.model import Device

    managed = Device(
        id="gw/eap1", site_id="home", name="EAP", role=DeviceRole.AP, adapter="w", managed_by="gw"
    )
    net = svc.runner.network()
    svc.runner.network = lambda: net.model_copy(update={"devices": [*net.devices, managed]})  # type: ignore[method-assign]
    assert d.owner("gw/eap1") == "gw"
    assert d.adapter("gw/eap1").context.device_id == "gw"


async def test_integration_that_cannot_translate_is_a_deploy_error(svc: Services) -> None:
    await svc.runner.observe_all()
    p = plan(parse(WANT), svc.runner.network(), RULES, secret=svc.store.get_secret)
    Writable.fail["ap"] = {"plan"}
    with pytest.raises(DeployError, match="ap: cannot translate the change"):
        await Deployer(svc.runner).prepare(p, "x", "t")


async def test_confirm_that_fails_restores_and_rolls_back(svc: Services) -> None:
    before = snapshot_json("gw")
    d, cid = await planned(svc)
    Writable.fail["gw"] = {"timer", "confirm"}
    assert await deployed(svc, d, cid) is ChangeStatus.ROLLED_BACK
    rec = svc.store.change(cid)
    assert rec is not None
    gw = rec.devices[0]
    assert "confirm failed: confirm refused" in (gw.error or "")
    assert gw.status is DeviceStatus.ROLLED_BACK and snapshot_json("gw") == before


async def test_unspecified_values_are_left_to_the_device(svc: Services) -> None:
    await svc.runner.observe_all()
    net = svc.runner.network()
    wlan = WlanValue(ssid="Example", security=Security.WPA2)
    seen = Change(kind=ChangeKind.WLAN, device_id="ap", site_id="home", key="Example", new=wlan)
    assert matches(net, seen, wlan, {})  # pmf and roaming None: whatever the device has
    assert not matches(net, seen, wlan.model_copy(update={"pmf": Pmf.REQUIRED}), {})
    gw = Writable.state["gw"]
    servers = [s.model_copy(update={"enabled": False, "pools": []}) for s in gw.dhcp_servers]
    Writable.state["gw"] = gw.model_copy(update={"dhcp_servers": servers})
    await svc.runner.observe_all()
    net = svc.runner.network()
    off = DhcpValue(
        enabled=False, pool=(ip("192.0.2.100"), ip("192.0.2.199")), dns=[ip("192.0.2.1")]
    )
    dhcp = Change(
        kind=ChangeKind.DHCP, device_id="gw", site_id="home", key="home/segment/native", new=off
    )
    assert matches(net, dhcp, off, {})  # a switched-off server reports no pool
    assert not matches(net, dhcp, off.model_copy(update={"enabled": True}), {})


# passphrase versions (#188) -------------------------------------------------------------------

OLD = "old passphrase"  # what initial() puts on the AP


def ap_fingerprint(ssid: str = "Example") -> str | None:
    return next(w.passphrase_fingerprint for w in Writable.state["ap"].wlans if w.ssid == ssid)


def versions(svc: Services, cid: str) -> dict[str, str]:
    rec = svc.store.change(cid)
    assert rec is not None
    return rec.passphrase_versions


async def test_revert_restores_the_replaced_passphrase(svc: Services) -> None:
    svc.store.set_secret("psk", OLD)
    svc.store.set_secret("psk", "the new passphrase")  # the old value is kept as the previous one
    assert svc.store.previous_secret("psk") == OLD
    d, cid = await planned(svc)
    assert await deployed(svc, d, cid) is ChangeStatus.APPLIED
    assert ap_fingerprint() == passphrase_fingerprint("Example", "the new passphrase")
    assert versions(svc, cid) == {"ap:wlan:Example": f"psk@{cid}"}
    assert svc.store.get_secret(f"psk@{cid}") == OLD
    # versions are not secrets of the desired state, and their values are shown nowhere
    assert svc.store.secret_names() == ["psk"] and svc.store.secret_versions() == [f"psk@{cid}"]
    rec = svc.store.change(cid)
    assert rec is not None
    dump = rec.model_dump_json() + "".join(e.detail for e in svc.store.events(cid))
    assert OLD not in dump and "the new passphrase" not in dump
    raw = svc.store._one("SELECT value FROM settings WHERE key = ?", (f"secret-version:psk@{cid}",))
    assert raw is not None and OLD not in raw["value"]
    assert ("ap", "passphrase-kept") in [(e.device_id, e.event) for e in svc.store.events(cid)]

    back = await d.revert(cid, "the old passphrase was fine", "tester")
    wlan = next(c for c in back.plan.changes if c.kind is ChangeKind.WLAN)
    assert isinstance(wlan.new, WlanValue) and wlan.new.passphrase_secret == f"psk@{cid}"
    assert await deployed(svc, d, back.id) is ChangeStatus.APPLIED
    assert ap_fingerprint() == passphrase_fingerprint("Example", OLD)
    assert Writable.secrets_seen == ["the new passphrase", OLD]
    # the revert keeps the passphrase it replaced in turn (and the version it set is in use)
    assert set(svc.store.secret_versions()) == {f"psk@{cid}", f"psk@{back.id}"}
    assert svc.store.get_secret(f"psk@{back.id}") == "the new passphrase"

    redo = await d.revert(back.id, "the new one after all", "tester")
    assert await deployed(svc, d, redo.id) is ChangeStatus.APPLIED
    assert ap_fingerprint() == passphrase_fingerprint("Example", "the new passphrase")
    # superseded: the first change's version is pruned
    assert set(svc.store.secret_versions()) == {f"psk@{back.id}", f"psk@{redo.id}"}
    assert svc.store.get_secret(f"psk@{redo.id}") == OLD
    # an unrelated later change of the SSID prunes the rest
    svc.store.set_secret("psk", "the newest passphrase")
    later = Deployer(svc.runner)
    p = plan(parse(WANT), svc.runner.network(), RULES, secret=svc.store.get_secret)
    newest = (await later.prepare(p, "rotate", "tester")).id
    assert await deployed(svc, later, newest) is ChangeStatus.APPLIED
    assert svc.store.secret_versions() == [f"psk@{newest}"]
    assert svc.store.get_secret(f"psk@{newest}") == "the new passphrase"


async def test_unknown_passphrase_is_reported_and_kept(svc: Services) -> None:
    d, cid = await planned(svc)  # only the new passphrase is stored
    assert await deployed(svc, d, cid) is ChangeStatus.APPLIED
    assert versions(svc, cid) == {}
    events = {e.event: e.detail for e in svc.store.events(cid)}
    assert "not known to Signalbox" in events["passphrase-unknown"]
    back = await d.revert(cid, "undo", "tester")
    assert await deployed(svc, d, back.id) is ChangeStatus.APPLIED
    # nothing to restore it from: the new passphrase stays (the backup has the old one)
    assert ap_fingerprint() == passphrase_fingerprint("Example", "the new passphrase")


async def test_passphrase_found_in_another_secret(svc: Services) -> None:
    svc.store.set_secret("old-psk", OLD)
    d, cid = await planned(svc)
    assert await deployed(svc, d, cid) is ChangeStatus.APPLIED
    assert svc.store.get_secret(f"psk@{cid}") == OLD
    back = await d.revert(cid, "undo", "tester")
    assert await deployed(svc, d, back.id) is ChangeStatus.APPLIED
    assert ap_fingerprint() == passphrase_fingerprint("Example", OLD)


async def test_device_without_fingerprint_trusts_what_signalbox_deployed(svc: Services) -> None:
    svc.store.set_secret("psk", "first passphrase")
    d, cid = await planned(svc)
    assert await deployed(svc, d, cid) is ChangeStatus.APPLIED
    assert versions(svc, cid) == {}
    assert svc.store.wlan_passphrase("ap", "Example") == ("first passphrase", [])

    def blind() -> None:  # a device that does not report passphrases
        ap = Writable.state["ap"]
        wlans = [w.model_copy(update={"passphrase_fingerprint": None}) for w in ap.wlans]
        Writable.state["ap"] = ap.model_copy(update={"wlans": wlans})

    blind()
    svc.store.set_secret("psk", "second passphrase")
    text = WANT.replace("security: wpa2-wpa3", "security: wpa3-sae")
    d, cid = await planned(svc, text)
    assert await deployed(svc, d, cid) is ChangeStatus.APPLIED
    assert svc.store.get_secret(f"psk@{cid}") == "first passphrase"
    blind()
    back = await d.revert(cid, "undo", "tester")
    assert await deployed(svc, d, back.id) is ChangeStatus.APPLIED
    assert Writable.secrets_seen[-1] == "first passphrase"


async def test_failed_deployment_keeps_no_version(svc: Services) -> None:
    svc.store.set_secret("psk", OLD)
    svc.store.set_secret("psk", "the new passphrase")
    d, cid = await planned(svc)
    Writable.fail["ap"] = {"noop"}
    assert await deployed(svc, d, cid) is ChangeStatus.ROLLED_BACK
    assert versions(svc, cid) == {}
    assert svc.store.secret_versions() == []
    assert svc.store.wlan_passphrase("ap", "Example") == (None, [])


async def test_rollback_by_inverse_restores_the_passphrase(svc: Services) -> None:
    svc.store.set_secret("psk", OLD)
    svc.store.set_secret("psk", "the new passphrase")
    await svc.runner.observe_all()
    net = svc.runner.network()
    old_w = observed_wlan(net, "ap", "Example")
    assert old_w is not None
    wlan = Change(
        kind=ChangeKind.WLAN,
        device_id="ap",
        site_id="home",
        key="Example",
        old=old_w,
        new=old_w.model_copy(update={"passphrase_secret": "psk"}),
    )
    old_d = observed_dhcp(net, "gw", "home/segment/native")
    assert old_d is not None
    dhcp = Change(
        kind=ChangeKind.DHCP,
        device_id="gw",
        site_id="home",
        key="home/segment/native",
        old=old_d,
        new=old_d.model_copy(update={"lease_seconds": 600}),
    )
    # the AP first, so that it is undone by its inverse when the gateway fails
    p = Plan(id="plan-ap-first", created_at=datetime.now(UTC), changes=[wlan, dhcp])
    d = Deployer(svc.runner)
    cid = (await d.prepare(p, "new passphrase, shorter leases", "tester")).id
    Writable.fail["gw"] = {"apply"}
    assert await deployed(svc, d, cid) is ChangeStatus.ROLLED_BACK
    rec = svc.store.change(cid)
    assert rec is not None and rec.devices[0].status is DeviceStatus.ROLLED_BACK
    assert "restore" not in Writable.log["ap"]  # the inverse set the old passphrase again
    assert ap_fingerprint() == passphrase_fingerprint("Example", OLD)
    assert svc.store.secret_versions() == []


async def test_removed_ssid_comes_back_with_its_passphrase(svc: Services) -> None:
    svc.store.set_secret("old-psk", OLD)
    await svc.runner.observe_all()
    net = svc.runner.network()
    gone = Change(
        kind=ChangeKind.WLAN,
        device_id="ap",
        site_id="home",
        key="Example",
        old=observed_wlan(net, "ap", "Example"),
    )
    d = Deployer(svc.runner)
    cid = (await d.prepare(make_plan([gone], net, RULES), "retire it", "tester")).id
    assert await deployed(svc, d, cid) is ChangeStatus.APPLIED
    assert Writable.state["ap"].wlans == []
    assert versions(svc, cid) == {"ap:wlan:Example": f"old-psk@{cid}"}
    assert svc.store.wlan_passphrase("ap", "Example") == (None, [f"old-psk@{cid}"])
    back = await d.revert(cid, "still needed", "tester")
    assert await deployed(svc, d, back.id) is ChangeStatus.APPLIED
    assert ap_fingerprint() == passphrase_fingerprint("Example", OLD)


async def test_two_ssids_with_one_secret_get_one_version_each(svc: Services) -> None:
    ap = Writable.state["ap"]
    second = ap.wlans[0].model_copy(
        update={
            "id": "ap/wlan/1",
            "ssid": "Example2",
            "passphrase_fingerprint": passphrase_fingerprint("Example2", "another old one"),
        }
    )
    Writable.state["ap"] = ap.model_copy(update={"wlans": [*ap.wlans, second]})
    svc.store.set_secret("old-psk", OLD)
    svc.store.set_secret("old-psk-2", "another old one")
    text = WANT.replace(
        "devices: [ap]}",
        "devices: [ap]}\n      - {ssid: Example2, security: wpa2-wpa3, passphrase_secret: psk,"
        " devices: [ap]}",
    )
    d, cid = await planned(svc, text)
    assert await deployed(svc, d, cid) is ChangeStatus.APPLIED
    assert versions(svc, cid) == {
        "ap:wlan:Example": f"psk@{cid}",
        "ap:wlan:Example2": f"psk@{cid}.2",
    }
    back = await d.revert(cid, "undo", "tester")
    assert await deployed(svc, d, back.id) is ChangeStatus.APPLIED
    assert ap_fingerprint() == passphrase_fingerprint("Example", OLD)
    assert ap_fingerprint("Example2") == passphrase_fingerprint("Example2", "another old one")


async def test_restoring_a_backup_forgets_the_deployed_passphrases(svc: Services) -> None:
    d, cid = await planned(svc)
    await deployed(svc, d, cid)
    assert svc.store.wlan_passphrase("ap", "Example") == ("the new passphrase", [])
    backup_id = next(b.id for b in svc.store.backups("ap") if b.change_id == cid)
    rec = await d.restore_backup(backup_id, "back", "tester")
    assert await deployed(svc, d, rec.id) is ChangeStatus.APPLIED
    assert svc.store.wlan_passphrase("ap", "Example") == (None, [])


def test_secret_versions_in_the_store(svc: Services) -> None:
    with pytest.raises(ValueError, match="not a secret version"):
        svc.store.put_secret_version("psk", "x")
    svc.store.put_secret_version("psk@chg-1", "v")
    svc.store.set_wlan_passphrase("ap", "Example", "v", ["psk@chg-1"])
    svc.store.set_secret("psk", "the new passphrase")  # the same value: no previous one
    assert svc.store.previous_secret("psk") is None
    svc.store.set_secret("psk", "another")
    svc.store.delete_secret("psk")
    assert svc.store.previous_secret("psk") is None
    svc.store.delete_secret_version("psk@chg-1")
    assert svc.store.get_secret("psk@chg-1") is None
    svc.store.delete_device("ap")
    assert svc.store.wlan_passphrase("ap", "Example") == (None, [])
