from collections.abc import Iterator
from pathlib import Path

import pytest

from factories import SITE
from signalbox.changes import plan
from signalbox.deploy import Deployer, DeployError, matches
from signalbox.desired import parse
from signalbox.history import ChangeStatus, DeviceStatus
from signalbox.model import DeviceRole, Link, LinkOrigin
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
