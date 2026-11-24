"""Annotations and acknowledged findings (#186): model, engine, desired state, store, API."""

import sqlite3
from collections.abc import Iterator
from datetime import timedelta
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient
from pydantic import ValidationError

from factories import (
    SITE,
    T0,
    acknowledgement,
    annotated,
    annotation,
    device,
    port,
    snapshot,
)
from signalbox import annotate, desired
from signalbox.merge import merge
from signalbox.model import (
    Acknowledgement,
    AnnotationSource,
    Client,
    DeviceRole,
    DeviceStatus,
    Expected,
    Neighbour,
    Network,
    Segment,
    Site,
    TargetKind,
    annotation_target,
    client_target,
    finding_fingerprint,
    target_kind,
)
from signalbox.rules import Result, RuleSettings, Severity, evaluate, found, rule
from signalbox.rules.annotation_checks import device_of, stale
from signalbox.secrets import load_vault
from signalbox.service import Services, build
from signalbox.sightings import ClientHistory, History
from signalbox.store import SCHEMA, DeviceRecord, Store
from signalbox.web.app import create_app
from test_runner import Dev

PW = "correct-horse-battery"
MAC = "02:00:00:00:00:44"
LAN = "home/segment/native"


def network(status: DeviceStatus = DeviceStatus.OK) -> Network:
    gw = snapshot(
        device("gw", name="Gateway"),
        status=status,
        ports=[port("gw", "lan"), port("gw", "wan")],
        segments=[Segment(id=LAN, site_id="home")],
        clients=[Client(id=f"gw/client/{MAC}", mac=MAC, seen_on="gw/port/lan")],
        neighbours=[
            Neighbour(
                id="gw/neighbour/x", local_port_id="gw/port/lan", chassis_id="02:00:00:00:00:77"
            )
        ],
    )
    return merge([SITE], [gw])


@rule("test.port", "Port", Severity.ERROR, "x")
def port_rule(net: Network) -> Iterator[Result]:
    for p in net.ports:
        yield found(f"{p.name} is slow", [p.id])


# model ------------------------------------------------------------------------------------


def test_targets_and_kinds() -> None:
    assert annotation_target(" 02:00:00:00:00:AA ") == "client/02:00:00:00:00:aa"
    assert annotation_target("client/02-00-00-00-00-AA") == "client/02:00:00:00:00:aa"
    assert annotation_target("sw/port/5") == "sw/port/5"
    assert client_target("02:00:00:00:00:01") == "client/02:00:00:00:00:01"
    with pytest.raises(ValueError):
        annotation_target(" ")
    with pytest.raises(ValueError):
        annotation_target("client/nope")
    assert target_kind("sw") is TargetKind.DEVICE
    assert target_kind("omada/ap-1") is TargetKind.DEVICE
    assert target_kind("omada/ap-1/port/3") is TargetKind.PORT
    assert target_kind("home/segment/native-gw") is TargetKind.SEGMENT
    assert target_kind("gw/subnet/lan") is TargetKind.SUBNET
    assert target_kind("gw/uplink/wan") is TargetKind.OTHER
    assert target_kind(client_target(MAC)) is TargetKind.CLIENT


def test_annotation_validates_expectations_per_kind() -> None:
    a = annotation("sw/port/5", label="  lab  ", notes=" ", expected={"uplink": True})
    assert a.label == "lab" and a.notes is None and a.kind() is TargetKind.PORT
    assert a.source is AnnotationSource.STORED
    annotation(MAC, expected={"static_address": True, "category": "printer"})
    annotation("sw", expected={"may_be_unreachable": True, "role": "switch"})
    with pytest.raises(ValidationError, match="uplink does not apply to a device"):
        annotation("sw", expected={"uplink": True})
    with pytest.raises(ValidationError, match="category, static_address does not apply"):
        annotation("sw/port/5", expected={"static_address": True, "category": "iot"})
    with pytest.raises(ValidationError):
        annotation("sw", tags=["x" * 41])


def test_acknowledgement_matching() -> None:
    with pytest.raises(ValidationError, match="names a finding or a target"):
        Acknowledgement(id="a", rule_id="r")
    ack = acknowledgement("r", "02:00:00:00:00:44", until=T0.replace(tzinfo=None))
    assert ack.target == client_target(MAC) and ack.until is not None and ack.until.tzinfo
    assert ack.active(T0 - timedelta(seconds=1)) and not ack.active(T0)
    assert ack.matches("r", "f1", [client_target(MAC)], "m")
    assert not ack.matches("other", "f1", [client_target(MAC)], "m")
    assert not ack.matches("r", "f1", ["x"], "m")
    one = acknowledgement("r", finding_id="f1", fingerprint=finding_fingerprint("m"))
    assert one.matches("r", "f1", [], "m")
    assert not one.matches("r", "f2", [], "m") and not one.matches("r", "f1", [], "changed")


def test_network_helpers() -> None:
    net = annotated(network(), annotation(MAC, label="printer", expected={"static_address": True}))
    assert net.annotation(MAC) is net.annotation(client_target(MAC)) is not None
    assert net.label(MAC) == "printer" and net.label("gw") is None
    assert net.expected(MAC).static_address is True
    assert net.expected("gw") == Expected()
    assert net.annotation("client/bad") is None
    for known in ("gw", "home", "gw/port/lan", LAN, client_target(MAC), "gw/neighbour/x"):
        assert net.knows(known), known
    assert not net.knows("gw/port/9")


# engine -----------------------------------------------------------------------------------


def test_evaluate_applies_acknowledgements() -> None:
    net = annotated(
        network(),
        acknowledgement("test.port", "gw/port/lan", reason="lab port"),
        acknowledgement("test.port", "gw/port/wan", until=T0 - timedelta(days=1), reason="old"),
    )
    out = evaluate(net, [port_rule], now=T0)
    found_ = {f.objects[0]: f for f in out if f.rule_id == "test.port"}
    lan, wan = found_["gw/port/lan"], found_["gw/port/wan"]
    assert lan.acknowledged is not None and lan.acknowledged.reason == "lab port"
    assert not lan.problem and wan.problem and wan.acknowledged is None
    expired = [f for f in out if f.rule_id == "ack.expired"]
    assert len(expired) == 1 and expired[0].severity is Severity.INFO
    assert "expired on 2026-01-14 (reason: old)" in expired[0].message
    assert "under Findings" in (expired[0].fix or "")
    # the finding id does not change with the acknowledgement (history stays continuous)
    plain = {f.id for f in evaluate(network(), [port_rule], now=T0)}
    assert lan.id in plain and wan.id in plain


def test_expired_declared_acknowledgement_points_to_the_desired_state() -> None:
    ack = Acknowledgement(
        id="d", rule_id="r", finding_id="f", until=T0, source=AnnotationSource.DECLARED
    )
    out = evaluate(annotated(Network(), ack), [], now=T0)
    assert [f.rule_id for f in out] == ["ack.expired"] and out[0].objects == []
    assert "desired state" in (out[0].fix or "")
    off = evaluate(
        annotated(Network(), ack), [], {"ack.expired": RuleSettings(enabled=False)}, now=T0
    )
    assert off == []


def test_lapse_when_the_message_changes() -> None:
    net = network()
    f = next(x for x in evaluate(net, [port_rule], now=T0) if x.objects == ["gw/port/lan"])
    ack = acknowledgement("test.port", finding_id=f.id, fingerprint=finding_fingerprint("other"))
    again = next(x for x in evaluate(annotated(net, ack), [port_rule], now=T0) if x.id == f.id)
    assert again.acknowledged is None


# desired state ----------------------------------------------------------------------------

YAML = f"""
sites:
  home:
    annotations:
      - target: {MAC.upper()}
        label: office printer
        owner: Example Owner
        expected: {{static_address: true, category: printer}}
      - target: gw/port/wan
        notes: to the modem
    acknowledgements:
      - rule: test.port
        target: gw/port/lan
        reason: lab port, slow on purpose
        until: 2027-01-01
      - rule: dhcp.static-in-pool
        finding: 0123456789abcdef
"""


def test_desired_state_declares_annotations() -> None:
    state = desired.parse(YAML)
    notes, acks = annotate.declared(state)
    assert [a.target for a in notes] == [client_target(MAC), "gw/port/wan"]
    assert all(a.source is AnnotationSource.DECLARED for a in [*notes, *acks])
    assert acks[0].until is not None and acks[0].until.isoformat() == "2027-01-01T00:00:00+00:00"
    assert acks[0].id.startswith("declared-") and acks[0].id != acks[1].id
    assert desired.parse(desired.dump(state)) == state
    merged = desired.parse(YAML).merged(
        desired.parse(YAML.replace(MAC.upper(), "02:00:00:00:00:45").replace("wan", "lan"))
    )
    assert len(merged.sites["home"].annotations) == 4
    assert annotate.declared(None) == ([], [])


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("sites: {home: {annotations: [{target: sw, expected: {uplink: true}}]}}", "uplink"),
        ("sites: {home: {acknowledgements: [{rule: r}]}}", "name a finding or a target"),
        (
            "sites: {a: {annotations: [{target: sw}]}, b: {annotations: [{target: sw}]}}",
            "annotation declared twice: sw",
        ),
    ],
)
def test_desired_state_refuses_bad_annotations(text: str, message: str) -> None:
    with pytest.raises(desired.DesiredError, match=message):
        desired.parse(text)


def test_combine_declared_beats_stored_and_export_round_trips() -> None:
    state = desired.parse(YAML)
    stored = [
        annotation(MAC, label="ignored: declared wins"),
        annotation("gw", owner="Example Owner", expected={"may_be_unreachable": True}),
        annotation("home/segment/20", purpose="lab"),
        annotation("02:00:00:00:00:99", label="unknown phone"),
    ]
    acks = [acknowledgement("test.port", "gw/port/wan", reason="r", until=T0)]
    net = annotate.apply(network(), state, stored, acks)
    assert net.label(MAC) == "office printer"
    assert net.expected("gw").may_be_unreachable is True
    assert len(net.acknowledgements) == 3
    assert annotate.apply(network(), None) == network()
    assert annotate.target_site(net, client_target(MAC)) == "home"
    assert annotate.target_site(net, "home/segment/20") == "home"
    assert annotate.target_site(net, "gw/port/lan") == "home"
    assert annotate.target_site(net, "elsewhere") is None
    text = annotate.export(net, net.annotations, net.acknowledgements)
    back = desired.parse(text)
    targets = [a.target for a in back.sites["home"].annotations]
    assert targets == ["client/02:00:00:00:00:99", "gw", "home/segment/20"]
    assert back.sites["home"].annotations[1].expected.may_be_unreachable is True
    assert [a.target for a in back.sites["home"].acknowledgements] == ["gw/port/wan"]
    assert annotate.export(Network(), [], []) == ""
    lonely = yaml.safe_load(annotate.export(Network(), [annotation("sw")], []))
    assert list(lonely["sites"]) == ["default"]


# store ------------------------------------------------------------------------------------


def test_store_keeps_annotations_and_acknowledgements(tmp_path: Path) -> None:
    s = Store(tmp_path / "db.sqlite", load_vault(tmp_path, env={}))
    try:
        s.put_annotation(annotation("gw", label="router", source=AnnotationSource.DECLARED))
        s.put_annotation(annotation("gw", label="main router"))
        assert [a.label for a in s.annotations()] == ["main router"]
        assert s.annotation("gw") is not None and s.annotation("x") is None
        assert s.annotations()[0].source is AnnotationSource.STORED
        s.put_acknowledgement(acknowledgement("r", "gw"))
        assert [a.id for a in s.acknowledgements()] == ["ack-r-gw"]
        assert s.delete_annotation("gw") and not s.delete_annotation("gw")
        assert s.delete_acknowledgement("ack-r-gw") and not s.delete_acknowledgement("ack-r-gw")
    finally:
        s.close()


def test_migration_from_schema_3_adds_the_tables(tmp_path: Path) -> None:
    path = tmp_path / "db.sqlite"
    db = sqlite3.connect(path)
    db.executescript(
        f"BEGIN; {SCHEMA[0]}; {SCHEMA[1]}; {SCHEMA[2]}; PRAGMA user_version = 3; COMMIT;"
    )
    db.execute("INSERT INTO sites (id, name) VALUES ('home', 'Home')")
    db.commit()
    db.close()
    s = Store(path, load_vault(tmp_path, env={}))
    try:
        assert s._db.execute("PRAGMA user_version").fetchone()[0] == len(SCHEMA) == 8
        assert s.sites() == [SITE] and s.annotations() == [] and s.acknowledgements() == []
        s.put_annotation(annotation("gw"))
        assert len(s.annotations()) == 1
    finally:
        s.close()


# annotations.stale ------------------------------------------------------------------------


def history(observations: int = 5, days: int = 30, **kw: object) -> History:
    return History(
        now=T0, since=T0 - timedelta(days=days + 1), observations=observations, days=days, **kw
    )


def stale_messages(net: Network, past: History) -> list[str]:
    return [r.message for r in stale.history_check(net, past)]  # type: ignore[misc]


def test_stale_annotations() -> None:
    net = annotated(
        merge(
            [SITE, Site(id="office", name="Office")],
            [snapshot(device("gw"), ports=[port("gw", "lan")])],
        ),
        annotation("gw", label="router"),
        annotation("gw/port/lan"),
        annotation("gw/port/9"),
        annotation("gone"),
        annotation("home/segment/20"),
        annotation("lab/segment/20"),
        annotation("office/segment/20"),
        annotation("02:00:00:00:00:01", label="old phone"),
        annotation("02:00:00:00:00:02", expected={"known_neighbour": True}),
        acknowledgement("r", "gw/port/7"),
        acknowledgement("r", finding_id="f"),
    )
    out = stale_messages(net, history())
    assert out == [
        "gw/port/9 has an annotation but is not reported by gw",
        "gone has an annotation but belongs to no device in Signalbox (removed or disabled)",
        "home/segment/20 has an annotation but is not reported by any device of the site",
        "lab/segment/20 has an annotation but belongs to a site that does not exist (lab)",
        "client/02:00:00:00:00:01 (old phone) has an annotation but has not been seen for 30 days",
        "gw/port/7 has an acknowledgement of r but is not reported by gw",
    ]
    assert stale_messages(net, History.empty()) == []
    # a client seen in the history period, or a history that is too short: not stale
    seen = ClientHistory(mac="02:00:00:00:00:01", first_seen=T0, last_seen=T0)
    assert not any(
        "old phone" in m for m in stale_messages(net, history(clients={"02:00:00:00:00:01": seen}))
    )
    short = History(now=T0, since=T0 - timedelta(days=2), observations=3, days=30)
    assert not any("old phone" in m for m in stale_messages(net, short))
    # a device that was not read completely: its objects cannot be judged
    partial = net.model_copy(update={"statuses": {"gw": DeviceStatus.PARTIAL}})
    assert not any(
        "gw/port" in m or "home/segment" in m for m in stale_messages(partial, history())
    )


def test_device_of_prefers_the_managed_device() -> None:
    net = merge(
        [SITE],
        [
            snapshot(
                device("c", role=DeviceRole.OTHER),
                extra_devices=[device("c/ap", role=DeviceRole.AP)],
            )
        ],
    )
    assert device_of(net, "c/ap/port/1") is not None and device_of(net, "c/ap/port/1").id == "c/ap"  # type: ignore[union-attr]
    assert device_of(net, "c/port/1").id == "c"  # type: ignore[union-attr]
    assert device_of(net, "x") is None


# API --------------------------------------------------------------------------------------


@pytest.fixture
def services(tmp_path: Path) -> Iterator[Services]:
    svc = build(
        tmp_path,
        env={"SIGNALBOX_AUTH_PASSWORD": PW},
        adapters={"dev": Dev},
        rules=[port_rule],
        link_sources=[],
    )
    svc.store.put_site(SITE)
    rec = DeviceRecord(
        id="gw", site_id="home", name="Gateway", role=DeviceRole.GATEWAY, adapter="dev"
    )
    svc.store.put_device(rec, {"url": "ok", "password": "pw"}, Dev.manifest.config)
    svc.store.save_snapshot(snapshot(device("gw"), ports=[port("gw", "lan"), port("gw", "wan")]))
    yield svc
    svc.close()


@pytest.fixture
def api(services: Services) -> Iterator[TestClient]:
    with TestClient(create_app(services, run_background=False)) as c:
        assert c.post("/api/login", json={"password": PW}).status_code == 200
        yield c


def test_api_annotations(api: TestClient, services: Services, tmp_path: Path) -> None:
    r = api.put(
        "/api/annotations/02:00:00:00:00:AA",
        json={"label": "printer", "expected": {"static_address": True}},
    )
    assert r.status_code == 200 and r.json()["target"] == "client/02:00:00:00:00:aa"
    assert r.json()["updated_at"]
    r = api.put(
        "/api/annotations/gw/port/lan", json={"notes": "desk", "expected": {"uplink": True}}
    )
    assert r.status_code == 200
    bad = api.put("/api/annotations/gw", json={"expected": {"uplink": True}})
    assert bad.status_code == 422 and "uplink does not apply" in bad.json()["message"]
    assert api.put("/api/annotations/client/zz", json={}).status_code == 422
    assert api.put("/api/annotations/gw", json={"tags": ["x" * 50]}).status_code == 422
    got = api.get("/api/annotations").json()
    assert [a["target"] for a in got["annotations"]] == ["client/02:00:00:00:00:aa", "gw/port/lan"]
    assert api.get("/api/network").json()["annotations"][1]["notes"] == "desk"
    exported = desired.parse(api.get("/api/annotations/export").json()["yaml"])
    assert len(exported.sites["home"].annotations) == 2
    assert api.delete("/api/annotations/gw/port/lan").status_code == 204
    assert api.delete("/api/annotations/gw/port/lan").status_code == 404
    assert api.delete("/api/annotations/client/zz").status_code == 422
    # declared in the desired state: read-only here
    (tmp_path / "desired").mkdir()
    (tmp_path / "desired" / "network.yaml").write_text(YAML)
    r = api.put(f"/api/annotations/{MAC}", json={"label": "x"})
    assert r.status_code == 409 and r.json()["error"] == "declared"
    assert api.delete(f"/api/annotations/{MAC}").status_code == 409
    sources = {a["target"]: a["source"] for a in api.get("/api/annotations").json()["annotations"]}
    assert (
        sources[client_target(MAC)] == "declared"
        and sources["client/02:00:00:00:00:aa"] == "stored"
    )
    declared_ack = next(
        a
        for a in api.get("/api/annotations").json()["acknowledgements"]
        if a["source"] == "declared"
    )
    assert api.delete(f"/api/acknowledgements/{declared_ack['id']}").status_code == 409
    # a broken desired state does not break the annotation API
    (tmp_path / "desired" / "network.yaml").write_text("sites: [")
    assert api.put(f"/api/annotations/{MAC}", json={"label": "x"}).status_code == 200


def test_api_acknowledge_a_finding(api: TestClient, services: Services) -> None:
    services.runner.evaluate()
    findings = api.get("/api/findings").json()
    lan = next(r["finding"] for r in findings if r["finding"]["objects"] == ["gw/port/lan"])
    wan = next(r["finding"] for r in findings if r["finding"]["objects"] == ["gw/port/wan"])
    assert api.post("/api/findings/nope/acknowledge", json={}).status_code == 404
    bad = api.post(
        f"/api/findings/{lan['id']}/acknowledge", json={"scope": "target", "target": "gw"}
    )
    assert bad.status_code == 422
    past = api.post(
        f"/api/findings/{lan['id']}/acknowledge", json={"until": "2020-01-01T00:00:00Z"}
    )
    assert past.status_code == 422
    r = api.post(f"/api/findings/{lan['id']}/acknowledge", json={"reason": " lab port "})
    assert (
        r.status_code == 201
        and r.json()["reason"] == "lab port"
        and r.json()["finding_id"] == lan["id"]
    )
    r2 = api.post(
        f"/api/findings/{wan['id']}/acknowledge",
        json={
            "scope": "target",
            "target": "gw/port/wan",
            "lapse_on_change": True,
            "until": "2099-01-01",
        },
    )
    assert (
        r2.status_code == 201 and r2.json()["target"] == "gw/port/wan" and r2.json()["fingerprint"]
    )
    after = {r["finding"]["id"]: r["finding"] for r in api.get("/api/findings").json()}
    assert after[lan["id"]]["acknowledged"]["reason"] == "lab port"
    assert after[wan["id"]]["acknowledged"]["target"] == "gw/port/wan"
    assert api.delete(f"/api/acknowledgements/{r.json()['id']}").status_code == 204
    assert api.delete(f"/api/acknowledgements/{r.json()['id']}").status_code == 404
    again = {r["finding"]["id"]: r["finding"] for r in api.get("/api/findings").json()}
    assert again[lan["id"]]["acknowledged"] is None


def test_plan_ignores_acknowledged_errors() -> None:
    from signalbox.changes import Plan

    f = evaluate(network(), [port_rule], now=T0)[0]
    acked = f.model_copy(update={"acknowledged": acknowledgement("test.port", f.objects[0])})
    plan = Plan(id="p", created_at=T0, changes=[], new_findings=[f, acked])
    assert plan.blocking == [f]
