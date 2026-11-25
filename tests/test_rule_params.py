"""Typed rule parameters and per-scope rule settings (#187, ADR 0027)."""

from pathlib import Path
from typing import Any

import pytest
import yaml

from factories import (
    SITE,
    T0,
    MiB,
    annotated,
    annotation,
    device,
    dhcp_server,
    health,
    snapshot,
    storage,
)
from signalbox.config import ConfigError
from signalbox.merge import merge
from signalbox.model import DeviceRole, Network, Segment, SegmentPurpose, Site, segment_id
from signalbox.rules import (
    ParamOrigin,
    RuleParams,
    RuleSettings,
    ScopeMatch,
    Severity,
    check_rule_settings,
    ctx,
    evaluate,
    param,
    rule,
    rules_schema,
)
from signalbox.rules._params import NO_FACTS, Resolver, bind, facts_of
from signalbox.rules.addressing import LeaseParams
from signalbox.rules.health import RULES as HEALTH
from signalbox.rules.health import StorageParams, storage_full
from signalbox.sightings import History

LAB = Site(id="lab", name="Lab")


def full(pct: int) -> Any:
    return health(storage=[storage("/overlay", total_bytes=100 * MiB, used_bytes=pct * MiB)])


def network(**devices: tuple[str, DeviceRole, int]) -> Network:
    """Devices by id: (site, role, storage fill in percent)."""
    snaps = [
        snapshot(device(i, role, site_id=site, health=full(pct)))
        for i, (site, role, pct) in devices.items()
    ]
    return merge([SITE, LAB], snaps)


def settings(raw: dict[str, Any]) -> dict[str, RuleSettings]:
    return {k: RuleSettings.model_validate(v) for k, v in raw.items()}


def run(net: Network, raw: dict[str, Any] | None = None) -> dict[str, str]:
    """Device id -> severity of its storage finding."""
    found = evaluate(
        net,
        [storage_full],
        settings(raw or {}),
        History(now=T0, since=T0, observations=1),
    )
    return {f.objects[0]: f.severity.value for f in found if f.rule_id == "health.storage-full"}


def test_defaults_are_unchanged_and_recorded() -> None:
    n = network(a=("home", DeviceRole.AP, 95), b=("home", DeviceRole.AP, 99))
    assert run(n) == {"a": "warning", "b": "error"}
    f = evaluate(n, [storage_full])[0]
    assert [(p.name, p.value, p.unit, p.origin) for p in f.parameters] == [
        ("warn_pct", 90.0, "%", ParamOrigin.DEFAULT),
        ("error_pct", 98.0, "%", ParamOrigin.DEFAULT),
    ]


def test_configuration_without_params_keeps_working() -> None:
    n = network(a=("home", DeviceRole.AP, 95))
    assert run(n, {"health.storage-full": {"severity": "info"}}) == {"a": "info"}
    assert run(n, {"health.storage-full": {"enabled": False}}) == {}


def test_rule_wide_params() -> None:
    n = network(a=("home", DeviceRole.AP, 95), b=("home", DeviceRole.AP, 97))
    raw = {"health.storage-full": {"params": {"warn_pct": 96, "error_pct": 97}}}
    assert run(n, raw) == {"b": "error"}
    f = evaluate(n, [storage_full], settings(raw))[0]
    assert {p.name: (p.value, p.origin) for p in f.parameters} == {
        "warn_pct": (96, ParamOrigin.RULE),
        "error_pct": (97, ParamOrigin.RULE),
    }


def test_site_scope_overrides_one_parameter() -> None:
    n = network(a=("home", DeviceRole.AP, 95), b=("lab", DeviceRole.AP, 95))
    raw = {
        "health.storage-full": {"scopes": [{"match": {"site": "Lab"}, "params": {"warn_pct": 97}}]}
    }
    assert run(n, raw) == {"a": "warning"}
    n2 = network(b=("lab", DeviceRole.AP, 97))
    f = evaluate(n2, [storage_full], settings(raw))[0]
    by_name = {p.name: p for p in f.parameters}
    assert by_name["warn_pct"].origin is ParamOrigin.SCOPE
    assert by_name["warn_pct"].scope == "site=Lab"
    assert by_name["error_pct"].origin is ParamOrigin.DEFAULT


def test_scope_disables_enables_and_changes_severity() -> None:
    n = network(
        a=("home", DeviceRole.AP, 95),
        b=("home", DeviceRole.SWITCH, 95),
        c=("lab", DeviceRole.AP, 95),
    )
    off = {"health.storage-full": {"scopes": [{"match": {"device_role": "ap"}, "enabled": False}]}}
    assert run(n, off) == {"b": "warning"}
    only_lab = {
        "health.storage-full": {
            "enabled": False,
            "scopes": [{"match": {"site": "lab"}, "enabled": True}],
        }
    }
    assert run(n, only_lab) == {"c": "warning"}
    louder = {"health.storage-full": {"scopes": [{"match": {"device": "b"}, "severity": "error"}]}}
    assert run(n, louder) == {"a": "warning", "b": "error", "c": "warning"}


def test_most_specific_scope_wins_then_the_first_listed() -> None:
    n = network(a=("lab", DeviceRole.AP, 95), b=("lab", DeviceRole.AP, 95))
    raw = {
        "health.storage-full": {
            "scopes": [
                {"match": {"device": "a"}, "params": {"warn_pct": 94}},
                {"match": {"site": "lab"}, "params": {"warn_pct": 99}},
            ]
        }
    }
    assert run(n, raw) == {"a": "warning"}
    tie = {
        "health.storage-full": {
            "scopes": [
                {"match": {"site": "lab"}, "params": {"warn_pct": 99}},
                {"match": {"site": "lab"}, "params": {"warn_pct": 50}},
            ]
        }
    }
    assert run(n, tie) == {}
    # more selectors are more specific than fewer of the same rank
    both = {
        "health.storage-full": {
            "scopes": [
                {"match": {"device_role": "ap"}, "params": {"warn_pct": 99}},
                {"match": {"device_role": "ap", "site": "lab"}, "params": {"warn_pct": 50}},
            ]
        }
    }
    assert run(n, both) == {"a": "warning", "b": "warning"}


def test_tag_scope_from_annotations() -> None:
    n = annotated(
        network(a=("home", DeviceRole.AP, 95), b=("home", DeviceRole.AP, 95)),
        annotation("a", tags=["spare"]),
    )
    raw = {"health.storage-full": {"scopes": [{"match": {"tag": "spare"}, "enabled": False}]}}
    assert run(n, raw) == {"b": "warning"}


def test_segment_selectors_reach_a_dhcp_server() -> None:
    gw = device("gw")
    srv = dhcp_server("gw", 30, lease_seconds=3 * 86400)
    seg = Segment(
        id=segment_id("home", 30), site_id="home", vlan=30, name="Lab", purpose=SegmentPurpose.LAB
    )
    n = Network(sites=[SITE], devices=[gw], segments=[seg], dhcp_servers=[srv])
    facts = facts_of(n, srv.id)
    assert {"30", "Lab", seg.id} <= facts.segment
    assert facts.segment_purpose is SegmentPurpose.LAB
    assert facts.device == {"gw"} and facts.site == {"home", "Home"}
    assert ScopeMatch(segment="30", segment_purpose=SegmentPurpose.LAB).matches(facts)
    assert not ScopeMatch(segment="20").matches(facts)
    r = Resolver(
        n,
        settings(
            {
                "dhcp.lease-time": {
                    "scopes": [{"match": {"segment": "30"}, "params": {"max_seconds": 60}}]
                }
            }
        ),
        {},
    )
    assert r.params(LeaseParams, srv.id).max_seconds == 60
    assert r.params(LeaseParams, None).max_seconds == LeaseParams().max_seconds


def test_facts_of_other_objects() -> None:
    n = Network(sites=[SITE], devices=[device("gw")])
    assert facts_of(n, None) is NO_FACTS
    assert facts_of(n, "nothing/with/this/id") is NO_FACTS
    assert facts_of(n, SITE).site == {"home", "Home"}
    assert facts_of(n, n.devices[0]).device_role is DeviceRole.GATEWAY


def test_ctx_params_outside_evaluate_are_the_defaults() -> None:
    assert ctx.params(StorageParams, "anything") == StorageParams()

    class Loose(RuleParams):
        x: int = param(1, unit="count", description="x")

    with pytest.raises(TypeError, match="not bound"):
        ctx.params(Loose)


def test_parameter_models_must_be_declared_with_param() -> None:
    class Bare(RuleParams):
        x: int = 1

    with pytest.raises(TypeError, match="param"):
        bind(Bare, "test.bare")

    class Once(RuleParams):
        x: int = param(1, unit="count", description="x")

    @rule("test.once", "t", Severity.INFO, "e", params=Once)
    def once(net: Network) -> Any:
        return iter(())

    assert once.params is Once
    with pytest.raises(ValueError, match="already belongs"):
        bind(Once, "test.other")


def test_scope_needs_a_selector() -> None:
    with pytest.raises(ValueError, match="at least one selector"):
        RuleSettings.model_validate({"scopes": [{"match": {}, "enabled": False}]})


def test_configuration_errors_name_the_setting() -> None:
    raw = {
        "health.storage-full": {
            "params": {"warn_pct": "lots"},
        },
        "dhcp.lease-time": {"params": {"min_seconds": 0, "typo": 1}},
        "wifi.channel-busy": {"scopes": [{"match": {"site": "lab"}, "params": {"info_pct": 500}}]},
        "dhcp.one-server": {"params": {"x": 1}},
        "not.installed": {"params": {"x": 1}},
        "also.not.installed": {"enabled": False},
    }
    from signalbox.rules import load_rules

    errors = check_rule_settings(load_rules(), settings(raw))
    text = "\n".join(errors)
    assert "rules.health.storage-full.params.warn_pct:" in text
    assert "rules.dhcp.lease-time.params.min_seconds:" in text
    assert "rules.dhcp.lease-time.params.typo:" in text
    assert "rules.wifi.channel-busy.scopes.0.params.info_pct:" in text
    assert "rules.dhcp.one-server.params: dhcp.one-server has no parameters" in text
    assert "rules.not.installed.params: not.installed is not an installed rule" in text
    assert "also.not.installed" not in text
    assert (
        check_rule_settings(load_rules(), settings({"time.offset": {"params": {"max_seconds": 5}}}))
        == []
    )


def test_bad_parameters_stop_the_start(tmp_path: Path) -> None:
    from signalbox.service import build

    (tmp_path / "signalbox.yaml").write_text(
        yaml.safe_dump({"rules": {"health.storage-full": {"params": {"warn_pct": 101}}}})
    )
    with pytest.raises(ConfigError, match=r"rules\.health\.storage-full\.params\.warn_pct"):
        build(tmp_path, env={}, adapters={}, rules=HEALTH, link_sources=[])


def test_schema_lists_every_parameter() -> None:
    from signalbox.rules import load_rules

    schema = rules_schema(load_rules())
    props = schema["properties"]
    assert "health.storage-full" in props and "poe.budget" in props
    ref = props["health.storage-full"]["properties"]["params"]["$ref"]
    storage_schema = schema["$defs"][ref.rsplit("/", 1)[1]]
    assert storage_schema["properties"]["warn_pct"]["unit"] == "%"
    assert storage_schema["properties"]["warn_pct"]["default"] == 90.0
    assert "ScopeMatch" in schema["$defs"]
