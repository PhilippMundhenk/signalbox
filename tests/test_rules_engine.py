from collections.abc import Iterator
from types import SimpleNamespace

import pytest

import signalbox.rules as engine
from factories import SITE, device, snapshot
from signalbox.merge import merge
from signalbox.model import DeviceStatus, Network, ReadError
from signalbox.rules import (
    Result,
    RuleSettings,
    Severity,
    evaluate,
    finding_id,
    found,
    incomplete,
    load_rules,
    rule,
)


@rule("test.devices", "Every device", Severity.WARNING, "Reports every device.")
def every_device(net: Network) -> Iterator[Result]:
    for d in net.devices:
        yield found(f"{d.name} exists", [d.id], fix="Nothing to fix.")
        yield incomplete(f"{d.name} not fully checked", [d.id])


@rule("test.boom", "Broken", Severity.INFO, "Always crashes.")
def boom(net: Network) -> Iterator[Result]:
    raise RuntimeError("bad data")
    yield  # pragma: no cover


def net_with(*snaps: object) -> Network:
    return merge([SITE], snaps)  # type: ignore[arg-type]


def test_findings_are_stable_sorted_and_marked() -> None:
    net = net_with(snapshot(device("gw")), snapshot(device("ap")))
    first = evaluate(net, [every_device])
    assert first == evaluate(net, [every_device])
    assert [f.severity for f in first] == ["warning", "warning", "info", "info"]
    real = [f for f in first if not f.incomplete]
    assert {f.message for f in real} == {"gw exists", "ap exists"}
    assert real[0].fix == "Nothing to fix." and real[0].title == "Every device"
    assert all(f.id == finding_id("test.devices", f.objects, "") for f in real)
    assert all(f.incomplete for f in first if f.severity == "info")


def test_key_separates_findings_on_same_objects() -> None:
    assert finding_id("r", ["a"], "x") != finding_id("r", ["a"], "y")
    assert finding_id("r", ["a", "b"]) == finding_id("r", ["b", "a"])


def test_settings_disable_and_override_severity() -> None:
    net = net_with(snapshot(device("gw")))
    out = evaluate(net, [every_device], {"test.devices": RuleSettings(severity=Severity.ERROR)})
    assert {f.severity for f in out if not f.incomplete} == {"error"}
    assert evaluate(net, [every_device], {"test.devices": RuleSettings(enabled=False)}) == []


def test_result_severity_beats_rule_default() -> None:
    @rule("test.sev", "Sev", Severity.INFO, "x")
    def sev(net: Network) -> Iterator[Result]:
        yield found("bad", ["x"], severity=Severity.ERROR)

    assert evaluate(Network(), [sev])[0].severity == "error"


def test_crashing_rule_is_an_error_finding() -> None:
    (f,) = evaluate(Network(), [boom])
    assert f.severity == "error" and f.rule_id == "test.boom"
    assert f.message == "rule failed: RuntimeError: bad data"


@pytest.mark.parametrize(
    ("status", "text", "fix"),
    [
        (DeviceStatus.UNREACHABLE, "gw is unreachable: refused", "address"),
        (DeviceStatus.AUTH_FAILED, "gw refused the login: refused", "password"),
        (DeviceStatus.UNTRUSTED, "gw presented a certificate that is not trusted: refused", "fin"),
    ],
)
def test_read_errors_become_findings(status: DeviceStatus, text: str, fix: str) -> None:
    snap = snapshot(
        device("gw"),
        status=status,
        errors=[ReadError(device_id="gw", capability="system", message="refused")],
    )
    (f,) = evaluate(net_with(snap), [])
    assert f.rule_id == "signalbox.read" and f.message == text and fix in (f.fix or "")
    assert f.severity == "warning" and f.objects == ["gw"]


def test_partial_read_error_and_unknown_device() -> None:
    snap = snapshot(
        device("gw"),
        status=DeviceStatus.PARTIAL,
        errors=[ReadError(device_id="gw", capability="dhcp", message="timeout")],
    )
    net = net_with(snap)
    orphan = net.model_copy(
        update={
            "errors": [*net.errors, ReadError(device_id="ghost", capability="dns", message="x")]
        }
    )
    out = evaluate(orphan, [])
    assert [f.message for f in out] == [
        "ghost: could not read dns: x",
        "gw: could not read dhcp: timeout",
    ]
    assert all(f.fix is None for f in out)
    assert evaluate(orphan, [], {"signalbox.read": RuleSettings(enabled=False)}) == []


def _eps(monkeypatch: pytest.MonkeyPatch, *targets: object) -> None:
    eps = [SimpleNamespace(name=f"ep{i}", load=lambda t=t: t) for i, t in enumerate(targets)]
    monkeypatch.setattr(engine, "entry_points", lambda group: eps)


def test_load_rules(monkeypatch: pytest.MonkeyPatch) -> None:
    _eps(monkeypatch, [every_device], boom)
    assert [r.id for r in load_rules()] == ["test.boom", "test.devices"]
    assert list(engine.all_rule_ids([boom])) == ["signalbox.read", "test.boom"]


def test_load_rules_rejects(monkeypatch: pytest.MonkeyPatch) -> None:
    _eps(monkeypatch, "not a rule")
    with pytest.raises(TypeError):
        load_rules()
    _eps(monkeypatch, boom, boom)
    with pytest.raises(ValueError, match="two rules"):
        load_rules()


def test_builtin_rules_are_registered() -> None:
    from signalbox.rules.builtin import RULES

    assert load_rules() == sorted(RULES, key=lambda r: r.id)


def test_every_builtin_rule_is_documented() -> None:
    from pathlib import Path

    from signalbox.rules.builtin import RULES

    text = (Path(__file__).resolve().parent.parent / "docs" / "RULES.md").read_text()
    missing = [r.id for r in RULES if f"### `{r.id}`" not in text]
    assert not missing, f"document these rules in docs/RULES.md: {missing}"
