import io
import json
import sys
from pathlib import Path

import pytest
from pydantic import SecretStr

from signalbox.adapters import AdapterContext, AdapterContractError
from signalbox.adapters.remote import RemoteError, config_model, load_remote, serve
from signalbox.model import DeviceRole, DeviceStatus
from signalbox.service import build, load_exporters
from signalbox.testing import assert_contract
from test_adapters import Fake

PROGRAM = [sys.executable, str(Path(__file__).parent / "programs" / "fake_remote.py")]


def ctx(cls, host: str = "192.0.2.2") -> AdapterContext:  # type: ignore[no-untyped-def]
    config = cls.manifest.config(host=host, password="pw")
    return AdapterContext(
        site_id="home", device_id="ap1", device_name="AP 1", role=DeviceRole.AP, config=config
    )


@pytest.fixture(scope="module")
def remote():  # type: ignore[no-untyped-def]
    return load_remote("fake", PROGRAM)


def test_manifest_and_config_from_the_program(remote) -> None:  # type: ignore[no-untyped-def]
    m = remote.manifest
    assert m.id == "fake" and m.capabilities == Fake.manifest.capabilities
    fields = m.config.model_fields
    assert fields["password"].annotation is SecretStr and fields["host"].is_required()


async def test_observe_out_of_process_passes_the_contract(remote) -> None:  # type: ignore[no-untyped-def]
    snap = await assert_contract(remote(ctx(remote)))
    assert snap.status is DeviceStatus.OK and snap.wlans and snap.ports


@pytest.mark.parametrize(
    ("host", "status"),
    [
        ("untrusted", DeviceStatus.UNTRUSTED),
        ("auth", DeviceStatus.AUTH_FAILED),
        ("down", DeviceStatus.UNREACHABLE),
    ],
)
async def test_failures_cross_the_process_boundary(remote, host: str, status: DeviceStatus) -> None:  # type: ignore[no-untyped-def]
    a = remote(ctx(remote, host))
    snap = await a.observe()
    assert snap.status is status and snap.errors[0].capability == "system"
    if status is DeviceStatus.UNTRUSTED:
        assert a.presented_fingerprint == "ab" * 32


def test_program_problems_are_contract_errors(tmp_path: Path) -> None:
    def prog(code: str) -> list[str]:
        p = tmp_path / f"p{abs(hash(code))}.py"
        p.write_text(code)
        return [sys.executable, str(p)]

    with pytest.raises(RemoteError, match="gave no answer"):
        load_remote("x", prog("import sys; sys.stderr.write('boom')"))
    with pytest.raises(RemoteError, match="invalid JSON"):
        load_remote("x", prog("print('{nope')"))
    with pytest.raises(RemoteError, match="without result or error"):
        load_remote("x", prog("print('{}')"))
    with pytest.raises(RemoteError, match="manifest refused"):
        load_remote("x", prog('print(\'{"error": "no"}\')'))
    with pytest.raises(RemoteError, match="invalid manifest"):
        load_remote("x", prog('print(\'{"result": {"id": "x"}}\')'))
    with pytest.raises(RemoteError, match="cannot start"):
        load_remote("x", ["/nonexistent/program"])
    with pytest.raises(RemoteError, match="the program says 'fake'"):
        load_remote("other", PROGRAM)


async def test_bad_snapshots_and_timeouts(tmp_path: Path, remote) -> None:  # type: ignore[no-untyped-def]
    def cls_with(code: str):  # type: ignore[no-untyped-def]
        p = tmp_path / f"s{abs(hash(code))}.py"
        p.write_text(code)
        return type("R", (remote,), {"command": (sys.executable, str(p))})

    bad = cls_with('print(\'{"result": {"device": 1}}\')')
    with pytest.raises(RemoteError, match="invalid snapshot"):
        await bad(ctx(remote)).observe()
    snap = await remote(ctx(remote)).observe()
    other = snap.model_copy(update={"device": snap.device.model_copy(update={"id": "zz"})})
    wrong = cls_with(f"print({json.dumps(json.dumps({'result': other.model_dump(mode='json')}))})")
    with pytest.raises(RemoteError, match="another device"):
        await wrong(ctx(remote)).observe()
    slow = cls_with("import time; time.sleep(5)")
    c = ctx(remote)
    c = AdapterContext(**{**c.__dict__, "timeout": 0.05})
    assert (await slow(c).observe()).errors[0].message == "the adapter program did not answer"
    odd = cls_with('print(\'{"error": "plain"}\')')
    assert (await odd(ctx(remote)).observe()).status is DeviceStatus.UNREACHABLE
    with pytest.raises(AdapterContractError):
        remote(
            AdapterContext(
                **{**ctx(remote).__dict__, "config": Fake.manifest.config(host="x", password="y")}
            )
        )


def test_serve_unknown_method_and_config_model_errors() -> None:
    out = io.StringIO()
    serve(Fake, io.StringIO('{"method": "x"}\n'), out)
    assert json.loads(out.getvalue())["error"]["message"] == "unknown method"
    with pytest.raises(RemoteError, match="must be an object"):
        config_model("x", {"type": "array"})
    with pytest.raises(RemoteError, match="simple type"):
        config_model("x", {"type": "object", "properties": {"a": {"type": "array"}}})
    m = config_model(
        "x", {"type": "object", "properties": {"n": {"type": "integer", "default": 3}}}
    )
    assert m().n == 3  # type: ignore[call-arg, attr-defined]


def test_configured_remote_adapters_are_loaded(tmp_path: Path) -> None:
    (tmp_path / "signalbox.yaml").write_text(
        "plugins: {remote_adapters: {fake: " + json.dumps(PROGRAM) + "}}\n"
    )
    svc = build(tmp_path, env={"SIGNALBOX_AUTH_PASSWORD": "x" * 12}, rules=[], link_sources=[])
    try:
        assert "fake" in svc.adapters and "openwrt" in svc.adapters
    finally:
        svc.close()
    (tmp_path / "signalbox.yaml").write_text(
        "plugins: {remote_adapters: {openwrt: " + json.dumps(PROGRAM) + "}}\n"
    )
    with pytest.raises(ValueError, match="id of an installed adapter"):
        build(tmp_path, env={"SIGNALBOX_AUTH_PASSWORD": "x" * 12}, rules=[], link_sources=[])


def test_exporter_plugins(monkeypatch: pytest.MonkeyPatch) -> None:
    from types import SimpleNamespace

    import signalbox.service as service

    seen: list[int] = []
    eps = [SimpleNamespace(name="e", load=lambda: lambda net, f: seen.append(len(f)))]
    monkeypatch.setattr(service, "entry_points", lambda group: eps)
    (fn,) = load_exporters()
    fn(None, [1, 2])  # type: ignore[arg-type]
    assert seen == [2]
    monkeypatch.setattr(
        service, "entry_points", lambda group: [SimpleNamespace(name="b", load=lambda: 5)]
    )
    with pytest.raises(TypeError, match="not callable"):
        load_exporters()


@pytest.mark.parametrize(
    ("host", "kind"),
    [("192.0.2.2", None), ("untrusted", "untrusted"), ("auth", "auth"), ("down", "unreachable")],
)
def test_serve_in_process(host: str, kind: str | None) -> None:
    sys.path.insert(0, str(Path(__file__).parent / "programs"))
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "prog", Path(__file__).parent / "programs" / "fake_remote.py"
    )
    assert spec and spec.loader
    source = (Path(__file__).parent / "programs" / "fake_remote.py").read_text()
    namespace: dict[str, object] = {"__file__": str(Path(__file__).parent / "programs" / "x.py")}
    exec(source.replace("raise SystemExit(serve(Program))", ""), namespace)
    program = namespace["Program"]
    out = io.StringIO()
    req = {
        "method": "observe",
        "context": {
            "site_id": "home",
            "device_id": "ap1",
            "device_name": "AP 1",
            "role": "ap",
            "config": {"host": host, "password": "pw"},
        },
    }
    serve(program, io.StringIO(json.dumps(req) + "\n"), out)  # type: ignore[arg-type]
    answer = json.loads(out.getvalue())
    if kind is None:
        assert answer["result"]["device"]["id"] == "ap1"
    else:
        assert answer["error"]["kind"] == kind
    manifest = io.StringIO()
    serve(program, io.StringIO('{"method": "manifest"}\n'), manifest)  # type: ignore[arg-type]
    assert (
        json.loads(manifest.getvalue())["result"]["config_schema"]["properties"]["password"][
            "format"
        ]
        == "password"
    )
