"""Wiring: configuration, store, adapters, rules and runner for one data directory."""

from __future__ import annotations

import os
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from importlib.metadata import entry_points
from pathlib import Path

from signalbox.adapters import Adapter, load_adapters
from signalbox.adapters.remote import load_remote
from signalbox.config import Config, load
from signalbox.desired import load as desired_load
from signalbox.model import Network, set_passphrase_digest_key
from signalbox.rules import Finding, Rule, load_rules
from signalbox.runner import LinkSource, Runner
from signalbox.secrets import load_vault
from signalbox.store import Store

DEFAULT_DATA = Path("/data")


@dataclass
class Services:
    data_dir: Path
    config: Config
    store: Store
    adapters: Mapping[str, type[Adapter]]
    rules: list[Rule]
    runner: Runner

    def close(self) -> None:
        self.runner.stop()
        self.store.close()


def data_dir_from(arg: str | None, env: Mapping[str, str] | None = None) -> Path:
    env = os.environ if env is None else env
    return Path(arg or env.get("SIGNALBOX_DATA") or DEFAULT_DATA)


def build(
    data_dir: Path,
    env: Mapping[str, str] | None = None,
    adapters: Mapping[str, type[Adapter]] | None = None,
    rules: list[Rule] | None = None,
    link_sources: list[LinkSource] | None = None,
) -> Services:
    config = load(data_dir, env)
    vault = load_vault(data_dir, env)
    store = Store(data_dir / "signalbox.sqlite", vault)
    set_passphrase_digest_key(vault.derive_key("passphrase-digest"))
    if adapters is None:
        adapters = dict(load_adapters())
        for aid, command in config.plugins.remote_adapters.items():
            if aid in adapters:
                raise ValueError(f"remote adapter {aid!r} has the id of an installed adapter")
            adapters[aid] = load_remote(aid, command)
    rules = load_rules() if rules is None else rules
    if link_sources is None:
        link_sources = _default_link_sources()
    runner = Runner(
        store,
        adapters,
        rules,
        config,
        link_sources=link_sources,
        desired_source=lambda: desired_load(data_dir),
    )
    runner.listeners.extend(load_exporters())
    return Services(data_dir, config, store, adapters, rules, runner)


Exporter = Callable[[Network, list[Finding]], None]


def load_exporters(group: str = "signalbox.exporters") -> list[Exporter]:
    """Exporter plugins: called with the network and the findings after every round."""
    out: list[Exporter] = []
    for ep in entry_points(group=group):
        target = ep.load()
        if not callable(target):
            raise TypeError(f"exporter {ep.name} is not callable")
        out.append(target)
    return out


def _default_link_sources() -> list[LinkSource]:
    from signalbox.topology import discovered_links

    return [discovered_links]
