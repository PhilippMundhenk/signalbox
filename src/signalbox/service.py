"""Wiring: configuration, store, adapters, rules and runner for one data directory."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from signalbox.adapters import Adapter, load_adapters
from signalbox.config import Config, load
from signalbox.desired import load as desired_load
from signalbox.rules import Rule, load_rules
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
    store = Store(data_dir / "signalbox.sqlite", load_vault(data_dir, env))
    adapters = load_adapters() if adapters is None else adapters
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
    return Services(data_dir, config, store, adapters, rules, runner)


def _default_link_sources() -> list[LinkSource]:
    from signalbox.topology import discovered_links

    return [discovered_links]
