"""Integration tests against the real device software (#136).

Each target (a VM or container started by ``.github/workflows/integration.yml``) is described
by environment variables ``IT_<TARGET>_<NAME>`` (not ``SIGNALBOX_*``: Signalbox refuses unknown
settings with that prefix). Without them the tests of that target are skipped; with
``REQUIRE_INTEGRATION=1`` (set in CI) a missing target fails instead.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

HERE = Path(__file__).parent


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    for item in items:
        if HERE in Path(str(item.fspath)).parents:
            item.add_marker(pytest.mark.integration)


def env_target(target: str, *names: str) -> dict[str, str]:
    """The variables ``IT_<target>_<name>``; skip (or fail in CI) when one is missing."""
    values = {n: os.environ.get(f"IT_{target}_{n}", "") for n in names}
    missing = [f"IT_{target}_{n}" for n, v in values.items() if not v]
    if missing:
        message = f"no {target} target configured ({', '.join(missing)})"
        if os.environ.get("REQUIRE_INTEGRATION") == "1":
            pytest.fail(message)
        pytest.skip(message)
    return values
