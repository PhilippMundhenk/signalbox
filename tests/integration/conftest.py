"""Integration tests against the real device software (#136).

Every test in this directory is marked ``integration``. A test asks for its target with the
``target`` fixture (``target("openwrt")``), which reads the target from environment variables:

    IT_<NAME>_URL              required: where the device answers (for example its API URL)
    IT_<NAME>_USER             login (read-only where the device has such a role)
    IT_<NAME>_PASSWORD         its password
    IT_<NAME>_WRITE_USER       login with write access (optional)
    IT_<NAME>_WRITE_PASSWORD   its password
    IT_<NAME>_PIN              SHA-256 certificate fingerprint to pin (optional: else the test
                               reads the certificate itself, trust on first use)
    IT_<NAME>_<ANYTHING>       anything else a target needs, in ``Target.extra``

(``IT_`` and not ``SIGNALBOX_``: Signalbox refuses unknown ``SIGNALBOX_*`` variables as
settings.) A target that is not configured skips its tests, unless ``REQUIRE_INTEGRATION`` is
set (CI): then they fail. The targets themselves (QEMU images, containers) are built and started
by tools/integration/<name>/ and .github/workflows/integration.yml; see docs/TESTING.md.
"""

from __future__ import annotations

import hashlib
import os
import socket
import ssl
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

import pytest

HERE = Path(__file__).parent


@dataclass(frozen=True)
class Target:
    """A real device (or emulated one) to test against."""

    name: str
    url: str
    username: str
    password: str
    write_username: str | None = None
    write_password: str | None = None
    pin: str | None = None
    extra: Mapping[str, str] = field(default_factory=dict)

    @property
    def host(self) -> str:
        return urlsplit(self.url).hostname or ""

    @property
    def port(self) -> int:
        parts = urlsplit(self.url)
        return parts.port or (443 if parts.scheme == "https" else 80)

    def fingerprint(self) -> str:
        """The pinned fingerprint, else the one the device presents now."""
        return self.pin or certificate_fingerprint(self.host, self.port)


def target_from_env(name: str, environ: Mapping[str, str] | None = None) -> Target | None:
    env = os.environ if environ is None else environ
    prefix = f"IT_{name.upper()}_"
    url = env.get(prefix + "URL")
    if not url:
        return None
    known = {"URL", "USER", "PASSWORD", "WRITE_USER", "WRITE_PASSWORD", "PIN"}
    return Target(
        name=name,
        url=url,
        username=env.get(prefix + "USER", ""),
        password=env.get(prefix + "PASSWORD", ""),
        write_username=env.get(prefix + "WRITE_USER") or None,
        write_password=env.get(prefix + "WRITE_PASSWORD") or None,
        pin=env.get(prefix + "PIN") or None,
        extra={
            k[len(prefix) :]: v
            for k, v in env.items()
            if k.startswith(prefix) and k[len(prefix) :] not in known
        },
    )


def certificate_fingerprint(host: str, port: int, timeout: float = 10) -> str:
    """SHA-256 of the certificate a TLS server presents (lower-case hex, no colons)."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with (
        socket.create_connection((host, port), timeout=timeout) as raw,
        ctx.wrap_socket(raw, server_hostname=host) as tls,
    ):
        der = tls.getpeercert(binary_form=True)
    assert der, "the server sent no certificate"
    return hashlib.sha256(der).hexdigest()


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    for item in items:
        if HERE in Path(str(item.path)).parents:
            item.add_marker(pytest.mark.integration)


@pytest.fixture(scope="session")
def target() -> Callable[[str], Target]:
    """``target("openwrt")``: the configured target, else skip (or fail in CI)."""

    def get(name: str) -> Target:
        found = target_from_env(name)
        if found is None:
            message = f"integration target {name!r} not configured (IT_{name.upper()}_URL)"
            if os.environ.get("REQUIRE_INTEGRATION"):
                pytest.fail(message + " but REQUIRE_INTEGRATION is set")
            pytest.skip(message)
        return found

    return get
