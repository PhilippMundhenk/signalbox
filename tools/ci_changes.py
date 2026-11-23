"""Decide which CI jobs a change needs (#245).

    python tools/ci_changes.py ci|integration [--base SHA] [--head SHA] [--files FILE...]

Prints ``name=value`` lines (for $GITHUB_OUTPUT). Pushes to main, the schedule and manual runs
select everything. Pull requests select by the changed paths; a path that no rule knows counts
as code, so a new kind of file never silently skips a job. The rules are documented in
CONTRIBUTING.md.
"""

from __future__ import annotations

import fnmatch
import json
import os
import subprocess
import sys

ADAPTERS = ("opnsense", "openwrt", "mikrotik", "omada", "linux")

# Shared code that every integration target depends on.
INTEGRATION_SHARED = (
    "src/signalbox/adapters/__init__.py",
    "src/signalbox/adapters/https.py",
    "src/signalbox/adapters/ssh.py",
    "src/signalbox/adapters/provision.py",
    "src/signalbox/model.py",
    "src/signalbox/deploy.py",
    "src/signalbox/changes.py",
    "src/signalbox/discovery*",
    "src/signalbox/recording.py",
    "src/signalbox/testing.py",
    "pyproject.toml",
    "tests/integration/__init__.py",
    "tests/integration/conftest.py",
    "tests/integration/lab.py",
    ".github/workflows/integration.yml",
    "tools/ci_changes.py",
)

DOCS = ("docs/*", "*.md", ".github/ISSUE_TEMPLATE/*")
PYTHON_VERSIONS = ("3.11", "3.12", "3.13")
CORE = (
    "src/signalbox/*.py",
    "src/signalbox/rules/*",
    "src/signalbox/adapters/*",
    "src/signalbox/sim/*",
    "src/signalbox/discovery/*",
)
E2E = ("src/signalbox/web/*", "tests/e2e/*", "tools/screenshots.py", *CORE)
DOCKER = (
    "Dockerfile",
    "docker-compose.yml",
    "pyproject.toml",
    "src/*",
    "tools/smoke.sh",
    ".dockerignore",
)
HA = ("src/signalbox/mqtt*.py", "tests/test_mqtt*.py", "tools/validate_ha_discovery.py")
CI_SELF = (".github/workflows/ci.yml", "tools/ci_changes.py")


def match(path: str, patterns: tuple[str, ...]) -> bool:
    # fnmatch's "*" also crosses "/", so "dir/*" means everything below dir
    return any(fnmatch.fnmatchcase(path, p) for p in patterns)


def any_match(files: list[str], patterns: tuple[str, ...]) -> bool:
    return any(match(f, patterns) for f in files)


def integration(files: list[str] | None) -> dict[str, object]:
    if files is None or any_match(files, INTEGRATION_SHARED):
        return dict.fromkeys(ADAPTERS, True)
    out: dict[str, object] = {}
    for a in ADAPTERS:
        own = (
            f"src/signalbox/adapters/{a}/*",
            f"src/signalbox/sim/{a}*",
            f"tests/integration/test_{a}_real.py",
            f"tools/integration/{a}/*",
            f"docs/adapters/{a}.md",
        )
        out[a] = any_match(files, own)
    return out


def ci(files: list[str] | None) -> dict[str, object]:
    if files is None or any_match(files, CI_SELF):
        return {
            "code": True,
            "docs": True,
            "pythons": list(PYTHON_VERSIONS),
            "e2e": True,
            "docker": True,
            "home_assistant": True,
        }
    # a *.md below src/, tests/ or tools/ is not documentation
    code_files = [
        f for f in files if not match(f, DOCS) or f.startswith(("src/", "tests/", "tools/"))
    ]
    code = bool(code_files)
    wide = any_match(files, ("src/*", "pyproject.toml"))
    return {
        "code": code,
        # the quick docs test is only needed when the full test job does not run
        "docs": not code,
        "pythons": list(PYTHON_VERSIONS) if wide else ["3.13"],
        "e2e": any_match(code_files, E2E),
        "docker": any_match(code_files, DOCKER),
        "home_assistant": any_match(code_files, HA),
    }


def changed_files(base: str, head: str) -> list[str]:
    out = subprocess.run(
        ["git", "diff", "--name-only", f"{base}...{head}"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    return [line for line in out.splitlines() if line]


def main(argv: list[str]) -> int:
    mode = argv[0]
    opts = argv[1:]
    files: list[str] | None
    if "--files" in opts:
        files = opts[opts.index("--files") + 1 :]
    else:
        event = os.environ.get("GITHUB_EVENT_NAME", "")
        base = opts[opts.index("--base") + 1] if "--base" in opts else ""
        head = opts[opts.index("--head") + 1] if "--head" in opts else "HEAD"
        files = changed_files(base, head) if event == "pull_request" and base else None
    result = integration(files) if mode == "integration" else ci(files)
    for key, value in result.items():
        text = json.dumps(value) if isinstance(value, list) else str(value).lower()
        print(f"{key}={text}")
    if files is not None:
        print(f"{len(files)} changed file(s)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
