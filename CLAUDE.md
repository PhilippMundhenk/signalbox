# Signalbox: notes for Claude Code

- Commands: `make lint`, `make test` (95 % coverage gate), `make e2e`, `make smoke`, `make demo`.
  Without make: `.venv/bin/ruff check . && .venv/bin/ruff format --check . && .venv/bin/mypy`,
  `.venv/bin/pytest -m "not e2e" --cov`. Run lint last before every commit.
- Design: docs/DESIGN.md; decisions: docs/adr/. Work log: GitHub issues, commit subjects end in `(#N)`.
- Core code never imports vendor code: adapters live in `src/signalbox/adapters/<id>/` and only
  return model objects (`src/signalbox/model.py`). Every adapter has a simulator in
  `src/signalbox/sim/` and passes `signalbox.testing` contract tests against it.
- New model field: model, `make schema` (docs/schema.json is checked by a test), rules/UI if used.
- UI under `src/signalbox/web/static/` has no build step. Strict CSP: no inline script or style,
  never put untrusted text into `innerHTML`.
- Localhost HTTP from a shell in the sandbox needs `NO_PROXY=127.0.0.1,localhost`.
- No private data anywhere: simulator data uses documentation prefixes (192.0.2.0/24,
  198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32) and locally administered MACs (02:...).
