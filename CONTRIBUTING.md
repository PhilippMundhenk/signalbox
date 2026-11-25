# Contributing

Bug reports, fixes, adapters for more devices and small focused features are welcome. Work is
tracked in [GitHub issues](https://github.com/PhilippMundhenk/signalbox/issues); open one before
a larger change.

## Setup and checks

Python 3.11 or newer.

    make install   # virtualenv in .venv with the dev dependencies
    make lint      # ruff check, ruff format --check, mypy --strict
    make test      # unit and simulator tests, 95 % line coverage gate
    make e2e       # browser tests (Playwright) against the device simulators
    make smoke     # builds the container and drives it
    make integration  # against the real device software (QEMU/containers; CI runs these)

`make test` never talks to real devices: every adapter ships a simulator, and the tests run the
real adapter code against it. The integration tests run the same adapters against the real
device software (official images in QEMU, vendor containers) in GitHub Actions; when the two
disagree, fix the adapter and make the simulator answer like the real software
([docs/TESTING.md](docs/TESTING.md)). Add tests with the code, not after. Run `make lint` as the
last step before every commit.

## Pull requests

Branch off `main` and open a PR; CI runs the checks, the browser tests and the container build.
Commit subjects reference the issue (`... (#12)`), bodies say what and why.

Pull requests start only the jobs their changed paths need (`tools/ci_changes.py`; pushes to
`main`, the nightly run and manual runs start everything). Require the checks `ci-ok` and
`integration-ok` in branch protection: they pass when jobs are skipped, fail when a needed job fails.

| Change | What runs |
| --- | --- |
| `docs/**`, `*.md`, issue templates only | lint, generated-docs test, secret scan |
| any other code, tests, tools | lint, tests on Python 3.13, secret scan |
| `src/**` or `pyproject.toml` | the above, plus tests on Python 3.11 and 3.12 |
| `src/signalbox/web/**`, `tests/e2e/**`, core code (`src/signalbox/*.py`, rules, adapters, sim, discovery) | plus browser tests |
| `Dockerfile`, `docker-compose.yml`, `pyproject.toml`, `src/**` | plus the Docker smoke test |
| `src/signalbox/mqtt*.py`, `tests/test_mqtt*.py`, `tools/validate_ha_discovery.py` | plus the Home Assistant schema check |
| `src/signalbox/adapters/<id>/`, `sim/<id>*`, `tests/integration/test_<id>_real.py`, `tools/integration/<id>/`, `docs/adapters/<id>.md` | the integration job of that target (opnsense, openwrt, mikrotik, omada, unifi, edgeos, linux) |
| shared adapter code (`adapters/__init__.py`, `https.py`, `ssh.py`, `provision.py`, `model.py`, `deploy.py`, `changes.py`, `discovery*`, `recording.py`, `testing.py`, `pyproject.toml`, `tests/integration/conftest.py`, `lab.py`) | all integration targets |
| the workflow files or `tools/ci_changes.py` | everything |

## Releases

`git tag vX.Y.Z && git push --tags` builds the image tags `X.Y.Z`, `X.Y`, `latest` and a GitHub
release. Add the notable changes to `CHANGELOG.md` first.

## Translations (#204)

The web interface reads message catalogues from `src/signalbox/web/static/i18n/<lang>.json` (flat
key to text maps with `{placeholders}`, plurals as `key.one` / `key.other`). `en.json` is the
source and the fallback for every missing key. To add a language, copy `en.json` to `<code>.json`,
translate what you can, and list it in `i18n/index.json` (`dir: "rtl"` for right-to-left). The
language follows the browser; Settings overrides it per browser.

- UI code uses `t('area.key', {param})` with literal keys only (`tests/test_i18n.py` checks that
  every key used exists in `en.json` and that no other catalogue has stale keys or changed
  placeholders).
- Texts from the server carry a stable id and parameters next to the English text (`mid=`,
  `fix_id=`, `params=` in rules; `message_id`/`fix_id`/`params` on `ReadError` and `Gap`;
  `title_id` on setup steps). The catalogue entry is `msg.<id>`; rule titles and explanations are
  `rule.<rule id>.title` / `.explanation`. Without an entry the English text is shown, so rules
  can be converted one at a time.
