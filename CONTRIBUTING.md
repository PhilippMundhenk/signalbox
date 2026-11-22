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

## Releases

`git tag vX.Y.Z && git push --tags` builds the image tags `X.Y.Z`, `X.Y`, `latest` and a GitHub
release. Add the notable changes to `CHANGELOG.md` first.
