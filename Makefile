PY ?= .venv/bin/python
BIN = .venv/bin

.PHONY: install lint format typecheck test e2e demo run docker smoke schema
install:
	python3 -m venv .venv && $(BIN)/pip install -e ".[dev]"
lint:
	$(BIN)/ruff check . && $(BIN)/ruff format --check . && $(BIN)/mypy
format:
	$(BIN)/ruff format . && $(BIN)/ruff check --fix .
test:
	$(BIN)/pytest -m "not e2e" --cov --cov-report=term-missing
e2e:
	$(BIN)/pytest -m e2e tests/e2e
schema:
	$(PY) -m signalbox schema > docs/schema.json
demo:
	$(PY) -m signalbox --data /tmp/signalbox-demo demo
run:
	$(PY) -m signalbox serve
docker:
	docker build -t signalbox:dev .
smoke:
	bash tools/smoke.sh
