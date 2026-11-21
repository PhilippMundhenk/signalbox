PY ?= .venv/bin/python
BIN = .venv/bin

.PHONY: install lint format typecheck test e2e demo run docker smoke schema screenshots docs
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
screenshots:
	NO_PROXY=127.0.0.1,localhost $(PY) tools/screenshots.py
docs:
	$(PY) tools/gen_docs.py && $(PY) tools/gen_api_doc.py
