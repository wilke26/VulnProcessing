# ---- Konfiguration ----
POETRY ?= poetry
PY      := $(POETRY) run python
UVICORN := $(POETRY) run uvicorn
RUFF    := $(POETRY) run ruff
BLACK   := $(POETRY) run black
PYTEST  := $(POETRY) run pytest

DC_FILE := deploy/docker/docker-compose.dev.yml

# ---- Phony Targets ----
.PHONY: help install export-schema validate format lint test run-api run-worker build \
        compose-up compose-down clean ci

help:
	@echo "Targets:"
	@echo "  install         - Poetry-Install"
	@echo "  export-schema   - Data Contract (JSON Schema) generieren"
	@echo "  validate FILE=… - Datei gegen Data Contract prüfen"
	@echo "  format          - black + ruff --fix"
	@echo "  lint            - ruff"
	@echo "  test            - pytest"
	@echo "  test-fast       - pytest ohne property-tests"
	@echo "  run-api         - FastAPI (Uvicorn) mit --reload"
	@echo "  run-worker      - Celery-Worker"
	@echo "  build           - Build (inkl. Schema-Export)"
	@echo "  compose-up      - Dev-Stack (API, Worker, Redis)"
	@echo "  compose-down    - Dev-Stack stoppen & entfernen"
	@echo "  clean           - Build-/Cache-Dateien entfernen"
	@echo "  ci              - Lint + Tests + Schema-Export"

# ---- Basics ----
install:
	$(POETRY) install

# ---- Data Contract ----
export-schema:
	$(PY) scripts/export_schema.py

validate:
	@[ -n "$(FILE)" ] || (echo "Bitte Datei angeben: make validate FILE=./data/samples/results.sample.json" && exit 1)
	$(PY) scripts/validate_file.py "$(FILE)"

# ---- Qualität ----
format:
	$(BLACK) .
	$(RUFF) --fix .

lint:
	$(RUFF) .

test:
	$(PYTEST) -q

test-fast:
	$(PYTEST) -q -m "not property"

# ---- Laufzeit (lokal) ----
run-api:
	$(UVICORN) app.main:app --host 127.0.0.1 --port 8000 --reload

run-worker:
	$(POETRY) run celery -A app.tasks.celery_app.celery worker --loglevel=INFO

# ---- Build/Release ----
build: export-schema
	$(POETRY) build

# ---- Docker Dev Stack ----
compose-up:
	docker compose -f $(DC_FILE) up --build

compose-down:
	docker compose -f $(DC_FILE) down -v

# ---- Aufräumen ----
clean:
	@find . -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
	@rm -rf .pytest_cache dist build 2>/dev/null || true

# ---- CI-ähnlicher Shortcut ----
ci: lint test export-schema
	@echo "CI-Checks ok."
