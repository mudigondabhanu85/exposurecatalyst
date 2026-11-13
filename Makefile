.PHONY: help install migrate run scheduler test lint security frontend frontend-dev diagrams docs docs-exports docker-build up down

PY ?= .venv/bin/python
BIN ?= .venv/bin

help:            ## Show targets
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-14s %s\n", $$1, $$2}'

install:         ## Create venv and install backend + dev + docs deps, frontend deps
	uv venv --python 3.12 .venv && uv pip install -e ".[dev,docs]"
	cd frontend && npm ci

migrate:         ## Apply DB migrations and seed roles
	$(BIN)/exposurecatalyst migrate

run:             ## API with embedded scheduler on :8000 (dev)
	EXCAT_SCHEDULER_EMBEDDED=true $(BIN)/exposurecatalyst serve --reload

scheduler:       ## Standalone scheduler
	$(BIN)/exposurecatalyst scheduler

test:            ## Run the test suite with coverage
	$(BIN)/pytest --cov=exposurecatalyst --cov-report=term-missing:skip-covered

lint:            ## Ruff + frontend type check
	$(BIN)/ruff check src tests migrations
	cd frontend && npm run typecheck

security:        ## SAST + dependency audit
	$(BIN)/bandit -q -r src -c pyproject.toml
	$(BIN)/pip-audit --skip-editable
	cd frontend && npm audit --omit=dev

frontend:        ## Production build of the SPA → frontend/dist
	cd frontend && npm run build

frontend-dev:    ## Vite dev server on :5173
	cd frontend && npm run dev

diagrams:        ## Render docs/diagrams/*.py → SVG / PNG@300dpi / .drawio
	$(PY) -m exposurecatalyst.docs diagrams

docs:            ## Diagrams + reference pages + MkDocs (strict) + DOCX/HTML guides → dist/docs/{site,exports}
	$(PY) -m exposurecatalyst.docs build

docs-exports:    ## Only the DOCX / standalone HTML guides (Pandoc locally or in Docker)
	$(PY) -m exposurecatalyst.docs exports

docker-build:    ## Build the container image
	docker build -t exposurecatalyst:0.5.0 .

up:              ## docker compose up (postgres, api, scheduler)
	docker compose up -d --build

down:
	docker compose down
