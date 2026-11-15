.PHONY: help install migrate run scheduler test lint security frontend frontend-dev diagrams docs docs-exports docker-build up down \
        compose-build smoke scan bundle logs ps

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

VERSION ?= $(shell $(PY) -c "import tomllib;print(tomllib.load(open('pyproject.toml','rb'))['project']['version'])" 2>/dev/null || echo local)
TRIVY ?= aquasec/trivy:0.57.1

docker-build:    ## Build the container image
	docker build --build-arg EXCAT_VERSION=$(VERSION) -t exposurecatalyst:$(VERSION) .

up:              ## docker compose up (init, postgres, migrate, api, scheduler, proxy → https://localhost)
	docker compose up -d --build

down:
	docker compose down

compose-build:   ## Build the app + proxy images used by docker compose
	docker compose build

smoke:           ## Full-stack compose smoke test in an isolated project (HTTPS, health, redirect); tears down
	./docker/smoke.sh

scan: compose-build  ## Trivy scan of the app and proxy images (fails on fixable HIGH/CRITICAL)
	@mkdir -p dist/scan
	@for img in exposurecatalyst:local exposurecatalyst-proxy:local; do \
	  echo "== $$img"; f=$$(echo $$img | tr ':/' '__').tar; \
	  docker save -o dist/scan/$$f $$img && \
	  docker run --rm -v "$(CURDIR)/dist/scan:/scan:ro" -v "$(CURDIR)/docker/trivy-secret.yaml:/cfg/secret.yaml:ro" \
	    $(TRIVY) image --quiet --input /scan/$$f --secret-config /cfg/secret.yaml \
	    --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 || exit 1; \
	done

bundle: compose-build  ## Air-gapped bundle: images (docker save) + compose files → dist/exposurecatalyst-<ver>-bundle.tar.gz
	@mkdir -p dist/bundle/docker
	docker compose --profile backup --profile scale pull --ignore-buildable --quiet postgres redis backup
	docker save -o dist/bundle/images.tar exposurecatalyst:local exposurecatalyst-proxy:local \
	  $$(docker compose --profile backup --profile scale config --images | grep -v '^exposurecatalyst' | sort -u)
	cp docker-compose.yml .env.example dist/bundle/
	cp -R docker/caddy docker/backup docker/compose.external-db.yml dist/bundle/docker/
	@if [ -f run.sh ]; then cp run.sh run.ps1 dist/bundle/; fi
	@if [ -f config/exposurecatalyst.example.yaml ]; then mkdir -p dist/bundle/config && cp config/exposurecatalyst.example.yaml dist/bundle/config/; fi
	tar -C dist -czf dist/exposurecatalyst-$(VERSION)-bundle.tar.gz bundle
	@echo "Bundle: dist/exposurecatalyst-$(VERSION)-bundle.tar.gz  (offline: docker load -i images.tar && docker compose up -d)"

logs:            ## Follow compose logs (SERVICE=api to filter)
	docker compose logs -f --tail 100 $(SERVICE)

ps:              ## Compose service status
	docker compose ps -a
