# syntax=docker/dockerfile:1.7
# ---- 1. Frontend -------------------------------------------------------------------------------
FROM node:20.18.0-alpine3.20 AS ui
WORKDIR /ui/frontend
COPY brand /ui/brand
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

# ---- 2. Python dependencies --------------------------------------------------------------------
FROM python:3.12.7-slim-bookworm AS build
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
RUN python -m venv /opt/venv
ENV PATH=/opt/venv/bin:$PATH
WORKDIR /src
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install .

# ---- 3. Documentation site (diagrams are pre-rendered and committed; CI re-renders them) ----------
FROM python:3.12.7-slim-bookworm AS docs
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /app
COPY pyproject.toml README.md CHANGELOG.md mkdocs.yml ./
COPY src ./src
COPY docs ./docs
RUN pip install -e ".[docs]" && python -m exposurecatalyst.docs build --skip-diagrams

# ---- 4. Runtime --------------------------------------------------------------------------------
FROM python:3.12.7-slim-bookworm AS runtime
LABEL org.opencontainers.image.title="exposurecatalyst" \
      org.opencontainers.image.description="ExposureCatalyst — Vulnerability Intelligence & Advisory Platform" \
      org.opencontainers.image.version="0.2.0"
RUN useradd --system --uid 10001 --home /app excat
COPY --from=build /opt/venv /opt/venv
WORKDIR /app
COPY alembic.ini CHANGELOG.md ./
COPY migrations ./migrations
COPY docs/help ./docs/help
COPY brand/assets/png ./brand/assets/png
COPY --from=ui /ui/frontend/dist ./frontend/dist
COPY --from=docs /app/dist/docs/site ./dist/docs/site
ENV PATH=/opt/venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    EXCAT_APP_ROOT=/app \
    EXCAT_FRONTEND_DIST_DIR=/app/frontend/dist \
    EXCAT_DOCS_SITE_DIR=/app/dist/docs/site \
    EXCAT_HELP_DIR=/app/docs/help \
    EXCAT_BRAND_DIR=/app/brand \
    EXCAT_CHANGELOG_PATH=/app/CHANGELOG.md
USER 10001
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/health/live', timeout=3).status == 200 else 1)"
CMD ["exposurecatalyst", "serve", "--host", "0.0.0.0", "--port", "8000"]
