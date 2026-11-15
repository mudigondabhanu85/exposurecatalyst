# syntax=docker/dockerfile:1.7
# Base images are pinned by version AND digest (update both together; `make scan` re-checks them).
ARG EXCAT_VERSION=1.3.0
# Registry for Docker Hub images: a pull-through mirror or corporate registry (digests keep builds identical).
ARG DOCKERHUB=docker.io
# ---- 1. Frontend -------------------------------------------------------------------------------
FROM ${DOCKERHUB}/library/node:20.20.2-alpine@sha256:fb4cd12c85ee03686f6af5362a0b0d56d50c58a04632e6c0fb8363f609372293 AS ui
WORKDIR /ui/frontend
COPY brand /ui/brand
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

# ---- 2. Python dependencies --------------------------------------------------------------------
FROM ${DOCKERHUB}/library/python:3.12.16-slim-bookworm@sha256:935c3c5b12357a7e10caa9c1e6ca5692344d97cf229832ef584be2cec9fc03df AS build
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
RUN python -m venv /opt/venv
ENV PATH=/opt/venv/bin:$PATH
WORKDIR /src
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install ".[aws]"   # boto3: Amazon SES API mail and Amazon Bedrock (IAM task role)

# ---- 3. Documentation site + DOCX / standalone HTML exports ---------------------------------------
# Diagrams and Mermaid renders are committed (CI re-renders them); Pandoc comes from its official image.
FROM ${DOCKERHUB}/pandoc/core:3.5-ubuntu@sha256:c001d27fe3907f0a307b66b8a5bbd59402aa4d1add2517070952f10a9067b1a1 AS docs
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1 DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends python3 python3-venv \
    && rm -rf /var/lib/apt/lists/* && python3 -m venv /opt/venv
ENV PATH=/opt/venv/bin:$PATH
WORKDIR /app
COPY pyproject.toml README.md CHANGELOG.md mkdocs.yml ./
COPY src ./src
COPY docs ./docs
COPY brand ./brand
RUN pip install -e ".[docs]" && python -m exposurecatalyst.docs build --skip-diagrams

# ---- 4. Reverse proxy (docker compose `proxy` service): Caddy + the built SPA assets ---------------------------
# Caddy built with xcaddy: pinned DNS-01 providers for ACME (Route 53, Cloudflare) and patched golang.org/x/net
# (CVE-2026-78661 in the stock 2.11.9 binary). Module checksums are verified against sum.golang.org.
FROM ${DOCKERHUB}/library/caddy:2.11.9-builder-alpine@sha256:646fee578e680989ca5c7fd1ce6f1de574d19fd71ef2221810cc0510a9f40c86 AS caddy-build
RUN XCADDY_SETCAP=0 xcaddy build v2.11.9 --output /usr/bin/caddy \
      --with github.com/caddy-dns/route53@v1.6.3 \
      --with github.com/caddy-dns/cloudflare@v0.2.4 \
      --replace golang.org/x/net=golang.org/x/net@v0.62.0 \
 && /usr/bin/caddy version && /usr/bin/caddy list-modules | grep -E '^dns.providers.(route53|cloudflare)$'

FROM ${DOCKERHUB}/library/caddy:2.11.9-alpine@sha256:003a97808e781aa9f7e75cc2f43d34d461099031faf5e20faefb9f61126836f0 AS proxy
ARG EXCAT_VERSION
LABEL org.opencontainers.image.title="exposurecatalyst-proxy" org.opencontainers.image.version="${EXCAT_VERSION}"
# uid 10003, primary group 10001 (shared with the app: reads certs/, shares the admin socket)
# The custom binary carries no file capabilities: the proxy binds 8080/8443 only and runs with cap_drop: ALL.
COPY --from=caddy-build /usr/bin/caddy /usr/bin/caddy
RUN addgroup -g 10001 excat && adduser -S -D -H -u 10003 -G excat excatproxy \
 && install -d -o 10003 -g 10001 -m 0750 /data /config && install -d -o 10003 -g 10001 -m 0770 /run/caddy-admin \
 && install -d -o 10001 -g 10001 -m 0750 /var/lib/excat/certs
COPY docker/caddy/Caddyfile /etc/caddy/Caddyfile
COPY --from=ui /ui/frontend/dist/assets /srv/assets
ENV XDG_DATA_HOME=/data XDG_CONFIG_HOME=/config
USER 10003:10001
EXPOSE 8080 8443
HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
  CMD wget -q -O /dev/null http://127.0.0.1:8080/healthz || exit 1
CMD ["caddy", "run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"]

# ---- 5. Runtime (default target: keep this stage LAST so `docker build .` builds the app) ----
FROM ${DOCKERHUB}/library/python:3.12.16-slim-bookworm@sha256:935c3c5b12357a7e10caa9c1e6ca5692344d97cf229832ef584be2cec9fc03df AS runtime
ARG EXCAT_VERSION
LABEL org.opencontainers.image.title="exposurecatalyst" \
      org.opencontainers.image.description="ExposureCatalyst — Vulnerability Intelligence & Advisory Platform" \
      org.opencontainers.image.version="${EXCAT_VERSION}"
RUN groupadd --system --gid 10001 excat && useradd --system --uid 10001 --gid 10001 --home /app excat \
 # State dirs for the Docker deployment: fresh named volumes inherit these owners/modes on first mount.
 # db-secret is group 70 (postgres:alpine) so the database can read only its own password file.
 && install -d -o 10001 -g 10001 -m 0750 /var/lib/excat /var/lib/excat/certs /var/lib/excat/uploads \
      /var/lib/excat/exports /var/lib/excat/backups \
 # admin socket dir: proxy (uid 10003, group 10001) creates the socket, the api connects
 && install -d -o 10001 -g 10001 -m 0770 /run/caddy-admin \
 && install -d -o 10001 -g 10001 -m 0700 /var/lib/excat/secrets \
 && install -d -o 10001 -g 70 -m 0750 /var/lib/excat/db-secret
COPY --from=build /opt/venv /opt/venv
WORKDIR /app
COPY alembic.ini CHANGELOG.md ./
COPY migrations ./migrations
COPY docs/help ./docs/help
COPY brand/assets/png ./brand/assets/png
COPY --from=ui /ui/frontend/dist ./frontend/dist
COPY --from=docs /app/dist/docs/site ./dist/docs/site
COPY --from=docs /app/dist/docs/exports ./dist/docs/exports
ENV PATH=/opt/venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    EXCAT_APP_ROOT=/app \
    EXCAT_FRONTEND_DIST_DIR=/app/frontend/dist \
    EXCAT_DOCS_SITE_DIR=/app/dist/docs/site \
    EXCAT_DOCS_EXPORTS_DIR=/app/dist/docs/exports \
    EXCAT_HELP_DIR=/app/docs/help \
    EXCAT_BRAND_DIR=/app/brand \
    EXCAT_CHANGELOG_PATH=/app/CHANGELOG.md
USER 10001
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/health/live', timeout=3).status == 200 else 1)"
CMD ["exposurecatalyst", "serve", "--host", "0.0.0.0", "--port", "8000"]

