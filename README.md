# ExposureCatalyst

**Vulnerability Intelligence & Advisory Platform.** ExposureCatalyst ingests new and updated CVEs from trusted
sources, correlates them with affected assets from your security and CTEM tools, and generates reviewable
stakeholder advisory emails.

> **Status: 1.4.0** — all six phases delivered: CVE Intelligence (NVD + CISA KEV + FIRST EPSS), Advisory Email
> Generator with approval workflow, 28 integrations (24 asset sources from Qualys to Mend, plus Jira, ServiceNow ITSM, Slack and Teams), Okta
> SAML or OIDC SSO + SailPoint SCIM, alerts, Security News, a multi-provider AI layer with redaction, guided tours,
> Terraform AWS reference deployment, and DOCX / standalone HTML documentation. 1.4 adds one-command Docker
> deployment with HTTPS, Certificates & Domain management, `run.sh`, and paid threat-intel subscriptions.
> See `CHANGELOG.md`.

## Run with Docker

```bash
git clone <your repository URL> exposurecatalyst && cd exposurecatalyst
./run.sh                                   # or: docker compose up -d        (Windows: .\run.ps1)
./run.sh logs api | grep -A3 "setup token" # one-time token (24 h)
open https://localhost/setup               # create the Super Admin (TOTP required), then sign in
```

Secrets and a self-signed certificate are generated on first start; only the proxy publishes ports (80/443).
Set your domain in `config/exposurecatalyst.yaml` (`fqdn`), install a certificate under Settings → Certificates &
Domain, and see `docs/getting-started/docker-quickstart.md`, `docs/operations/run-sh.md` and
`docs/reference/deployment-config.md`. Optional features are behind flags (`features.*`, all off by default).

## Quick start (Docker, explicit .env)

```bash
cp .env.example .env
# set POSTGRES_PASSWORD and EXCAT_ENCRYPTION_KEY in .env; generate the key with:
python3 -c "import base64,os;print(base64.urlsafe_b64encode(os.urandom(32)).decode())"
docker compose up -d --build                                  # init, postgres, migrate, api, scheduler, proxy
docker compose exec api exposurecatalyst create-admin --username breakglass --email you@example.com
open https://localhost                                       # app (docs at /docs, API at /api/docs)
# the previous plain-HTTP endpoint: docker compose --profile direct up -d → http://localhost:8000
```

`create-admin` prints a TOTP secret/URI once — add it to an authenticator app; it is required at login.

## Local development

```bash
uv venv --python 3.12 && uv pip install -e ".[dev,docs]"
cp .env.example .env && sed -i '' 's/^EXCAT_ENV=.*/EXCAT_ENV=dev/' .env   # dev: SQLite, http cookies
make migrate
.venv/bin/exposurecatalyst create-admin --username admin --no-mfa         # dev only
make run          # API + embedded scheduler on :8000
make frontend-dev # Vite on :5173 proxying /api and /docs
make test
make docs         # diagrams + Mermaid + reference pages + MkDocs + DOCX/HTML guides → dist/docs/{site,exports}
```

## Repository layout

```
src/exposurecatalyst/
  api/            FastAPI routers (auth, cves, sources, advisories, integrations, sso, scim, alerts, news, ai, help…)
  ingestion/      http client (SSRF guard, rate limit, backoff), nvd/kev/epss sources, scheduler
  advisories/     templates, rendering, .eml/PDF/Excel, SMTP     connectors/  Qualys, Tanium, Wiz, REST, ServiceNow
  sso/            SAML SP, identity mapping      alerts/  rule engine     news/  feeds     ai/  providers + guard
  maintenance.py  retention + secret re-encryption
  security/       rbac, sessions, passwords (Argon2id), crypto (Fernet), ssrf, audit (hash chain), middleware
  models/         SQLAlchemy 2.x models     help/  in-app help loader (RBAC-filtered Markdown)
  docs/           documentation build + DOCX/HTML export pipeline
migrations/       Alembic (portable across PostgreSQL/MySQL/MariaDB/SQL Server/Oracle/SQLite)
frontend/         React + TypeScript + Tailwind SPA
docs/             MkDocs source; docs/help/*.md is ALSO the in-app help (single source of truth)
docs/diagrams/    Python "diagrams" sources → docs/assets/diagrams/*.{svg,png,drawio}
infra/terraform/  AWS reference deployment (see its README)
tests/            pytest suite (mocked upstream APIs)
```

## Production

Deploy with `infra/terraform` (CloudFront + WAF → ALB → ECS Fargate, Aurora PostgreSQL, Network Firewall
egress allowlist). Read *Installation & deployment*, *Network*, *Disaster recovery* and the *Runbooks* in the
docs. The migration task runs as the database owner and provisions the DML-only `excat_app` role the app
runs as (`exposurecatalyst migrate --app-role excat_app`).

## Security highlights

Argon2id passwords · server-side sessions (hashed tokens, idle + absolute timeout) · CSRF tokens bound to the
session + Origin check · strict CSP · lockout + per-IP rate limiting · TOTP for local admins · server-side RBAC
on every endpoint with privilege-escalation guard · hash-chained append-only audit log · SSRF guard + egress
allowlist on all outbound calls · secrets encrypted at rest and redacted from logs. See `SECURITY.md` and
`docs/security/`.
