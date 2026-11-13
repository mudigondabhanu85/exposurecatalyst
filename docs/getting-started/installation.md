# Installation & deployment

## Prerequisites

| Component | Version | Notes |
|---|---|---|
| Docker + Compose | 24+ | Local or single-node deployment |
| Python | 3.12 | Development only (the image bundles it) |
| Node.js | 20+ | Frontend development only |
| PostgreSQL | 14+ (16 recommended) | Aurora PostgreSQL in AWS. MySQL, MariaDB, SQL Server and Oracle are supported via extras |
| Graphviz *or* Docker | — | Only to regenerate diagrams |

## Local (Docker Compose)

```bash
cp .env.example .env
# In .env set POSTGRES_PASSWORD and EXCAT_ENCRYPTION_KEY. Generate the key with:
python3 -c "import base64,os;print(base64.urlsafe_b64encode(os.urandom(32)).decode())"
docker compose up -d --build                            # postgres → api (migrates) → scheduler
docker compose exec api exposurecatalyst create-admin --username breakglass --email secops@example.com
```

Open `http://localhost:8000`. The CLI prints a TOTP secret once; add it to your authenticator. The first
ingestion starts within a minute and fetches the last 7 days from NVD
(`EXCAT_INITIAL_BACKFILL_DAYS`). For a full history backfill:

```bash
docker compose exec scheduler exposurecatalyst ingest nvd --since 2015-01-01
```

!!! warning "NVD API key"
    Without a key, NVD allows 5 requests per 30 seconds, so a full backfill takes hours. Request a free key at
    nvd.nist.gov and set `EXCAT_NVD_API_KEY` to raise the limit to 50.

## Development

```bash
uv venv --python 3.12 && uv pip install -e ".[dev,docs]"
cp .env.example .env    # then set EXCAT_ENV=dev, EXCAT_COOKIE_SECURE=false
make migrate && .venv/bin/exposurecatalyst create-admin --username admin --no-mfa
make run                # API + embedded scheduler on :8000
make frontend-dev       # Vite dev server on :5173 (proxies /api and /docs)
make test lint docs
```

## Databases

| Engine | URL example | Extra |
|---|---|---|
| PostgreSQL / Aurora | `postgresql+psycopg://excat:***@host:5432/excat?sslmode=verify-full` | built-in |
| MySQL / MariaDB | `mysql+pymysql://excat:***@host:3306/excat?ssl_ca=/certs/ca.pem` | `.[mysql]` |
| SQL Server / Azure SQL | `mssql+pyodbc://excat:***@host/excat?driver=ODBC+Driver+18+for+SQL+Server&Encrypt=yes` | `.[mssql]` |
| Oracle | `oracle+oracledb://excat:***@host:1521/?service_name=EXCAT` | `.[oracle]` |
| SQLite | `sqlite:///./exposurecatalyst.db` | dev only (rejected when `EXCAT_ENV=prod`) |

The schema uses only portable types and named constraints. `exposurecatalyst migrate` applies Alembic
migrations and seeds the system roles.

!!! tip "Least-privilege DB account"
    Run migrations with a DDL-capable role and the application with a DML-only role. Grant only
    `INSERT, SELECT` on `audit_log` so the application can't alter history, even on engines without the
    PostgreSQL immutability trigger.

## AWS

The production reference deployment is described in [High-level AWS architecture](../architecture/high-level.md).
The reference Terraform (VPC, WAF, CloudFront, ALB, ECS Fargate, Aurora, ElastiCache, Network Firewall, KMS, monitoring) is in `infra/terraform/`. See `infra/terraform/README.md` for usage, and [Network](../architecture/network.md) and [Disaster recovery](../operations/disaster-recovery.md) for the design.
