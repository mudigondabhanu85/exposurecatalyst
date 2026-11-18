# Quick start with Docker

One command brings up the whole platform behind HTTPS. This is an addition to the existing ways of running
ExposureCatalyst ([Installation & deployment](installation.md)); nothing about `make run` or the AWS reference
deployment changes.

## Requirements

- Docker Engine 24+ (or Docker Desktop) with **Compose v2.24+** (`docker compose version`)
- 4 GB RAM, 5 GB free disk, ports **80** and **443** free (or choose others, below)
- Outbound HTTPS to the CVE sources (NVD, CISA, FIRST) — directly or through a [corporate proxy](../admin-guide/proxy-and-ca.md)

## 1. Clone and start

```bash
git clone <your repository URL> exposurecatalyst && cd exposurecatalyst
./run.sh            # or: docker compose up -d      (Windows: .\run.ps1)
```

`./run.sh` adds preflight checks, backups before migrations and automatic rollback (see the
[run.sh reference](../operations/run-sh.md)); plain `docker compose up -d` works too.

On first start the one-shot `init` container generates every secret (encryption key, database and Redis
passwords) into protected volumes and a **self-signed certificate** for the configured domain, then `migrate`
creates the schema and the API, scheduler and proxy start in order, each gated on the previous one's health.

## 2. Create the first administrator

The API prints a one-time **setup token** (valid 24 h, single use):

```bash
./run.sh logs api | grep -A3 "setup token"      # or: docker compose logs api
```

Open **https://localhost/setup** (your browser warns about the self-signed certificate until you install a
real one), enter the token, create the break-glass **Super Admin** and enrol an authenticator app (TOTP is
mandatory). The wizard disappears once a user exists; there are no default passwords anywhere.

## 3. Sign in and configure

Sign in at **https://localhost**. Next steps:

1. **Domain** — set `fqdn` in `config/exposurecatalyst.yaml` and run `./run.sh` ([Map your domain](../admin-guide/map-your-domain.md)).
2. **Certificate** — Settings → Certificates & Domain ([TLS certificates](../admin-guide/tls-certificates.md)).
3. **SSO, SMTP, integrations** — as in the Admin guide.

## Ports, profiles and options

| Need | Setting |
|---|---|
| Other ports | `http_port` / `https_port` in `config/exposurecatalyst.yaml` (or `EXCAT_HTTP_PORT` / `EXCAT_HTTPS_PORT` in `.env`) |
| The previous plain-HTTP endpoint on 127.0.0.1:8000 | `docker compose --profile direct up -d` |
| Scheduled database backups | `COMPOSE_PROFILES=backup` in `.env` |
| Local LLM | `--profile ollama` (then add `http://ollama:11434` under AI Providers; needs `EXCAT_AI_ALLOW_PRIVATE_ENDPOINTS=true`) |
| Extra job runners + Redis | `--profile scale` |
| External database | [Migrating into Docker](migrate-to-docker.md#external-database) |
| Offline / air-gapped host | [Air-gapped install](air-gapped.md) |

The services, networks and volumes are described in [Container topology](../architecture/containers.md); every
configuration key is listed in [Deployment configuration](../reference/deployment-config.md).
