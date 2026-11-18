# Deployment configuration (Docker, YAML, feature flags)

Application settings are documented in [Configuration](configuration.md) (every `EXCAT_*` variable). This page
covers what the Docker deployment adds.

**Precedence** (highest first): non-empty environment variable (shell / `.env`) › `EXCAT_<NAME>_FILE` ›
`config/exposurecatalyst.yaml` › default. The YAML file is read only when `EXCAT_CONFIG_FILE` points at it
(docker compose and `run.sh` do), so a copy in a checkout never changes `make run` or the tests.

## config/exposurecatalyst.yaml

| Key | Default | Read by | Meaning |
|---|---|---|---|
| `fqdn` | unset (Docker: `localhost`) | app, run.sh | Public hostname; drives every derived URL ([Map your domain](../admin-guide/map-your-domain.md)) |
| `http_port` / `https_port` | 80 / 443 | run.sh, app | Published ports; `https_port` also goes into the public URL |
| `tls_mode` | `self-signed` | app | `self-signed` · `uploaded` · `acme` (informational; the page shows the active source) |
| `hsts` / `hsts_max_age_seconds` | unset / 63072000 | app | Strict-Transport-Security; unset = previous behaviour (on when `EXCAT_COOKIE_SECURE`) |
| `trusted_proxies` | private ranges | run.sh → proxy | Load balancers whose X-Forwarded-* the proxy trusts |
| `outbound_proxy` | unset | run.sh | Exported as `HTTPS_PROXY` / `HTTP_PROXY` |
| `timezone` | UTC | run.sh | Container `TZ` (logs); the app computes in UTC |
| `database_url` | unset | app, run.sh | External database (run.sh adds the external-db override) |
| `log_level` | INFO | app | |
| `features.ui_tls_management` | false | app | Certificates & Domain: install / CSR / rollback / trusted CA |
| `features.acme` | false | app | ACME / Let's Encrypt |
| `features.subscriptions` | false | app, scheduler | Threat Intel & News Subscriptions |
| `features.run_watch_mode` | false | run.sh | `./run.sh watch` |

Turning a flag off restores the previous behaviour exactly (endpoints answer 403, screens are hidden, the
scheduler skips the work). In the environment, flags are `EXCAT_FEATURES__<NAME>=true`.

## .env / compose variables

| Variable | Default | Meaning |
|---|---|---|
| `EXCAT_ENCRYPTION_KEY`, `POSTGRES_PASSWORD` | generated | Leave empty for generation by `init`; existing values are kept |
| `EXCAT_<NAME>_FILE` | — | Read any setting from a file (Docker secrets); explicit values win |
| `EXCAT_BOOTSTRAP_ADMIN` | true | Empty installation: create the default `breakglass` Super Admin with a generated password (forced change + MFA). `false` = setup-token wizard |
| `EXCAT_BOOTSTRAP_ADMIN_USERNAME` | breakglass | Its username |
| `EXCAT_FQDN`, `EXCAT_HTTP_PORT`, `EXCAT_HTTPS_PORT` | — | Same as the YAML keys |
| `EXCAT_HTTPS_PORT_SUFFIX` | `:<port>` when not 443 (run.sh) | Port kept in HTTP→HTTPS redirects |
| `EXCAT_BIND_ADDRESS` | 0.0.0.0 | Host interface for 80/443 |
| `EXCAT_WEB_CONCURRENCY` | 1 | API worker processes (login rate limits are per process) |
| `EXCAT_EDGE_SUBNET` / `EXCAT_PROXY_IP` | 172.30.250.0/24 / .10 | Proxy network; trusted X-Forwarded-For range |
| `EXCAT_TRUSTED_PROXIES` | private_ranges | See `trusted_proxies` |
| `EXCAT_IMAGE_TAG` | local | Image tag (`:rollback` / `:<tag>-rollback` for rollbacks) |
| `EXCAT_DOCKERHUB_MIRROR` | docker.io | Registry mirror for base images (digests unchanged) |
| `EXCAT_DATABASE_URL` | bundled postgres | External database URL |
| `COMPOSE_FILE` | docker-compose.yml | Add `docker/compose.external-db.yml` for an external database |
| `COMPOSE_PROFILES` | — | `backup`, `scale`, `ollama`, `direct`, `devmail` |
| `EXCAT_BACKUP_INTERVAL_HOURS` / `_RETENTION_DAYS` | 24 / 14 | Backup profile |
| `EXCAT_WORKER_REPLICAS` | 1 | Scale profile |
| `EXCAT_DIRECT_PORT` | 8000 | Direct profile |
| `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY` | — | Outbound proxy |
| `EXCAT_CA_BUNDLE` | — | Extra trusted CAs for outbound TLS (without the UI) |
| `EXCAT_ACME_CLOUDFLARE_API_TOKEN` / AWS credentials | — | ACME DNS-01 |
| `EXCAT_HEALTH_TIMEOUT`, `EXCAT_WATCH_INTERVAL`, `EXCAT_MIN_FREE_GB` | 300, 30, 5 | run.sh |

New application settings in 1.4 (all optional): `fqdn`, `http_port`, `https_port`, `tls_mode`, `hsts`,
`hsts_max_age_seconds`, `trusted_proxies`, `outbound_proxy`, `timezone`, `deployment`, `config_file`,
`certs_dir`, `setup_token_hours`, `bootstrap_admin`, `bootstrap_admin_username`, `secrets_dir`, `features`.
