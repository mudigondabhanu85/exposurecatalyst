# run.sh reference

`./run.sh` (Linux/macOS, bash 3.2+) and `.\run.ps1` (Windows, PowerShell 7 or 5.1) start, update and restart the
Docker deployment safely. They are additions: `docker compose up -d` and `make run` keep working.

| Command | What it does |
|---|---|
| *(none)* | Preflight → lock → detect changes → rebuild only affected images → tag `:rollback` → `pg_dump` before migrations → `up --wait` → record state. Exits 0 with "nothing changed" when everything is current and healthy |
| `start` | Start without rebuilding |
| `stop` | Stop (data kept) |
| `restart` | Restart and wait for health |
| `update` | `git pull --ff-only` on the current branch (refuses local changes to tracked files), then as above |
| `status` | Services, health, version, served certificate |
| `logs [service]` | Follow logs |
| `backup` | `pg_dump` of the bundled PostgreSQL into the `backups` volume |
| `restore <file>` | Takes a safety backup, then restores after you type `RESTORE` (non-interactive: `EXCAT_CONFIRM_RESTORE=RESTORE`) |
| `watch` | Every `EXCAT_WATCH_INTERVAL` s (30) apply changes; requires `features.run_watch_mode: true` — dev/test only |
| `doctor` | Health, certificate expiry, FQDN DNS resolution, disk, versions |
| `initial-password` | Print the generated password of the default `breakglass` account (shown only on request; invalid once changed) |
| `help` | Usage |

**Preflight**: Docker and Compose ≥ 2.24, ports free or held by our proxy, ≥ `EXCAT_MIN_FREE_GB` (5) free,
`config/exposurecatalyst.yaml` and `.env` created from the examples if missing.

**Change detection** hashes source code, Dockerfiles, compose files, lockfiles, `.env` and the YAML config
(state in `.run/state`): source changes rebuild the app image; frontend/Caddy changes rebuild the proxy image;
configuration-only changes just recreate containers (no rebuild, no backup).

**On failure** it prints the failing services' logs, re-tags the `:rollback` images (`:<tag>-rollback` for a
custom `EXCAT_IMAGE_TAG`) and starts them, and prints the exact `./run.sh restore …` command for the
pre-migration backup. The database is **never** restored automatically.

**Configuration**: values come from the shell, then `.env`, then `config/exposurecatalyst.yaml` (fqdn, ports,
trusted proxies, outbound proxy, timezone, external database). Environment: `EXCAT_HEALTH_TIMEOUT` (300),
`EXCAT_WATCH_INTERVAL` (30), `EXCAT_MIN_FREE_GB` (5).

**Exit codes**: 0 ok · 1 failed (rolled back where possible) · 2 usage · 3 preflight · 4 locked · 5 aborted.
Output is timestamped to the console and `logs/run.log`; secrets are never printed.
