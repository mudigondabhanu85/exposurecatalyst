# Troubleshooting (Docker)

Start with `./run.sh doctor` and `./run.sh logs <service>`.

| Symptom | Cause / fix |
|---|---|
| `port 80 is in use by another program` | Another web server holds the port: stop it, or set `http_port` / `https_port` |
| Browser warns about the certificate | Self-signed certificate (first start): install one — [TLS certificates](../admin-guide/tls-certificates.md) |
| `400 Invalid host header` | The browser uses a name other than `fqdn`: fix DNS / bookmark, or set `fqdn` |
| `403` on every POST after changing the domain | Stale tab on the old URL: reload from `https://<fqdn>` |
| Forgot the break-glass password after changing it | Another Super Admin resets it (Users & RBAC), or `docker compose exec api exposurecatalyst create-admin --username recovery` |
| `./run.sh initial-password` says no password | Existing installation, `EXCAT_BOOTSTRAP_ADMIN=false`, or the API container isn't running |
| No setup token in the logs | Users already exist (the wizard is only for empty installations), or the token expired: `docker compose restart api` prints a fresh one |
| `toomanyrequests` while building | Docker Hub rate limit: `docker login`, or set `EXCAT_DOCKERHUB_MIRROR` |
| `exec /usr/bin/caddy: operation not permitted` | A custom proxy image with file capabilities: use the provided `proxy` build target |
| `migrate` exited non-zero | `./run.sh logs migrate`; database unreachable or wrong credentials (`POSTGRES_PASSWORD` must match the one the volume was created with) |
| `EXCAT_ENCRYPTION_KEY_FILE: cannot read …` | The `secrets` volume is missing: restore it from backup; never generate a new key for existing data |
| Outbound calls fail with certificate errors | TLS inspection: upload the proxy's CA as the Trusted CA bundle — [Corporate proxy and custom CA](../admin-guide/proxy-and-ca.md) |
| Scheduler unhealthy | `./run.sh logs scheduler`; its heartbeat stops if the process hangs — `./run.sh restart` |
