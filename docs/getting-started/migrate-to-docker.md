# Migrating an existing deployment into Docker

Moving data is always **opt-in and verified**; nothing is moved automatically.

## Already on the previous docker-compose

Nothing to migrate: the service is still `postgres` and the volume still `pgdata`, so `./run.sh` reuses your
data. `POSTGRES_PASSWORD` and `EXCAT_ENCRYPTION_KEY` from your `.env` are kept (the init container only
generates values that are missing). The app is now at `https://<fqdn>`; the old `http://127.0.0.1:8000`
endpoint is available with `--profile direct`.

## From a local / other PostgreSQL (or SQLite) installation

1. Stop the old instance's API and scheduler.
2. Export: `pg_dump --format=custom --no-owner -f excat.dump "<old URL>"` (SQLite: export with the same app
   version into PostgreSQL first, e.g. run `exposurecatalyst migrate` against an empty PostgreSQL and copy the
   data with your preferred tool).
3. Copy the old **`EXCAT_ENCRYPTION_KEY`** into `.env` — stored secrets are encrypted with it.
4. Start the Docker stack once (`./run.sh`), then copy the dump into the backups volume and restore it:
   ```bash
   docker run --rm -v exposurecatalyst_backups:/b -v "$PWD":/in alpine cp /in/excat.dump /b/
   ./run.sh restore excat.dump
   ```
5. Verify: sign in, compare counts (CVEs, advisories, users), `exposurecatalyst audit-verify` in the api
   container, and run **Test** on SMTP, SSO and integrations (proves the encryption key is right).

## External database

Keep the database where it is:

```env
# .env
COMPOSE_FILE=docker-compose.yml:docker/compose.external-db.yml
EXCAT_DATABASE_URL=postgresql+psycopg://excat@db.example.internal:5432/excat?sslmode=verify-full
EXCAT_DATABASE_PASSWORD=…
```

(or set `database_url` in `config/exposurecatalyst.yaml` and use `./run.sh`, which adds the override for you).
MySQL/MariaDB, SQL Server and Oracle work as described in Settings → Database (the image needs the matching
extra).
