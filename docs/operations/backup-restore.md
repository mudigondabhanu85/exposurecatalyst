# Backup and restore (Docker)

| What | How |
|---|---|
| On demand | `./run.sh backup` → `excat-YYYYMMDDTHHMMSSZ.dump` (pg_dump custom format) in the `backups` volume |
| Before every upgrade | automatic in `./run.sh` when the app image changes |
| Scheduled | `COMPOSE_PROFILES=backup` → every `EXCAT_BACKUP_INTERVAL_HOURS` (24), kept `EXCAT_BACKUP_RETENTION_DAYS` (14) |
| List | `docker compose --profile backup run --rm --no-deps --entrypoint ls backup -l /backups` |
| Copy off the host | `docker run --rm -v exposurecatalyst_backups:/b -v "$PWD":/out alpine cp /b/<file> /out/` |
| Restore | `./run.sh restore <file>` (safety backup first, typed confirmation, services stopped during restore) |

**Also back up** the `secrets` volume (the encryption key) — without it, stored credentials (SMTP, SSO,
integrations, subscriptions, certificate keys) cannot be decrypted. Keep it separate from database backups.

External databases: use your platform's backups (RDS snapshots, etc.); `./run.sh backup` covers the bundled
PostgreSQL only. The AWS reference deployment is covered by [Disaster recovery](disaster-recovery.md).
