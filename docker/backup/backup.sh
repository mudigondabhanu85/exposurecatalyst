#!/bin/sh
# Scheduled pg_dump (compose profile `backup`). Custom-format dumps in the backups volume, pruned after
# EXCAT_BACKUP_RETENTION_DAYS. The password is read from the secret file, never passed on the command line.
set -eu
: "${EXCAT_BACKUP_INTERVAL_HOURS:=24}" "${EXCAT_BACKUP_RETENTION_DAYS:=14}" "${PGHOST:=postgres}" "${PGUSER:=excat}" "${PGDATABASE:=excat}"
PGPASSWORD="$(cat /run/db-secret/db_password)"
export PGPASSWORD PGHOST PGUSER PGDATABASE
umask 077
once() {
  f="/backups/excat-$(date -u +%Y%m%dT%H%M%SZ).dump"
  pg_dump --format=custom --no-owner --file="$f.part" && mv "$f.part" "$f"
  echo "[backup] $(date -u +%FT%TZ) wrote $(basename "$f") ($(du -h "$f" | cut -f1))"
  find /backups -name 'excat-*.dump' -mtime +"$EXCAT_BACKUP_RETENTION_DAYS" -print -delete
}
if [ "${1:-}" = "once" ]; then once; exit 0; fi
while true; do once || echo "[backup] FAILED" >&2; sleep $((EXCAT_BACKUP_INTERVAL_HOURS * 3600)); done
