#!/usr/bin/env bash
# ExposureCatalyst — start / update / restart the Docker deployment safely.
#
#   ./run.sh                 bring the app up, or apply changes since the last successful run and restart
#   ./run.sh help            all subcommands
#
# Safety: preflight checks, a lock (no overlapping runs), change detection (only affected images are rebuilt),
# :rollback image tags and a database backup before migrations, health-gated success, automatic image rollback on
# failure (the database is never restored without your explicit confirmation). Output is timestamped to the
# console and logs/run.log. Secrets are never printed. Works with bash 3.2+ (macOS) and Linux.
#
# Exit codes: 0 ok · 1 deploy/command failed (rolled back where possible) · 2 usage · 3 preflight failed ·
#             4 another run holds the lock · 5 aborted by the user
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"
STATE_DIR="$ROOT/.run"
STATE_FILE="$STATE_DIR/state"
LOCK_DIR="$STATE_DIR/lock"
LOG_DIR="$ROOT/logs"
LOG_FILE="$LOG_DIR/run.log"
CONFIG="$ROOT/config/exposurecatalyst.yaml"
CONFIG_EXAMPLE="$ROOT/config/exposurecatalyst.example.yaml"
HEALTH_TIMEOUT="${EXCAT_HEALTH_TIMEOUT:-300}"
WATCH_INTERVAL="${EXCAT_WATCH_INTERVAL:-30}"
MIN_FREE_GB="${EXCAT_MIN_FREE_GB:-5}"
APP_IMAGE="exposurecatalyst:${EXCAT_IMAGE_TAG:-local}"
PROXY_IMAGE="exposurecatalyst-proxy:${EXCAT_IMAGE_TAG:-local}"
MIN_COMPOSE="2.24.0"

mkdir -p "$STATE_DIR" "$LOG_DIR"
chmod 700 "$STATE_DIR" 2>/dev/null || true

# ---- output ----------------------------------------------------------------------------------------------
ts() { date -u +%Y-%m-%dT%H:%M:%SZ; }
log() { printf '%s %s\n' "$(ts)" "$*" | tee -a "$LOG_FILE"; }
ok() { log "✔ $*"; }
warn() { log "! $*" >&2; }
die() { local code=$1; shift; log "✘ $*" >&2; exit "$code"; }

# ---- lock ------------------------------------------------------------------------------------------------
release_lock() { rm -rf "$LOCK_DIR"; }
acquire_lock() {
  if mkdir "$LOCK_DIR" 2>/dev/null; then
    echo $$ >"$LOCK_DIR/pid"
    trap release_lock EXIT
    trap 'release_lock; exit 130' INT TERM
    return 0
  fi
  local pid; pid=$(cat "$LOCK_DIR/pid" 2>/dev/null || echo "")
  if [ -n "$pid" ] && ! kill -0 "$pid" 2>/dev/null; then
    warn "removing stale lock left by pid $pid"
    rm -rf "$LOCK_DIR"
    acquire_lock
    return
  fi
  die 4 "another ./run.sh is running (pid ${pid:-?}); remove $LOCK_DIR if that is not true"
}

# ---- configuration (YAML → compose variables; .env and the shell always win) ------------------------------
# Minimal reader for the flat example format: top-level `key: value` and `features:` → `  name: value`.
yaml_get() {
  local key=$1 file=${2:-$CONFIG}
  [ -f "$file" ] || return 0
  case "$key" in
    features.*)
      awk -v k="${key#features.}" '
        /^features:/ {f=1; next}
        f && /^[^ #]/ {f=0}
        f && $1 == k":" {sub(/^[^:]*:[ \t]*/, ""); sub(/[ \t]+#.*$/, ""); gsub(/^["'\'']|["'\'']$/, ""); print; exit}
      ' "$file" ;;
    *)
      awk -v k="$key" '
        $1 == k":" && $0 !~ /^[ \t]/ {sub(/^[^:]*:[ \t]*/, ""); sub(/[ \t]+#.*$/, ""); gsub(/^["'\'']|["'\'']$/, ""); print; exit}
      ' "$file" ;;
  esac
}

dotenv_has() {  # non-empty KEY in .env?
  [ -f "$ROOT/.env" ] && grep -Eq "^[[:space:]]*$1=[^[:space:]#]" "$ROOT/.env"
}

dotenv_get() {  # value of KEY in .env (last wins; inline " # comments" and surrounding quotes removed)
  [ -f "$ROOT/.env" ] || return 0
  { grep -E "^[[:space:]]*$1=" "$ROOT/.env" || true; } | tail -1 | cut -d= -f2- \
    | sed -e 's/[[:space:]]#.*$//' -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' -e 's/^"\(.*\)"$/\1/' -e "s/^'\(.*\)'$/\1/"
}

adopt_dotenv() {  # keys this script itself needs: shell > .env (compose reads .env on its own as well)
  local k v current
  for k in EXCAT_FQDN EXCAT_HTTP_PORT EXCAT_HTTPS_PORT EXCAT_HTTPS_PORT_SUFFIX EXCAT_IMAGE_TAG EXCAT_HEALTH_TIMEOUT \
           EXCAT_WATCH_INTERVAL EXCAT_MIN_FREE_GB EXCAT_FEATURES__RUN_WATCH_MODE COMPOSE_PROJECT_NAME COMPOSE_FILE; do
    eval "current=\${$k:-}"
    if [ -z "$current" ]; then
      v=$(dotenv_get "$k")
      if [ -n "$v" ]; then export "$k=$v"; fi
    fi
  done
  HEALTH_TIMEOUT="${EXCAT_HEALTH_TIMEOUT:-300}"
  WATCH_INTERVAL="${EXCAT_WATCH_INTERVAL:-30}"
  MIN_FREE_GB="${EXCAT_MIN_FREE_GB:-5}"
  APP_IMAGE="exposurecatalyst:${EXCAT_IMAGE_TAG:-local}"
  PROXY_IMAGE="exposurecatalyst-proxy:${EXCAT_IMAGE_TAG:-local}"
}

# export VAR from YAML key unless already set in the shell or .env (adopt_dotenv ran first)
env_or_yaml() {
  local var=$1 key=$2 value current
  eval "current=\${$var:-}"
  if [ -n "$current" ]; then return 0; fi
  value=$(yaml_get "$key")
  if [ -n "$value" ]; then export "$var=$value"; fi
}

ensure_config() {
  if [ ! -f "$CONFIG" ] && [ -f "$CONFIG_EXAMPLE" ]; then
    cp "$CONFIG_EXAMPLE" "$CONFIG"
    ok "created config/exposurecatalyst.yaml from the example (edit fqdn and features there)"
  fi
  if [ ! -f "$ROOT/.env" ] && [ -f "$ROOT/.env.example" ]; then
    cp "$ROOT/.env.example" "$ROOT/.env"
    chmod 600 "$ROOT/.env" 2>/dev/null || true
    ok "created .env from .env.example (secrets stay empty: the init container generates them)"
  fi
}

load_config() {
  adopt_dotenv
  env_or_yaml EXCAT_FQDN fqdn
  env_or_yaml EXCAT_HTTP_PORT http_port
  env_or_yaml EXCAT_HTTPS_PORT https_port
  env_or_yaml EXCAT_TRUSTED_PROXIES trusted_proxies
  env_or_yaml TZ timezone
  local proxy; proxy=$(yaml_get outbound_proxy)
  if [ -n "$proxy" ]; then
    [ -n "${HTTPS_PROXY:-}" ] || dotenv_has HTTPS_PROXY || export HTTPS_PROXY="$proxy"
    [ -n "${HTTP_PROXY:-}" ] || dotenv_has HTTP_PROXY || export HTTP_PROXY="$proxy"
  fi
  local https_port="${EXCAT_HTTPS_PORT:-443}"
  if [ -z "${EXCAT_HTTPS_PORT_SUFFIX:-}" ] && [ "$https_port" != "443" ]; then
    export EXCAT_HTTPS_PORT_SUFFIX=":$https_port"
  fi
  if [ -n "$(yaml_get database_url)" ] && [ -z "${COMPOSE_FILE:-}" ]; then
    export COMPOSE_FILE="docker-compose.yml:docker/compose.external-db.yml"
  fi
  FQDN="${EXCAT_FQDN:-localhost}"
  if [ "$https_port" = "443" ]; then URL="https://$FQDN"; else URL="https://$FQDN:$https_port"; fi
}

flag_on() {  # features.<name> from env EXCAT_FEATURES__<NAME> or YAML
  local name=$1 upper value
  upper=$(printf '%s' "$name" | tr '[:lower:]' '[:upper:]')
  eval "value=\${EXCAT_FEATURES__$upper:-}"
  [ -n "$value" ] || value=$(yaml_get "features.$name")
  case "$value" in true|True|TRUE|yes|1|on) return 0 ;; *) return 1 ;; esac
}

dc() { docker compose "$@"; }

# ---- preflight -------------------------------------------------------------------------------------------
version_ge() {  # $1 >= $2 (dotted numbers)
  [ "$(printf '%s\n%s\n' "$2" "$1" | sort -t. -k1,1n -k2,2n -k3,3n | head -1)" = "$2" ]
}

port_busy_by_other() {  # true if something other than our proxy listens on the host port
  local port=$1 owned
  owned=$( { dc port proxy 8080 2>/dev/null; dc port proxy 8443 2>/dev/null; } || true)
  if printf '%s\n' "$owned" | grep -Eq ":$port\$"; then
    return 1  # ours: the running proxy publishes it
  fi
  if command -v lsof >/dev/null 2>&1; then
    lsof -nP -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1 && return 0 || return 1
  fi
  (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null && return 0
  return 1
}

preflight() {
  command -v docker >/dev/null 2>&1 || die 3 "Docker is not installed (https://docs.docker.com/get-docker/)"
  docker info >/dev/null 2>&1 || die 3 "the Docker daemon is not running or not reachable"
  local cv; cv=$(docker compose version --short 2>/dev/null | sed 's/^v//') || true
  [ -n "$cv" ] || die 3 "Docker Compose v2 is required (docker compose …)"
  version_ge "$cv" "$MIN_COMPOSE" || die 3 "Docker Compose $cv is too old; $MIN_COMPOSE or newer is required"
  local p
  for p in "${EXCAT_HTTP_PORT:-80}" "${EXCAT_HTTPS_PORT:-443}"; do
    if port_busy_by_other "$p"; then die 3 "port $p is in use by another program (set http_port/https_port)"; fi
  done
  local free_kb; free_kb=$(df -Pk "$ROOT" | awk 'NR==2 {print $4}')
  if [ "$free_kb" -lt $((MIN_FREE_GB * 1024 * 1024)) ]; then
    die 3 "less than ${MIN_FREE_GB} GB free disk space in $ROOT ($((free_kb / 1024 / 1024)) GB)"
  fi
  ok "preflight: docker $(docker version --format '{{.Server.Version}}' 2>/dev/null), compose $cv, ports ${EXCAT_HTTP_PORT:-80}/${EXCAT_HTTPS_PORT:-443}, disk $((free_kb / 1024 / 1024)) GB free"
}

# ---- change detection ------------------------------------------------------------------------------------
sha() { if command -v sha256sum >/dev/null 2>&1; then sha256sum; else shasum -a 256; fi; }

hash_paths() {  # content hash of tracked + untracked (non-ignored) files under the given paths
  local list
  if git -C "$ROOT" rev-parse >/dev/null 2>&1; then
    list=$(git -C "$ROOT" ls-files -co --exclude-standard -- "$@" 2>/dev/null | LC_ALL=C sort)
  else
    list=$(cd "$ROOT" && find "$@" -type f -not -path '*/node_modules/*' -not -path '*/__pycache__/*' 2>/dev/null | LC_ALL=C sort)
  fi
  {
    printf '%s\n' "$list"
    printf '%s\n' "$list" | while IFS= read -r f; do [ -f "$ROOT/$f" ] && cat "$ROOT/$f"; done
  } | sha | cut -c1-64
}

compute_hashes() {
  APP_HASH=$(hash_paths Dockerfile .dockerignore pyproject.toml README.md CHANGELOG.md mkdocs.yml alembic.ini src migrations docs brand frontend docker/caddy/Caddyfile)
  PROXY_HASH=$(hash_paths Dockerfile .dockerignore frontend brand docker/caddy)
  CONF_HASH=$( { hash_paths docker-compose.yml docker/compose.external-db.yml docker/backup; \
                 [ -f "$ROOT/.env" ] && sha <"$ROOT/.env"; [ -f "$CONFIG" ] && sha <"$CONFIG"; \
                 env | grep -E '^(EXCAT_|COMPOSE_|HTTPS?_PROXY|NO_PROXY|TZ=)' | LC_ALL=C sort | sha; } | sha | cut -c1-64)
}

state_get() { [ -f "$STATE_FILE" ] && sed -n "s/^$1=//p" "$STATE_FILE" | tail -1 || true; }

save_state() {
  local version=$1 tmp="$STATE_FILE.tmp"
  { echo "app_hash=$APP_HASH"; echo "proxy_hash=$PROXY_HASH"; echo "conf_hash=$CONF_HASH"
    echo "version=$version"; echo "last_success=$(ts)"; echo "url=$URL"; } >"$tmp"
  mv "$tmp" "$STATE_FILE"
}

# ---- health ----------------------------------------------------------------------------------------------
running_services() { dc ps --services --filter status=running 2>/dev/null || true; }

all_healthy() {
  local out; out=$(dc ps --format '{{.Service}}|{{.State}}|{{.Health}}' 2>/dev/null) || return 1
  [ -n "$out" ] || return 1
  printf '%s\n' "$out" | awk -F'|' '
    $1=="init" || $1=="migrate" {next}
    $2!="running" {bad=1} $3!="" && $3!="healthy" {bad=1}
    END {exit bad}'
}

app_version() {
  curl -sk --max-time 5 --resolve "$FQDN:${EXCAT_HTTPS_PORT:-443}:127.0.0.1" "$URL/api/health/ready" 2>/dev/null \
    | sed -n 's/.*"version":"\([^"]*\)".*/\1/p'
}

show_failure() {
  warn "deployment failed; service status:"
  dc ps -a 2>&1 | tee -a "$LOG_FILE" >&2 || true
  local svc failing
  failing=$(dc ps -a --format '{{.Service}}|{{.State}}|{{.Health}}|{{.ExitCode}}' 2>/dev/null \
      | awk -F'|' '($1=="init"||$1=="migrate") {if ($4!="0") print $1; next}
                   $2!="running" || ($3!="" && $3!="healthy") {print $1}' || true)
  [ -n "$failing" ] || failing="api migrate"
  for svc in $failing; do
    warn "last logs of $svc:"
    dc logs --no-color --tail 60 "$svc" 2>&1 | tee -a "$LOG_FILE" >&2 || true
  done
}

# ---- backup / rollback -----------------------------------------------------------------------------------
LAST_BACKUP=""
backup_db() {  # pg_dump into the backups volume (bundled PostgreSQL only)
  if ! running_services | grep -qx postgres; then
    log "backup: bundled PostgreSQL not running (first start or external database) — skipped"
    return 0
  fi
  log "backup: pg_dump → backups volume"
  local out
  if out=$(dc --profile backup run --rm --no-deps -T backup once 2>&1); then
    LAST_BACKUP=$(printf '%s\n' "$out" | sed -n 's/.*wrote \(excat-[^ ]*\.dump\).*/\1/p' | tail -1)
    ok "backup: ${LAST_BACKUP:-written}"
  else
    printf '%s\n' "$out" >>"$LOG_FILE"
    die 1 "database backup failed — not applying changes (see logs/run.log)"
  fi
}

rollback_ref() {  # exposurecatalyst:local → exposurecatalyst:rollback; custom tags get <tag>-rollback
  local repo=${1%:*} tag=${1##*:}
  if [ "$tag" = "local" ]; then echo "$repo:rollback"; else echo "$repo:$tag-rollback"; fi
}

tag_rollback() {
  local img
  for img in "$APP_IMAGE" "$PROXY_IMAGE"; do
    if docker image inspect "$img" >/dev/null 2>&1; then docker tag "$img" "$(rollback_ref "$img")"; fi
  done
}

restore_images() {
  local img restored=0
  for img in "$APP_IMAGE" "$PROXY_IMAGE"; do
    if docker image inspect "$(rollback_ref "$img")" >/dev/null 2>&1; then
      docker tag "$(rollback_ref "$img")" "$img"; restored=1
    fi
  done
  if [ "$restored" = 1 ]; then
    warn "rolling back to the previous images"
    if dc up -d --remove-orphans --wait --wait-timeout "$HEALTH_TIMEOUT" >>"$LOG_FILE" 2>&1; then
      ok "previous version is running again"
    else
      warn "the previous version did not become healthy either — check: ./run.sh logs"
    fi
  else
    warn "no :rollback images exist (first deployment) — nothing to roll back to"
  fi
  if [ -n "$LAST_BACKUP" ]; then
    warn "if the failed version changed the database schema, restore the pre-migration backup:"
    warn "    ./run.sh restore $LAST_BACKUP      (asks for confirmation; never automatic)"
  fi
}

# ---- main flow -------------------------------------------------------------------------------------------
deploy() {
  ensure_config
  load_config
  preflight
  compute_hashes
  local prev_app prev_proxy prev_conf
  prev_app=$(state_get app_hash); prev_proxy=$(state_get proxy_hash); prev_conf=$(state_get conf_hash)
  if [ "$APP_HASH" = "$prev_app" ] && [ "$PROXY_HASH" = "$prev_proxy" ] && [ "$CONF_HASH" = "$prev_conf" ] && all_healthy; then
    if [ -n "${WATCHING:-}" ]; then  # watch mode: quiet when idle (still recorded in logs/run.log)
      printf '%s %s\n' "$(ts)" "unchanged" >>"$LOG_FILE"
    else
      ok "nothing changed since $(state_get last_success) and all services are healthy — $URL ($(state_get version))"
    fi
    return 0
  fi
  local build_app=0 build_proxy=0
  { [ "$APP_HASH" != "$prev_app" ] || ! docker image inspect "$APP_IMAGE" >/dev/null 2>&1; } && build_app=1
  { [ "$PROXY_HASH" != "$prev_proxy" ] || ! docker image inspect "$PROXY_IMAGE" >/dev/null 2>&1; } && build_proxy=1
  log "changes: app image $( [ $build_app = 1 ] && echo rebuild || echo unchanged ), proxy image $( [ $build_proxy = 1 ] && echo rebuild || echo unchanged ), configuration $( [ "$CONF_HASH" != "$prev_conf" ] && echo changed || echo unchanged )"
  tag_rollback
  if [ $build_app = 1 ]; then
    log "building $APP_IMAGE"
    dc build api >>"$LOG_FILE" 2>&1 || { tail -30 "$LOG_FILE" >&2; die 1 "image build failed (nothing was changed)"; }
  fi
  if [ $build_proxy = 1 ]; then
    log "building $PROXY_IMAGE"
    dc build proxy >>"$LOG_FILE" 2>&1 || { tail -30 "$LOG_FILE" >&2; die 1 "image build failed (nothing was changed)"; }
  fi
  [ $build_app = 1 ] && backup_db
  log "starting services (migrations run first; waiting up to ${HEALTH_TIMEOUT}s for health)"
  if dc up -d --remove-orphans --wait --wait-timeout "$HEALTH_TIMEOUT" >>"$LOG_FILE" 2>&1; then
    local version; version=$(app_version); version=${version:-unknown}
    save_state "$version"
    ok "ExposureCatalyst $version is up: $URL"
    if [ "$FQDN" = "localhost" ]; then log "  (self-signed certificate until you install one — Settings → Certificates & Domain)"; fi
    if dc logs api 2>/dev/null | grep "one-time setup token" >/dev/null; then
      log "  first run: open $URL/setup — token: ./run.sh logs api | grep -A3 'setup token'"
    fi
    return 0
  fi
  show_failure
  restore_images
  exit 1
}

# ---- subcommands -----------------------------------------------------------------------------------------
cmd_status() {
  load_config
  dc ps -a
  if all_healthy; then ok "all services healthy — $URL ($(app_version))"; else warn "not all services are healthy"; fi
  [ -f "$STATE_FILE" ] && log "last successful run: $(state_get last_success) (version $(state_get version))"
  cert_days || true
}

cert_days() {
  command -v openssl >/dev/null 2>&1 || return 0
  local end
  end=$(printf '' | openssl s_client -connect "127.0.0.1:${EXCAT_HTTPS_PORT:-443}" -servername "$FQDN" 2>/dev/null \
        | openssl x509 -noout -enddate -issuer 2>/dev/null) || return 0
  [ -n "$end" ] && log "certificate: $(printf '%s' "$end" | tr '\n' ' ')"
}

cmd_backup() {
  load_config
  running_services | grep -qx postgres || die 1 "the bundled PostgreSQL is not running (use your DBA's backups for an external database)"
  backup_db
  log "backups: docker compose --profile backup run --rm --no-deps --entrypoint ls backup -l /backups"
}

cmd_restore() {
  local file=${1:-}
  [ -n "$file" ] || die 2 "usage: ./run.sh restore <excat-YYYYMMDDTHHMMSSZ.dump>"
  case "$file" in */*|*..*) die 2 "give the backup file name only (it is read from the backups volume)";; esac
  load_config
  running_services | grep -qx postgres || die 1 "the bundled PostgreSQL must be running"
  dc --profile backup run --rm --no-deps -T --entrypoint test backup -f "/backups/$file" \
    || die 1 "backup $file not found in the backups volume"
  warn "This REPLACES the current database with $file. Current data not in that backup is lost."
  warn "A safety backup of the current database is taken first."
  local answer=""
  if [ -t 0 ]; then read -r -p "Type RESTORE to continue: " answer; else answer="${EXCAT_CONFIRM_RESTORE:-}"; fi
  [ "$answer" = "RESTORE" ] || die 5 "restore aborted"
  acquire_lock
  backup_db
  log "stopping api / scheduler / proxy"
  dc stop proxy api scheduler >>"$LOG_FILE" 2>&1 || true
  log "restoring $file"
  if dc --profile backup run --rm --no-deps -T --entrypoint sh backup -c \
      'PGPASSWORD="$(cat /run/db-secret/db_password)" pg_restore -h postgres -U excat -d excat --clean --if-exists --no-owner "/backups/'"$file"'"' \
      >>"$LOG_FILE" 2>&1; then
    ok "database restored"
  else
    warn "pg_restore reported errors (see logs/run.log); starting the services anyway"
  fi
  dc up -d --wait --wait-timeout "$HEALTH_TIMEOUT" >>"$LOG_FILE" 2>&1 && ok "services up: $URL" || die 1 "services did not become healthy"
}

cmd_update() {
  git -C "$ROOT" rev-parse >/dev/null 2>&1 || die 1 "not a git checkout; download the new release instead"
  if [ -n "$(git -C "$ROOT" status --porcelain --untracked-files=no)" ]; then
    die 1 "local changes in tracked files — commit or stash them before ./run.sh update"
  fi
  local branch; branch=$(git -C "$ROOT" rev-parse --abbrev-ref HEAD)
  log "git pull --ff-only (branch $branch)"
  git -C "$ROOT" pull --ff-only >>"$LOG_FILE" 2>&1 || die 1 "git pull failed (see logs/run.log)"
  ok "now at $(git -C "$ROOT" log -1 --format='%h %s')"
  deploy
}

cmd_watch() {
  load_config
  flag_on run_watch_mode || die 1 "watch mode is disabled — set features.run_watch_mode: true in config/exposurecatalyst.yaml (dev/test only)"
  log "watch mode: checking for changes every ${WATCH_INTERVAL}s (Ctrl-C to stop)"
  release_lock; trap - EXIT INT TERM
  export WATCHING=1
  while true; do
    ( acquire_lock; deploy ) || warn "apply failed; will retry on the next change"
    sleep "$WATCH_INTERVAL"
  done
}

cmd_doctor() {
  ensure_config
  load_config
  local rc=0
  log "== versions"
  log "docker $(docker version --format '{{.Server.Version}}' 2>/dev/null || echo '?'), compose $(docker compose version --short 2>/dev/null || echo '?'), bash $BASH_VERSION"
  log "images: $(docker image inspect "$APP_IMAGE" --format '{{index .Config.Labels "org.opencontainers.image.version"}}' 2>/dev/null || echo 'not built') (app), $(docker image inspect "$PROXY_IMAGE" >/dev/null 2>&1 && echo present || echo 'not built') (proxy)"
  log "== services"
  if all_healthy; then ok "all services healthy"; else warn "not all services healthy"; rc=1; fi
  dc ps -a --format '{{.Service}}: {{.State}} {{.Health}}' 2>/dev/null | while IFS= read -r l; do log "  $l"; done
  log "== domain"
  log "fqdn: $FQDN  url: $URL"
  if [ "$FQDN" != "localhost" ]; then
    local ip=""
    if command -v dig >/dev/null 2>&1; then ip=$(dig +short "$FQDN" | tail -1); fi
    if [ -z "$ip" ] && command -v getent >/dev/null 2>&1; then ip=$(getent hosts "$FQDN" | awk '{print $1; exit}'); fi
    if [ -n "$ip" ]; then ok "$FQDN resolves to $ip"; else warn "$FQDN does not resolve (create the DNS record — see Map your domain)"; rc=1; fi
  fi
  log "== certificate"
  cert_days || warn "could not read the served certificate"
  log "== disk"
  local free_kb; free_kb=$(df -Pk "$ROOT" | awk 'NR==2 {print $4}')
  if [ "$free_kb" -lt $((MIN_FREE_GB * 1024 * 1024)) ]; then warn "only $((free_kb / 1024 / 1024)) GB free"; rc=1; else ok "$((free_kb / 1024 / 1024)) GB free"; fi
  docker system df 2>/dev/null | while IFS= read -r l; do log "  $l"; done
  log "== last run"
  log "$( [ -f "$STATE_FILE" ] && echo "success at $(state_get last_success), version $(state_get version)" || echo 'no successful run recorded')"
  return $rc
}

usage() {
  cat <<'EOF'
Usage: ./run.sh [command]

  (no command)    bring the app up, or apply changes since the last successful run and restart
  start           start the services (no rebuild)
  stop            stop the services (data is kept)
  restart         restart the services and wait for health
  update          git pull (current branch, fast-forward only) then apply as above
  status          service status, health, version, certificate
  logs [service]  follow logs (all services, or e.g. api, proxy, scheduler)
  backup          pg_dump of the bundled PostgreSQL into the backups volume
  restore <file>  restore a backup (asks for confirmation; takes a safety backup first)
  watch           poll for changes every EXCAT_WATCH_INTERVAL s (30) and apply them — needs
                  features.run_watch_mode: true (dev/test only)
  doctor          diagnostics: health, certificate, DNS, disk, versions
  help            this help

Configuration: config/exposurecatalyst.yaml (created from the example on first run) and .env.
Environment: EXCAT_HEALTH_TIMEOUT (300), EXCAT_WATCH_INTERVAL (30), EXCAT_MIN_FREE_GB (5).
Log: logs/run.log
EOF
}

main() {
  local cmd=${1:-}
  [ $# -gt 0 ] && shift
  case "$cmd" in
    "") acquire_lock; deploy ;;
    start) acquire_lock; ensure_config; load_config; preflight
           dc up -d --no-build --wait --wait-timeout "$HEALTH_TIMEOUT" >>"$LOG_FILE" 2>&1 \
             && ok "started: $URL" || { show_failure; exit 1; } ;;
    stop) acquire_lock; adopt_dotenv; dc stop >>"$LOG_FILE" 2>&1; ok "stopped (data kept)" ;;
    restart) acquire_lock; load_config; dc restart >>"$LOG_FILE" 2>&1
             dc up -d --no-build --wait --wait-timeout "$HEALTH_TIMEOUT" >>"$LOG_FILE" 2>&1 \
               && ok "restarted: $URL" || { show_failure; exit 1; } ;;
    update) acquire_lock; cmd_update ;;
    status) cmd_status ;;
    logs) adopt_dotenv; dc logs -f --tail 200 "$@" ;;
    backup) acquire_lock; cmd_backup ;;
    restore) cmd_restore "$@" ;;
    watch) cmd_watch ;;
    doctor) cmd_doctor ;;
    help|-h|--help) usage ;;
    *) usage >&2; exit 2 ;;
  esac
}

main "$@"
