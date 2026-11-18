#!/usr/bin/env bash
# Compose smoke test (CI job `compose-smoke`, `make smoke`): bring the full stack up in an isolated project,
# wait for health, check HTTPS end to end through the proxy, then tear everything down (volumes included).
# Uses its own project name, ports and subnet, so it never touches a running deployment.
set -euo pipefail
cd "$(dirname "$0")/.."
export COMPOSE_PROJECT_NAME="${SMOKE_PROJECT:-excat-smoke}"
export EXCAT_HTTP_PORT="${SMOKE_HTTP_PORT:-18080}" EXCAT_HTTPS_PORT="${SMOKE_HTTPS_PORT:-18443}"
export EXCAT_EDGE_SUBNET="${SMOKE_SUBNET:-172.30.251.0/24}" EXCAT_PROXY_IP="${SMOKE_PROXY_IP:-172.30.251.10}"
export EXCAT_BIND_ADDRESS=127.0.0.1 EXCAT_HTTPS_PORT_SUFFIX=":${EXCAT_HTTPS_PORT}"
export EXCAT_FQDN=localhost   # public URL is derived: https://localhost:${EXCAT_HTTPS_PORT}
TIMEOUT="${SMOKE_TIMEOUT:-300}"
log() { printf '%s [smoke] %s\n' "$(date -u +%FT%TZ)" "$*"; }
cleanup() { log "tearing down"; docker compose down -v --remove-orphans >/dev/null 2>&1 || true; }
trap cleanup EXIT

log "building and starting ${COMPOSE_PROJECT_NAME}"
docker compose up -d --build --wait --wait-timeout "$TIMEOUT" || {
  docker compose ps -a; docker compose logs --tail 80; exit 1; }
docker compose ps -a --format '{{.Service}}\t{{.Status}}'

base="https://localhost:${EXCAT_HTTPS_PORT}"
check() {  # name expected-status url [extra curl args]
  local name=$1 want=$2 url=$3; shift 3
  local got; got=$(curl -sk -o /dev/null -w '%{http_code}' "$@" "$url")
  [[ "$got" == "$want" ]] || { log "FAIL $name: $url → $got (want $want)"; docker compose logs --tail 40 api proxy; exit 1; }
  log "ok   $name ($got)"
}
check "health over HTTPS" 200 "$base/api/health/ready"
check "login page over HTTPS" 200 "$base/login"
check "HTTP→HTTPS redirect" 308 "http://localhost:${EXCAT_HTTP_PORT}/login"
check "docs require login" 303 "$base/docs/"
check "API requires auth" 401 "$base/api/cves"
curl -sk "$base/api/health/ready" | grep -q '"database":"up"' || { log "FAIL database not up"; exit 1; }
log "ok   database up"
if docker compose logs init | grep -q "self-signed certificate generated"; then
  log "ok   bootstrap generated secrets + certificate"
fi
# default break-glass account: generated password, forced change before anything else
pw=$(docker compose exec -T api cat /var/lib/excat/secrets/initial_admin_password 2>/dev/null || true)
if [[ -n "$pw" ]]; then
  jar=$(mktemp)
  check "break-glass login" 200 "$base/api/auth/login" -c "$jar" -H "Origin: $base" -H 'Content-Type: application/json' \
    -d "{\"username\":\"breakglass\",\"password\":\"$pw\"}"
  curl -sk -b "$jar" "$base/api/auth/me" | grep -q '"must_change_password":true' || { log "FAIL must_change_password not set"; exit 1; }
  log "ok   password change forced at first sign-in"
  check "admin API blocked until password change" 403 "$base/api/admin/users" -b "$jar"
  rm -f "$jar"
fi
if curl -sk "$base/api/auth/sso" | grep -q '"setup_required":true'; then   # EXCAT_BOOTSTRAP_ADMIN=false → wizard
  token=$(docker compose logs api 2>/dev/null | grep -A3 "one-time setup token" | sed -n 's/^.*|[[:space:]]*\([A-Za-z0-9_-]\{20,\}\)[[:space:]]*$/\1/p' | head -1)
  [[ -n "$token" ]] || { log "FAIL setup token not found in api logs"; exit 1; }
  check "setup token (no token)" 401 "$base/api/setup/verify"
  check "setup token from api logs" 200 "$base/api/setup/verify" -H "Authorization: Bearer $token"
fi
log "PASS"
