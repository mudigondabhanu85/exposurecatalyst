#!/bin/sh
# Proxy entrypoint: use the Caddyfile persisted by Settings → Certificates & Domain (ACME mode) when present and
# valid, otherwise the image default (certificate files from the certs volume). A broken generated file can never
# keep the proxy down.
set -eu
default=/etc/caddy/Caddyfile
persisted=/certs/proxy/Caddyfile
cfg=$default
if [ -f "$persisted" ]; then
  if caddy validate --config "$persisted" --adapter caddyfile >/dev/null 2>&1; then
    cfg=$persisted
  else
    echo "[proxy] $persisted is invalid; falling back to the default configuration" >&2
  fi
fi
echo "[proxy] using $cfg"
exec caddy run --config "$cfg" --adapter caddyfile
