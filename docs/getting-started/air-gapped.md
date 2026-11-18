# Air-gapped install

On a connected machine with the same CPU architecture:

```bash
make bundle        # → dist/exposurecatalyst-<version>-bundle.tar.gz
```

The bundle holds every image (`docker save`: app, proxy, PostgreSQL, Redis, backup) and the compose files,
Caddyfile, `run.sh` / `run.ps1` and example configuration. On the offline host:

```bash
tar xzf exposurecatalyst-<version>-bundle.tar.gz && cd bundle
docker load -i images.tar
./run.sh            # or docker compose up -d
```

Offline, CVE sources and integrations need either a reachable internal mirror (set the source URLs and
`EXCAT_EGRESS_ALLOWLIST`) or an outbound proxy; the app runs fine without them, with data from manual entry
and imports. Verify image digests against the release notes before loading.
