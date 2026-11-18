# Upgrades (Docker)

```bash
./run.sh update        # git pull --ff-only, rebuild changed images, backup, migrate, health-gated restart
```

Or from a release archive / air-gapped bundle: replace the files (keep `.env`, `config/exposurecatalyst.yaml`
and the Docker volumes), load new images if offline, then `./run.sh`.

- Migrations are additive and run in the `migrate` container before the app starts; a backup is taken first.
- If the new version fails its healthchecks, `run.sh` restarts the previous images and prints the restore
  command for the pre-migration backup (only needed if the failed version changed the schema).
- New feature flags default to off: an upgrade never changes behaviour until you enable them.
- Read each release's notes in `CHANGELOG.md` (also in the app: Help Center → What's new).
