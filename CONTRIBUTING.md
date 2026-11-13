# Contributing

1. `make install`, then `make test lint security` must pass before you open a PR.
2. **Every feature ships its help and docs in the same PR**: update `docs/help/<page>.md` (wrap admin-only steps
   in `<!-- requires: perm -->`), add tooltip keys to `docs/help/tooltips.yml`, and update or add pages under
   `docs/`. Run `make docs`. The build is strict.
3. New endpoints **must** depend on `require(Permission.X)`. `tests/test_auth_rbac.py` fails if a route is
   reachable anonymously.
4. Outbound HTTP **must** go through `ingestion.http.SourceClient` (SSRF guard, allowlist, retries).
5. Schema changes need an Alembic migration (`alembic revision --autogenerate`), reviewed for portability:
   no dialect-specific types, and named constraints.
6. Architecture changes update the relevant `docs/diagrams/*.py` and add an ADR in `docs/architecture/adr/`.
7. Never log secrets. Add sensitive key names to the redaction pattern in `exposurecatalyst/logging.py` if needed.
8. Commit messages: imperative mood, reference the issue, and keep the CHANGELOG `Unreleased` section current.
