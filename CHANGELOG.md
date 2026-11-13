# Changelog

All notable changes to ExposureCatalyst. The format follows [Keep a Changelog](https://keepachangelog.com/)
and the project uses [Semantic Versioning](https://semver.org/).

## [0.1.0] — 2026-11-13 — Phase 1

### Added
- **CVE Intelligence**: ingestion from NVD API 2.0 (incremental by last-modified window, ≤120-day chunks,
  paginated, 5 or 50 req/30 s rate limits), CISA KEV (ETag conditional fetch, truncation guard) and FIRST EPSS
  (per-CVE API or bulk CSV). Records are normalized and de-duplicated, with per-field provenance and a
  timeline of material changes.
- Search by CVE ID or keyword, and filter by vendor, product, severity, CVSS range, EPSS threshold, KEV,
  exploit availability and date range. Results can be sorted and paginated, and searches saved per user.
- CVE detail view with all CVSS assessments, CPE version ranges, references (patch and exploit tagged), an
  affected-assets panel (empty state until Phase 3) and **Create Advisory Email** hand-off.
- Source health strip, **Refresh now**, per-source interval and enable/disable settings, recent job runs,
  scheduler heartbeat.
- **Security**: local accounts with Argon2id passwords, TOTP MFA for break-glass admins, lockout and per-IP
  rate limiting, server-side sessions with idle and absolute timeouts, CSRF tokens plus an Origin check,
  strict CSP, server-side RBAC with six default roles and an escalation guard, a hash-chained append-only
  audit log (with a PostgreSQL trigger), an SSRF guard and egress allowlist, Fernet encryption of secrets at
  rest, and log redaction.
- **Help**: help drawer on every page, ⓘ tooltips, Help Center (search, glossary, FAQ, shortcuts, what's new)
  and RBAC-filtered help content. The help Markdown is shared with the docs.
- **Docs and diagrams**: MkDocs Material site, generated configuration and RBAC reference pages, ADRs, and
  the high-level AWS architecture diagram as `diagrams` source, SVG, 300 DPI PNG and editable `.drawio`.
- Docker image, docker-compose (PostgreSQL, API, scheduler) and a CI pipeline.
