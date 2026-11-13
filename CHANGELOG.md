# Changelog

All notable changes to ExposureCatalyst. The format follows [Keep a Changelog](https://keepachangelog.com/)
and the project uses [Semantic Versioning](https://semver.org/).

## [0.2.0] — 2026-11-13 — Phase 2 + brand identity

### Added
- **Advisory Email Generator**: create from CVE with pre-filled details; unique `EXCAT-YYYY-NNNN` IDs;
  editable subject and sections; To/CC/BCC with validation and distribution lists; draft → review →
  approved → sent workflow with segregation of duties; full delivery and audit history.
- Asset validation matrix (Validated = Yes only where assets were identified), cross-source de-duplication,
  manual rows and counts labelled *Manual*, and CSV/XLSX upload.
- Delivery: SMTP (STARTTLS/SSL, confirmation dialog), Copy for Outlook (rich HTML), `.eml` Outlook drafts
  (`X-Unsent: 1`) with the Excel attachment, HTML and PDF.
- Branded Excel export: logo, navy header rows, frozen headers, fitted columns, consolidated and per-source
  sheets, formula-injection guard.
- Versioned advisory templates (Critical, High, Informational, Executive) with sandboxed Jinja and approval.
- Settings → SMTP with an encrypted password and a test email.
- **Brand identity**: brand kit in `brand/`; tokens and self-hosted Inter / Space Grotesk; navy top bar
  with wordmark; branded login, loading and error screens; favicons, PWA manifest and Open Graph image;
  branded Swagger/ReDoc; email header logo (CID or data URI); branded docs theme and diagram title blocks.

### Changed
- Severity badges moved to a dedicated palette distinct from brand orange (WCAG AA). Links are now navy with
  an orange underline.

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
