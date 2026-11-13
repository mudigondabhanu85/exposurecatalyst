# Changelog

All notable changes to ExposureCatalyst. The format follows [Keep a Changelog](https://keepachangelog.com/)
and the project uses [Semantic Versioning](https://semver.org/).

## [0.4.0] — 2026-11-13 — Phase 4: identity, governance and alerts

### Added
- **Okta SAML 2.0 SSO**: strict validation, signed AuthnRequests, stored request IDs matched to
  `InResponseTo`, assertion replay cache, IdP-initiated off by default, JIT provisioning, downloadable SP
  metadata, IdP metadata import (URL restricted to Okta domains, or XML).
- **SailPoint**: group → role mapping (the only source of SSO users' roles) with sync status, and a
  **SCIM 2.0** server (Users and Groups with filter, PATCH and soft delete) with hashed bearer tokens.
- **Alerts & scheduling**: rules on severity, CVSS, EPSS, KEV added, vendor/product watchlist, keywords and
  affected assets. Immediate (throttled) or digest delivery by email, Slack or Teams. Evaluated every
  scheduler tick.
- Custom role editor. Setup wizard for Okta and SailPoint. Identity flow diagram. Sequence diagrams (SAML
  sign-in, hourly fetch, advisory send, alert trigger). Okta, SailPoint and alerts guides. RBAC docs.

### Fixed
- The "every API route requires authentication" test didn't see routes nested by FastAPI 0.16x, so it
  checked almost nothing. It now walks nested routers and asserts coverage (> 80 routes). No unprotected route
  was found.
- Diagram legends overflowed their boxes (`fixedsize` default from the diagrams library).

## [0.3.0] — 2026-11-13 — Phase 3: integrations

### Added
- Connector framework: plugin interface and registry, per-connector config schema, default field maps with
  per-integration overrides, encrypted write-only credentials, Settings → Integrations with a guided setup
  and *Save & test*.
- Connectors: **Qualys VMDR** (CVE→QID KnowledgeBase map and Host List Detection), **Wiz** (OAuth2 and GraphQL
  vulnerability findings), **Tanium** (Gateway GraphQL sensor filter), **ServiceNow CMDB** (Vulnerability
  Response vulnerable items and CMDB enrichment of owner / business unit / environment), **Zafran** and
  **ArmorCode** (configurable REST).
- CVE detail *Affected assets* panel with cross-tool de-duplication and **Check now**. Advisory **Pull from
  integrations** fills the validation matrix (Yes / No / Not Integrated) and keeps manual rows.
- Per-(integration, CVE) result cache (`EXCAT_CONNECTOR_CACHE_MINUTES`), result cap with a truncation flag,
  per-tool failure isolation.
- Integration guides for every connector, a help topic, and an updated data model, API and security docs.

### Changed
- The hardened outbound HTTP client now supports any method and per-connector host allowlists.

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
