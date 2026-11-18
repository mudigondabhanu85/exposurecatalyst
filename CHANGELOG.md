# Changelog

All notable changes to ExposureCatalyst. The format follows [Keep a Changelog](https://keepachangelog.com/)
and the project uses [Semantic Versioning](https://semver.org/).

## [1.4.0] — 2026-11-17 — Docker deployment, Certificates & Domain, run.sh, subscriptions

All additions; existing features, APIs, data and the `make run` / AWS deployments are unchanged. New behaviour
is behind flags that default to off: `features.ui_tls_management`, `features.acme`, `features.subscriptions`,
`features.run_watch_mode`.

### Added
- **One-command Docker deployment** (`docker compose up -d` → `https://<fqdn>`): Caddy proxy (only published
  service, TLS 1.2/1.3, HTTP→HTTPS, hot reload over an admin unix socket), one-shot `init` (secrets +
  self-signed certificate, never overwrites) and `migrate` services, health-gated start order, internal backend
  network, non-root read-only containers with all capabilities dropped, digest-pinned images, resource limits,
  log rotation; profiles `direct`, `scale` (worker + Redis), `backup`, `ollama`, `devmail`; external-database
  override; corporate proxy and registry-mirror support; `make smoke`, `make scan` (Trivy), `make bundle`
  (air-gapped). CI: Trivy image scan and a compose smoke job.
- `EXCAT_<NAME>_FILE` for any setting; optional YAML config (`config/exposurecatalyst.yaml`, opt-in via
  `EXCAT_CONFIG_FILE`); `fqdn` driving every derived URL (SAML, OIDC, email links, Host allowlist, CSRF
  origins, certificate SAN) with domain-change detection and admin banners; configurable HSTS.
- **Default break-glass account** on an empty installation: `breakglass` Super Admin with a per-install generated
  password (`./run.sh initial-password`; never logged); a new password and MFA enrolment are forced at first
  sign-in (every other route answers 403 until then). Migration 0010 adds `users.must_change_password`
  (additive). `EXCAT_BOOTSTRAP_ADMIN=false` uses the **first-run setup wizard** instead (one-time setup token in
  the API logs → break-glass Super Admin with mandatory TOTP).
- **Settings → Certificates & Domain**: certificate status, derived URLs, install (PEM / bundle / PKCS#12 /
  paste) with full validation, CSR generation with server-side keys, automatic restore on failed activation,
  one-click rollback, trusted CA bundle for outbound TLS, ACME (HTTP-01 / DNS-01), expiry emails 30/14/7/1.
- **run.sh / run.ps1**: preflight, lock, change detection, selective rebuild, backup before migrations,
  health-gated apply with automatic image rollback; start, stop, restart, update, status, logs, backup,
  restore, watch, doctor.
- **Threat Intel & News Subscriptions**: 17 vendor presets plus custom REST / RSS / TAXII 2.1 / manual sources,
  JSONPath field mapping with Test & preview, manual intel with TLP and attachments, CSV / JSON / STIX import,
  licence metadata with usage, quotas and renewal reminders, redistribution controls enforced in advisory emails
  and AI context; new permission `intel:manage`.
- Migrations 0008 (TLS certificates, CSRs) and 0009 (subscriptions, intel items, attachments): new tables only,
  tested downgrades.
- Docs: Docker quick start, deployment configuration, Map your domain, TLS certificates, corporate proxy & CA,
  run.sh, backup/restore, upgrades, migrating into Docker, air-gapped install, subscriptions, troubleshooting,
  container topology diagram; in-app help for Certificates & Domain and Subscriptions.

### Changed
- Base images moved to current patch releases (the previous Python base had fixable HIGH/CRITICAL OS CVEs).
- The plain-HTTP `127.0.0.1:8000` port of the compose stack moved to `--profile direct`.

### Security
- Secret files and certificate keys are permission-restricted; private keys are Fernet-encrypted in the
  database and never returned; outbound trust bundle applied only while one is uploaded; subscription URLs are
  host-pinned and SSRF-checked including token and pagination URLs; TLP:RED never leaves the platform.

## [1.3.0] — 2026-11-14 — Microsoft 365 OAuth2 and Amazon SES email

### Added
- **Microsoft 365 OAuth2** delivery: SMTP AUTH `XOAUTH2` with an app-only Entra ID token (client
  credentials, `https://outlook.office365.com/.default`). Commercial/GCC and GCC High/DoD clouds. Tokens are
  cached until shortly before expiry. The client secret is encrypted, write-only and rotatable. STARTTLS or
  SSL/TLS is required.
- **Amazon SES API** delivery: SESv2 `SendEmail` with the raw MIME message (logo and Excel attachment
  intact), batches of 50 recipients, optional configuration set. Credentials come from the AWS default
  chain (the ECS task role), so no keys are stored.
- Settings → SMTP: delivery-method selector and presets (Microsoft 365, Microsoft 365 GCC High, Amazon SES
  API, Amazon SES SMTP, corporate relay). **Send test** reports the message ID.
- Terraform: `ses_identity_arns` grants the API and scheduler task roles `ses:SendEmail`/`SendRawEmail` on
  those identities and allowlists `email.<region>.amazonaws.com`. `smtp_egress_cidrs` passes TCP 587 to
  explicit relay CIDRs. `login.microsoftonline.com` was added to the default egress list.
- SMTP admin guide: Entra ID app registration and Exchange Online PowerShell steps, SES identity and
  sandbox steps, egress guidance. New threat-model rows for mail credentials and mail-settings SSRF.

### Fixed
- The container image now installs the `aws` extra (boto3). Before this, the Amazon Bedrock AI provider
  could not run in the image, and the SES API needs boto3 too.
- Reference deployment: SMTP on 587 could not pass the Network Firewall. STARTTLS has no TLS SNI, so the
  domain allowlist dropped it. Use `smtp_egress_cidrs` or the SES API.

## [1.2.0] — 2026-11-14 — Additional connectors, tickets & sharing

### Added
- **18 more asset-source connectors** (the spec's *Additional connectors*): Tenable Vulnerability Management
  and Tenable Security Center, Rapid7 InsightVM, CrowdStrike Falcon Spotlight, Microsoft Defender
  Vulnerability Management, Prisma Cloud (Compute), Orca, Snyk, Brinqa, Cisco Vulnerability Management
  (Kenna), Vulcan, Axonius, Armis, runZero, Nucleus, XM Cyber, Checkmarx One and Mend. Each has region
  presets where the vendor has regions, least-privilege prerequisites, a default field map and an
  integration guide.
- **Action connectors**: Jira (Cloud and Data Center), ServiceNow ITSM, Slack (bot token or incoming
  webhook) and Microsoft Teams (Workflows webhook). From an approved or sent advisory, users with
  `advisory:send` can create a ticket or post it under the new **Tickets & sharing** panel. Every attempt
  is recorded (migration `0007`, `advisory_actions`) and audited (`advisory.ticket_created` /
  `advisory.shared`). Action connectors are never queried for assets.
- Connector catalog is grouped by category, with a filter box and an **API defaults** badge. *Documented
  API* means it follows the vendor's public reference. *Confirm defaults* means the reference is
  tenant-gated, so the endpoint, filter, body and field map are editable settings to confirm per tenant.
- Configurable REST connector: `{setting}` path variables, JSON body templates (`"{{cve}}"`,
  `"{{limit}}"`), and offset pagination inside POST bodies.
- Field mapping understands epoch-second and epoch-millisecond dates.

### Fixed
- CrowdStrike's OAuth token endpoint answers `201 Created`, which is now accepted.

### Security
- Self-hosted tools (Tenable Security Center, on-prem Axonius and Jira Data Center) have no SaaS domain,
  so their host must be in `EXCAT_EGRESS_ALLOWLIST`.
- Token endpoints on other hosts (Entra ID, Checkmarx IAM) are allowed for egress but rejected as base URLs.
- Slack and Teams webhook URLs are validated (https, vendor host) when saved and again when used.
- OData `nextLink` pagination from Defender is followed only on the same host.
- Values interpolated into vendor query languages (FQL, AQL, OData, Kenna search) are sanitized.

## [1.1.0] — 2026-11-14 — OpenID Connect sign-in

### Added
- **OpenID Connect sign-in** as the alternative to SAML 2.0 (both can be enabled). Authorization Code flow
  with PKCE (S256) as a confidential client, built on Authlib/joserfc. Hashed single-use `state`, `nonce`
  bound to the ID token, PKCE verifier encrypted server-side, full ID-token validation (JWKS signature,
  asymmetric algorithms only, `iss`, `aud`/`azp`, `exp`/`iat`, `nonce`), `email_verified` enforced, groups
  from the ID token or userinfo, automatic JWKS refetch on signing-key rotation.
- Discovery hardening: the issuer must be https on an Okta domain or the egress allowlist, and every
  discovered endpoint must be on the issuer's host.
- Settings → Identity & SSO → **Alternative: OpenID Connect** (write-only client secret, *Test discovery*,
  enable/disable, test sign-in), login-page button, Okta OIDC admin guide, OIDC sequence diagram, threat-model
  rows. Migration `0006` (`oidc_requests`), purged daily by retention.

### Security
- **Least-privilege database role.** `exposurecatalyst migrate --app-role excat_app` (PostgreSQL) creates or
  updates a runtime role with `SELECT, INSERT, UPDATE, DELETE` only and `SELECT, INSERT` on `audit_log`, plus
  default privileges for future tables. It's idempotent and also rotates the password
  (`EXCAT_APP_DB_PASSWORD`). Terraform now runs the API and scheduler as `excat_app` with their own secret.
  A dedicated migration task, whose execution role is the only one that can read the Aurora master
  secret, applies migrations and the grants. Verified on PostgreSQL 16: DDL, TRUNCATE, DROP, audit-log
  UPDATE/DELETE and self-escalation are all refused.

### Changed
- SAML and OIDC share one sign-in completion path, so account matching, JIT provisioning, local-account
  protection and group → role rules are identical for both.

 — 2026-11-13 — Phase 6: hardening, AWS deployment and documentation

### Added
- **Terraform AWS reference deployment** (`infra/terraform`): VPC with public, firewall, private-app and
  isolated-data subnets across two AZs; AWS Network Firewall domain allowlist; VPC endpoints; CloudFront +
  WAF; ALB restricted to CloudFront; ECS Fargate API and scheduler; Aurora PostgreSQL (Multi-AZ, KMS,
  managed rotated password); ElastiCache; Secrets Manager; GuardDuty, Security Hub, CloudTrail, flow logs;
  CloudWatch alarms. Validated in CI and scanned with Trivy (no HIGH/CRITICAL).
- **Encryption key rotation**: `EXCAT_ENCRYPTION_KEYS_PREVIOUS` (MultiFernet) and
  `exposurecatalyst rotate-secrets [--dry-run]`.
- **Data retention**: daily maintenance job and `exposurecatalyst retention`, configurable per data type,
  audited.
- **Guided tours** per role (Analyst, Approver, Admin, Viewer), automatic on first sign-in, replayable from
  the header.
- **Diagrams**: network, multi-region DR, DFD Level 0 and Level 1 with trust boundaries and data
  classification, and logical components, each as SVG, 300-DPI PNG and editable draw.io.
- **Security documentation**: STRIDE threat model per trust boundary, AWS controls mapping, data retention.
- **Operations documentation**: monitoring and metrics, disaster recovery, and runbooks for source,
  scheduler, connector, SMTP, AI, alert failures, IdP certificate and key rotation, backup and restore,
  DR failover and upgrades.
- **Documentation exports**: User, Administrator, Security & Architecture and Complete guides as branded
  DOCX (cover, TOC, numbered headings, page numbers, landscape diagram pages) and single-file HTML, built by
  `make docs` and in the container image. Downloadable from **Help Center → Download documentation**,
  filtered by role.

### Changed
- `EXCAT_DATABASE_PASSWORD` is merged into the database URL, so the password can come from a separate
  secret.
- react-router-dom upgraded to 7.
- Login `next` redirects reject backslashes as well as absolute URLs.

### Fixed
- Two Mermaid diagrams (SAML sequence, advisory state machine) failed to render because of `;` and `:` in
  labels.

### Known limitations
- OIDC sign-in is not implemented (SAML 2.0 only).
- The Terraform deploys a single region; the DR secondary region and SQS/EventBridge worker mode are
  documented designs, not provisioned.
- Connectors and AI providers are verified against recorded/mocked responses, not live tenants.

## [0.5.0] — 2026-11-13 — Phase 5: Security News and AI

### Added
- **Security News**: 13 curated feeds (CISA, major security press, vendor threat intel). Hardened RSS/Atom
  parsing. URL and headline de-duplication with cross-outlet clustering. CVE extraction linked to CVE
  Intelligence. Topic tags and filters. Feed management with per-feed health. Headline and excerpt only.
- **AI provider layer**: 27 providers across commercial, cloud (Azure OpenAI, Bedrock, Vertex, watsonx, NIM),
  aggregators and self-hosted. Per-feature routing with fallback, provider allowlist, monthly budget,
  per-user rate limit, usage and cost tracking.
- **AI features**: CVE plain/executive summaries, risk narrative with priority, remediation guidance, advisory
  draft suggestions, news brief with themes and threat actors, natural-language search, analyst assistant,
  Ask Help with citations.
- **Data protection**: redaction of environment identifiers before external calls (restored for the user),
  untrusted-content fencing, schema-validated and grounded outputs, image-free rendering.

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
