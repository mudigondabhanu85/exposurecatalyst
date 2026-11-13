# Security overview (Phase 1)

ExposureCatalyst handles sensitive data: asset inventories, integration credentials and recipient lists. It
is designed to align with **OWASP ASVS Level 2**. This page covers the controls implemented in Phase 1. The
full STRIDE threat model, data-flow diagrams and AWS controls mapping follow in Phase 6.

## Data classification

| Class | Examples | Handling |
|---|---|---|
| **Restricted** | Integration API keys, SMTP and DB credentials, TOTP seeds, session tokens | Encrypted at rest (Fernet / KMS + Secrets Manager), never logged, never returned to the UI |
| **Confidential** | Asset data (hostnames, IPs, owners), recipient lists, audit log | Authenticated and authorized access only. Redacted before any external AI call (Phase 5) |
| **Internal** | Architecture docs, configuration | Authenticated users only (`/docs` requires login) |
| **Public** | CVE, KEV and EPSS data, news | Treated as **untrusted input** |

## Authentication & sessions

- Argon2id password hashing (`t=3, m=64 MiB, p=2`), transparently re-hashed when parameters change.
  Dummy-hash verification for unknown users to resist timing-based enumeration.
- Password policy: at least 12 characters, at most 256, not containing the username, not trivially
  repetitive.
- Lockout after 5 failures for 15 minutes, per-IP sliding-window rate limit, and generic error messages.
- TOTP (RFC 6238) with ±1 step drift and **replay protection** (last used counter stored). Required for local
  admins before admin APIs can be used.
- Server-side sessions: see [ADR-0002](../architecture/adr/0002-server-side-sessions.md).

## Authorization

- Permission checks via `require(...)` on every endpoint. A test enumerates all routes and asserts that
  anonymous access returns 401.
- Escalation guard: nobody can grant permissions they don't hold, or change their own roles.
- Object-level checks (for example, saved searches are scoped to their owner and return 404 otherwise).

## Input validation and output encoding

- Pydantic v2 models with bounds on every input. Sort keys are whitelisted. LIKE wildcards are escaped.
- SQL only through SQLAlchemy bound parameters.
- Upstream content (CVE descriptions, references) is rendered as **text**. Reference URLs are restricted to
  `http(s)` at ingestion and opened with `rel="noopener noreferrer nofollow"`.
- In-app Markdown is rendered without raw HTML.

## HTTP security headers

Strict CSP (see [ADR-0005](../architecture/adr/0005-csp-scoping.md)), HSTS (two years, includeSubDomains),
`X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: strict-origin-when-cross-origin`,
`Permissions-Policy`, `Cross-Origin-Opener-Policy: same-origin`, and `Cache-Control: no-store` on the API.
Unhandled errors return a generic 500. Stack traces only go to logs.

## SSRF and egress

Every outbound request passes `validate_outbound_url`:

- `https` only, and no credentials in the URL
- the host must match `EXCAT_EGRESS_ALLOWLIST` (exact match, or `*.domain` for subdomains)
- IP literals and **DNS-resolved addresses** are rejected if they are private, loopback, link-local,
  multicast, reserved, CGNAT or IPv4-mapped IPv6
- cloud metadata endpoints (`169.254.169.254`, `fd00:ec2::254`, `169.254.170.2`, `metadata.google.internal`, …)
  are always blocked unless `EXCAT_SSRF_ALLOW_PRIVATE_NETWORKS=true`
- redirects aren't followed

In AWS, the Network Firewall domain allowlist enforces the same policy at the network layer.

## Advisory and email controls (Phase 2)

| Risk | Control |
|---|---|
| Server-side template injection by template authors | Template bodies and subjects render in Jinja's `ImmutableSandboxedEnvironment` with autoescape, and are test-rendered on save. The layout, header and footer are code-owned |
| HTML injection from CVE or analyst text | Autoescaping everywhere. Line breaks become `<br />` only after escaping |
| Unreviewed content leaving the platform | Send and every export require `approved`. Edits are only possible in `draft` |
| Self-approval | The author can't approve (advisories and template versions), even with both roles |
| Email header injection | CR/LF/control characters stripped from subject and display names. Addresses validated |
| BCC disclosure | BCC only in the SMTP envelope. Present in the `.eml` draft so Outlook can send it |
| SSRF via SMTP relay | Host resolved and checked (metadata always blocked, private ranges opt-in), port allowlist, TLS verification |
| CSV/formula injection in Excel | Values starting with `= + - @` are prefixed and forced to text. Uploaded XLSX read with `data_only` and `defusedxml` |
| Malicious uploads | `.csv`/`.xlsx` only, size and row limits, XLSX magic check |
| Preview rendering | Served with its own CSP (`default-src 'none'; sandbox`), framed only by the app, and shown in a `sandbox` iframe |
| PDF renderer fetching remote resources | `link_callback` blocks everything except embedded `data:` images |

## Secrets management

- `EXCAT_ENCRYPTION_KEY` (Fernet) encrypts secrets stored in the DB. In AWS it's delivered from Secrets Manager
  (KMS CMK) into the ECS task definition `secrets`, never baked into images.
- **Rotation**: generate a new key and re-encrypt with the rotation command (Phase 3, when connector credentials
  are introduced). Rotate DB credentials with Secrets Manager rotation.
- Production startup **refuses** to run without an encryption key, with insecure cookies, with SQLite, or with
  SQL echo enabled.

## Logging and audit

- Structured JSON logs with request IDs. Keys matching password/secret/token/api_key/authorization/cookie/totp/
  credential/session are **redacted** recursively. Query strings are never logged, because they may contain
  search terms.
- The **audit log** is append-only and hash-chained. It records logins (success and failure), lockouts, MFA
  enrolment, password changes, user and role changes, source configuration changes and refresh requests.
  On PostgreSQL a trigger blocks `UPDATE/DELETE/TRUNCATE`. `exposurecatalyst audit-verify` detects tampering.

**Never logged**: passwords, TOTP codes or seeds, session or CSRF tokens, API keys, full request bodies,
query strings.

## Supply chain and SDLC

- CI runs `ruff` (including flake8-bandit rules), `bandit`, `pip-audit`, the tests, the frontend type check
  and build, and a strict docs build.
- Frontend dependencies are pinned to exact versions. The container runs as non-root with a read-only
  filesystem in compose.

## Reporting vulnerabilities

See `SECURITY.md` at the repository root.
