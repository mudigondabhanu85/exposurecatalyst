# API reference

The interactive OpenAPI documentation is served by the application at **`/api/docs`** (Swagger UI) and
**`/api/redoc`**. The raw schema is at `/api/openapi.json`. Disable them in production with
`EXCAT_API_DOCS_ENABLED=false` if required.

## Authentication

The API uses the same session as the web UI.

```bash
BASE=https://excat.example.com
# 1. Log in. Stores the session and CSRF cookies.
curl -sc jar -H 'Content-Type: application/json' \
  -d '{"username":"analyst","password":"…","totp_code":"123456"}' $BASE/api/auth/login | jq .csrf_token
# 2. Read-only calls need only the cookie.
curl -sb jar "$BASE/api/cves?severity=CRITICAL&kev=true&page_size=50"
# 3. State-changing calls also need the CSRF token (and a same-origin or no Origin header).
CSRF=$(curl -sb jar $BASE/api/auth/me | jq -r .csrf_token)
curl -sb jar -X POST -H "X-CSRF-Token: $CSRF" $BASE/api/sources/refresh
```

Service accounts and API tokens for automation are planned for a later phase.

## Endpoints (Phase 1)

| Method & path | Permission | Purpose |
|---|---|---|
| `GET /api/health/live`, `/api/health/ready` | public | Liveness / readiness (DB check) |
| `POST /api/auth/login` · `POST /api/auth/logout` · `GET /api/auth/me` | — / session | Session management |
| `POST /api/auth/mfa/setup` · `/mfa/enable` · `/password` | session | MFA enrolment, password change |
| `GET /api/cves` | `cve:view` | Search: `q, vendor, product, severity[], cvss_min, cvss_max, epss_min, kev, exploit, published_from/to, modified_from/to, sort, page, page_size≤200` |
| `GET /api/cves/{cve_id}` · `/assets` | `cve:view` | Detail, affected-asset panel |
| `GET/POST/DELETE /api/saved-searches` | `cve:view` | Per-user saved searches |
| `GET /api/sources` · `GET /api/sources/runs` | `cve:view` | Source health, scheduler heartbeat, job history |
| `POST /api/sources/refresh[?source=]` | `cve:refresh` | Queue a refresh (202) |
| `PATCH /api/sources/{name}` | `source:manage` | `enabled`, `interval_minutes` (5–10080) |
| `GET /api/help`, `/pages/{id}`, `/search`, `/tooltips`, `/changelog` | session | RBAC-filtered help |
| `GET /api/admin/rbac` · `GET/POST /api/admin/users` · `PUT /users/{id}/roles` · `PATCH /users/{id}` | `user:manage` | Users and role assignment |
| `POST/PUT /api/admin/roles` | `role:manage` | Custom roles |
| `GET /api/admin/audit` | `audit:view` | Audit log (keyset pagination via `before_id`) |
| `GET/POST /api/advisories` · `GET/PATCH /api/advisories/{id}` | any advisory perm / `advisory:create` | List, create from CVE, read, edit draft |
| `POST /api/advisories/{id}/submit` · `/approve` · `/reject` · `/cancel` | `advisory:create` / `advisory:approve` | Workflow (author cannot approve) |
| `POST /api/advisories/{id}/send` `{confirm: true}` | `advisory:send` | SMTP delivery (approved only) |
| `GET /api/advisories/{id}/export/{eml\|html\|pdf\|xlsx\|clipboard}` | `advisory:export` | Exports (approved or sent only) |
| `GET /api/advisories/{id}/preview` · `/history` | any advisory perm | Sandboxed HTML preview, audit trail |
| `POST/PUT/DELETE /api/advisories/{id}/assets…` · `POST …/assets/upload` · `PUT …/sources/{source}` | `advisory:create` | Manual assets, CSV/XLSX import, manual counts |
| `GET/POST/DELETE /api/distribution-lists` | `advisory:create` | Saved recipient sets |
| `GET /api/templates` · `POST /api/templates/{id}/versions` · `POST /api/template-versions/{id}/submit\|approve` | `template:manage` / `advisory:approve` | Versioned templates |
| `GET/PUT /api/settings/smtp` · `POST /api/settings/smtp/test` | `settings:manage` | SMTP configuration (password never returned) |
| `GET /api/integrations/catalog` · `GET/POST /api/integrations` · `PATCH/DELETE /api/integrations/{id}` · `POST …/{id}/test` | `integration:manage` | Connectors (secrets write-only) |
| `GET /api/cves/{cve_id}/assets` · `POST …/assets/refresh` | `cve:view` / `cve:refresh` | Affected assets across integrations (refresh bypasses the cache) |
| `POST /api/advisories/{id}/assets/pull` `{force}` | `advisory:create` | Pull integration findings into a draft advisory |
| `GET /api/auth/sso` · `GET /api/saml/metadata` · `GET /api/auth/saml/login` · `POST /api/auth/saml/acs` | public | SSO status, SP metadata download, SP-initiated login, assertion consumer |
| `GET/PUT /api/settings/sso/saml` · `POST …/saml/metadata` | `sso:manage` | SAML configuration, IdP metadata import (URL or XML) |
| `GET/POST/DELETE /api/settings/sso/mappings` | `sso:manage` (+ `role:manage` to change) | Group → role mappings and sync status |
| `GET/POST/DELETE /api/settings/scim/tokens` | `sso:manage` (+ `user:manage` to create) | SCIM bearer tokens (shown once) |
| `/scim/v2/{ServiceProviderConfig, ResourceTypes, Schemas, Users, Groups}` | SCIM bearer token | SCIM 2.0 provisioning (RFC 7644) |
| `GET/POST /api/alerts` · `PUT/DELETE /api/alerts/{id}` · `POST …/{id}/run` · `GET …/{id}/events` | `settings:manage` | Alert rules |
| `DELETE /api/admin/roles/{id}` | `role:manage` | Delete a custom role (unassigned only) |
| `GET /metrics` | network-restricted | Prometheus metrics |

## Errors

| Code | Meaning |
|---|---|
| 401 | Not authenticated or session expired. Body may include `mfa_required` on login |
| 403 | Missing permission, CSRF failure, cross-origin request, or MFA enrolment required |
| 409 | Conflict (duplicate name, system role edit, self-modification) |
| 422 | Validation error |
| 423 | Account locked |
| 429 | Rate limited |
