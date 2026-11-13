# Data model

The schema is managed by Alembic (`migrations/`) and uses only portable types (`JSON`, `DateTime(timezone=True)`,
`String(n)`), named constraints, and `IN`-list batching of at most 500 values. That keeps it compatible
with PostgreSQL, MySQL/MariaDB, SQL Server, Oracle and SQLite.

## Entity-relationship diagram (Phase 1)

```mermaid
erDiagram
    users ||--o{ user_roles : has
    roles ||--o{ user_roles : grants
    roles ||--o{ role_permissions : contains
    users ||--o{ user_sessions : owns
    users ||--o{ saved_searches : owns
    cves ||--o{ cve_products : affects
    cves ||--o{ cve_events : timeline
    source_state ||--o{ job_runs : "runs (by source)"
    users {
      int id PK
      string username UK
      string email UK
      string password_hash "Argon2id; NULL for SSO"
      text totp_secret_enc "Fernet-encrypted"
      bool totp_enabled
      int failed_login_count
      datetime locked_until
    }
    roles { int id PK
      string name UK
      bool is_system }
    role_permissions { int id PK
      int role_id FK
      string permission }
    user_sessions { string token_hash PK "SHA-256 of cookie"
      int user_id FK
      string csrf_token
      bool mfa_verified
      datetime expires_at
      datetime last_seen_at }
    cves { int id PK
      string cve_id UK
      string severity
      float cvss_score
      float epss_score
      bool kev
      date kev_due_date
      bool exploit_available
      json cvss_metrics
      json references
      json provenance }
    cve_products { int id PK
      int cve_pk FK
      string vendor
      string product
      string cpe }
    cve_events { int id PK
      int cve_pk FK
      string event_type
      datetime occurred_at }
    source_state { string source PK
      string status
      datetime cursor_at
      json meta }
    job_runs { int id PK
      string source
      string status }
    saved_searches { int id PK
      int user_id FK
      json query }
    audit_log { int id PK
      string action
      string prev_hash
      string hash UK }
    app_settings { string key PK
      json value }
```

## Data dictionary

| Table.field | Type | Description | Source |
|---|---|---|---|
| `cves.cve_id` | string(32), unique | CVE identifier, upper-case | NVD / KEV |
| `cves.title` | string(512) | KEV vulnerability name, otherwise the first sentence of the description | KEV / derived |
| `cves.description` | text | English description (untrusted text, rendered as plain text) | NVD (KEV stub) |
| `cves.vuln_status` | string(64) | NVD analysis status | NVD |
| `cves.severity` | string(16) | CRITICAL/HIGH/MEDIUM/LOW/NONE/UNKNOWN from the headline CVSS | derived |
| `cves.cvss_score` / `cvss_version` / `cvss_vector` | float / string | Headline CVSS (preference order configurable) | NVD |
| `cves.cvss_metrics` | JSON list | Every assessment: `{version, score, vector, severity, source, type}` | NVD |
| `cves.epss_score` / `epss_percentile` / `epss_date` | float / float / date | EPSS probability, percentile and model date | FIRST |
| `cves.epss_checked_at` | datetime | Last EPSS lookup (avoids re-asking hourly) | system |
| `cves.kev`, `kev_date_added`, `kev_due_date`, `kev_required_action`, `kev_ransomware_use` | bool / date / text | CISA KEV fields | KEV |
| `cves.exploit_available` / `exploit_refs` | bool / JSON | Public exploit reference or KEV listing | NVD / KEV |
| `cves.patch_refs` | JSON | References tagged Patch / Vendor Advisory / Mitigation / Release Notes | NVD |
| `cves.cwes` | JSON | CWE IDs | NVD |
| `cves.references` | JSON | `{url, source, tags}`, http(s) only, de-duplicated by URL | NVD |
| `cves.provenance` | JSON | `{field: {source, at}}` for every merged field | system |
| `cves.published_at` / `last_modified_at` | datetime (UTC) | NVD publication and last modification | NVD |
| `cve_products.*` | | Vendor, product, CPE 2.3 string, version range bounds, vulnerable flag, source | NVD / KEV |
| `cve_events.event_type` | string | PUBLISHED, MODIFIED, KEV_ADDED, KEV_REMOVED, EPSS_CHANGED | system |
| `source_state.cursor_at` | datetime | NVD: end of the last fully ingested lastModified window | system |
| `source_state.meta` | JSON | KEV: `etag`, `catalog_version` | system |
| `source_state.refresh_requested_at` | datetime | Pending **Refresh now** | user |
| `user_sessions.token_hash` | string(64) | SHA-256 of the session cookie. The raw token is never stored | system |
| `audit_log.prev_hash` / `hash` | string(64) | Hash chain: `sha256(prev_hash + canonical_json(row))` | system |

## Retention (defaults; configurable in Phase 6)

| Data | Retention |
|---|---|
| CVE records, products, events | Indefinite (public data) |
| `job_runs` | 90 days |
| `user_sessions` (expired or revoked) | 30 days |
| `audit_log` | ≥ 1 year online, then archived to S3 with Object Lock (compliance mode) |
| Saved searches | Until the user is deleted |
