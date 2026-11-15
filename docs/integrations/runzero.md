# runZero

Assets runZero has seen with the CVE (its own scanning plus imported vulnerability data).

> **Confirm against your tenant.** This vendor's API reference is not public. The defaults below follow its usual pattern, and every one of them (endpoint, filter, body, results key, pagination, field map) is an editable setting. Run **Save & test**, then **Check now** on a CVE you know is present before enabling.

## Prerequisites

- runZero Platform with vulnerability data (scanner or integrations)
- Organization export token (read-only); self-hosted consoles must be in EXCAT_EGRESS_ALLOWLIST

## Setup

1. Settings → Integrations → **runZero → Set up**.
2. Base URL: `https://console.runzero.com` (or your self-hosted console, allowlisted).
3. **Save & test**, then enable.

### Settings

| Setting | Notes |
|---|---|
| Base URL | e.g. `https://console.runzero.com` · allowed: `console.runzero.com`, `*.runzero.com` |
| Organization export token * | Organization → Export token (read-only) · encrypted, never shown again |

## How it works

`GET /api/v1.0/export/org/vulnerabilities.json?search=cve:"<CVE>"` returns every matching vulnerability
record (one per asset) with the asset's names, addresses and OS. Auth: organization *export* token (Bearer).

## Field mapping (defaults)

| Normalized | runZero |
|---|---|
| hostname | `names.0` |
| ip_address | `addresses.0` |
| os | `os` |
| resource_id | `asset_id` |
| business_unit | `site_name` |
| environment | `tags` |
| detection_date | `vulnerability_first_detected_ts` |
| source_ref | `vulnerability_id` |

Override any path under **Field mapping (advanced)**.

## Rate limits

The connector sends at most 2 request(s) per 1 s, retries `429`/`5xx` with backoff and honours `Retry-After`.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `HTTP 401` | Use an organization **export** token |
| `Base URL rejected` | Use the vendor's API host, or allowlist a custom/on-prem host |
| `HTTP 401` / `403` | Check the credential and its read-only role or scopes |
