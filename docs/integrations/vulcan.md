# Vulcan Cyber

Vulnerability instances and assets consolidated by Vulcan Cyber (Tenable Exposure Management for Vulcan).

> **Confirm against your tenant.** This vendor's API reference is not public. The defaults below follow its usual pattern, and every one of them (endpoint, filter, body, results key, pagination, field map) is an editable setting. Run **Save & test**, then **Check now** on a CVE you know is present before enabling.

## Prerequisites

- Vulcan API token (Settings → API Tokens) for a read-only user
- Confirm the vulnerabilities endpoint and CVE filter in Vulcan's API reference

## Setup

1. Settings → Integrations → **Vulcan Cyber → Set up**.
2. Base URL: your Vulcan tenant.
3. Confirm the endpoint, CVE parameter and results key.
4. **Save & test**, then enable.

### Settings

| Setting | Notes |
|---|---|
| Base URL | e.g. `https://example.vulcancyber.com` · allowed: `*.vulcancyber.com`, `*.vulcan.io` |
| API key / token * | encrypted, never shown again |
| Auth header | default `Authorization` |
| Auth value prefix | e.g. 'Bearer ' (note the space) · default `Bearer ` |
| Findings endpoint path | {setting} placeholders allowed · default `/api/v1/vulnerabilities` |
| CVE filter parameter | Query parameter (GET, or POST without a body template) · default `cve` |
| HTTP method | default `GET` |
| Request body (JSON, POST) | "{{cve}}" and "{{limit}}" are substituted |
| Results key (dotted path) | default `data` |
| Pagination | default `page` |
| Page / cursor / offset parameter | default `page` |
| Next-cursor / total-pages key (dotted) | default `total_pages` |
| Page size | default `500` |
| Connection test path | default `/api/v1/assets` |

## How it works

`GET /api/v1/vulnerabilities?cve=<CVE>` (page-numbered). Endpoint, filter parameter and results key are settings.

## Field mapping (defaults)

| Normalized | Vulcan |
|---|---|
| hostname | `asset.hostname` |
| ip_address | `asset.ip_address` |
| os | `asset.os` |
| cloud_account | `asset.cloud_account` |
| resource_id | `asset.external_id` |
| owner | `asset.owners.0` |
| business_unit | `asset.business_group` |
| environment | `asset.environment` |
| detection_date | `first_seen` |
| source_ref | `id` |

Override any path under **Field mapping (advanced)**.

## Rate limits

The connector sends at most 10 request(s) per 1 s, retries `429`/`5xx` with backoff and honours `Retry-After`.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `Base URL rejected` | Use the vendor's API host, or allowlist a custom/on-prem host |
| `HTTP 401` / `403` | Check the credential and its read-only role or scopes |
