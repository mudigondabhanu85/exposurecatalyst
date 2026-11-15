# XM Cyber

Entities exposed by a CVE in XM Cyber attack-path analysis (choke points and critical assets included).

> **Confirm against your tenant.** This vendor's API reference is not public. The defaults below follow its usual pattern, and every one of them (endpoint, filter, body, results key, pagination, field map) is an editable setting. Run **Save & test**, then **Check now** on a CVE you know is present before enabling.

## Prerequisites

- XM Cyber API key (Settings → API Keys) with read access
- Confirm the entity endpoint and CVE filter parameter in XM Cyber's API reference

## Setup

1. Settings → Integrations → **XM Cyber → Set up**.
2. Base URL: your XM Cyber tenant.
3. Confirm the endpoint and CVE parameter in XM Cyber's API docs.
4. **Save & test**, then enable.

### Settings

| Setting | Notes |
|---|---|
| Base URL | e.g. `https://example.clients.xmcyber.com` · allowed: `*.clients.xmcyber.com`, `*.xmcyber.com` |
| API key / token * | encrypted, never shown again |
| Auth header | default `X-Api-Key` |
| Auth value prefix | e.g. 'Bearer ' (note the space) |
| Findings endpoint path | {setting} placeholders allowed · default `/api/systemReport/entities` |
| CVE filter parameter | Query parameter (GET, or POST without a body template) · default `cve` |
| HTTP method | default `GET` |
| Request body (JSON, POST) | "{{cve}}" and "{{limit}}" are substituted |
| Results key (dotted path) | default `data` |
| Pagination | default `page` |
| Page / cursor / offset parameter | default `page` |
| Next-cursor / total-pages key (dotted) | default `paging.totalPages` |
| Page size | default `100` |
| Connection test path | default `/api/systemReport/entities` |

## How it works

`GET /api/systemReport/entities?cve=<CVE>` (page-numbered). Endpoint and filter parameter are settings.

## Field mapping (defaults)

| Normalized | XM Cyber |
|---|---|
| hostname | `name` |
| ip_address | `ipAddresses.0` |
| os | `os.name` |
| cloud_account | `accountId` |
| resource_id | `entityId` |
| business_unit | `labels` |
| environment | `environment` |
| source_ref | `entityId` |

Override any path under **Field mapping (advanced)**.

## Rate limits

The connector sends at most 10 request(s) per 1 s, retries `429`/`5xx` with backoff and honours `Retry-After`.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `Base URL rejected` | Use the vendor's API host, or allowlist a custom/on-prem host |
| `HTTP 401` / `403` | Check the credential and its read-only role or scopes |
