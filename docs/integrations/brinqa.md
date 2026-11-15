# Brinqa

Unified vulnerability findings and their assets from the Brinqa risk platform.

> **Confirm against your tenant.** This vendor's API reference is not public. The defaults below follow its usual pattern, and every one of them (endpoint, filter, body, results key, pagination, field map) is an editable setting. Run **Save & test**, then **Check now** on a CVE you know is present before enabling.

## Prerequisites

- Brinqa API token for a read-only service user (Administration → API access)
- Confirm the data-model endpoint and BQL filter in your Brinqa API reference

## Setup

1. Settings → Integrations → **Brinqa → Set up**.
2. Base URL: your Brinqa instance.
3. Confirm the endpoint and BQL filter against your data model; adjust *Request body (JSON)* and the field mapping.
4. **Save & test**, then enable.

### Settings

| Setting | Notes |
|---|---|
| Base URL | e.g. `https://example.brinqa.net` · allowed: `*.brinqa.net`, `*.brinqa.com` |
| API key / token * | encrypted, never shown again |
| Auth header | default `Authorization` |
| Auth value prefix | e.g. 'Bearer ' (note the space) · default `Bearer ` |
| Findings endpoint path | {setting} placeholders allowed · default `/api/caasm/model/vulnerabilities/` |
| CVE filter parameter | Query parameter (GET, or POST without a body template) · default `cveIds` |
| HTTP method | default `POST` |
| Request body (JSON, POST) | "{{cve}}" and "{{limit}}" are substituted · default `{"filter": "cveIds = \"{{cve}}\" AND status != \"Closed\"", "limit": "{{limit}}"` |
| Results key (dotted path) | default `data` |
| Pagination | default `offset` |
| Page / cursor / offset parameter | default `skip` |
| Next-cursor / total-pages key (dotted) |  |
| Page size | default `200` |
| Connection test path | default `/api/caasm/model/assets/` |

## How it works

`POST` to the Brinqa data-model endpoint with a BQL filter on `cveIds`, paged with `skip`. The filter and returned fields are the *Request body (JSON)* setting.

## Field mapping (defaults)

| Normalized | Brinqa |
|---|---|
| hostname | `targets.0.hostnames.0` |
| ip_address | `targets.0.ipAddresses.0` |
| os | `targets.0.operatingSystem` |
| cloud_account | `targets.0.cloudAccountId` |
| resource_id | `targets.0.uid` |
| owner | `targets.0.owner` |
| business_unit | `targets.0.businessUnit` |
| environment | `targets.0.environment` |
| detection_date | `firstFound` |
| source_ref | `uid` |

Override any path under **Field mapping (advanced)**.

## Rate limits

The connector sends at most 10 request(s) per 1 s, retries `429`/`5xx` with backoff and honours `Retry-After`.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `Base URL rejected` | Use the vendor's API host, or allowlist a custom/on-prem host |
| `HTTP 401` / `403` | Check the credential and its read-only role or scopes |
