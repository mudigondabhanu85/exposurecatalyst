# Orca Security

Cloud assets with the CVE, from Orca's agentless side-scanning (serving-layer query API).

> **Confirm against your tenant.** This vendor's API reference is not public. The defaults below follow its usual pattern, and every one of them (endpoint, filter, body, results key, pagination, field map) is an editable setting. Run **Save & test**, then **Check now** on a CVE you know is present before enabling.

## Prerequisites

- Orca API token (Settings → Users & Permissions → API) with a read-only role
- Region base URL; confirm the serving-layer query model in Orca's API reference

## Setup

1. Settings → Integrations → **Orca Security → Set up**.
2. Pick the region.
3. Confirm the query model and field names in Orca's API reference (Settings → API); adjust *Request body (JSON)* and the field mapping if they differ.
4. **Save & test**, then enable.

### Settings

| Setting | Notes |
|---|---|
| Base URL | e.g. `https://api.orcasecurity.io` · allowed: `*.orcasecurity.io` |
| API key / token * | encrypted, never shown again |
| Auth header | default `Authorization` |
| Auth value prefix | e.g. 'Bearer ' (note the space) · default `Token ` |
| Findings endpoint path | {setting} placeholders allowed · default `/api/serving-layer/query` |
| CVE filter parameter | Query parameter (GET, or POST without a body template) |
| HTTP method | default `POST` |
| Request body (JSON, POST) | "{{cve}}" and "{{limit}}" are substituted · default `{"query": {"models": ["Vulnerability"], "type": "object_set", "with": {"type": "` |
| Results key (dotted path) | default `data` |
| Pagination | default `offset` |
| Page / cursor / offset parameter | default `start_at_index` |
| Next-cursor / total-pages key (dotted) | default `total_items` |
| Page size | default `500` |
| Connection test path | default `/api/user/session` |

Regions: US (`https://api.orcasecurity.io`), EU (`https://app.eu.orcasecurity.io`), AU (`https://app.au.orcasecurity.io`), IL (`https://app.il.orcasecurity.io`), IN (`https://app.in.orcasecurity.io`).

## How it works

`POST /api/serving-layer/query` with a *Vulnerability* object-set query filtered on `CveId`, paged with `start_at_index` inside the body. The query is the *Request body (JSON)* setting.

## Field mapping (defaults)

| Normalized | Orca |
|---|---|
| hostname | `data.Asset.name` |
| ip_address | `data.Asset.data.PrivateIps.0` |
| os | `data.Asset.data.OsDistribution` |
| cloud_account | `data.CloudAccount.name` |
| resource_id | `data.Asset.data.AssetUniqueId` |
| environment | `data.Asset.data.Tags.environment` |
| detection_date | `data.CreatedAt` |
| source_ref | `id` |

Override any path under **Field mapping (advanced)**.

## Rate limits

The connector sends at most 10 request(s) per 1 s, retries `429`/`5xx` with backoff and honours `Retry-After`.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `Base URL rejected` | Use the vendor's API host, or allowlist a custom/on-prem host |
| `HTTP 401` / `403` | Check the credential and its read-only role or scopes |
