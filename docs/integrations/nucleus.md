# Nucleus Security

Active findings for a CVE in a Nucleus project, with their asset instances.

> **Confirm against your tenant.** This vendor's API reference is not public. The defaults below follow its usual pattern, and every one of them (endpoint, filter, body, results key, pagination, field map) is an editable setting. Run **Save & test**, then **Check now** on a CVE you know is present before enabling.

## Prerequisites

- Nucleus API key for a user with View Assets (projectassets-read) on the project
- Project ID; confirm the findings-search body in Nucleus → View API Docs

## Setup

1. Settings → Integrations → **Nucleus Security → Set up**.
2. Base URL: your Nucleus instance; *Project ID* from the project URL. Add one integration per project.
3. **Save & test**, then enable.

### Settings

| Setting | Notes |
|---|---|
| Base URL | e.g. `https://example.nucleussec.com` · allowed: `*.nucleussec.com` |
| API key / token * | encrypted, never shown again |
| Project ID * | Numeric ID from the project URL |
| Auth header | default `x-apikey` |
| Auth value prefix | e.g. 'Bearer ' (note the space) |
| Findings endpoint path | {setting} placeholders allowed · default `/nucleus/api/projects/{project_id}/findings/search` |
| CVE filter parameter | Query parameter (GET, or POST without a body template) · default `finding_cve` |
| HTTP method | default `POST` |
| Request body (JSON, POST) | "{{cve}}" and "{{limit}}" are substituted · default `{"finding_cve": "{{cve}}", "finding_status": "Active"}` |
| Results key (dotted path) |  |
| Pagination | default `offset` |
| Page / cursor / offset parameter | default `start` |
| Next-cursor / total-pages key (dotted) |  |
| Page size | default `100` |
| Connection test path | default `/nucleus/api/projects/{project_id}` |

## How it works

`POST /nucleus/api/projects/{project_id}/findings/search` with `{"finding_cve": CVE, "finding_status": "Active"}`, paged with `start`/`limit`. Each result is a finding instance on one asset.

## Field mapping (defaults)

| Normalized | Nucleus |
|---|---|
| hostname | `asset_name` |
| ip_address | `ip_address` |
| os | `operating_system_name` |
| owner | `asset_owner` |
| business_unit | `asset_groups` |
| environment | `asset_environment` |
| detection_date | `finding_discovered` |
| source_ref | `finding_number` |

Override any path under **Field mapping (advanced)**.

## Rate limits

The connector sends at most 10 request(s) per 1 s, retries `429`/`5xx` with backoff and honours `Retry-After`.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `Base URL rejected` | Use the vendor's API host, or allowlist a custom/on-prem host |
| `HTTP 401` / `403` | Check the credential and its read-only role or scopes |
