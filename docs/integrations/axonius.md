# Axonius

Correlated devices (from every Axonius adapter) whose software has the CVE.

## Prerequisites

- API key and secret for a user with the Viewer role (Account → API Key)
- Software/vulnerability adapters connected so devices carry software CVEs
- Add the host to EXCAT_EGRESS_ALLOWLIST for an on-prem instance

## Setup

1. Settings → Integrations → **Axonius → Set up**.
2. Base URL: your Axonius instance (SaaS or on-prem; on-prem needs `EXCAT_EGRESS_ALLOWLIST`).
3. Optional *Extra AQL* is ANDed with the CVE filter, e.g. `("labels" == "Production")`.
4. **Save & test**, then enable.

### Settings

| Setting | Notes |
|---|---|
| Base URL | e.g. `https://example.on.axonius.com` · allowed: `*.axonius.com`, `*.on.axonius.com` |
| API key * | encrypted, never shown again |
| API secret * | encrypted, never shown again |
| Extra AQL (optional) | ANDed with the CVE filter, e.g. ("labels" == "Production") |

## How it works

The AQL filter `("specific_data.data.software_cves.cve_id" == "<CVE>")` runs over the correlated device
view; fields are requested explicitly and offset-paged. Auth: `api-key` + `api-secret` headers.
Axonius returns dotted field names as keys, so records are nested before field mapping.

## Field mapping (defaults)

| Normalized | Axonius |
|---|---|
| hostname | `specific_data.data.hostname` |
| ip_address | `specific_data.data.network_interfaces.ips` |
| os | `specific_data.data.os.type_distribution` |
| cloud_account | `specific_data.data.cloud_account` |
| resource_id | `specific_data.data.cloud_id` |
| owner | `specific_data.data.owner` |
| environment | `labels` |
| detection_date | `specific_data.data.first_seen` |
| source_ref | `internal_axon_id` |

Override any path under **Field mapping (advanced)**.

## Rate limits

The connector sends at most 5 request(s) per 1 s, retries `429`/`5xx` with backoff and honours `Retry-After`.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `HTTP 401` | Regenerate key/secret |
| No devices | Software/vulnerability adapters must populate *software_cves* |
| `Base URL rejected` | Use the vendor's API host, or allowlist a custom/on-prem host |
| `HTTP 401` / `403` | Check the credential and its read-only role or scopes |
