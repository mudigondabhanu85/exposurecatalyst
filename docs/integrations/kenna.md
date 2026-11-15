# Cisco Vulnerability Management (Kenna)

Open vulnerabilities for the CVE and their assets from Cisco Vulnerability Management.

> **Confirm against your tenant.** This vendor's API reference is not public. The defaults below follow its usual pattern, and every one of them (endpoint, filter, body, results key, pagination, field map) is an editable setting. Run **Save & test**, then **Check now** on a CVE you know is present before enabling.

## Prerequisites

- API key for a read-only user (Settings → API Keys)
- Your region's API host (US, EU or CA)

## Setup

1. Settings → Integrations → **Cisco Vulnerability Management (Kenna) → Set up**.
2. Pick the region.
3. If CVE searches return nothing, adjust *Search query* to your instance's search-terms syntax (`{cve}` is replaced). Non-matching CVEs are dropped client-side.
4. **Save & test**, then enable.

### Settings

| Setting | Notes |
|---|---|
| Base URL | e.g. `https://api.kennasecurity.com` · allowed: `api.kennasecurity.com`, `api.us.kennasecurity.com`, `api.eu.kennasecurity.com`, `api.ca.kennasecurity.com` |
| API key (X-Risk-Token) * | encrypted, never shown again |
| Search query | Kenna search terms; {cve} is replaced · default `cve:"{cve}"` |

Regions: US (`https://api.kennasecurity.com`), EU (`https://api.eu.kennasecurity.com`), CA (`https://api.ca.kennasecurity.com`).

## How it works

Vulnerabilities are searched with the Kenna search-terms `q` parameter (default `cve:"<CVE>"`, a setting)
and `status[]=open`; each vulnerability's `asset_id` is resolved with `GET /assets/{id}` (cached).
Auth: `X-Risk-Token`. Search pagination is capped by Kenna at 20 pages.

## Field mapping (defaults)

| Normalized | Cisco Vulnerability Management |
|---|---|
| hostname | `asset.hostname` |
| ip_address | `asset.ip_address` |
| os | `asset.operating_system` |
| resource_id | `asset.external_id` |
| owner | `asset.owner` |
| business_unit | `asset.asset_groups.name` |
| environment | `asset.tags` |
| detection_date | `first_found_on` |
| source_ref | `id` |

Override any path under **Field mapping (advanced)**.

## Rate limits

The connector sends at most 5 request(s) per 1 s, retries `429`/`5xx` with backoff and honours `Retry-After`.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `HTTP 401` | Wrong region or API key |
| No results | Adjust *Search query* |
| `Base URL rejected` | Use the vendor's API host, or allowlist a custom/on-prem host |
| `HTTP 401` / `403` | Check the credential and its read-only role or scopes |
