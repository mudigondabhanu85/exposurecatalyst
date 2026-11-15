# Rapid7 InsightVM

Assets with the CVE from InsightVM scans and Insight Agents (cloud Integrations API v4).

> **Confirm against your tenant.** This vendor's API reference is not public. The defaults below follow its usual pattern, and every one of them (endpoint, filter, body, results key, pagination, field map) is an editable setting. Run **Save & test**, then **Check now** on a CVE you know is present before enabling.

## Prerequisites

- InsightVM with the cloud Integrations API (console paired to the Insight Platform)
- Insight API key for a user with read access to the relevant sites/asset groups
- Your Insight region (the base URL)

## Setup

1. Settings → Integrations → **Rapid7 InsightVM → Set up**.
2. Pick your Insight region.
3. Optional *Asset filter*, e.g. `asset.tags IN ['Production']`.
4. If your release uses a different search field, change *Vulnerability filter* (`{cve}` is replaced).
5. **Save & test**, then enable.

### Settings

| Setting | Notes |
|---|---|
| Base URL | e.g. `https://us.api.insight.rapid7.com` · allowed: `*.api.insight.rapid7.com` |
| Insight API key * | Insight Platform → Settings → API Keys (organization or user key) · encrypted, never shown again |
| Vulnerability filter | {cve} is replaced with the CVE ID · default `vulnerability.cveIds IN ['{cve}']` |
| Asset filter (optional) | e.g. asset.tags IN ['Production'] |

Regions: US (`https://us.api.insight.rapid7.com`), US2 (`https://us2.api.insight.rapid7.com`), US3 (`https://us3.api.insight.rapid7.com`), EU (`https://eu.api.insight.rapid7.com`), CA (`https://ca.api.insight.rapid7.com`), AU (`https://au.api.insight.rapid7.com`), AP (`https://ap.api.insight.rapid7.com`), ME-CENTRAL-1 (`https://me-central-1.api.insight.rapid7.com`), AP-SOUTH-2 (`https://ap-south-2.api.insight.rapid7.com`).

## How it works

The asset search takes two filter strings in the body: `asset` and `vulnerability`. The default
vulnerability filter is `vulnerability.cveIds IN ['<CVE>']`; it is a setting because the search language
has evolved between releases. Cursor pagination via `metadata.cursor`. Auth: `X-Api-Key` (Insight
platform user or organization key).

## Field mapping (defaults)

| Normalized | Rapid7 InsightVM |
|---|---|
| hostname | `host_name` |
| ip_address | `ip` |
| os | `os_description` |
| resource_id | `id` |
| cloud_account | `aws_account_id` |
| detection_date | `last_assessed_for_vulnerabilities` |
| source_ref | `id` |

Override any path under **Field mapping (advanced)**.

## Rate limits

The connector sends at most 5 request(s) per 1 s, retries `429`/`5xx` with backoff and honours `Retry-After`.

## Troubleshooting

| Symptom | Fix |
|---|---|
| All assets returned | The filter was not applied: check *Vulnerability filter* syntax for your release |
| `HTTP 401` | Wrong region or key |
| `Base URL rejected` | Use the vendor's API host, or allowlist a custom/on-prem host |
| `HTTP 401` / `403` | Check the credential and its read-only role or scopes |
