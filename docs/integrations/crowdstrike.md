# CrowdStrike Falcon Spotlight

Hosts with an open Falcon Spotlight vulnerability for the CVE (sensor-based, no scans).

## Prerequisites

- Falcon Spotlight / Exposure Management subscription
- API client (Support and resources → API clients and keys) with scope Vulnerabilities: Read
- Your cloud's API base URL (US-1, US-2, EU-1 or US-GOV-1)

## Setup

1. Settings → Integrations → **CrowdStrike Falcon Spotlight → Set up**.
2. Pick your cloud (US-1, US-2, EU-1, US-GOV-1).
3. Flight Control parents: set *Member CID* to query a child tenant.
4. **Save & test**, then enable.

### Settings

| Setting | Notes |
|---|---|
| Base URL | e.g. `https://api.crowdstrike.com` · allowed: `api.crowdstrike.com`, `api.us-2.crowdstrike.com`, `api.eu-1.crowdstrike.com`, `api.laggar.gcw.crowdstrike.com` |
| API client ID * |  |
| API client secret * | encrypted, never shown again |
| Statuses | Comma-separated Spotlight statuses · default `open,reopen` |
| Member CID (Flight Control, optional) |  |

Regions: US-1 (`https://api.crowdstrike.com`), US-2 (`https://api.us-2.crowdstrike.com`), EU-1 (`https://api.eu-1.crowdstrike.com`), US-GOV-1 (`https://api.laggar.gcw.crowdstrike.com`).

## How it works

OAuth2 client credentials (`POST /oauth2/token`), then
`GET /spotlight/combined/vulnerabilities/v1?filter=cve.id:'<CVE>'+status:['open','reopen']&facet=host_info`
with `after`-token pagination. Required API scope: *Vulnerabilities: Read*.

## Field mapping (defaults)

| Normalized | CrowdStrike Falcon Spotlight |
|---|---|
| hostname | `host_info.hostname` |
| ip_address | `host_info.local_ip` |
| os | `host_info.os_version` |
| cloud_account | `host_info.service_provider_account_id` |
| resource_id | `host_info.instance_id` |
| business_unit | `host_info.groups.name` |
| environment | `host_info.tags` |
| detection_date | `created_timestamp` |
| source_ref | `id` |

Override any path under **Field mapping (advanced)**.

## Rate limits

The connector sends at most 10 request(s) per 1 s, retries `429`/`5xx` with backoff and honours `Retry-After`.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `HTTP 403` | API client lacks *Vulnerabilities: Read* |
| `HTTP 401` on token | Wrong cloud: the base URL must match the tenant's cloud |
| `Base URL rejected` | Use the vendor's API host, or allowlist a custom/on-prem host |
| `HTTP 401` / `403` | Check the credential and its read-only role or scopes |
