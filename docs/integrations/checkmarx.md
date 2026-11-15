# Checkmarx One

Applications whose latest Checkmarx One SCA scan includes a vulnerable package for the CVE.

## Prerequisites

- Checkmarx One API key for a user with view-projects and view-results permissions
- Tenant name and region; SCA scanner enabled on the projects

## Setup

1. Settings → Integrations → **Checkmarx One → Set up**.
2. Pick the region and enter the tenant name and API key.
3. *Max projects* bounds how many projects are checked per CVE (default 500).
4. **Save & test**, then enable.

### Settings

| Setting | Notes |
|---|---|
| Base URL | e.g. `https://ast.checkmarx.net` · allowed: `ast.checkmarx.net`, `us.ast.checkmarx.net`, `eu.ast.checkmarx.net`, `eu-2.ast.checkmarx.net`, `deu.ast.checkmarx.net`, `anz.ast.checkmarx.net`, `ind.ast.checkmarx.net`, `sng.ast.checkmarx.net`, `mea.ast.checkmarx.net` |
| Tenant name * |  |
| API key * | Identity and Access Management → API Keys · encrypted, never shown again |
| Max projects to check | default `500` |

Regions: US (`https://ast.checkmarx.net`), US2 (`https://us.ast.checkmarx.net`), EU (`https://eu.ast.checkmarx.net`), EU2 (`https://eu-2.ast.checkmarx.net`), DEU (`https://deu.ast.checkmarx.net`), ANZ (`https://anz.ast.checkmarx.net`), India (`https://ind.ast.checkmarx.net`), Singapore (`https://sng.ast.checkmarx.net`), UAE (`https://mea.ast.checkmarx.net`).

## How it works

Checkmarx One has no organization-wide CVE search, so the connector walks projects (`GET /api/projects`),
takes each project's last completed scan (`GET /api/projects/last-scan`) and reads its SCA results
(`GET /api/results?scan-id=…`), keeping results whose ID / CVE name equals the CVE. Bounded by
*Max projects*. Auth: API key (an OAuth refresh token) exchanged at the tenant's IAM realm.

## Field mapping (defaults)

| Normalized | Checkmarx One |
|---|---|
| hostname | `project.name` |
| resource_id | `project.id` |
| os | `data.packageIdentifier` |
| owner | `project.tags.owner` |
| business_unit | `project.groups` |
| environment | `project.tags.environment` |
| detection_date | `firstFoundAt` |
| source_ref | `similarityId` |

Override any path under **Field mapping (advanced)**.

## Rate limits

The connector sends at most 10 request(s) per 1 s, retries `429`/`5xx` with backoff and honours `Retry-After`.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `did not return an access token` | Wrong tenant/region or API key expired |
| Slow lookups | Lower *Max projects*; every project's latest scan is read |
| `Base URL rejected` | Use the vendor's API host, or allowlist a custom/on-prem host |
| `HTTP 401` / `403` | Check the credential and its read-only role or scopes |
