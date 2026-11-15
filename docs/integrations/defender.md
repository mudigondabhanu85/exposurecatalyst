# Microsoft Defender Vulnerability Management

Devices exposed to the CVE according to Defender Vulnerability Management.

## Prerequisites

- Entra ID app registration with application permission WindowsDefenderATP → Vulnerability.Read.All (and Machine.Read.All for device IPs), admin consent granted
- Client secret (or rotate one) — stored encrypted

## Setup

1. Settings → Integrations → **Microsoft Defender Vulnerability Management → Set up**.
2. Enter tenant ID (GUID or verified domain), client ID and secret; choose the cloud.
3. Pick the API host closest to your tenant's data (Global works everywhere).
4. Untick *Look up device IPs* if you did not grant Machine.Read.All.
5. **Save & test**, then enable.

### Settings

| Setting | Notes |
|---|---|
| Base URL | e.g. `https://api.securitycenter.microsoft.com` · allowed: `api.securitycenter.microsoft.com`, `api-us.securitycenter.microsoft.com`, `api-eu.securitycenter.microsoft.com`, `api-uk.securitycenter.microsoft.com`, `api-au.securitycenter.microsoft.com`, `api.security.microsoft.com`, `*.securitycenter.microsoft.us` |
| Directory (tenant) ID * |  |
| Application (client) ID * |  |
| Client secret * | encrypted, never shown again |
| Cloud | default `Commercial` |
| Look up device IPs (Machine.Read.All) | default `True` |

Regions: Global (`https://api.securitycenter.microsoft.com`), US (`https://api-us.securitycenter.microsoft.com`), EU (`https://api-eu.securitycenter.microsoft.com`), UK (`https://api-uk.securitycenter.microsoft.com`), GCC (`https://api-gcc.securitycenter.microsoft.us`), GCC High / DoD (`https://api-gov.securitycenter.microsoft.us`).

## How it works

Entra ID app (client credentials, `https://api.securitycenter.microsoft.com/.default`), then
`GET /api/machines/SoftwareVulnerabilitiesByMachine?$filter=cveId eq '<CVE>'` with `@odata.nextLink`
pagination. Required application permission: *Vulnerability.Read.All* (plus *Machine.Read.All* for IPs).

## Field mapping (defaults)

| Normalized | Microsoft Defender VM |
|---|---|
| hostname | `deviceName` |
| ip_address | `lastIpAddress` |
| os | `osPlatform` |
| resource_id | `deviceId` |
| business_unit | `rbacGroupName` |
| detection_date | `firstSeenTimestamp` |
| source_ref | `id` |

Override any path under **Field mapping (advanced)**.

## Rate limits

The connector sends at most 30 request(s) per 60 s, retries `429`/`5xx` with backoff and honours `Retry-After`.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `AADSTS7000215` | Invalid client secret |
| `HTTP 403` | Grant Vulnerability.Read.All and admin consent |
| IPs empty | Grant Machine.Read.All or untick *Look up device IPs* |
| `Base URL rejected` | Use the vendor's API host, or allowlist a custom/on-prem host |
| `HTTP 401` / `403` | Check the credential and its read-only role or scopes |
