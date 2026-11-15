# Armis Centrix

Managed, unmanaged, IoT and OT devices Armis associates with the CVE.

> **Confirm against your tenant.** This vendor's API reference is not public. The defaults below follow its usual pattern, and every one of them (endpoint, filter, body, results key, pagination, field map) is an editable setting. Run **Save & test**, then **Check now** on a CVE you know is present before enabling.

## Prerequisites

- Armis API secret key for a user with read-only (Read Only / Viewer) permissions
- Your tenant URL (https://<tenant>.armis.com)

## Setup

1. Settings → Integrations → **Armis Centrix → Set up**.
2. Base URL: `https://<tenant>.armis.com`.
3. **Save & test**, then enable.

### Settings

| Setting | Notes |
|---|---|
| Base URL | e.g. `https://example.armis.com` · allowed: `*.armis.com` |
| API secret key * | Settings → API Management · encrypted, never shown again |

## How it works

Auth: secret key → `POST /api/v1/access_token/` → token sent as `Authorization: <token>`. Search:
`GET /api/v1/search/` with `from`/`length` paging (`data.next`).

## Field mapping (defaults)

| Normalized | Armis |
|---|---|
| hostname | `name` |
| ip_address | `ipAddress` |
| os | `operatingSystem` |
| resource_id | `macAddress` |
| business_unit | `site.name` |
| environment | `boundaries` |
| detection_date | `firstSeen` |
| source_ref | `id` |

Override any path under **Field mapping (advanced)**.

## Rate limits

The connector sends at most 5 request(s) per 1 s, retries `429`/`5xx` with backoff and honours `Retry-After`.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `did not return an access token` | Wrong secret key or tenant URL |
| `Base URL rejected` | Use the vendor's API host, or allowlist a custom/on-prem host |
| `HTTP 401` / `403` | Check the credential and its read-only role or scopes |
