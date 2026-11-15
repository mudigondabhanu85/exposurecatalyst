# Prisma Cloud (Compute / CWPP)

Hosts, images and running containers impacted by the CVE in Prisma Cloud Compute.

## Prerequisites

- Prisma Cloud access key for a role with Vulnerabilities (Monitor) read permission
- Compute console path (Runtime Security → System → Utilities → Path to Console)

## Setup

1. Settings → Integrations → **Prisma Cloud (Compute / CWPP) → Set up**.
2. Base URL: the Compute **Path to Console** (Runtime Security → System → Utilities).
3. Optional *Collections* to scope results.
4. **Save & test**, then enable.

### Settings

| Setting | Notes |
|---|---|
| Base URL | e.g. `https://us-east1.cloud.twistlock.com/us-1-111111111` · allowed: `*.cloud.twistlock.com`, `*.prismacloud.io` |
| Access key ID * |  |
| Secret key * | encrypted, never shown again |
| Collections (optional) | Comma-separated collection names |
| Include images / containers | default `True` |

## How it works

Returns the hosts and deployed images (with their running containers) impacted by the CVE. Auth: access key
→ `POST /api/v1/authenticate` → bearer token (valid ~1 h). The base URL is the Compute console path
(Runtime Security → System → Utilities → Path to Console), e.g. `https://us-east1.cloud.twistlock.com/us-1-23`.

## Field mapping (defaults)

| Normalized | Prisma Cloud |
|---|---|
| hostname | `host` |
| resource_id | `resource_id` |
| environment | `collection` |
| source_ref | `resource_id` |

Override any path under **Field mapping (advanced)**.

## Rate limits

The connector sends at most 10 request(s) per 1 s, retries `429`/`5xx` with backoff and honours `Retry-After`.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `HTTP 401` | Access key expired or the role lacks Vulnerabilities read |
| No results right after a scan | Impacted-resource stats refresh every 24 h (or Refresh in Vulnerability Explorer) |
| `Base URL rejected` | Use the vendor's API host, or allowlist a custom/on-prem host |
| `HTTP 401` / `403` | Check the credential and its read-only role or scopes |
