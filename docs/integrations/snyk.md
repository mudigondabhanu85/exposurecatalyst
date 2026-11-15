# Snyk

Projects (code repos, container images, IaC) with an open Snyk issue for the CVE.

## Prerequisites

- Snyk Enterprise plan (Reporting API) and a service account with the Org Collaborator / read role
- Organization IDs (Settings → General → Organization ID)

## Setup

1. Settings → Integrations → **Snyk → Set up**.
2. Pick the region; enter one or more organization IDs (comma-separated).
3. **Save & test**, then enable.

### Settings

| Setting | Notes |
|---|---|
| Base URL | e.g. `https://api.snyk.io` · allowed: `api.snyk.io`, `api.us.snyk.io`, `api.eu.snyk.io`, `api.au.snyk.io` |
| Service account token * | encrypted, never shown again |
| Organization IDs * | Comma-separated org UUIDs |

Regions: SNYK-US-01 (`https://api.snyk.io`), SNYK-US-02 (`https://api.us.snyk.io`), SNYK-EU-01 (`https://api.eu.snyk.io`), SNYK-AU-01 (`https://api.au.snyk.io`).

## How it works

Uses the v1 Reporting API `POST /v1/reporting/issues/latest` with `filters.identifier = <CVE>` (the REST
issues API has no CVE filter). Auth: `Authorization: token <service-account token>`.

## Field mapping (defaults)

| Normalized | Snyk |
|---|---|
| hostname | `project.name` |
| resource_id | `project.id` |
| os | `project.targetFile` |
| owner | `project.owner` |
| environment | `project.environment` |
| detection_date | `introducedDate` |
| source_ref | `issue.id` |

Override any path under **Field mapping (advanced)**.

## Rate limits

The connector sends at most 5 request(s) per 1 s, retries `429`/`5xx` with backoff and honours `Retry-After`.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `HTTP 403` on reporting | The Reporting API needs an Enterprise plan |
| `UUID` | Use org IDs, not slugs |
| `Base URL rejected` | Use the vendor's API host, or allowlist a custom/on-prem host |
| `HTTP 401` / `403` | Check the credential and its read-only role or scopes |
