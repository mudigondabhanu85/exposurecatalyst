# Mend.io

Projects with a vulnerable open-source dependency for the CVE (Mend SCA).

> **Confirm against your tenant.** This vendor's API reference is not public. The defaults below follow its usual pattern, and every one of them (endpoint, filter, body, results key, pagination, field map) is an editable setting. Run **Save & test**, then **Check now** on a CVE you know is present before enabling.

## Prerequisites

- Mend service user with the Organization Viewer role and its user key
- Organization UUID (Settings → Integrate)

## Setup

1. Settings → Integrations → **Mend.io → Set up**.
2. Pick the region; enter the service user's email, user key and organization UUID.
3. *Max projects* bounds how many projects are checked per CVE (default 500).
4. **Save & test**, then enable.

### Settings

| Setting | Notes |
|---|---|
| Base URL | e.g. `https://api-saas.mend.io` · allowed: `api-saas.mend.io`, `api-saas-eu.mend.io`, `api-app-eu.mend.io`, `api-saas-sg.mend.io`, `*.mend.io`, `*.whitesourcesoftware.com` |
| Service user email * |  |
| User key * | encrypted, never shown again |
| Organization UUID * |  |
| Max projects to check | default `500` |

Regions: US (`https://api-saas.mend.io`), EU (`https://api-saas-eu.mend.io`), APAC (`https://api-saas-sg.mend.io`).

## How it works

Login: `POST /api/v3.0/login` (email + user key + org UUID) → refresh token →
`POST /api/v3.0/login/accessToken` → JWT. Mend has no organization-wide CVE search in the API, so the
connector lists projects (`GET /api/v3.0/orgs/{org}/projects`) and reads each project's security findings
(`GET /api/v3.0/projects/{project}/dependencies/findings/security?search=vulnerabilityName:equals:<CVE>`),
bounded by *Max projects*.

## Field mapping (defaults)

| Normalized | Mend |
|---|---|
| hostname | `project.name` |
| resource_id | `project.uuid` |
| os | `component.name` |
| business_unit | `project.applicationName` |
| detection_date | `createdAt` |
| source_ref | `uuid` |

Override any path under **Field mapping (advanced)**.

## Rate limits

The connector sends at most 5 request(s) per 1 s, retries `429`/`5xx` with backoff and honours `Retry-After`.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `Mend login failed` | Check email, user key and org UUID; the user needs API access |
| `Base URL rejected` | Use the vendor's API host, or allowlist a custom/on-prem host |
| `HTTP 401` / `403` | Check the credential and its read-only role or scopes |
