# Tenable Vulnerability Management (Tenable.io)

Assets with the CVE from Tenable Vulnerability Management scans and agents.

## Prerequisites

- API keys for a user with the Basic or Scan Operator role and CAN VIEW on the relevant asset tags
- Settings → My Account → API Keys (keys are shown once)

## Setup

1. Settings → Integrations → **Tenable Vulnerability Management (Tenable.io) → Set up**.
2. Pick the region (Commercial or FedRAMP); paste the access and secret keys.
3. *Look-back (days)*: only assets with the vulnerability seen in that window (default 30).
4. **Save & test**, then enable.

### Settings

| Setting | Notes |
|---|---|
| Base URL | e.g. `https://cloud.tenable.com` · allowed: `cloud.tenable.com`, `fedcloud.tenable.com` |
| Access key * | encrypted, never shown again |
| Secret key * | encrypted, never shown again |
| Look-back (days) | Assets with the vulnerability seen in the last N days · default `30` |

Regions: Commercial (`https://cloud.tenable.com`), FedRAMP (`https://fedcloud.tenable.com`).

## How it works

* Tenable.io: `GET /workbenches/assets` filtered by `plugin.attributes.cve.raw` = CVE (one call returns up
  to 5,000 assets seen in the last *N* days). Auth: `X-ApiKeys: accessKey=…;secretKey=…`.
* Tenable.sc: `POST /rest/analysis` (`type=vuln`, tool `listvuln`, filter `cveID = CVE`), paged with
  `startOffset`/`endOffset`. Auth: `x-apikey: accesskey=…; secretkey=…;` (API keys, 5.13+).

## Field mapping (defaults)

| Normalized | Tenable Vulnerability Management |
|---|---|
| hostname | `fqdn.0` |
| ip_address | `ipv4.0` |
| os | `operating_system.0` |
| cloud_account | `aws_owner_id` |
| resource_id | `aws_ec2_instance_id.0` |
| detection_date | `last_seen` |
| source_ref | `id` |

Override any path under **Field mapping (advanced)**.

## Rate limits

The connector sends at most 5 request(s) per 1 s, retries `429`/`5xx` with backoff and honours `Retry-After`.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `HTTP 401` | Keys revoked or regenerated; create new keys |
| Fewer assets than the UI | Increase *Look-back*; workbenches return at most 5,000 assets |
| `Base URL rejected` | Use the vendor's API host, or allowlist a custom/on-prem host |
| `HTTP 401` / `403` | Check the credential and its read-only role or scopes |
