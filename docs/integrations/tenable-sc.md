# Tenable Security Center (Tenable.sc)

Vulnerability instances for the CVE across Tenable Security Center repositories (on-prem).

## Prerequisites

- Tenable Security Center 5.13+ with API keys enabled (System → Configuration → Security)
- Keys for a user whose group can view the relevant repositories
- Add the console host to EXCAT_EGRESS_ALLOWLIST (self-hosted)

## Setup

1. Settings → Integrations → **Tenable Security Center (Tenable.sc) → Set up**.
2. Add the console host to `EXCAT_EGRESS_ALLOWLIST` (and `EXCAT_SSRF_ALLOW_PRIVATE_NETWORKS=true` if it resolves to a private address).
3. *Data source*: `cumulative` (current) or `patched`.
4. **Save & test**, then enable.

### Settings

| Setting | Notes |
|---|---|
| Base URL | e.g. `https://securitycenter.example.internal` · allowed: self-hosted (allowlist required) |
| Access key * | encrypted, never shown again |
| Secret key * | encrypted, never shown again |
| Data source | default `cumulative` |

## How it works

* Tenable.io: `GET /workbenches/assets` filtered by `plugin.attributes.cve.raw` = CVE (one call returns up
  to 5,000 assets seen in the last *N* days). Auth: `X-ApiKeys: accessKey=…;secretKey=…`.
* Tenable.sc: `POST /rest/analysis` (`type=vuln`, tool `listvuln`, filter `cveID = CVE`), paged with
  `startOffset`/`endOffset`. Auth: `x-apikey: accesskey=…; secretkey=…;` (API keys, 5.13+).

## Field mapping (defaults)

| Normalized | Tenable Security Center |
|---|---|
| hostname | `dnsName` |
| ip_address | `ip` |
| os | `operatingSystem` |
| resource_id | `uuid` |
| business_unit | `repository.name` |
| detection_date | `firstSeen` |
| source_ref | `pluginID` |

Override any path under **Field mapping (advanced)**.

## Rate limits

The connector sends at most 10 request(s) per 1 s, retries `429`/`5xx` with backoff and honours `Retry-After`.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `self-hosted: add … to EXCAT_EGRESS_ALLOWLIST` | Allowlist the console host |
| `Tenable.sc error: …` | API keys disabled, or the user's group lacks repository access |
| `Base URL rejected` | Use the vendor's API host, or allowlist a custom/on-prem host |
| `HTTP 401` / `403` | Check the credential and its read-only role or scopes |
