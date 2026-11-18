# Threat Intel & News Subscriptions

Paid and licensed intelligence feeds the **CVE Intelligence** (per-CVE panel) and **Security News** tabs, with
source attribution on every item. Requires `features.subscriptions: true`; configuration needs
`integration:manage`, manual intel and imports `intel:manage` (Super Admin, Admin, Security Analyst).
Free sources (NVD, CISA KEV, EPSS, RSS news feeds) are unaffected.

## Pre-built connectors

| Vendor | Type | Auth | Maps | API defaults |
|---|---|---|---|---|
| Recorded Future | REST | api_key_header | Vulnerabilities (risk ≥ 65) → CVE Intelligence | Documented API |
| Google Threat Intelligence / Mandiant | REST | oauth2_cc | Vulnerabilities → CVE Intelligence | Documented API |
| VulnCheck | REST | bearer | VulnCheck KEV → CVE Intelligence | Documented API |
| Flashpoint (VulnDB) | REST | bearer | Vulnerability intelligence → CVE Intelligence | **Confirm defaults** |
| Intel 471 | REST | basic | CVE reports → CVE Intelligence | **Confirm defaults** |
| CrowdStrike Falcon Intelligence | REST | oauth2_cc | Intelligence reports → Security News, Vulnerabilities → CVE Intelligence | Documented API |
| Microsoft Defender Threat Intelligence | REST | oauth2_cc | Threat intelligence articles → Security News | Documented API |
| Cyware (CTIX TAXII) | TAXII | basic | TAXII 2.1 (STIX vulnerability → CVE, report → news) | **Confirm defaults** |
| ThreatConnect | REST | api_key_header | Vulnerability groups → CVE Intelligence | **Confirm defaults** |
| Anomali ThreatStream | REST | api_key_header | Vulnerabilities → CVE Intelligence | **Confirm defaults** |
| Feedly for Threat Intelligence | REST | bearer | Board / feed stream → Security News | Documented API |
| Silobreaker (authenticated RSS) | RSS | none | RSS/Atom → Security News | **Confirm defaults** |
| Dataminr | REST | oauth2_cc | Alerts → Security News | **Confirm defaults** |
| SOCRadar | REST | api_key_query | Incidents → Security News | **Confirm defaults** |
| Cybersixgill | REST | oauth2_cc | DVE feed → CVE Intelligence | **Confirm defaults** |
| ReliaQuest GreyMatter Digital Risk | REST | basic | Triage item events → Security News | **Confirm defaults** |
| Securin | REST | api_key_header | Vulnerability intelligence → CVE Intelligence | **Confirm defaults** |

Every preset value — base URL, auth, endpoints, parameters, pagination and the JSONPath field mapping — is
editable. **Confirm defaults** marks vendors whose API reference is tenant-gated or whose API has several
variants: run **Test & preview** (it shows the first parsed records and the first raw record before you save).
Cyware and Silobreaker use request-signed REST APIs, so they are offered through their TAXII and RSS exports.

## Custom sources

| Type | Settings |
|---|---|
| REST (JSON) | Base URL; auth: API-key header, API-key query parameter, bearer, basic, OAuth2 client credentials, custom headers (JSON, stored encrypted); endpoints (GET path, query parameters with `{since_iso}`, `{since_epoch}`, `{since_epoch_ms}`, `{since_date}`, `{limit}`); results path; pagination (offset, page, cursor, next URL, Link header); field mapping |
| Authenticated RSS / Atom | Feed URL + auth → Security News |
| TAXII 2.1 | API root + collection ID; STIX 2.1 `vulnerability` → CVE intel, `report` → news; `added_after` incremental |
| Manual / file drop | No pulls: manual entry and imports only |

**Field mapping** uses a safe JSONPath subset (`$.a.b`, `[n]`, `[-1]`, `[*]`, `['key']`; `=value` sets a constant):
CVE fields `cve_id`, `title`, `summary`, `description`, `severity` (labels or 0–10 / 0–100 scores),
`exploited`, `references`, `published`; news fields `title`, `summary`, `url`, `published`, `tags`; plus
`external_id` (de-duplication). CVE IDs are also found in titles and descriptions.

Polling interval (default 60 min), rate limit (requests/minute), page size and the first-pull window are per
subscription. Pulls are incremental from the newest stored item.

## Manual entry and import

From a CVE (**Add intel**) or Security News → Subscription intelligence: CVE-linked or standalone items with
source subscription, analyst notes, TLP and PDF/HTML attachments (always downloaded, sandboxed). Bulk import of
CSV, JSON or STIX 2.1 bundles shows a validation preview first. Manual items are labelled
**Manual — <subscription>** everywhere and are never overwritten by pulls.

## Licence metadata and usage

Contract owner, licence tier, seats, API quota (per day / month / year), start and renewal dates, cost center,
notes. The table shows API calls against the quota (pulls stop when the quota is used up), items stored, the last
successful pull and an error log. Renewal reminders are emailed at 60, 30 and 7 days to integration admins and
the contract owner.

## Redistribution controls

| Control | Effect |
|---|---|
| Content in stakeholder emails | **Full** (title, summary, details, references) · **Summary only** · **None** — enforced in the advisory email's "Threat intelligence (licensed sources)" section |
| Allow sending to external AI providers | Off by default; only allowed sources' content is added to AI context |
| Default TLP | Applied to pulled items. **TLP:RED** is never emailed or sent to AI and is visible only with `intel:manage` |

## Security

Credentials are encrypted and write-only. Every URL — base, token endpoint, pagination links — must be https on
the subscription's host, the vendor's hosts or `EXCAT_EGRESS_ALLOWLIST`, and must not resolve to private or
metadata addresses. Pulls are GET-only, rate-limited, size-capped, and isolated per subscription. Every
configuration change, pull, import and manual edit is audited.
