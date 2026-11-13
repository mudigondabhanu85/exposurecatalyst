# Qualys VMDR

## Prerequisites

- Qualys subscription with **API access** enabled (contact Qualys support if it isn't).
- A dedicated API user with the **Reader** role, or a custom role with *API Access* and VM/VMDR read. Scope its
  asset groups to the assets you want correlated.
- Your platform's API server URL, under **Help → About → Security Operations Center (SOC)**. For example
  `https://qualysapi.qg2.apps.qualys.com` (US2) or `https://qualysapi.qualys.eu` (EU1).

## Setup

1. Settings → Integrations → **Qualys VMDR → Set up**.
2. Base URL: your API server. API username and password: the API user.
3. Optional: *Detection statuses* (default `New,Active,Re-Opened`). Add `Fixed` only if you want fixed
   detections counted.
4. **Save & test**. This calls `/msp/about.php`, then you can enable the integration.

## How it works

1. **CVE → QID.** The KnowledgeBase API can't filter by CVE, so ExposureCatalyst keeps a CVE→QID map built
   from `/api/2.0/fo/knowledge_base/vuln/?action=list&details=Basic`. The first sync covers QIDs modified in
   the last *Initial KnowledgeBase window* days (default 1825). After that it re-syncs incrementally
   (`last_modified_after`) at most every 24 hours.
2. **QID → hosts.** `/api/2.0/fo/asset/host/vm/detection/?action=list&qids=…&status=…&truncation_limit=1000`.
   Pagination follows the `WARNING/URL` link, only on the same host.

## Field mapping (defaults)

| Normalized | Qualys |
|---|---|
| hostname | `DNS` (falls back to `DNS_DATA/HOSTNAME`, then NetBIOS) |
| ip_address | `IP` |
| os | `OS` |
| resource_id / cloud_account | `CLOUD_RESOURCE_ID` (or `EC2_INSTANCE_ID`) / `CLOUD_ACCOUNT_ID` |
| detection_date | `FIRST_FOUND_DATETIME` |
| source_ref | `QID-<qid>` |

## Rate limits

Qualys enforces per-subscription API limits, by default about 300 calls/hour with a concurrency of 2. The
connector is limited to 300 calls/hour and retries `409`/`429` with backoff, honouring `Retry-After`. The first
KnowledgeBase sync is the most expensive call. Run a **Check now** outside business hours after setup.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `HTTP 401` | Wrong credentials, or the user is locked or not API-enabled |
| `Qualys error 1965/1960` | Concurrency or rate limit exceeded. The next check retries |
| 0 assets, but Qualys shows detections | The CVE→QID map may not include the QID yet (newly published). Wait for the next daily KB sync, or widen *Initial KnowledgeBase window* and re-save to force a full sync |
| `pagination link points to a different host` | Base URL doesn't match your platform's API server |
