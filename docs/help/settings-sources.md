---
id: settings-sources
title: Settings — CVE Sources
page: /settings/sources
permission: source:manage
summary: Enable or disable CVE sources, set refresh intervals and check ingestion health.
keywords: [sources, nvd, kev, epss, interval, scheduler, health, api key]
docs: admin-guide/ingestion-sources/
---

## What this page is for

Shows the health of each CVE source and lets admins set how often it refreshes. Phase 1 sources are
NVD API 2.0, CISA KEV and FIRST EPSS.

## How to use it

1. Check the **Health** badge: *Healthy*, *Degraded* (stale or one failure), *Failing* (3+ consecutive
   failures), *Pending* (never run) or *Disabled*.
2. Change **Interval (minutes)** and click **Save**. The minimum is 5 and the default is 60. The scheduler
   picks up the change at its next tick, with no restart needed.
3. Untick **Enabled** to pause a source.
4. Click **Refresh now** to queue an immediate run.
5. Check **Recent runs** for per-run record counts and errors.

## Fields and columns

| Field | Meaning | Example |
|---|---|---|
| Last success | Time of the most recent successful run (UTC) | `2026-11-13 09:00` |
| Records | Records processed in the last run | `412` |
| Last error | Sanitized error message (never contains secrets) | `SourceHTTPError: nvd: HTTP 403` |
| Scheduler | Whether the scheduler heartbeat arrived within the last 3 ticks | `Running` |

## Required permissions

`cve:view` to see health. `cve:refresh` for **Refresh now**. `source:manage` to change settings.

## Common errors

- **NVD `HTTP 403`**: the API key is invalid or revoked. Request a new key at nvd.nist.gov and set
  `EXCAT_NVD_API_KEY`.
- **`host ... is not in the egress allowlist`**: an upstream URL changed. Add the host to
  `EXCAT_EGRESS_ALLOWLIST`, and in AWS also to the Network Firewall domain allowlist.
- **KEV "catalogue has only N entries — refusing to apply"**: CISA returned a truncated file. The app kept
  the previous data and will retry.

## Learn more

See [Ingestion sources](../admin-guide/ingestion-sources.md) and the
[source outage runbook](../operations/runbooks.md).
