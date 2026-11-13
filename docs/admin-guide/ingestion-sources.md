# CVE ingestion sources

## How scheduling works

A scheduler process (the `scheduler` container, or `EXCAT_SCHEDULER_EMBEDDED=true` for single-node dev)
**ticks every 60 seconds**. On each tick it:

1. writes a heartbeat (shown as *Scheduler running* in the UI),
2. finds sources that are **due**: enabled, and either never run, past their interval, or with a pending
   **Refresh now** request,
3. **claims** each due source with an atomic `UPDATE … WHERE status <> 'running'`, so two schedulers or replicas
   never run the same source at once (a crashed run becomes re-claimable after `EXCAT_JOB_STALE_AFTER_MINUTES`),
4. runs NVD, then KEV, then EPSS, so newly created CVEs get scores in the same tick,
5. records a job run and the source health.

Because intervals and refresh requests live in the database, changes take effect without a restart. In AWS,
Amazon EventBridge Scheduler can trigger the same tick instead (see [architecture](../architecture/high-level.md)).

## Resilience

| Concern | Control |
|---|---|
| Rate limits | Token bucket per source (NVD: 5 or 50 / 30 s; EPSS: 60 / min; KEV: 10 / min) |
| Transient errors | Retries on 408/425/429/5xx and transport errors, with exponential backoff and jitter (`EXCAT_HTTP_BACKOFF_*`). `Retry-After` is honoured |
| Permanent errors | 4xx (other than 408/425/429) fail fast and are shown in source health |
| Partial progress | NVD commits per page and advances its cursor only after a whole window succeeds |
| Clock skew / late indexing | 5-minute overlap on each NVD window |
| Bad upstream data | Invalid records are skipped and counted. KEV refuses to apply a catalog with fewer than 100 entries |
| SSRF / exfiltration | Every URL must be `https`, on `EXCAT_EGRESS_ALLOWLIST`, and resolve to a public IP. Redirects aren't followed |

## Settings

Per-source **Enabled** and **Interval** are set in **Settings → CVE Sources** (`source:manage`). Global
defaults are in the [configuration reference](../reference/configuration.md): `EXCAT_FETCH_INTERVAL_MINUTES`,
`EXCAT_INITIAL_BACKFILL_DAYS`, `EXCAT_NVD_API_KEY`, `EXCAT_EPSS_BULK_THRESHOLD`.

## Manual runs

```bash
exposurecatalyst ingest nvd                      # one incremental run now
exposurecatalyst ingest nvd --since 2020-01-01   # historical backfill (chunked into 120-day windows)
exposurecatalyst ingest kev
exposurecatalyst ingest epss
```

## Metrics

`/metrics` (Prometheus) exposes `excat_ingestion_runs_total{source,status}`,
`excat_ingestion_records_total{source}`, `excat_ingestion_duration_seconds{source}` and
`excat_source_last_success_timestamp{source}`. Alert when `time() - last_success > 3 × interval`.
