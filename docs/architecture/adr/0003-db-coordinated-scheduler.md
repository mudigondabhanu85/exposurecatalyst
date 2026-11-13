# ADR-0003: DB-coordinated scheduler tick

**Status:** Accepted · **Date:** 2026-11-13

## Context
Fetch intervals are configurable per source at runtime, users can request **Refresh now**, and deployments
range from a single container to multiple Fargate tasks. Classic per-job cron schedules need restarts or IPC
to change, and run duplicates when several schedulers exist.

## Decision
A single fixed-rate **tick** (60 seconds) reads `source_state`. It decides what is due from the interval,
the last attempt and any refresh request, then **claims** each source with an atomic conditional `UPDATE`.
Work runs only if the claim affected one row. Stale claims expire after `EXCAT_JOB_STALE_AFTER_MINUTES`.

## Consequences
- ✅ Interval changes and manual refreshes take effect within one tick, with no restart.
- ✅ Safe with N schedulers or replicas. The trigger can be APScheduler (single node), EventBridge Scheduler or
  Celery beat (scaled) without code changes.
- ⚠️ Up to one tick of latency for manual refresh. The UI says so.
