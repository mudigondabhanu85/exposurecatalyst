# Runbooks

Phase 1 runbooks. Connector, SMTP and failed-job runbooks are added with their features, and the full set,
including backup, restore and DR, follows in Phase 6.

## RB-01: CVE source outage or failing source

**Signal**: source health shows *Failing*, the `excat_source_last_success_timestamp` alarm fires, or users report
stale data.

1. Open **Settings → CVE Sources** and read **Last error**, or run
   `GET /api/sources/runs`.
2. Classify the error:

    | Error | Likely cause | Action |
    |---|---|---|
    | `HTTP 403` (NVD) | Invalid or revoked API key | Rotate `EXCAT_NVD_API_KEY` in Secrets Manager and redeploy the tasks |
    | `HTTP 429`, `giving up after N attempts` | Upstream rate limit or outage | None. Backoff retries next tick. Check the NVD/CISA status pages |
    | `host … is not in the egress allowlist` | Upstream changed domain | Update `EXCAT_EGRESS_ALLOWLIST` **and** the Network Firewall rule group |
    | `cannot resolve host` / `ConnectError` | DNS or egress path down | Check the NAT gateway, Network Firewall and route tables |
    | `catalogue has only N entries` (KEV) | Truncated upstream file | None. Previous KEV data is kept. Retries next tick |

3. After fixing, click **Refresh now** and confirm the health badge turns *Healthy*.
4. If the outage lasted longer than the NVD 120-day window (unlikely), run a backfill:
   `exposurecatalyst ingest nvd --since <last success date>`.

## RB-02: Scheduler not running

**Signal**: banner *Scheduler not running*, or no new job runs.

1. Check the service: `docker compose ps scheduler` or the ECS service desired/running count.
2. Check the logs for `scheduler_started` and errors (DB connectivity, configuration validation).
3. A source stuck in `running` after a crash is re-claimed automatically after
   `EXCAT_JOB_STALE_AFTER_MINUTES` (120). To release it immediately, an admin can set `status='error'` for that
   row in `source_state`. This is audited in the DB change log.

## RB-03: Locked-out administrator

1. Another admin with `user:manage` clicks **Unlock** in Settings → Users & RBAC.
2. If no admin can sign in, use the break-glass account. As a last resort, on the host:
   `exposurecatalyst create-admin --username recovery-<date>`. Review and disable it afterwards. All steps
   are recorded in the audit log.

## RB-04: Audit chain verification failure

1. Run `exposurecatalyst audit-verify`. Note the first bad row ID.
2. Treat it as a **security incident**: preserve DB snapshots, compare with the S3 archive (Phase 6) and
   CloudTrail/RDS logs to identify who modified the table.
