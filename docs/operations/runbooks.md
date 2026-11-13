# Runbooks

Each runbook lists the **signal** (how you find out), then the steps. Alarms are described in
[Monitoring](monitoring.md). Every administrative action below is recorded in the audit log.

| ID | Runbook |
|---|---|
| RB-01 | CVE source outage or failing source |
| RB-02 | Scheduler not running / failed job |
| RB-03 | Locked-out administrator |
| RB-04 | Audit chain verification failure |
| RB-05 | Integration (connector) failure |
| RB-06 | SMTP / advisory delivery failure |
| RB-07 | AI provider failure |
| RB-08 | Okta (IdP) signing certificate rotation |
| RB-09 | Encryption key rotation |
| RB-10 | Backup and restore |
| RB-11 | Disaster recovery failover |
| RB-12 | Upgrade and database migration |
| RB-13 | Alert delivery failure |

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

## RB-02: Scheduler not running / failed job

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
2. Treat it as a **security incident**: preserve DB snapshots, compare with RDS snapshots and
   CloudTrail/RDS logs to identify who modified the table.

## RB-05: Integration (connector) failure

**Signal**: the CVE asset panel shows *Error* for a tool, `connector_check_failed` in API logs, or
**Settings → Integrations → Test** fails.

1. Run **Test** on the integration and read the message (credentials are never shown).
2. Classify:

    | Error | Action |
    |---|---|
    | `401` / `403` | Credential expired or role removed. Rotate it in the tool, then paste the new value (write-only field) |
    | `429` | Vendor rate limit. Wait. Results are cached, so retries are cheap |
    | `host … is not in the egress allowlist` | Vendor changed API host. Update the base URL, `EXCAT_EGRESS_ALLOWLIST` and the firewall rule group |
    | Timeout | Check the vendor status page. Other tools keep working (per-tool isolation) |

3. Other integrations are unaffected. Advisories can still be created; add affected assets manually if needed.

## RB-06: SMTP / advisory delivery failure

**Signal**: an advisory send returns an error, or the delivery record shows *failed*.

1. **Settings → SMTP → Send test email** to your own address.
2. `535 authentication failed`: rotate the SMTP password (write-only). `Connection refused` / timeout: check
   the relay host, port (587 STARTTLS / 465 SSL) and the firewall allowlist. `550 relay denied`: the sender
   address isn't permitted on the relay.
3. Fallback: download the approved advisory as **.eml** and send it from Outlook. The approval and export are
   still audited.

## RB-07: AI provider failure

**Signal**: AI panels show *AI unavailable*, or usage shows repeated errors.

1. **Settings → AI Providers → Test** on the provider. If a fallback provider is configured, requests already
   route to it.
2. Budget exhausted: raise the monthly budget or wait for the period reset.
3. AI is optional. Everything else keeps working. To disable it completely, switch the AI policy off.

## RB-08: Okta (IdP) signing certificate rotation

ExposureCatalyst trusts **one** IdP signing certificate at a time, so schedule the switch in a quiet window.

1. In Okta (app → **Sign On** → **SAML Signing Certificates**), generate the new certificate. Don't activate it yet.
2. Make sure a local break-glass admin can sign in (RB-03).
3. Activate the new certificate in Okta, then immediately **Settings → Identity & SSO → Import metadata** (or
   paste the new certificate) and save. SSO sign-ins fail with *signature validation failed* in the seconds
   between these two steps.
4. Test a sign-in in a private window. Existing sessions are unaffected.

For the SP side, no certificate is required unless signed AuthnRequests are enabled.

## RB-09: Encryption key rotation

Secrets in the database are encrypted with `EXCAT_ENCRYPTION_KEY` (Fernet).

1. Generate a key: `exposurecatalyst gen-key`.
2. Deploy with the **new** key as `EXCAT_ENCRYPTION_KEY` and the old one in `EXCAT_ENCRYPTION_KEYS_PREVIOUS`
   (comma-separated). Both keys decrypt; the new one encrypts.
3. Run `exposurecatalyst rotate-secrets --dry-run`, then `exposurecatalyst rotate-secrets`.
4. Remove the old key from `EXCAT_ENCRYPTION_KEYS_PREVIOUS` and redeploy.

The database password is rotated by RDS (Secrets Manager managed). Tasks pick it up on restart.

## RB-10: Backup and restore

**Backups**: Aurora automated backups (14 days, point-in-time) and the final snapshot on deletion. Export
files in S3 are versioned.

**Restore (point in time)**

1. Restore the cluster to a new identifier:
   `aws rds restore-db-cluster-to-point-in-time --source-db-cluster-identifier <id> --db-cluster-identifier <id>-restore --restore-to-time <UTC>`
   then create an instance in the restored cluster.
2. Validate on the restored cluster: `exposurecatalyst audit-verify` and spot-check recent advisories.
3. Point the application at it (update the database endpoint, redeploy) **or** copy the needed rows back.
4. Record the incident and the restore time.

Test restores at least quarterly. The restored cluster must use the same KMS key, and the same
`EXCAT_ENCRYPTION_KEY` is needed to read secrets.

**Local / Compose**: `docker compose exec db pg_dump -U excat -Fc excat > backup.dump` and
`pg_restore --clean -d excat backup.dump`.

## RB-11: Disaster recovery failover

See [Disaster recovery](disaster-recovery.md) for the design, RPO/RTO and the step-by-step failover and
failback procedure.

## RB-12: Upgrade and database migration

1. Read the [changelog](../changelog.md) for breaking changes.
2. Take a manual snapshot (`aws rds create-db-cluster-snapshot`).
3. Deploy the new image. The API container runs `exposurecatalyst migrate` (Alembic) before serving. On ECS,
   run it as a one-off task first: `exposurecatalyst migrate`.
4. Check `/api/health/ready`, the version in the footer, and that the scheduler logs `scheduler_started`.
5. Rollback: redeploy the previous image. If a migration must be undone, restore the snapshot (migrations
   are forward-only in production).

## RB-13: Alert delivery failure

**Signal**: `alert_run_failed` alarm.

1. **Settings → Alerts**: open the rule's recent deliveries and the error.
2. Slack/Teams `404` or `410`: the webhook was deleted. Paste a new webhook URL. Email failures: RB-06.
3. Events are retried on the next run; nothing is sent twice for the same rule and CVE.
