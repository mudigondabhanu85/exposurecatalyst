# Monitoring & metrics

## Health endpoints

| Endpoint | Meaning | Used by |
|---|---|---|
| `GET /api/health/live` | Process is up | Container health check |
| `GET /api/health/ready` | Database reachable | ALB target group, Compose `depends_on` |

## Prometheus metrics

`GET /metrics` (when `EXCAT_METRICS_ENABLED=true`). In AWS it's blocked at CloudFront and the ALB and only
reachable inside the VPC.

| Metric | Type | Labels | Use |
|---|---|---|---|
| `excat_ingestion_runs_total` | Counter | `source`, `status` | Failure rate per source |
| `excat_ingestion_records_total` | Counter | `source` | Throughput |
| `excat_ingestion_duration_seconds` | Histogram | `source` | Slow sources |
| `excat_source_last_success_timestamp` | Gauge | `source` | **Freshness**: alert when older than 2 × the interval |

## Structured log events

Logs are JSON (structlog) to stdout, shipped to CloudWatch Logs (KMS encrypted). Secrets are never logged.

| Event | Level | Meaning |
|---|---|---|
| `source_run_failed` | error | Ingestion run failed (RB-01) |
| `source_http_retry` | warning | Upstream retry with backoff |
| `nvd_record_skipped` | warning | One malformed NVD record was skipped |
| `connector_check_failed` | warning | Integration lookup failed (RB-05) |
| `alert_run_failed` | error | Alert evaluation or delivery failed (RB-13) |
| `maintenance_failed` | error | Retention job failed |
| `unhandled_error` | error | Generic 500 returned to a user |

## CloudWatch alarms (Terraform `observability.tf`)

All alarms notify the SNS topic `alarm_email` subscribes to.

| Alarm | Condition |
|---|---|
| `alb-5xx` | Target 5xx responses above threshold |
| `unhealthy-targets` | Healthy host count below 1 |
| `aurora-cpu` | Aurora CPU high for 15 minutes |
| `source_run_failed` | ≥ 3 failed source runs in the period |
| `alert_run_failed` | ≥ 1 failed alert run |
| `unhandled_error` | ≥ 5 unhandled errors |

Security detection (GuardDuty, Security Hub, CloudTrail, VPC flow logs, Network Firewall alerts) is described
in [AWS security controls](../security/aws-controls.md).

## In the application

- **Settings → CVE Sources**: per-source health, last success, last error and run history.
- Header banner when the scheduler heartbeat is stale.
- **Settings → AI Providers**: usage and spend against budget.
- `exposurecatalyst audit-verify` checks the audit hash chain (schedule it daily).
