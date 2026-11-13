# Data retention

A daily maintenance job (part of the scheduler tick) deletes data older than the configured period and
writes an audit entry (`maintenance.retention`) with the counts. Run it on demand with
`exposurecatalyst retention`.

| Data | Default | Setting |
|---|---|---|
| Sessions (expired or revoked) | 30 days | `EXCAT_RETENTION_SESSIONS_DAYS` |
| Ingestion job-run history | 90 days | `EXCAT_RETENTION_JOB_RUNS_DAYS` |
| AI usage records | 400 days | `EXCAT_RETENTION_AI_USAGE_DAYS` |
| Delivered alert events | 365 days | `EXCAT_RETENTION_ALERT_EVENTS_DAYS` |
| News items | 90 days | `EXCAT_NEWS_RETENTION_DAYS` |
| SAML request IDs | 1 day | fixed |
| CVE records | kept (public data, re-ingestible) | — |
| Advisories, delivery records | kept (business record) | Delete per your records policy |
| **Audit log** | **kept** (append-only, trigger-protected) | Archive per policy; never edited in place |
| Correlation cache | Overwritten on refresh | — |
| AI prompts and responses | **Not stored** | — |
| Backups | 14 days | Terraform `backup_retention_period` |
| CloudWatch logs | 365 days (app), 90 days (flow logs) | Terraform `observability.tf` |

Personal data held is limited to user accounts (name, email, username), recipient addresses and asset owner
names from integrations. Deactivating an SSO user (SCIM) removes access immediately; the user row stays for
audit attribution.
