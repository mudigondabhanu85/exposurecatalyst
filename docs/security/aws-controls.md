# AWS security controls mapping

| Control objective | AWS service / configuration (Terraform) | Application control |
|---|---|---|
| Identity & least privilege | IAM task role per service (`compute.tf`). Execution role reads only the app and RDS secrets | RBAC with `require()` on every route. SoD |
| Secrets | Secrets Manager (generated Fernet key, RDS-managed rotated DB password), KMS CMK | Fernet-encrypted secrets in the DB, write-only APIs, `rotate-secrets` |
| Encryption at rest | KMS CMK for Aurora, S3 exports, CloudWatch Logs, ElastiCache, SNS, ECR, CloudTrail | — |
| Encryption in transit | ACM TLS (CloudFront TLSv1.2_2021, ALB TLS 1.3 policy), `rds.force_ssl`, Redis TLS | HSTS, `sslmode=require`, STARTTLS/SSL for SMTP |
| Edge protection | AWS WAF (Common, KnownBadInputs, SQLi, IP reputation, login rate limit), CloudFront | Origin check, CSRF, rate limiting, lockout |
| Origin protection | ALB SG = CloudFront prefix list. Secret `X-Origin-Verify` header. `/metrics` blocked | — |
| Network segmentation | 3-tier subnets. Isolated data tier. Security groups by role | — |
| Egress control | AWS Network Firewall domain allowlist (drop + alert). VPC endpoints | SSRF guard + `EXCAT_EGRESS_ALLOWLIST` |
| Detection | GuardDuty, Security Hub (FSBP), CloudTrail (multi-region, validation), VPC flow logs, firewall alert logs | Audit log, structured logs |
| Monitoring & response | CloudWatch alarms → SNS (5xx, unhealthy targets, DB CPU, source failures, alert failures, unhandled errors) | Source health UI, scheduler heartbeat |
| Resilience | Multi-AZ ALB/ECS/Aurora/Redis. Backups (14 d). Deletion protection | DB-claimed scheduler, idempotent ingestion |
| Data residency | Single region. Optional Bedrock in-region for AI | AI provider allowlist, redaction |
