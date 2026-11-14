# ExposureCatalyst — AWS reference deployment (Terraform)

Implements the [high-level](../../docs/architecture/high-level.md) and [network](../../docs/architecture/network.md)
architecture in one region across two Availability Zones.

| File | Resources |
|---|---|
| `network.tf` | VPC, public / firewall / app / data subnets per AZ, IGW, NAT per AZ, routing that **forces app egress through Network Firewall**, security groups, VPC flow logs, VPC endpoints (S3, Secrets Manager, KMS, SQS, Logs, ECR, STS, EventBridge, optional Bedrock) |
| `firewall.tf` | AWS Network Firewall with a STRICT-ORDER **domain allowlist** (TLS SNI / HTTP Host), drop + alert by default |
| `security.tf` | KMS CMK (rotation on), Secrets Manager secret with a generated Fernet key and Redis auth token |
| `data.tf` | Aurora PostgreSQL 16 (Multi-AZ, encrypted, `rds.force_ssl`, RDS-managed rotated master secret, 14-day backups, deletion protection), ElastiCache Redis (Multi-AZ, TLS, auth), S3 exports (SSE-KMS, versioning, TLS-only, lifecycle) and static assets (OAC) |
| `compute.tf` | ECR (immutable, scan on push), ECS Fargate cluster, **API** and **scheduler** services (ARM64, read-only root FS, non-root), least-privilege task roles, ALB that only forwards CloudFront traffic carrying a secret origin header, `/metrics` blocked |
| `edge.tf` | ACM certificates (DNS-validated), AWS WAF (managed rule groups and a login rate limit), CloudFront (ALB origin + S3 OAC for `/assets/*`, `/brand/*`), Route 53 aliases |
| `observability.tf` | KMS-encrypted log groups, SNS alarm topic, alarms (ALB 5xx, unhealthy targets, Aurora CPU, `source_run_failed`, `alert_run_failed`, `unhandled_error`), GuardDuty, Security Hub (FSBP), multi-region CloudTrail with log validation |

## Deploy

```bash
cd infra/terraform
cp terraform.tfvars.example terraform.tfvars            # domain, hosted zone, image tag, alarm email
# configure the encrypted S3 backend in versions.tf first — state contains generated secrets
terraform init && terraform plan -out plan && terraform apply plan

# build & push the image (ARM64)
REPO=$(terraform output -raw ecr_repository_url)
aws ecr get-login-password | docker login --username AWS --password-stdin "${REPO%/*}"
docker buildx build --platform linux/arm64 -t "$REPO:1.0.0" --push ../..

# static assets to S3 (served by CloudFront under /assets and /brand)
aws s3 sync ../../frontend/dist/assets "s3://$(terraform output -raw static_bucket)/assets" --cache-control "public,max-age=31536000,immutable"
aws s3 sync ../../frontend/dist/brand  "s3://$(terraform output -raw static_bucket)/brand"

# run migrations once per release (also creates/updates the DML-only app role), then roll the services.
# On the very first deploy, run this before the services start: they can't connect until the role exists.
eval "$(terraform output -raw run_migrations)"
aws ecs update-service --cluster exposurecatalyst-prod --service api --force-new-deployment
aws ecs update-service --cluster exposurecatalyst-prod --service scheduler --force-new-deployment
```

Create the break-glass admin with a one-off task (`command: ["exposurecatalyst","create-admin",...]`). It is
interactive, so use ECS Exec on a temporary task, or set the password from Secrets Manager. Then configure Okta
SSO in the app.

## Security notes

- Validated with `terraform validate` and scanned with Trivy: **no HIGH/CRITICAL findings**. Three accepted
  findings carry `#trivy:ignore` comments with the reason: the public ALB (CloudFront-only), app egress on
  443/587 (domain allowlist enforced by Network Firewall), and SSE-S3 on the public static-asset bucket.
  Remaining low/medium findings: CloudFront/S3 access logging and CloudTrail→CloudWatch delivery. Enable them
  if your logging standard requires it (they need an ACL-enabled log bucket).
- **Least-privilege database access.** The API and scheduler connect as `excat_app` (`db_app_username`), a
  role with `SELECT, INSERT, UPDATE, DELETE` only, and `SELECT, INSERT` on `audit_log`. They can't create,
  alter, drop or truncate anything, and their execution role can't read the Aurora master secret. Only the
  **migration task** (`run_migrations` output, its own execution role) gets the master credentials: it runs
  `exposurecatalyst migrate --app-role excat_app`, which applies Alembic migrations and then creates or
  updates the role, its password (secret `<prefix>/db-app`) and its grants. It's idempotent, and default
  privileges cover tables added by later migrations.
- **Rotating the app DB password**: put a new value in the `<prefix>/db-app` secret (or taint
  `random_password.db_app` and apply), run the migration task, then force a new deployment of both services.
  The master password is rotated by RDS and is only read by the migration task at launch.
- `sslmode=require` encrypts the database connection. For `verify-full`, add the RDS CA bundle to the image and
  set `sslrootcert`.
- Add new outbound hosts (news feeds, integrations, AI providers, SMTP relay) to `egress_domains` **and** to
  `EXCAT_EGRESS_ALLOWLIST` (derived automatically from the same variable).

## Not included (yet)

- **Asynchronous workers (SQS/EventBridge).** The reference architecture shows them as the scale-out path.
  This release runs ingestion, correlation and alerting in the `scheduler` service (one task, DB-claimed). They
  aren't provisioned until the worker mode exists, to avoid unused infrastructure.
- **DR secondary region.** The [DR design](../../docs/operations/disaster-recovery.md) uses Aurora Global
  Database, S3 CRR, replicated secrets and multi-Region keys. A secondary-region stack isn't part of this
  module.
