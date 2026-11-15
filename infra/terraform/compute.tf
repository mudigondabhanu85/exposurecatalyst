resource "aws_ecr_repository" "app" {
  name                 = var.name
  image_tag_mutability = "IMMUTABLE"
  image_scanning_configuration { scan_on_push = true }
  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = aws_kms_key.data.arn
  }
}

resource "aws_ecs_cluster" "this" {
  name = local.prefix
  setting {
    name  = "containerInsights"
    value = "enabled"
  }
}

# ---- IAM: one execution role, one task role per service (least privilege) -------------------------
data "aws_iam_policy_document" "ecs_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "execution" {
  name               = "${local.prefix}-ecs-execution"
  assume_role_policy = data.aws_iam_policy_document.ecs_assume.json
}

resource "aws_iam_role_policy_attachment" "execution" {
  role       = aws_iam_role.execution.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_role_policy" "execution_secrets" {
  name = "read-app-secrets"
  role = aws_iam_role.execution.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = ["secretsmanager:GetSecretValue"],
      Resource = [aws_secretsmanager_secret.app.arn, aws_secretsmanager_secret.db_app.arn] },
      { Effect = "Allow", Action = ["kms:Decrypt"], Resource = [aws_kms_key.data.arn] },
    ]
  })
}

# The migration task is the only task that can read the Aurora master secret.
resource "aws_iam_role" "execution_migrate" {
  name               = "${local.prefix}-ecs-execution-migrate"
  assume_role_policy = data.aws_iam_policy_document.ecs_assume.json
}

resource "aws_iam_role_policy_attachment" "execution_migrate" {
  role       = aws_iam_role.execution_migrate.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_role_policy" "execution_migrate_secrets" {
  name = "read-migration-secrets"
  role = aws_iam_role.execution_migrate.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = ["secretsmanager:GetSecretValue"],
        Resource = [aws_secretsmanager_secret.app.arn, aws_secretsmanager_secret.db_app.arn,
      aws_rds_cluster.this.master_user_secret[0].secret_arn] },
      { Effect = "Allow", Action = ["kms:Decrypt"], Resource = [aws_kms_key.data.arn] },
    ]
  })
}

resource "aws_iam_role" "migrate" {
  name               = "${local.prefix}-migrate-task"
  assume_role_policy = data.aws_iam_policy_document.ecs_assume.json
}

resource "aws_iam_role" "api" {
  name               = "${local.prefix}-api-task"
  assume_role_policy = data.aws_iam_policy_document.ecs_assume.json
}

resource "aws_iam_role" "scheduler" {
  name               = "${local.prefix}-scheduler-task"
  assume_role_policy = data.aws_iam_policy_document.ecs_assume.json
}

data "aws_iam_policy_document" "exports" {
  statement {
    actions   = ["s3:GetObject", "s3:PutObject"]
    resources = ["${aws_s3_bucket.exports.arn}/*"]
  }
  statement {
    actions   = ["kms:GenerateDataKey", "kms:Decrypt"]
    resources = [aws_kms_key.data.arn]
  }
}

resource "aws_iam_role_policy" "api_exports" {
  name   = "exports"
  role   = aws_iam_role.api.id
  policy = data.aws_iam_policy_document.exports.json
}

resource "aws_iam_role_policy" "scheduler_exports" {
  name   = "exports"
  role   = aws_iam_role.scheduler.id
  policy = data.aws_iam_policy_document.exports.json
}

resource "aws_iam_role_policy" "api_bedrock" {
  count = var.enable_bedrock ? 1 : 0
  name  = "bedrock-invoke"
  role  = aws_iam_role.api.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["bedrock:InvokeModel", "bedrock:Converse"],
    Resource = "arn:${data.aws_partition.current.partition}:bedrock:${var.region}::foundation-model/*" }]
  })
}

resource "aws_iam_role_policy" "ses_send" {
  for_each = length(var.ses_identity_arns) > 0 ? { api = aws_iam_role.api.id, scheduler = aws_iam_role.scheduler.id } : {}
  name     = "ses-send"
  role     = each.value
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow", Action = ["ses:SendEmail", "ses:SendRawEmail"]
      Resource = concat(var.ses_identity_arns, [
        "arn:${data.aws_partition.current.partition}:ses:${var.region}:${data.aws_caller_identity.current.account_id}:configuration-set/*"
      ])
    }]
  })
}

# ---- task definitions -------------------------------------------------------------------------------
locals {
  allowlist = join(",", [for d in local.egress_domains : startswith(d, ".") ? "*${d}" : d])
  environment = [
    { name = "EXCAT_ENV", value = "prod" },
    { name = "EXCAT_PUBLIC_URL", value = local.public_url },
    { name = "EXCAT_DATABASE_URL", value = "postgresql+psycopg://${var.db_app_username}@${aws_rds_cluster.this.endpoint}:5432/excat?sslmode=require" },
    { name = "EXCAT_LOG_JSON", value = "true" },
    { name = "EXCAT_COOKIE_SECURE", value = "true" },
    { name = "EXCAT_API_DOCS_ENABLED", value = "false" },
    { name = "EXCAT_EGRESS_ALLOWLIST", value = local.allowlist },
    { name = "EXCAT_SCHEDULER_EMBEDDED", value = "false" },
  ]
  secrets = [
    { name = "EXCAT_ENCRYPTION_KEY", valueFrom = "${aws_secretsmanager_secret.app.arn}:EXCAT_ENCRYPTION_KEY::" },
    { name = "EXCAT_DATABASE_PASSWORD", valueFrom = "${aws_secretsmanager_secret.db_app.arn}:password::" },
  ]
  migrate_environment = [for e in local.environment : e.name == "EXCAT_DATABASE_URL" ? {
    name = e.name, value = "postgresql+psycopg://excat_admin@${aws_rds_cluster.this.endpoint}:5432/excat?sslmode=require"
  } : e]
  migrate_secrets = [
    { name = "EXCAT_ENCRYPTION_KEY", valueFrom = "${aws_secretsmanager_secret.app.arn}:EXCAT_ENCRYPTION_KEY::" },
    { name = "EXCAT_DATABASE_PASSWORD", valueFrom = "${aws_rds_cluster.this.master_user_secret[0].secret_arn}:password::" },
    { name = "EXCAT_APP_DB_PASSWORD", valueFrom = "${aws_secretsmanager_secret.db_app.arn}:password::" },
  ]
  container_common = {
    image                  = "${aws_ecr_repository.app.repository_url}:${var.image_tag}"
    essential              = true
    readonlyRootFilesystem = true
    user                   = "10001"
    environment            = local.environment
    secrets                = local.secrets
    mountPoints            = [{ sourceVolume = "tmp", containerPath = "/tmp" }]
    linuxParameters        = { initProcessEnabled = true }
  }
}

resource "aws_ecs_task_definition" "api" {
  family                   = "${local.prefix}-api"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 1024
  memory                   = 2048
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = aws_iam_role.api.arn
  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "ARM64"
  }
  volume { name = "tmp" }
  container_definitions = jsonencode([merge(local.container_common, {
    name         = "api"
    command      = ["exposurecatalyst", "serve", "--host", "0.0.0.0", "--port", "8000", "--forwarded-allow-ips", "*"]
    portMappings = [{ containerPort = 8000, protocol = "tcp" }]
    logConfiguration = { logDriver = "awslogs", options = {
    awslogs-group = aws_cloudwatch_log_group.api.name, awslogs-region = var.region, awslogs-stream-prefix = "api" } }
  })])
}

resource "aws_ecs_task_definition" "scheduler" {
  family                   = "${local.prefix}-scheduler"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 512
  memory                   = 1024
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = aws_iam_role.scheduler.arn
  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "ARM64"
  }
  volume { name = "tmp" }
  container_definitions = jsonencode([merge(local.container_common, {
    name    = "scheduler"
    command = ["exposurecatalyst", "scheduler"]
    logConfiguration = { logDriver = "awslogs", options = {
    awslogs-group = aws_cloudwatch_log_group.scheduler.name, awslogs-region = var.region, awslogs-stream-prefix = "scheduler" } }
  })])
}

# One-off: Alembic migrations + seed as the master user, then (re)apply the DML-only runtime role.
resource "aws_ecs_task_definition" "migrate" {
  family                   = "${local.prefix}-migrate"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 512
  memory                   = 1024
  execution_role_arn       = aws_iam_role.execution_migrate.arn
  task_role_arn            = aws_iam_role.migrate.arn
  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "ARM64"
  }
  volume { name = "tmp" }
  container_definitions = jsonencode([merge(local.container_common, {
    name        = "migrate"
    environment = local.migrate_environment
    secrets     = local.migrate_secrets
    command     = ["exposurecatalyst", "migrate", "--app-role", var.db_app_username]
    logConfiguration = { logDriver = "awslogs", options = {
    awslogs-group = aws_cloudwatch_log_group.api.name, awslogs-region = var.region, awslogs-stream-prefix = "migrate" } }
  })])
}

resource "aws_ecs_service" "api" {
  name                   = "api"
  cluster                = aws_ecs_cluster.this.id
  task_definition        = aws_ecs_task_definition.api.arn
  desired_count          = var.api_desired_count
  launch_type            = "FARGATE"
  enable_execute_command = false
  propagate_tags         = "SERVICE"
  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }
  network_configuration {
    subnets          = aws_subnet.app[*].id
    security_groups  = [aws_security_group.app.id]
    assign_public_ip = false
  }
  load_balancer {
    target_group_arn = aws_lb_target_group.api.arn
    container_name   = "api"
    container_port   = 8000
  }
  depends_on = [aws_lb_listener.https]
}

# Exactly one scheduler; the DB claim makes extra replicas safe but unnecessary.
resource "aws_ecs_service" "scheduler" {
  name            = "scheduler"
  cluster         = aws_ecs_cluster.this.id
  task_definition = aws_ecs_task_definition.scheduler.arn
  desired_count   = 1
  launch_type     = "FARGATE"
  propagate_tags  = "SERVICE"
  network_configuration {
    subnets          = aws_subnet.app[*].id
    security_groups  = [aws_security_group.app.id]
    assign_public_ip = false
  }
}

# ---- ALB (reachable only from CloudFront, and only with the origin-verify header) -----------------
resource "random_password" "origin_verify" {
  length  = 40
  special = false
}

# Internet-facing by necessity (CloudFront custom origin), but only reachable from CloudFront's origin-facing
# prefix list (SG) and only forwards requests carrying the secret X-Origin-Verify header (listener rule).
#trivy:ignore:AVD-AWS-0053
resource "aws_lb" "this" {
  name                       = local.prefix
  load_balancer_type         = "application"
  internal                   = false
  subnets                    = aws_subnet.public[*].id
  security_groups            = [aws_security_group.alb.id]
  drop_invalid_header_fields = true
  enable_deletion_protection = true
}

resource "aws_lb_target_group" "api" {
  name        = "${local.prefix}-api"
  port        = 8000
  protocol    = "HTTP"
  target_type = "ip"
  vpc_id      = aws_vpc.this.id
  health_check {
    path    = "/api/health/ready"
    matcher = "200"
  }
}

resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.this.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = aws_acm_certificate_validation.alb.certificate_arn
  default_action {
    type = "fixed-response"
    fixed_response {
      content_type = "text/plain"
      message_body = "Forbidden"
      status_code  = "403"
    }
  }
}

resource "aws_lb_listener_rule" "block_metrics" {
  listener_arn = aws_lb_listener.https.arn
  priority     = 5
  action {
    type = "fixed-response"
    fixed_response {
      content_type = "text/plain"
      message_body = "Not found"
      status_code  = "404"
    }
  }
  condition {
    path_pattern { values = ["/metrics", "/metrics/*"] }
  }
}

resource "aws_lb_listener_rule" "from_cloudfront" {
  listener_arn = aws_lb_listener.https.arn
  priority     = 10
  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.api.arn
  }
  condition {
    http_header {
      http_header_name = "X-Origin-Verify"
      values           = [random_password.origin_verify.result]
    }
  }
}
