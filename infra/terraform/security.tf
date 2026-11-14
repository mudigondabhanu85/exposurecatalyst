resource "aws_kms_key" "data" {
  description             = "${local.prefix} data (Aurora, S3, secrets, logs, SQS)"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Sid = "Root", Effect = "Allow", Principal = { AWS = "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root" }, Action = "kms:*", Resource = "*" },
      { Sid = "CloudWatchLogs", Effect = "Allow", Principal = { Service = "logs.${var.region}.amazonaws.com" },
      Action = ["kms:Encrypt*", "kms:Decrypt*", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:Describe*"], Resource = "*" },
      { Sid = "CloudTrail", Effect = "Allow", Principal = { Service = "cloudtrail.amazonaws.com" },
      Action = ["kms:GenerateDataKey*", "kms:DescribeKey"], Resource = "*" },
    ]
  })
}

resource "aws_kms_alias" "data" {
  name          = "alias/${local.prefix}-data"
  target_key_id = aws_kms_key.data.key_id
}

# Application Fernet key (EXCAT_ENCRYPTION_KEY): 32 random bytes, URL-safe base64.
resource "random_id" "fernet" { byte_length = 32 }

resource "random_password" "redis" {
  length  = 48
  special = false
}

resource "aws_secretsmanager_secret" "app" {
  name       = "${local.prefix}/app"
  kms_key_id = aws_kms_key.data.arn
}

resource "aws_secretsmanager_secret_version" "app" {
  secret_id = aws_secretsmanager_secret.app.id
  secret_string = jsonencode({
    EXCAT_ENCRYPTION_KEY = replace(replace(random_id.fernet.b64_std, "+", "-"), "/", "_")
    REDIS_AUTH_TOKEN     = random_password.redis.result
  })
}

# Runtime database role (DML only). The migration task creates/updates it from this secret; the API and
# scheduler connect with it and never receive the Aurora master credentials.
resource "random_password" "db_app" {
  length  = 40
  special = false
}

resource "aws_secretsmanager_secret" "db_app" {
  name       = "${local.prefix}/db-app"
  kms_key_id = aws_kms_key.data.arn
}

resource "aws_secretsmanager_secret_version" "db_app" {
  secret_id     = aws_secretsmanager_secret.db_app.id
  secret_string = jsonencode({ username = var.db_app_username, password = random_password.db_app.result })
}
