resource "aws_db_subnet_group" "this" {
  name       = local.prefix
  subnet_ids = aws_subnet.data[*].id
}

resource "aws_rds_cluster_parameter_group" "this" {
  name   = "${local.prefix}-pg16"
  family = "aurora-postgresql16"
  parameter {
    name  = "rds.force_ssl"
    value = "1"
  }
  parameter {
    name  = "log_min_duration_statement"
    value = "1000"
  }
}

resource "aws_rds_cluster" "this" {
  cluster_identifier                  = local.prefix
  engine                              = "aurora-postgresql"
  engine_version                      = "16.4"
  database_name                       = "excat"
  master_username                     = "excat_admin"
  manage_master_user_password         = true # RDS-managed secret in Secrets Manager, rotated automatically
  master_user_secret_kms_key_id       = aws_kms_key.data.arn
  storage_encrypted                   = true
  kms_key_id                          = aws_kms_key.data.arn
  db_subnet_group_name                = aws_db_subnet_group.this.name
  vpc_security_group_ids              = [aws_security_group.db.id]
  db_cluster_parameter_group_name     = aws_rds_cluster_parameter_group.this.name
  backup_retention_period             = 14
  preferred_backup_window             = "03:00-04:00"
  copy_tags_to_snapshot               = true
  deletion_protection                 = true
  skip_final_snapshot                 = false
  final_snapshot_identifier           = "${local.prefix}-final"
  iam_database_authentication_enabled = true
  enabled_cloudwatch_logs_exports     = ["postgresql"]
}

resource "aws_rds_cluster_instance" "this" {
  count                           = 2 # writer + reader in different AZs (Multi-AZ)
  identifier                      = "${local.prefix}-${count.index}"
  cluster_identifier              = aws_rds_cluster.this.id
  instance_class                  = "db.r6g.large"
  engine                          = aws_rds_cluster.this.engine
  engine_version                  = aws_rds_cluster.this.engine_version
  availability_zone               = local.azs[count.index]
  performance_insights_enabled    = true
  performance_insights_kms_key_id = aws_kms_key.data.arn
  auto_minor_version_upgrade      = true
}

resource "aws_elasticache_subnet_group" "this" {
  name       = local.prefix
  subnet_ids = aws_subnet.data[*].id
}

resource "aws_elasticache_replication_group" "this" {
  replication_group_id       = local.prefix
  description                = "ExposureCatalyst cache / rate limits / optional Celery broker"
  engine                     = "redis"
  engine_version             = "7.1"
  node_type                  = "cache.t4g.small"
  num_cache_clusters         = 2
  automatic_failover_enabled = true
  multi_az_enabled           = true
  subnet_group_name          = aws_elasticache_subnet_group.this.name
  security_group_ids         = [aws_security_group.redis.id]
  at_rest_encryption_enabled = true
  kms_key_id                 = aws_kms_key.data.arn
  transit_encryption_enabled = true
  auth_token                 = random_password.redis.result
}

# ---- S3: exports/archives and static SPA assets ---------------------------------------------------
resource "aws_s3_bucket" "exports" { bucket = "${local.prefix}-exports-${data.aws_caller_identity.current.account_id}" }
resource "aws_s3_bucket" "static" { bucket = "${local.prefix}-static-${data.aws_caller_identity.current.account_id}" }

resource "aws_s3_bucket_public_access_block" "exports" {
  bucket                  = aws_s3_bucket.exports.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_public_access_block" "static" {
  bucket                  = aws_s3_bucket.static.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "exports" {
  bucket = aws_s3_bucket.exports.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_versioning" "static" {
  bucket = aws_s3_bucket.static.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "exports" {
  bucket = aws_s3_bucket.exports.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.data.arn
    }
    bucket_key_enabled = true
  }
}

# Static assets are public, content-hashed JS/CSS/brand files served through CloudFront OAC; SSE-S3 avoids a
# KMS key policy that would have to reference the distribution (cycle). No confidential data is stored here.
#trivy:ignore:AVD-AWS-0132
resource "aws_s3_bucket_server_side_encryption_configuration" "static" {
  bucket = aws_s3_bucket.static.id
  rule {
    apply_server_side_encryption_by_default { sse_algorithm = "AES256" }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "exports" {
  bucket = aws_s3_bucket.exports.id
  rule {
    id     = "retain-exports"
    status = "Enabled"
    filter {}
    noncurrent_version_expiration { noncurrent_days = 90 }
    expiration { days = 730 }
  }
}

resource "aws_s3_bucket_policy" "exports" {
  bucket = aws_s3_bucket.exports.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Sid = "TLSOnly", Effect = "Deny", Principal = "*", Action = "s3:*",
      Resource = [aws_s3_bucket.exports.arn, "${aws_s3_bucket.exports.arn}/*"],
    Condition = { Bool = { "aws:SecureTransport" = "false" } } }]
  })
}

resource "aws_s3_bucket_policy" "static" {
  bucket = aws_s3_bucket.static.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Sid    = "CloudFrontOAC", Effect = "Allow", Principal = { Service = "cloudfront.amazonaws.com" },
        Action = "s3:GetObject", Resource = "${aws_s3_bucket.static.arn}/*",
      Condition = { StringEquals = { "AWS:SourceArn" = aws_cloudfront_distribution.this.arn } } },
      { Sid      = "TLSOnly", Effect = "Deny", Principal = "*", Action = "s3:*",
        Resource = [aws_s3_bucket.static.arn, "${aws_s3_bucket.static.arn}/*"],
      Condition = { Bool = { "aws:SecureTransport" = "false" } } },
    ]
  })
}
