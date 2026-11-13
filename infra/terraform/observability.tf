resource "aws_cloudwatch_log_group" "api" {
  name              = "/ecs/${local.prefix}/api"
  retention_in_days = 365
  kms_key_id        = aws_kms_key.data.arn
}

resource "aws_cloudwatch_log_group" "scheduler" {
  name              = "/ecs/${local.prefix}/scheduler"
  retention_in_days = 365
  kms_key_id        = aws_kms_key.data.arn
}

resource "aws_cloudwatch_log_group" "flow" {
  name              = "/vpc/${local.prefix}/flow"
  retention_in_days = 90
  kms_key_id        = aws_kms_key.data.arn
}

resource "aws_cloudwatch_log_group" "firewall" {
  name              = "/network-firewall/${local.prefix}/alerts"
  retention_in_days = 365
  kms_key_id        = aws_kms_key.data.arn
}

resource "aws_iam_role" "flow_logs" {
  name = "${local.prefix}-flow-logs"
  assume_role_policy = jsonencode({ Version = "2012-10-17", Statement = [{ Effect = "Allow", Action = "sts:AssumeRole",
  Principal = { Service = "vpc-flow-logs.amazonaws.com" } }] })
}

resource "aws_iam_role_policy" "flow_logs" {
  name = "write-logs"
  role = aws_iam_role.flow_logs.id
  policy = jsonencode({ Version = "2012-10-17", Statement = [{ Effect = "Allow",
    Action = ["logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogStreams"],
  Resource = "${aws_cloudwatch_log_group.flow.arn}:*" }] })
}

resource "aws_sns_topic" "alarms" {
  name              = "${local.prefix}-alarms"
  kms_master_key_id = aws_kms_key.data.id
}

resource "aws_sns_topic_subscription" "email" {
  count     = var.alarm_email == "" ? 0 : 1
  topic_arn = aws_sns_topic.alarms.arn
  protocol  = "email"
  endpoint  = var.alarm_email
}

# Application signals from structured logs (see docs/operations/runbooks.md)
locals {
  log_signals = {
    source_run_failed = { group = aws_cloudwatch_log_group.scheduler.name, pattern = "{ $.event = \"source_run_failed\" }", threshold = 3 }
    alert_run_failed  = { group = aws_cloudwatch_log_group.scheduler.name, pattern = "{ $.event = \"alert_run_failed\" }", threshold = 1 }
    unhandled_error   = { group = aws_cloudwatch_log_group.api.name, pattern = "{ $.event = \"unhandled_error\" }", threshold = 5 }
  }
}

resource "aws_cloudwatch_log_metric_filter" "signals" {
  for_each       = local.log_signals
  name           = each.key
  log_group_name = each.value.group
  pattern        = each.value.pattern
  metric_transformation {
    name      = each.key
    namespace = "ExposureCatalyst"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "signals" {
  for_each            = local.log_signals
  alarm_name          = "${local.prefix}-${each.key}"
  namespace           = "ExposureCatalyst"
  metric_name         = each.key
  statistic           = "Sum"
  period              = 3600
  evaluation_periods  = 1
  threshold           = each.value.threshold
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alarms.arn]
}

resource "aws_cloudwatch_metric_alarm" "alb_5xx" {
  alarm_name          = "${local.prefix}-alb-5xx"
  namespace           = "AWS/ApplicationELB"
  metric_name         = "HTTPCode_Target_5XX_Count"
  dimensions          = { LoadBalancer = aws_lb.this.arn_suffix }
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 2
  threshold           = 20
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alarms.arn]
}

resource "aws_cloudwatch_metric_alarm" "unhealthy" {
  alarm_name          = "${local.prefix}-unhealthy-targets"
  namespace           = "AWS/ApplicationELB"
  metric_name         = "HealthyHostCount"
  dimensions          = { LoadBalancer = aws_lb.this.arn_suffix, TargetGroup = aws_lb_target_group.api.arn_suffix }
  statistic           = "Minimum"
  period              = 60
  evaluation_periods  = 3
  threshold           = 1
  comparison_operator = "LessThanThreshold"
  alarm_actions       = [aws_sns_topic.alarms.arn]
}

resource "aws_cloudwatch_metric_alarm" "db_cpu" {
  alarm_name          = "${local.prefix}-aurora-cpu"
  namespace           = "AWS/RDS"
  metric_name         = "CPUUtilization"
  dimensions          = { DBClusterIdentifier = aws_rds_cluster.this.cluster_identifier }
  statistic           = "Average"
  period              = 300
  evaluation_periods  = 3
  threshold           = 80
  comparison_operator = "GreaterThanThreshold"
  alarm_actions       = [aws_sns_topic.alarms.arn]
}

# ---- account security services ---------------------------------------------------------------------
resource "aws_guardduty_detector" "this" {
  count  = var.enable_security_services ? 1 : 0
  enable = true
}

resource "aws_securityhub_account" "this" {
  count = var.enable_security_services ? 1 : 0
}

resource "aws_securityhub_standards_subscription" "fsbp" {
  count         = var.enable_security_services ? 1 : 0
  standards_arn = "arn:${data.aws_partition.current.partition}:securityhub:${var.region}::standards/aws-foundational-security-best-practices/v/1.0.0"
  depends_on    = [aws_securityhub_account.this]
}

resource "aws_s3_bucket" "trail" { bucket = "${local.prefix}-cloudtrail-${data.aws_caller_identity.current.account_id}" }

resource "aws_s3_bucket_public_access_block" "trail" {
  bucket                  = aws_s3_bucket.trail.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "trail" {
  bucket = aws_s3_bucket.trail.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.data.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_versioning" "trail" {
  bucket = aws_s3_bucket.trail.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_policy" "trail" {
  bucket = aws_s3_bucket.trail.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Sid = "AclCheck", Effect = "Allow", Principal = { Service = "cloudtrail.amazonaws.com" }, Action = "s3:GetBucketAcl", Resource = aws_s3_bucket.trail.arn },
      { Sid      = "Write", Effect = "Allow", Principal = { Service = "cloudtrail.amazonaws.com" }, Action = "s3:PutObject",
        Resource = "${aws_s3_bucket.trail.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*",
      Condition = { StringEquals = { "s3:x-amz-acl" = "bucket-owner-full-control" } } },
      { Sid = "TLSOnly", Effect = "Deny", Principal = "*", Action = "s3:*", Resource = [aws_s3_bucket.trail.arn, "${aws_s3_bucket.trail.arn}/*"],
      Condition = { Bool = { "aws:SecureTransport" = "false" } } },
    ]
  })
}

resource "aws_cloudtrail" "this" {
  name                          = local.prefix
  s3_bucket_name                = aws_s3_bucket.trail.id
  is_multi_region_trail         = true
  include_global_service_events = true
  enable_log_file_validation    = true
  kms_key_id                    = aws_kms_key.data.arn
  depends_on                    = [aws_s3_bucket_policy.trail]
}
