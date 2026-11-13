output "url" { value = local.public_url }
output "cloudfront_domain" { value = aws_cloudfront_distribution.this.domain_name }
output "ecr_repository_url" { value = aws_ecr_repository.app.repository_url }
output "static_bucket" { value = aws_s3_bucket.static.bucket }
output "exports_bucket" { value = aws_s3_bucket.exports.bucket }
output "alarm_topic_arn" { value = aws_sns_topic.alarms.arn }

output "run_migrations" {
  description = "One-off migration task (run before updating the services)."
  value = join(" ", ["aws ecs run-task --cluster", aws_ecs_cluster.this.name, "--launch-type FARGATE",
    "--task-definition", aws_ecs_task_definition.api.family,
    "--network-configuration 'awsvpcConfiguration={subnets=[${join(",", aws_subnet.app[*].id)}],securityGroups=[${aws_security_group.app.id}]}'",
  "--overrides '{\"containerOverrides\":[{\"name\":\"api\",\"command\":[\"exposurecatalyst\",\"migrate\"]}]}'"])
}
