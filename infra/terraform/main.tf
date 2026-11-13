data "aws_availability_zones" "available" { state = "available" }
data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

locals {
  prefix = "${var.name}-${var.environment}"
  azs    = slice(data.aws_availability_zones.available.names, 0, 2)
  tags   = { Application = "ExposureCatalyst", Environment = var.environment, ManagedBy = "terraform" }
  # /16 → public /24, firewall /28, app /22, data /24 per AZ (matches docs/assets/diagrams/network.svg)
  public_cidrs   = [for i in range(2) : cidrsubnet(var.vpc_cidr, 8, i)]
  firewall_cidrs = [for i in range(2) : cidrsubnet(var.vpc_cidr, 12, 160 + i)]
  app_cidrs      = [for i in range(2) : cidrsubnet(var.vpc_cidr, 6, 5 + i)]
  data_cidrs     = [for i in range(2) : cidrsubnet(var.vpc_cidr, 8, 40 + i)]
  public_url     = "https://${var.domain_name}"
}
