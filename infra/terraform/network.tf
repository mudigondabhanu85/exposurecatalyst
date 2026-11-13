resource "aws_vpc" "this" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = { Name = local.prefix }
}

resource "aws_internet_gateway" "this" { vpc_id = aws_vpc.this.id }

resource "aws_subnet" "public" {
  count             = 2
  vpc_id            = aws_vpc.this.id
  cidr_block        = local.public_cidrs[count.index]
  availability_zone = local.azs[count.index]
  tags              = { Name = "${local.prefix}-public-${local.azs[count.index]}", Tier = "public" }
}

resource "aws_subnet" "firewall" {
  count             = 2
  vpc_id            = aws_vpc.this.id
  cidr_block        = local.firewall_cidrs[count.index]
  availability_zone = local.azs[count.index]
  tags              = { Name = "${local.prefix}-firewall-${local.azs[count.index]}", Tier = "firewall" }
}

resource "aws_subnet" "app" {
  count             = 2
  vpc_id            = aws_vpc.this.id
  cidr_block        = local.app_cidrs[count.index]
  availability_zone = local.azs[count.index]
  tags              = { Name = "${local.prefix}-app-${local.azs[count.index]}", Tier = "private" }
}

resource "aws_subnet" "data" {
  count             = 2
  vpc_id            = aws_vpc.this.id
  cidr_block        = local.data_cidrs[count.index]
  availability_zone = local.azs[count.index]
  tags              = { Name = "${local.prefix}-data-${local.azs[count.index]}", Tier = "isolated" }
}

resource "aws_eip" "nat" {
  count  = 2
  domain = "vpc"
}

resource "aws_nat_gateway" "this" {
  count         = 2
  allocation_id = aws_eip.nat[count.index].id
  subnet_id     = aws_subnet.public[count.index].id
  depends_on    = [aws_internet_gateway.this]
}

locals {
  # Network Firewall endpoint id per AZ
  fw_endpoint = { for s in tolist(aws_networkfirewall_firewall.egress.firewall_status[0].sync_states) :
  s.availability_zone => s.attachment[0].endpoint_id }
}

# Public: default → IGW; return traffic to app subnets goes back through the firewall (symmetric).
resource "aws_route_table" "public" {
  count  = 2
  vpc_id = aws_vpc.this.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.this.id
  }
  route {
    cidr_block      = local.app_cidrs[count.index]
    vpc_endpoint_id = local.fw_endpoint[local.azs[count.index]]
  }
  tags = { Name = "${local.prefix}-public-${count.index}" }
}

# Firewall subnets: inspected traffic leaves via the NAT gateway in the same AZ.
resource "aws_route_table" "firewall" {
  count  = 2
  vpc_id = aws_vpc.this.id
  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.this[count.index].id
  }
  tags = { Name = "${local.prefix}-firewall-${count.index}" }
}

# App subnets: all internet-bound traffic is forced through the Network Firewall endpoint.
resource "aws_route_table" "app" {
  count  = 2
  vpc_id = aws_vpc.this.id
  route {
    cidr_block      = "0.0.0.0/0"
    vpc_endpoint_id = local.fw_endpoint[local.azs[count.index]]
  }
  tags = { Name = "${local.prefix}-app-${count.index}" }
}

# Data subnets: no default route at all (isolated).
resource "aws_route_table" "data" {
  vpc_id = aws_vpc.this.id
  tags   = { Name = "${local.prefix}-data" }
}

resource "aws_route_table_association" "public" {
  count          = 2
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public[count.index].id
}

resource "aws_route_table_association" "firewall" {
  count          = 2
  subnet_id      = aws_subnet.firewall[count.index].id
  route_table_id = aws_route_table.firewall[count.index].id
}

resource "aws_route_table_association" "app" {
  count          = 2
  subnet_id      = aws_subnet.app[count.index].id
  route_table_id = aws_route_table.app[count.index].id
}

resource "aws_route_table_association" "data" {
  count          = 2
  subnet_id      = aws_subnet.data[count.index].id
  route_table_id = aws_route_table.data.id
}

resource "aws_flow_log" "vpc" {
  vpc_id               = aws_vpc.this.id
  traffic_type         = "ALL"
  log_destination_type = "cloud-watch-logs"
  log_destination      = aws_cloudwatch_log_group.flow.arn
  iam_role_arn         = aws_iam_role.flow_logs.arn
}

# ---- security groups ------------------------------------------------------------------------------
data "aws_ec2_managed_prefix_list" "cloudfront" { name = "com.amazonaws.global.cloudfront.origin-facing" }

resource "aws_security_group" "alb" {
  name        = "${local.prefix}-alb"
  description = "ALB: HTTPS from CloudFront origin-facing IPs only"
  vpc_id      = aws_vpc.this.id
  ingress {
    description     = "HTTPS from CloudFront"
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    prefix_list_ids = [data.aws_ec2_managed_prefix_list.cloudfront.id]
  }
  egress {
    description = "To app tasks"
    from_port   = 8000
    to_port     = 8000
    protocol    = "tcp"
    cidr_blocks = local.app_cidrs
  }
}

resource "aws_security_group" "app" {
  name        = "${local.prefix}-app"
  description = "ECS tasks"
  vpc_id      = aws_vpc.this.id
  ingress {
    description     = "From ALB"
    from_port       = 8000
    to_port         = 8000
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }
  # Destinations are SaaS hosts by name; security groups cannot express domains. The domain allowlist is enforced
  # by AWS Network Firewall on the app subnets' only internet route (see firewall.tf).
  #trivy:ignore:AVD-AWS-0104
  egress {
    description = "HTTPS (via Network Firewall allowlist / VPC endpoints)"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  #trivy:ignore:AVD-AWS-0104
  egress {
    description = "SMTP submission (relay / SES), via Network Firewall"
    from_port   = 587
    to_port     = 587
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    description = "PostgreSQL"
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = local.data_cidrs
  }
  egress {
    description = "Redis TLS"
    from_port   = 6379
    to_port     = 6379
    protocol    = "tcp"
    cidr_blocks = local.data_cidrs
  }
}

resource "aws_security_group" "db" {
  name        = "${local.prefix}-db"
  description = "Aurora: 5432 from app only"
  vpc_id      = aws_vpc.this.id
  ingress {
    description     = "PostgreSQL from app tasks"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.app.id]
  }
}

resource "aws_security_group" "redis" {
  name        = "${local.prefix}-redis"
  description = "Redis: 6379 from app only"
  vpc_id      = aws_vpc.this.id
  ingress {
    description     = "Redis from app tasks"
    from_port       = 6379
    to_port         = 6379
    protocol        = "tcp"
    security_groups = [aws_security_group.app.id]
  }
}

resource "aws_security_group" "endpoints" {
  name        = "${local.prefix}-vpce"
  description = "Interface endpoints: 443 from app"
  vpc_id      = aws_vpc.this.id
  ingress {
    description     = "HTTPS from app tasks"
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [aws_security_group.app.id]
  }
}

# ---- VPC endpoints (AWS API traffic never crosses the internet) -----------------------------------
resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.this.id
  service_name      = "com.amazonaws.${var.region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = aws_route_table.app[*].id
}

resource "aws_vpc_endpoint" "interface" {
  for_each            = toset(concat(["secretsmanager", "kms", "sqs", "logs", "ecr.api", "ecr.dkr", "sts", "events"], var.enable_bedrock ? ["bedrock-runtime"] : []))
  vpc_id              = aws_vpc.this.id
  service_name        = "com.amazonaws.${var.region}.${each.key}"
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true
  subnet_ids          = aws_subnet.app[*].id
  security_group_ids  = [aws_security_group.endpoints.id]
}
