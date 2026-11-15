# Egress allowlist enforced at the network layer (defence in depth with the app's SSRF guard).
resource "aws_networkfirewall_rule_group" "allow_domains" {
  name     = "${local.prefix}-egress-allow"
  type     = "STATEFUL"
  capacity = 500
  rule_group {
    rules_source {
      rules_source_list {
        generated_rules_type = "ALLOWLIST"
        target_types         = ["TLS_SNI", "HTTP_HOST"]
        targets              = local.egress_domains
      }
    }
    rule_variables {
      ip_sets {
        key = "HOME_NET"
        ip_set { definition = local.app_cidrs }
      }
    }
    stateful_rule_options { rule_order = "STRICT_ORDER" }
  }
}

# SMTP submission (587) to explicit relay CIDRs: STARTTLS has no SNI at connect time, so it can't be domain-matched.
resource "aws_networkfirewall_rule_group" "allow_smtp" {
  count    = length(var.smtp_egress_cidrs) > 0 ? 1 : 0
  name     = "${local.prefix}-egress-smtp"
  type     = "STATEFUL"
  capacity = 50
  rule_group {
    rules_source {
      dynamic "stateful_rule" {
        for_each = var.smtp_egress_cidrs
        content {
          action = "PASS"
          header {
            protocol         = "TCP"
            source           = "$HOME_NET"
            source_port      = "ANY"
            destination      = stateful_rule.value
            destination_port = "587"
            direction        = "FORWARD"
          }
          rule_option {
            keyword  = "sid"
            settings = [tostring(1000 + stateful_rule.key)]
          }
        }
      }
    }
    rule_variables {
      ip_sets {
        key = "HOME_NET"
        ip_set { definition = local.app_cidrs }
      }
    }
    stateful_rule_options { rule_order = "STRICT_ORDER" }
  }
}

resource "aws_networkfirewall_firewall_policy" "egress" {
  name = "${local.prefix}-egress"
  firewall_policy {
    stateless_default_actions          = ["aws:forward_to_sfe"]
    stateless_fragment_default_actions = ["aws:forward_to_sfe"]
    stateful_engine_options { rule_order = "STRICT_ORDER" }
    stateful_default_actions = ["aws:drop_established", "aws:alert_established"]
    stateful_rule_group_reference {
      priority     = 100
      resource_arn = aws_networkfirewall_rule_group.allow_domains.arn
    }
    dynamic "stateful_rule_group_reference" {
      for_each = aws_networkfirewall_rule_group.allow_smtp
      content {
        priority     = 90
        resource_arn = stateful_rule_group_reference.value.arn
      }
    }
  }
}

resource "aws_networkfirewall_firewall" "egress" {
  name                = "${local.prefix}-egress"
  vpc_id              = aws_vpc.this.id
  firewall_policy_arn = aws_networkfirewall_firewall_policy.egress.arn
  dynamic "subnet_mapping" {
    for_each = aws_subnet.firewall[*].id
    content { subnet_id = subnet_mapping.value }
  }
}

resource "aws_networkfirewall_logging_configuration" "egress" {
  firewall_arn = aws_networkfirewall_firewall.egress.arn
  logging_configuration {
    log_destination_config {
      log_type             = "ALERT"
      log_destination_type = "CloudWatchLogs"
      log_destination      = { logGroup = aws_cloudwatch_log_group.firewall.name }
    }
  }
}
