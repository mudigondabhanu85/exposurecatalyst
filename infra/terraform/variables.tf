variable "name" {
  type    = string
  default = "exposurecatalyst"
}

variable "environment" {
  type    = string
  default = "prod"
}

variable "region" {
  type    = string
  default = "us-east-1"
}

variable "vpc_cidr" {
  type    = string
  default = "10.20.0.0/16"
}

variable "domain_name" {
  description = "Public hostname users browse to, e.g. excat.example.com (becomes EXCAT_PUBLIC_URL)."
  type        = string
}

variable "hosted_zone_id" {
  description = "Route 53 public hosted zone for domain_name (DNS validation + alias records)."
  type        = string
}

variable "image_tag" {
  description = "Immutable image tag in ECR to deploy (e.g. git SHA or 1.0.0)."
  type        = string
  default     = "1.0.0"
}

variable "api_desired_count" {
  type    = number
  default = 2
}

variable "egress_domains" {
  description = "Domains the application may reach (Network Firewall TLS SNI / HTTP Host allowlist)."
  type        = list(string)
  default = [
    "services.nvd.nist.gov", "www.cisa.gov", "api.first.org", "epss.empiricalsecurity.com",
    ".bleepingcomputer.com", "feeds.feedburner.com", ".securityweek.com", ".darkreading.com", "therecord.media",
    "krebsonsecurity.com", "isc.sans.edu", "unit42.paloaltonetworks.com", "blog.talosintelligence.com",
    ".microsoft.com", ".crowdstrike.com",
    ".qualys.com", ".app.wiz.io", "auth.app.wiz.io", ".cloud.tanium.com", ".service-now.com",
    ".zafran.io", ".armorcode.com",
    ".okta.com", "hooks.slack.com", ".webhook.office.com", ".logic.azure.com",
    "login.microsoftonline.com", # Entra ID tokens: Microsoft 365 SMTP OAuth2, Defender
  ]
}

variable "ses_identity_arns" {
  description = <<-EOT
    Verified Amazon SES identities (domain or address ARNs) the app may send as. Non-empty grants the API and
    scheduler task roles ses:SendEmail / ses:SendRawEmail on them (Settings → SMTP → Amazon SES API) and
    allows the SES API endpoint through the Network Firewall.
  EOT
  type        = list(string)
  default     = []
}

variable "smtp_egress_cidrs" {
  description = <<-EOT
    Destination CIDRs allowed on TCP 587 through the Network Firewall (SMTP relay / Microsoft 365). STARTTLS
    carries no TLS SNI when the connection opens, so the domain allowlist cannot match it: list your relay or
    Exchange Online's published SMTP ranges. Empty = SMTP egress blocked (use the SES API instead).
  EOT
  type        = list(string)
  default     = []
}

variable "alarm_email" {
  description = "Optional email subscribed to the alarm SNS topic."
  type        = string
  default     = ""
}

variable "enable_bedrock" {
  description = "Grant the API task role bedrock:InvokeModel / Converse (AI features via Amazon Bedrock)."
  type        = bool
  default     = false
}

variable "enable_security_services" {
  description = "Enable GuardDuty and Security Hub in this account/region (skip if managed centrally)."
  type        = bool
  default     = true
}

variable "db_app_username" {
  description = "PostgreSQL role the API and scheduler use (DML only, created by the migration task)."
  type        = string
  default     = "excat_app"
  validation {
    condition     = can(regex("^[a-z_][a-z0-9_]{0,62}$", var.db_app_username)) && var.db_app_username != "excat_admin"
    error_message = "Lower-case PostgreSQL identifier, different from the master user."
  }
}
