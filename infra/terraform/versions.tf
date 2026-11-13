terraform {
  required_version = ">= 1.6"
  required_providers {
    aws    = { source = "hashicorp/aws", version = "~> 5.80" }
    random = { source = "hashicorp/random", version = "~> 3.6" }
  }
  # Use an encrypted remote backend: state contains generated secrets (Fernet key, Redis auth token).
  # backend "s3" { bucket = "…-tfstate" key = "exposurecatalyst/terraform.tfstate" region = "us-east-1"
  #                encrypt = true kms_key_id = "alias/…" use_lockfile = true }
}

provider "aws" {
  region = var.region
  default_tags { tags = local.tags }
}

# CloudFront certificates and CLOUDFRONT-scope WAF must live in us-east-1.
provider "aws" {
  alias  = "us_east_1"
  region = "us-east-1"
  default_tags { tags = local.tags }
}
