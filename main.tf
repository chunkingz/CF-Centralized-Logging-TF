
# based on the architecture seen here: https://docs.aws.amazon.com/solutions/latest/centralized-logging/overview.html

# 1a
# [CloudTrail ✅, EC2, VPC Flow Logs]

# 1b
# Cloud watch Logs ✅

# 2
# [Kinesis Data streams, Lambda, Kinesis Data Firehose] ✅

# 3
# Amazon OpenSearch Service ✅


terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "4.18.0"
    }
  }
}

provider "aws" {
  region     = var.region
  access_key = var.access_key
  secret_key = var.secret_key
}

# make module call here
module "deploy-centralized-logging" {
  source = "./modules/"
}

