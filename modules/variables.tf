

variable "logging_vpc_id" {
  default = ""
  type = string
  description = "vpc ID where opensearch will be accessible"
}

variable "logging_cidr_blocks" {
  default = []
}

variable "domain" {
  default = "aws_opensearch_domain"
  type = string
  description = "name of the opensearch domain"
}

variable "log_item" {
  default = "aws_cloudwatch"
  type = string
  description = ""
}

variable "service" {
  default = "firehose"
  type = string
  description = ""
}

variable "vpc" {
  default = "aws_vpc"
  type = string
  description = ""
}

variable "opensearch_url" {
  default = "opensearchservice.amazonaws.com"
  type = string
  description = ""
}

variable "ui_bucket_name" {
  default = "log_bucket"
  type = string
  description = ""
}

