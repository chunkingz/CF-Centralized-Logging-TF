variable "logging_vpc_id" {
  default = ""
  type = string
  description = "vpc ID where opensearch will be accessible"
}

variable "logging_cidr_blocks" {
  default = []
}

variable "domain" {
  default = ""
  type = string
  description = "name of the opensearch domain"
}
