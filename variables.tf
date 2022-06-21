
variable "region" {
  default = "us-east-1"
  type = string
  description = "AWS Region"
}

variable "access_key" {
  default = ""
  type = string
  description = "AWS Access Key ID"
}

variable "secret_key" {
  default = ""
  type = string
  description = "AWS Secret Access Key"
}

