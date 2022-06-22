

# Display VPC deets
output "vpc" {
  value = data.aws_vpc.vpc_data
}

# Display subnet data
output "subnet" {
  value = data.aws_subnets.subnet_data
}

