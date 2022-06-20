#cloudwatch

#make this a "for each" in a list of variables
#################
resource "aws_cloudwatch_log_stream" "service-log-stream" {
  name           = "${var.log_item}_log_stream"
  log_group_name = aws_cloudwatch_log_group.central.name
}

data "aws_iam_policy_document" "service-logging-policy" {
  statement {
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]

    resources = [aws_cloudwatch_log_group.central.arn]

    principals {
      identifiers = ["${var.service}.amazonaws.com"]
      type        = "Service"
    }
  }
}

resource "aws_cloudwatch_log_group" "central" {
  name = "Central"

  tags = {
    Name = aws_cloudwatch_log_group.central.name
    # var.tags
  }
}

#cloudwatch log destination
resource "aws_cloudwatch_log_destination" "central_log_destination" {
  name       = "central_log_destination"
  role_arn   = aws_iam_role.cloudwatch_log_destination_role.arn
  target_arn = aws_kinesis_stream.Kinesis_stream.arn
  depends_on = [
    aws_iam_role.cloudwatch_log_destination_role,
    aws_kinesis_stream.Kinesis_stream
  ]
}

#kinesis
resource "aws_kinesis_stream" "Kinesis_stream" {
  name             = "Kinesis_stream"
  shard_count      = 1
  retention_period = 48

  shard_level_metrics = [
    "IncomingBytes",
    "OutgoingBytes",
  ]

  stream_mode_details {
    stream_mode = "PROVISIONED"
  }
}

resource "aws_kinesis_firehose_delivery_stream" "extended_s3_stream" {
  name        = "terraform-kinesis-firehose-extended-s3-test-stream"
  destination = "extended_s3"

  extended_s3_configuration {
    role_arn   = aws_iam_role.firehose_role.arn
    bucket_arn = aws_s3_bucket.logging.arn

    processing_configuration {
      enabled = "true"

      processors {
        type = "Lambda"

        parameters {
          parameter_name  = "LambdaArn"
          parameter_value = "${aws_lambda_function.lambda_processor.arn}:$LATEST"
        }
      }
    }
  }
}

#opensearch
data "aws_region" "current" {}

data "aws_caller_identity" "current" {}

resource "aws_security_group" "opensearch" {
  name        = "${var.vpc}-opensearch-${var.domain}"
  description = "Managed by Terraform"
  vpc_id      = var.logging_vpc_id

  ingress {
    from_port = 443
    to_port   = 443
    protocol  = "tcp"

    cidr_blocks = [
      var.logging_cidr_blocks
    ]
  }
}

resource "aws_iam_service_linked_role" "opensearch_linked_role" {
  aws_service_name = "opensearchservice.amazonaws.com"
}

resource "aws_opensearch_domain" "example" {
  domain_name    = var.domain
  engine_version = "OpenSearch_1.0"

  cluster_config {
    instance_type          = "m4.large.search"
    zone_awareness_enabled = true
  }

  vpc_options {
    subnet_ids = [
      data.aws_subnet_ids.example.ids[0],
      data.aws_subnet_ids.example.ids[1],
    ]

    security_group_ids = [aws_security_group.example.id]
  }

  advanced_options = {
    "rest.action.multi.allow_explicit_index" = "true"
  }

  access_policies = <<CONFIG
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": "es:*",
            "Principal": "*",
            "Effect": "Allow",
            "Resource": "arn:aws:es:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:domain/${var.domain}/*"
        }
    ]
}
CONFIG

  tags = {
    Domain = "TestDomain"
  }

  depends_on = [aws_iam_service_linked_role.example]
}

#s3 bucket
resource "aws_s3_bucket" "logging" {
  bucket = "logging-bucket"
}

resource "aws_s3_bucket_acl" "logging_bucket_acl" {
  bucket = aws_s3_bucket.logging.id
  acl    = "private"
}

resource "aws_s3_bucket_policy" "logging_bucket_policy" {
  bucket = aws_s3_bucket.logging.id
  policy = <<EOF
{
  "Id": "logging_bucket_policy",
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "bucket_policy_${var.ui_bucket_name}_root",
      "Action": ["s3:ListBucket"],
      "Effect": "Allow",
      "Resource": [
        "${aws_s3_bucket.logging.arn}",
        "${aws_s3_bucket.logging.arn}/*"
      ]
      "Principal": {"AWS":"${aws_iam_role.firehose_role.arn}"}
    }
  ]
}
EOF
}

#iam roles
resource "aws_iam_role" "firehose_role" {
  name = "firehose_role"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "firehose.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
}

resource "aws_iam_role" "lambda_iam" {
  name = "lambda_iam"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
}

resource "aws_iam_role" "cloudwatch_log_destination_role" {
  name = "cloudwatch_log_destination_role"
  managed_policy_arns = [aws_iam_policy.cloudwatch_log_destination_policy.arn]
  assume_role_policy = <<EOF
  {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Action": "sts:AssumeRole",
        "Effect": "Allow",
        "Sid": "",
        "Principal": {
          "Service": "logs.amazonaws.com"
        }
      }
    ]
  }
EOF
}

  resource "aws_iam_policy" "cloudwatch_log_destination_policy" {
  name        = "cloudwatch_log_destination_policy"
  policy = <<EOF
  {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Action": ["logs:*", "kinesis:*"],
        "Effect": "Allow",
        "Resource": "*"
      }
    ]
  }
EOF
}

#lambda
resource "aws_lambda_function" "lambda_processor" {
  filename      = "lambda.zip"
  function_name = "firehose_lambda_processor"
  role          = aws_iam_role.lambda_iam.arn
  handler       = "exports.handler"
  runtime       = "nodejs12.x"
}
