
data "aws_caller_identity" "current" {
}


data "aws_partition" "current" {
}


data "aws_region" "current" {
}


locals  {
  CLMap = {
    Metric = {
      SendAnonymousMetric = "Yes"
      MetricsEndpoint = "https://metrics.awssolutionsbuilder.com/generic"
    }
  }
  ESMap = {
    NodeCount = {
      Small = "4"
      Medium = "6"
      Large = "6"
    }
    MasterSize = {
      Small = "c5.large.elasticsearch"
      Medium = "c5.large.elasticsearch"
      Large = "c5.large.elasticsearch"
    }
    InstanceSize = {
      Small = "r5.large.elasticsearch"
      Medium = "r5.2xlarge.elasticsearch"
      Large = "r5.4xlarge.elasticsearch"
    }
  }
  demoDeploymentCheck = var.demo_template == "Yes"
  JumpboxDeploymentCheck = var.jumpbox_deploy == "Yes"
  # CDKMetadataAvailable = anytrue(['anytrue([\'data.aws_region.current.name == "af-south-1"\', \'data.aws_region.current.name == "ap-east-1"\', \'data.aws_region.current.name == "ap-northeast-1"\', \'data.aws_region.current.name == "ap-northeast-2"\', \'data.aws_region.current.name == "ap-south-1"\', \'data.aws_region.current.name == "ap-southeast-1"\', \'data.aws_region.current.name == "ap-southeast-2"\', \'data.aws_region.current.name == "ca-central-1"\', \'data.aws_region.current.name == "cn-north-1"\', \'data.aws_region.current.name == "cn-northwest-1"\'])', 'anytrue([\'data.aws_region.current.name == "eu-central-1"\', \'data.aws_region.current.name == "eu-north-1"\', \'data.aws_region.current.name == "eu-south-1"\', \'data.aws_region.current.name == "eu-west-1"\', \'data.aws_region.current.name == "eu-west-2"\', \'data.aws_region.current.name == "eu-west-3"\', \'data.aws_region.current.name == "me-south-1"\', \'data.aws_region.current.name == "sa-east-1"\', \'data.aws_region.current.name == "us-east-1"\', \'data.aws_region.current.name == "us-east-2"\'])', 'anytrue([\'data.aws_region.current.name == "us-west-1"\', \'data.aws_region.current.name == "us-west-2"\'])'])
  CDKMetadataAvailable = anytrue([anytrue([data.aws_region.current.name == "af-south-1", data.aws_region.current.name == "ap-east-1", data.aws_region.current.name == "ap-northeast-1", data.aws_region.current.name == "ap-northeast-2", data.aws_region.current.name == "ap-south-1", data.aws_region.current.name == "ap-southeast-1", data.aws_region.current.name == "ap-southeast-2", data.aws_region.current.name == "ca-central-1", data.aws_region.current.name == "cn-north-1", data.aws_region.current.name == "cn-northwest-1"]), anytrue([data.aws_region.current.name == "eu-central-1", data.aws_region.current.name == "eu-north-1", data.aws_region.current.name == "eu-south-1", data.aws_region.current.name == "eu-west-1", data.aws_region.current.name == "eu-west-2", data.aws_region.current.name == "eu-west-3", data.aws_region.current.name == "me-south-1", data.aws_region.current.name == "sa-east-1", data.aws_region.current.name == "us-east-1", data.aws_region.current.name == "us-east-2"]), anytrue([data.aws_region.current.name == "us-west-1", data.aws_region.current.name == "us-west-2"])])
}


variable "domain_name" {
  type = string
  default = "centralizedlogging"
}


variable "admin_email" {
  type = string
}


variable "cluster_size" {
  description = "Elasticsearch cluster size; small (4 data nodes), medium (6 data nodes), large (6 data nodes)"
  type = string
  default = "Small"
}


variable "demo_template" {
  description = "Deploy demo template for sample data and logs?"
  type = string
  default = "No"
}


variable "spoke_accounts" {
  description = "Account IDs which you want to allow for centralized logging (comma separated list eg. 11111111,22222222)"
  type = string
}


variable "spoke_regions" {
  description = "Regions which you want to allow for centralized logging (comma separated list eg. us-east-1,us-west-2)"
  type = string
  default = "All"
}


variable "jumpbox_deploy" {
  description = "Do you want to deploy jumbox?"
  type = string
  default = "No"
}


variable "jumpbox_key" {
  description = "Key pair name for jumpbox (You may leave this empty if you chose 'No' above)"
  type = string
}


variable "windows_ami" {
  type = string
  default = "/aws/service/ami-windows-latest/Windows_Server-2019-English-Full-Base"
}


resource "aws_iam_role" "helper_role_d1833_f54" {
  assume_role_policy = {
    Statement = [{
      "Action": "sts:AssumeRole", Effect: "Allow", 
      "Principal": {"Service": "lambda.amazonaws.com"}
      }]
    Version = "2012-10-17"
  }
}


resource "aws_iam_policy" "helper_role_policy175990_bad" {
  policy = {
    Statement = [{"Action": ['"logs:CreateLogStream"', '"logs:PutLogEvents"', '"logs:CreateLogGroup"'], 'Effect': '"Allow"', 'Resource': ['join("", ["arn:", data.aws_region.current.name, ":logs:", data.aws_region.current.name, ":", data.aws_region.current.name, ":log-group:*"])', 'join("", ["arn:", data.aws_region.current.name, ":logs:", data.aws_region.current.name, ":", data.aws_region.current.name, ":log-group:*:log-stream:*"])']}, {"Action": ['"ec2:DescribeRegions"', '"logs:PutDestination"', '"logs:DeleteDestination"', '"logs:PutDestinationPolicy"'], 'Effect': '"Allow"', 'Resource': '"*"'}, {"Action": '"iam:CreateServiceLinkedRole"', 'Condition': {'StringLike': {'iam:AWSServiceName': '"es.amazonaws.com"'}}, 'Effect': '"Allow"', 'Resource': 'join("", ["arn:", data.aws_region.current.name, ":iam::*:role/aws-service-role/es.amazonaws.com/AWSServiceRoleForAmazonElasticsearchService*"])'}]
    Version = "2012-10-17"
  }
  name = "HelperRolePolicy175990BAD"
  // CF Property(Roles) = ['aws_iam_role.helper_role_d1833_f54.arn']
}


resource "aws_lambda_function" "helper_lambda_ac9474_f4" {
  code_signing_config_arn = {
    S3Bucket = "solutions-${data.aws_region.current.name}"
    S3Key = "centralized-logging/v4.0.1/asset9b4c683682a0773735625e441eabc438ac1d2b4ef65d28093ba33154aaaa2a66.zip"
  }
  role = aws_iam_role.helper_role_d1833_f54.arn
  description = "centralized-logging -  solution helper functions"


  environment {
    variables = {
    LOG_LEVEL = "info"
    METRICS_ENDPOINT = local.CLMap["Metric"]["MetricsEndpoint"]
    SEND_METRIC = local.CLMap["Metric"]["SendAnonymousMetric"]
    CUSTOM_SDK_USER_AGENT = "AwsSolution/SO0009/v4.0.1"
  }
  }
  handler = "index.handler"
  runtime = "nodejs14.x"
  timeout = "300"
}


resource "aws_iam_role" "helper_providerframeworkon_event_service_role1962_dd43" {
  assume_role_policy = {
    Statement = [{"Action": '"sts:AssumeRole"', 'Effect': '"Allow"', 'Principal': {'Service': '"lambda.amazonaws.com"'}}]
    Version = "2012-10-17"
  }
  managed_policy_arns = ['join("", ["arn:", data.aws_region.current.name, ":iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"])']
}


resource "aws_iam_policy" "helper_providerframeworkon_event_service_role_default_policy7_c54367_b" {
  policy = {
    Statement = [{"Action": '"lambda:InvokeFunction"', 'Effect': '"Allow"', 'Resource': 'aws_lambda_function.helper_lambda_ac9474_f4.arn'}]
    Version = "2012-10-17"
  }
  name = "HelperProviderframeworkonEventServiceRoleDefaultPolicy7C54367B"
  // CF Property(Roles) = ['aws_iam_role.helper_providerframeworkon_event_service_role1962_dd43.arn']
}


resource "aws_lambda_function" "helper_providerframeworkon_event1079_de9_d" {
  code_signing_config_arn = {
    S3Bucket = "solutions-${data.aws_region.current.name}"
    S3Key = "centralized-logging/v4.0.1/assetc691172cdeefa2c91b5a2907f9d81118e47597634943344795f1a844192dd49c.zip"
  }
  role = aws_iam_role.helper_providerframeworkon_event_service_role1962_dd43.arn
  description = "AWS CDK resource provider framework - onEvent (CL-PrimaryStack/HelperProvider)"


  environment {
    variables = {
    USER_ON_EVENT_FUNCTION_ARN = aws_lambda_function.helper_lambda_ac9474_f4.arn
  }
  }
  handler = "assetc691172cdeefa2c91b5a2907f9d81118e47597634943344795f1a844192dd49c/framework.onEvent"
  runtime = "nodejs12.x"
  timeout = "900"
}


resource "aws_shield_protection" "create_uuid" {
  // CF Property(ServiceToken) = aws_lambda_function.helper_providerframeworkon_event1079_de9_d.arn
}


resource "aws_iam_service_linked_role" "create_es_service_role" {
  aws_service_name = aws_lambda_function.helper_providerframeworkon_event1079_de9_d.arn
}


resource "aws_macie2_custom_data_identifier" "launch_data" {
  description = "SO0009"
  // CF Property(SolutionVersion) = "v4.0.1"
  // CF Property(SolutionUuid) = aws_shield_protection.create_uuid.id
  maximum_match_distance = "PrimaryStack"
}


resource "aws_cognito_user_pool" "es_user_pool7_dc126_a8" {


  account_recovery_setting {
    // CF Property(RecoveryMechanisms) = [{'Name': '"verified_email"', 'Priority': '"1"'}]
  }
  admin_create_user_config = {
    AllowAdminCreateUserOnly = "True"
  }
  auto_verified_attributes = ['"email"']
  email_verification_message = "The verification code to your new account is {####}"
  email_verification_subject = "Verify your new account"
  password_policy = {
    PasswordPolicy = {
      MinimumLength = "8"
      RequireLowercase = "True"
      RequireNumbers = "True"
      RequireSymbols = "True"
      RequireUppercase = "True"
      TemporaryPasswordValidityDays = "3"
    }
  }
  schema = [{'mutable': '"True"', 'name': '"email"', 'required': '"True"'}]
  sms_verification_message = "The verification code to your new account is {####}"
  username_attributes = ['"email"']
  user_pool_add_ons = {
    AdvancedSecurityMode = "ENFORCED"
  }
  verification_message_template = {
    DefaultEmailOption = "CONFIRM_WITH_CODE"
    EmailMessage = "The verification code to your new account is {####}"
    EmailSubject = "Verify your new account"
    SmsMessage = "The verification code to your new account is {####}"
  }
}


resource "aws_cognito_user_pool_domain" "es_user_pool_es_cognito_domain4_e1_d658_b" {
  domain = join("", [var.domain_name, "-", aws_shield_protection.create_uuid.id])
  user_pool_id = aws_cognito_user_pool.es_user_pool7_dc126_a8.arn
}


resource "aws_cognito_user_pool" "admin_user" {
  admin_create_user_config = aws_cognito_user_pool.es_user_pool7_dc126_a8.arn
  username_attributes = [{'Name': '"email"', 'Value': 'var.admin_email'}]
  name = var.admin_email
}


resource "aws_cognito_identity_pool" "es_identity_pool" {
  allow_unauthenticated_identities = False
}


resource "aws_iam_role" "cognito_auth_role7_b7_e27_c0" {
  assume_role_policy = {
    Statement = [{"Action": '"sts:AssumeRoleWithWebIdentity"', 'Condition': {'StringEquals': {'cognito-identity.amazonaws.com:aud': 'aws_cognito_identity_pool.es_identity_pool.id'}, 'ForAnyValue:StringLike': {'cognito-identity.amazonaws.com:amr': '"authenticated"'}}, 'Effect': '"Allow"', 'Principal': {'Federated': '"cognito-identity.amazonaws.com"'}}]
    Version = "2012-10-17"
  }
}


resource "aws_cognito_identity_pool_roles_attachment" "identity_pool_role_attachment" {
  identity_pool_id = aws_cognito_identity_pool.es_identity_pool.id
  roles = {
    authenticated = aws_iam_role.cognito_auth_role7_b7_e27_c0.arn
  }
}


resource "aws_iam_role" "es_cognito_role0_fb5690_b" {
  assume_role_policy = {
    Statement = [{"Action": '"sts:AssumeRole"', 'Effect': '"Allow"', 'Principal': {'Service': '"es.amazonaws.com"'}}]
    Version = "2012-10-17"
  }
  force_detach_policies = [{'PolicyDocument': {'Statement': [{"Action": ['"cognito-idp:DescribeUserPool"', '"cognito-idp:CreateUserPoolClient"', '"cognito-idp:DeleteUserPoolClient"', '"cognito-idp:DescribeUserPoolClient"', '"cognito-idp:AdminInitiateAuth"', '"cognito-idp:AdminUserGlobalSignOut"', '"cognito-idp:ListUserPoolClients"', '"cognito-identity:DescribeIdentityPool"', '"cognito-identity:UpdateIdentityPool"', '"cognito-identity:SetIdentityPoolRoles"', '"cognito-identity:GetIdentityPoolRoles"'], 'Effect': '"Allow"', 'Resource': '"*"'}], 'Version': '"2012-10-17"'}, 'PolicyName': '"ESCognitoAccess"'}]
}


resource "aws_iam_policy" "es_cognito_role_default_policy007_a3108" {
  policy = {
    Statement = [{"Action": '"iam:PassRole"', 'Condition': {'StringLike': {'iam:PassedToService': '"cognito-identity.amazonaws.com"'}}, 'Effect': '"Allow"', 'Resource': 'aws_iam_role.es_cognito_role0_fb5690_b.arn'}]
    Version = "2012-10-17"
  }
  name = "ESCognitoRoleDefaultPolicy007A3108"
  // CF Property(Roles) = ['aws_iam_role.es_cognito_role0_fb5690_b.arn']
}


resource "aws_iam_role" "firehose_role_aa67_c190" {
  assume_role_policy = {
    Statement = [{"Action": '"sts:AssumeRole"', 'Effect': '"Allow"', 'Principal': {'Service': '"firehose.amazonaws.com"'}}]
    Version = "2012-10-17"
  }
}


resource "aws_iot_thing_group" "vpc_flow_log_group9559_e1_e7" {
  // CF Property(RetentionInDays) = "731"
}


resource "aws_iam_role" "flow_role5_e4_ef2_f1" {
  assume_role_policy = {
    Statement = [{"Action": '"sts:AssumeRole"', 'Effect': '"Allow"', 'Principal': {'Service': '"vpc-flow-logs.amazonaws.com"'}}]
    Version = "2012-10-17"
  }
}


resource "aws_iam_policy" "flow_role_default_policy_a5122836" {
  policy = {
    Statement = [{"Action": ['"logs:CreateLogStream"', '"logs:PutLogEvents"', '"logs:DescribeLogStreams"'], 'Effect': '"Allow"', 'Resource': 'aws_iot_thing_group.vpc_flow_log_group9559_e1_e7.arn'}, {"Action": '"iam:PassRole"', 'Effect': '"Allow"', 'Resource': 'aws_iam_role.flow_role5_e4_ef2_f1.arn'}]
    Version = "2012-10-17"
  }
  name = "flowRoleDefaultPolicyA5122836"
  // CF Property(Roles) = ['aws_iam_role.flow_role5_e4_ef2_f1.arn']
}


resource "aws_vpc" "esvpc3_cead2_a7" {
  cidr_block = "10.0.0.0/16"
  enable_dns_hostnames = "True"
  enable_dns_support = "True"
  instance_tenancy = "default"
  tags = [{'Key': '"Name"', 'Value': '"CL-PrimaryStack/ESVPC"'}]
}


resource "aws_subnet" "esvpces_isolated_subnet_subnet1_subnet_bc48_a527" {
  cidr_block = "10.0.0.0/24"
  vpc_id = aws_vpc.esvpc3_cead2_a7.arn
  availability_zone = element(data.aws_availability_zones.available.names, 0)
  map_public_ip_on_launch = False
  tags = [{'Key': '"aws-cdk:subnet-name"', 'Value': '"ESIsolatedSubnet"'}, {'Key': '"aws-cdk:subnet-type"', 'Value': '"Isolated"'}, {'Key': '"Name"', 'Value': '"CL-PrimaryStack/ESVPC/ESIsolatedSubnetSubnet1"'}]
}


resource "aws_route_table" "esvpces_isolated_subnet_subnet1_route_table122122_fc" {
  vpc_id = aws_vpc.esvpc3_cead2_a7.arn
  tags = [{'Key': '"Name"', 'Value': '"CL-PrimaryStack/ESVPC/ESIsolatedSubnetSubnet1"'}]
}


resource "aws_route_table_association" "esvpces_isolated_subnet_subnet1_route_table_association9_f413854" {
  route_table_id = aws_route_table.esvpces_isolated_subnet_subnet1_route_table122122_fc.id
  subnet_id = aws_subnet.esvpces_isolated_subnet_subnet1_subnet_bc48_a527.id
}


resource "aws_subnet" "esvpces_isolated_subnet_subnet2_subnet_f8_d4_db34" {
  cidr_block = "10.0.1.0/24"
  vpc_id = aws_vpc.esvpc3_cead2_a7.arn
  availability_zone = element(data.aws_availability_zones.available.names, 1)
  map_public_ip_on_launch = False
  tags = [{'Key': '"aws-cdk:subnet-name"', 'Value': '"ESIsolatedSubnet"'}, {'Key': '"aws-cdk:subnet-type"', 'Value': '"Isolated"'}, {'Key': '"Name"', 'Value': '"CL-PrimaryStack/ESVPC/ESIsolatedSubnetSubnet2"'}]
}


resource "aws_route_table" "esvpces_isolated_subnet_subnet2_route_table4_a8_b83_e0" {
  vpc_id = aws_vpc.esvpc3_cead2_a7.arn
  tags = [{'Key': '"Name"', 'Value': '"CL-PrimaryStack/ESVPC/ESIsolatedSubnetSubnet2"'}]
}


resource "aws_route_table_association" "esvpces_isolated_subnet_subnet2_route_table_association_a11_eb5_c0" {
  route_table_id = aws_route_table.esvpces_isolated_subnet_subnet2_route_table4_a8_b83_e0.id
  subnet_id = aws_subnet.esvpces_isolated_subnet_subnet2_subnet_f8_d4_db34.id
}


resource "aws_subnet" "esvpces_public_subnet_subnet1_subnet12560704" {
  cidr_block = "10.0.2.0/24"
  vpc_id = aws_vpc.esvpc3_cead2_a7.arn
  availability_zone = element(data.aws_availability_zones.available.names, 0)
  map_public_ip_on_launch = "True"
  tags = [{'Key': '"aws-cdk:subnet-name"', 'Value': '"ESPublicSubnet"'}, {'Key': '"aws-cdk:subnet-type"', 'Value': '"Public"'}, {'Key': '"Name"', 'Value': '"CL-PrimaryStack/ESVPC/ESPublicSubnetSubnet1"'}]
}


resource "aws_route_table" "esvpces_public_subnet_subnet1_route_table45432090" {
  vpc_id = aws_vpc.esvpc3_cead2_a7.arn
  tags = [{'Key': '"Name"', 'Value': '"CL-PrimaryStack/ESVPC/ESPublicSubnetSubnet1"'}]
}


resource "aws_route_table_association" "esvpces_public_subnet_subnet1_route_table_association1_e172_c60" {
  route_table_id = aws_route_table.esvpces_public_subnet_subnet1_route_table45432090.id
  subnet_id = aws_subnet.esvpces_public_subnet_subnet1_subnet12560704.id
}


resource "aws_route" "esvpces_public_subnet_subnet1_default_route2_aa9703_d" {
  route_table_id = aws_route_table.esvpces_public_subnet_subnet1_route_table45432090.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id = aws_internet_gateway.esvpcigw68_e8_aea9.id
}


resource "aws_subnet" "esvpces_public_subnet_subnet2_subnet9_c1_fc6_f7" {
  cidr_block = "10.0.3.0/24"
  vpc_id = aws_vpc.esvpc3_cead2_a7.arn
  availability_zone = element(data.aws_availability_zones.available.names, 1)
  map_public_ip_on_launch = "True"
  tags = [{'Key': '"aws-cdk:subnet-name"', 'Value': '"ESPublicSubnet"'}, {'Key': '"aws-cdk:subnet-type"', 'Value': '"Public"'}, {'Key': '"Name"', 'Value': '"CL-PrimaryStack/ESVPC/ESPublicSubnetSubnet2"'}]
}


resource "aws_route_table" "esvpces_public_subnet_subnet2_route_table_ec1_d6_b54" {
  vpc_id = aws_vpc.esvpc3_cead2_a7.arn
  tags = [{'Key': '"Name"', 'Value': '"CL-PrimaryStack/ESVPC/ESPublicSubnetSubnet2"'}]
}


resource "aws_route_table_association" "esvpces_public_subnet_subnet2_route_table_association63160086" {
  route_table_id = aws_route_table.esvpces_public_subnet_subnet2_route_table_ec1_d6_b54.id
  subnet_id = aws_subnet.esvpces_public_subnet_subnet2_subnet9_c1_fc6_f7.id
}


resource "aws_route" "esvpces_public_subnet_subnet2_default_route93518_dd8" {
  route_table_id = aws_route_table.esvpces_public_subnet_subnet2_route_table_ec1_d6_b54.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id = aws_internet_gateway.esvpcigw68_e8_aea9.id
}


resource "aws_internet_gateway" "esvpcigw68_e8_aea9" {
  tags = [{'Key': '"Name"', 'Value': '"CL-PrimaryStack/ESVPC"'}]
}


resource "aws_vpn_gateway_attachment" "esvpcvpcgw707_ec835" {
  vpc_id = aws_internet_gateway.esvpcigw68_e8_aea9.id
}


resource "aws_flow_log" "esvpces_vpc_flow_flow_log10_a9_b76_f" {
  eni_id = aws_vpc.esvpc3_cead2_a7.arn
  log_destination_type = "cloud-watch-logs"
  traffic_type = "ALL"
  iam_role_arn = aws_iam_role.flow_role5_e4_ef2_f1.arn
  log_group_name = aws_iot_thing_group.vpc_flow_log_group9559_e1_e7.arn
  tags = [{'Key': '"Name"', 'Value': '"CL-PrimaryStack/ESVPC"'}]
}


resource "aws_security_group" "essge420_b5_a1" {
  description = "CL-PrimaryStack/ESSG"
  egress = [{'cidr_blocks': 'aws_vpc.esvpc3_cead2_a7.cidr_block', 'description': '"allow outbound https"', 'from_port': '"443"', 'protocol': '"tcp"', 'to_port': '"443"'}]
  ingress = [{'cidr_blocks': 'aws_vpc.esvpc3_cead2_a7.cidr_block', 'description': '"allow inbound https traffic"', 'from_port': '"443"', 'protocol': '"tcp"', 'to_port': '"443"'}]
  vpc_id = aws_vpc.esvpc3_cead2_a7.arn
}


resource "aws_elasticsearch_domain" "es_domain_b45006_da" {
  access_policies = {
    Version = "2012-10-17"
    Statement = [{'Effect': '"Allow"', "Action": ['"es:ESHttpGet"', '"es:ESHttpDelete"', '"es:ESHttpPut"', '"es:ESHttpPost"', '"es:ESHttpHead"', '"es:ESHttpPatch"'], 'Principal': {'AWS': 'aws_iam_role.cognito_auth_role7_b7_e27_c0.arn'}, 'Resource': 'join("", ["arn:", data.aws_region.current.name, ":es:", data.aws_region.current.name, ":", data.aws_region.current.name, ":domain/", var.domain_name, "/*"])'}, {'Effect': '"Allow"', "Action": ['"es:DescribeElasticsearchDomain"', '"es:DescribeElasticsearchDomains"', '"es:DescribeElasticsearchDomainConfig"', '"es:ESHttpPost"', '"es:ESHttpPut"', '"es:HttpGet"'], 'Principal': {'AWS': 'aws_iam_role.firehose_role_aa67_c190.arn'}, 'Resource': 'join("", ["arn:", data.aws_region.current.name, ":es:", data.aws_region.current.name, ":", data.aws_region.current.name, ":domain/", var.domain_name, "/*"])'}]
  }
  cognito_options = {
    Enabled = "True"
    IdentityPoolId = aws_cognito_identity_pool.es_identity_pool.id
    RoleArn = aws_iam_role.es_cognito_role0_fb5690_b.arn
    UserPoolId = aws_cognito_user_pool.es_user_pool7_dc126_a8.arn
  }
  domain_endpoint_options = {
    EnforceHTTPS = "True"
    TLSSecurityPolicy = "Policy-Min-TLS-1-0-2019-07"
  }
  domain_name = var.domain_name
  ebs_options = {
    EBSEnabled = "True"
    VolumeSize = "10"
    VolumeType = "gp2"
  }
  cluster_config = {
    DedicatedMasterCount = "3"
    DedicatedMasterEnabled = "True"
    DedicatedMasterType = local.ESMap["MasterSize"]["var.cluster_size"]
    InstanceCount = local.ESMap["NodeCount"]["var.cluster_size"]
    InstanceType = local.ESMap["InstanceSize"]["var.cluster_size"]
    ZoneAwarenessConfig = {
      AvailabilityZoneCount = "2"
    }
    ZoneAwarenessEnabled = "True"
  }
  elasticsearch_version = "7.7"
  advanced_options = {
    Enabled = "True"
  }
  log_publishing_options = {
  }
  node_to_node_encryption = {
    Enabled = "True"
  }
  vpc_options = {
    SecurityGroupIds = ['aws_security_group.essge420_b5_a1.id']
    SubnetIds = ['aws_subnet.esvpces_isolated_subnet_subnet1_subnet_bc48_a527.id', 'aws_subnet.esvpces_isolated_subnet_subnet2_subnet_f8_d4_db34.id']
  }
}


resource "aws_iam_policy" "auth_role_policy_ab4_a1_e56" {
  policy = {
    Statement = [{"Action": ['"es:ESHttpGet"', '"es:ESHttpDelete"', '"es:ESHttpPut"', '"es:ESHttpPost"', '"es:ESHttpHead"', '"es:ESHttpPatch"'], 'Effect': '"Allow"', 'Resource': 'aws_elasticsearch_domain.es_domain_b45006_da.arn'}]
    Version = "2012-10-17"
  }
  name = "authRolePolicyAB4A1E56"
  // CF Property(Roles) = ['aws_iam_role.cognito_auth_role7_b7_e27_c0.arn']
}


resource "aws_sqs_queue" "dlq09_c78_acc" {
  kms_master_key_id = "alias/aws/sqs"
}


resource "aws_iam_role" "cl_transformer_service_role016_cad3_c" {
  assume_role_policy = {
    Statement = [{"Action": '"sts:AssumeRole"', 'Effect': '"Allow"', 'Principal': {'Service': '"lambda.amazonaws.com"'}}]
    Version = "2012-10-17"
  }
  managed_policy_arns = ['join("", ["arn:", data.aws_region.current.name, ":iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"])']
}


resource "aws_iam_policy" "cl_transformer_service_role_default_policy_c34581_d1" {
  policy = {
    Statement = [{"Action": '"sqs:SendMessage"', 'Effect': '"Allow"', 'Resource': 'aws_sqs_queue.dlq09_c78_acc.arn'}, {"Action": ['"kinesis:DescribeStreamSummary"', '"kinesis:GetRecords"', '"kinesis:GetShardIterator"', '"kinesis:ListShards"', '"kinesis:SubscribeToShard"'], 'Effect': '"Allow"', 'Resource': 'aws_kinesis_stream.cl_data_stream4_dfb5423.arn'}, {"Action": '"kinesis:DescribeStream"', 'Effect': '"Allow"', 'Resource': 'aws_kinesis_stream.cl_data_stream4_dfb5423.arn'}, {"Action": '"firehose:PutRecordBatch"', 'Effect': '"Allow"', 'Resource': 'aws_kinesis_firehose_delivery_stream.cl_firehose.arn'}]
    Version = "2012-10-17"
  }
  name = "CLTransformerServiceRoleDefaultPolicyC34581D1"
  // CF Property(Roles) = ['aws_iam_role.cl_transformer_service_role016_cad3_c.arn']
}


resource "aws_lambda_function" "cl_transformer433_f8853" {
  code_signing_config_arn = {
    S3Bucket = "solutions-${data.aws_region.current.name}"
    S3Key = "centralized-logging/v4.0.1/assetb9316d9a0f47aa8516cdc62510095e3fcad7da2127a60add35eef432d3e28c30.zip"
  }
  role = aws_iam_role.cl_transformer_service_role016_cad3_c.arn
  dead_letter_config = {
    TargetArn = aws_sqs_queue.dlq09_c78_acc.arn
  }
  description = "centralized-logging - Lambda function to transform log events and send to kinesis firehose"


  environment {
    variables = {
    LOG_LEVEL = "info"
    SOLUTION_ID = "SO0009"
    SOLUTION_VERSION = "v4.0.1"
    UUID = aws_shield_protection.create_uuid.id
    CLUSTER_SIZE = var.cluster_size
    DELIVERY_STREAM = "CL-Firehose"
    METRICS_ENDPOINT = local.CLMap["Metric"]["MetricsEndpoint"]
    SEND_METRIC = local.CLMap["Metric"]["SendAnonymousMetric"]
    CUSTOM_SDK_USER_AGENT = "AwsSolution/SO0009/v4.0.1"
  }
  }
  handler = "index.handler"
  runtime = "nodejs14.x"
  timeout = "300"
}


resource "aws_lambda_event_source_mapping" "cl_transformer_kinesis_event_source_cl_primary_stack_cl_data_stream_fc34105_c3_b10_d828" {
  function_name = aws_lambda_function.cl_transformer433_f8853.arn
  batch_size = "100"
  event_source_arn = aws_kinesis_stream.cl_data_stream4_dfb5423.arn
  starting_position = "TRIM_HORIZON"
}


resource "aws_sns_topic" "topic_bfc7_af6_e" {
  display_name = "CL-Lambda-Error"
  kms_master_key_id = join("", ["arn:", data.aws_region.current.name, ":kms:", data.aws_region.current.name, ":", data.aws_region.current.name, ":alias/aws/sns"])
}


resource "aws_sns_topic_subscription" "topic_token_subscription178_f3_f75_e" {
  protocol = "email"
  topic_arn = aws_sns_topic.topic_bfc7_af6_e.id
  endpoint = var.admin_email
}


resource "aws_cloudwatch_metric_alarm" "cl_lambda_error_alarm289_f6_b50" {
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods = "1"
  alarm_actions = ['aws_sns_topic.topic_bfc7_af6_e.id']
  dimensions = [{'Name': '"FunctionName"', 'Value': 'aws_lambda_function.cl_transformer433_f8853.arn'}]
  metric_name = "Errors"
  namespace = "AWS/Lambda"
  period = "300"
  statistic = "Sum"
  threshold = "0.05"
}


resource "aws_kinesis_stream" "cl_data_stream4_dfb5423" {
  shard_count = "1"
  retention_period = "24"
  encryption_type = {
    EncryptionType = "KMS"
    KeyId = "alias/aws/kinesis"
  }
}


resource "aws_s3_bucket" "access_logs_bucket83982689" {
  acl = "LogDeliveryWrite"
  bucket = {
    ServerSideEncryptionConfiguration = [{'ServerSideEncryptionByDefault': {'SSEAlgorithm': '"AES256"'}}]
  }


  grant {
    // CF Property(BlockPublicAcls) = "True"
    // CF Property(BlockPublicPolicy) = "True"
    // CF Property(IgnorePublicAcls) = "True"
    uri = "True"
  }
}


resource "aws_s3_bucket" "cl_bucket116_f9_f6_b" {
  bucket = {
    ServerSideEncryptionConfiguration = [{'ServerSideEncryptionByDefault': {'SSEAlgorithm': '"AES256"'}}]
  }


  logging {
    target_bucket = aws_s3_bucket.access_logs_bucket83982689.id
    target_prefix = "cl-access-logs"
  }


  grant {
    // CF Property(BlockPublicAcls) = "True"
    // CF Property(BlockPublicPolicy) = "True"
    // CF Property(IgnorePublicAcls) = "True"
    uri = "True"
  }
}


resource "aws_s3_bucket_policy" "cl_bucket_policy_f1_df7_d4_f" {
  bucket = aws_s3_bucket.cl_bucket116_f9_f6_b.id
  policy = {
    Statement = [{"Action": ['"s3:Put*"', '"s3:Get*"'], 'Effect': '"Allow"', 'Principal': {'AWS': 'aws_iam_role.firehose_role_aa67_c190.arn'}, 'Resource': ['aws_s3_bucket.cl_bucket116_f9_f6_b.arn', 'join("", [aws_s3_bucket.cl_bucket116_f9_f6_b.arn, "/*"])']}]
    Version = "2012-10-17"
  }
}


resource "aws_iot_thing_group" "firehose_log_group1_b45149_b" {
  name = "/aws/kinesisfirehose/CL-Firehose"
  // CF Property(RetentionInDays) = "731"
}


resource "aws_cloudwatch_log_stream" "firehose_es_log_stream_c35_dd04_e" {
  log_group_name = aws_iot_thing_group.firehose_log_group1_b45149_b.arn
  name = "ElasticsearchDelivery"
}


resource "aws_cloudwatch_log_stream" "firehose_s3_log_stream_b4_dcf7_b1" {
  log_group_name = aws_iot_thing_group.firehose_log_group1_b45149_b.arn
  name = "S3Delivery"
}


resource "aws_iam_policy" "firehose_policy3_a3_b2_df8" {
  policy = {
    Statement = [{"Action": ['"s3:AbortMultipartUpload"', '"s3:GetBucketLocation"', '"s3:GetObject"', '"s3:ListBucket"', '"s3:ListBucketMultipartUploads"', '"s3:PutObject"'], 'Effect': '"Allow"', 'Resource': ['join("", ["arn:", data.aws_region.current.name, ":s3:::", aws_s3_bucket.cl_bucket116_f9_f6_b.id])', 'join("", ["arn:", data.aws_region.current.name, ":s3:::", aws_s3_bucket.cl_bucket116_f9_f6_b.id, "/*"])']}, {"Action": ['"kms:GenerateDataKey"', '"kms:Decrypt"'], 'Condition': {'StringEquals': {'kms:ViaService': 'join("", ["s3.", data.aws_region.current.name, ".amazonaws.com"])'}, 'StringLike': {'kms:EncryptionContext:aws:s3:arn': ['join("", ["arn:", data.aws_region.current.name, ":s3:::", aws_s3_bucket.cl_bucket116_f9_f6_b.id, "/*"])']}}, 'Effect': '"Allow"', 'Resource': 'join("", ["arn:", data.aws_region.current.name, ":kms:", data.aws_region.current.name, ":", data.aws_region.current.name, ":key/*"])'}, {"Action": ['"ec2:DescribeVpcs"', '"ec2:DescribeVpcAttribute"', '"ec2:DescribeSubnets"', '"ec2:DescribeSecurityGroups"', '"ec2:DescribeNetworkInterfaces"', '"ec2:CreateNetworkInterface"', '"ec2:CreateNetworkInterfacePermission"', '"ec2:DeleteNetworkInterface"'], 'Effect': '"Allow"', 'Resource': '"*"'}, {"Action": ['"es:DescribeElasticsearchDomain"', '"es:DescribeElasticsearchDomains"', '"es:DescribeElasticsearchDomainConfig"', '"es:ESHttpPost"', '"es:ESHttpPut"'], 'Effect': '"Allow"', 'Resource': ['join("", ["arn:", data.aws_region.current.name, ":es:", data.aws_region.current.name, ":", data.aws_region.current.name, ":domain/", aws_elasticsearch_domain.es_domain_b45006_da.arn])', 'join("", ["arn:", data.aws_region.current.name, ":es:", data.aws_region.current.name, ":", data.aws_region.current.name, ":domain/", aws_elasticsearch_domain.es_domain_b45006_da.arn, "/*"])']}, {"Action": '"es:ESHttpGet"', 'Effect': '"Allow"', 'Resource': ['join("", ["arn:", data.aws_region.current.name, ":es:", data.aws_region.current.name, ":", data.aws_region.current.name, ":domain/", aws_elasticsearch_domain.es_domain_b45006_da.arn, "/_all/_settings"])', 'join("", ["arn:", data.aws_region.current.name, ":es:", data.aws_region.current.name, ":", data.aws_region.current.name, ":domain/", aws_elasticsearch_domain.es_domain_b45006_da.arn, "/_cluster/stats"])', 'join("", ["arn:", data.aws_region.current.name, ":es:", data.aws_region.current.name, ":", data.aws_region.current.name, ":domain/", aws_elasticsearch_domain.es_domain_b45006_da.arn, "/cwl-kinesis/_mapping/kinesis"])', 'join("", ["arn:", data.aws_region.current.name, ":es:", data.aws_region.current.name, ":", data.aws_region.current.name, ":domain/", aws_elasticsearch_domain.es_domain_b45006_da.arn, "/_nodes"])', 'join("", ["arn:", data.aws_region.current.name, ":es:", data.aws_region.current.name, ":", data.aws_region.current.name, ":domain/", aws_elasticsearch_domain.es_domain_b45006_da.arn, "/_nodes/*/stats"])', 'join("", ["arn:", data.aws_region.current.name, ":es:", data.aws_region.current.name, ":", data.aws_region.current.name, ":domain/", aws_elasticsearch_domain.es_domain_b45006_da.arn, "/_stats"])', 'join("", ["arn:", data.aws_region.current.name, ":es:", data.aws_region.current.name, ":", data.aws_region.current.name, ":domain/", aws_elasticsearch_domain.es_domain_b45006_da.arn, "/cwl-kinesis/_stats"])']}, {"Action": ['"logs:PutLogEvents"', '"logs:CreateLogStream"'], 'Effect': '"Allow"', 'Resource': 'aws_iot_thing_group.firehose_log_group1_b45149_b.arn'}, {"Action": '"kms:Decrypt"', 'Condition': {'StringEquals': {'kms:ViaService': 'join("", ["kinesis.", data.aws_region.current.name, ".amazonaws.com"])'}, 'StringLike': {'kms:EncryptionContext:aws:kinesis:arn': 'aws_kinesis_stream.cl_data_stream4_dfb5423.arn'}}, 'Effect': '"Allow"', 'Resource': 'join("", ["arn:", data.aws_region.current.name, ":kms:", data.aws_region.current.name, ":", data.aws_region.current.name, ":key/*"])'}]
    Version = "2012-10-17"
  }
  name = "CL-Firehose-Policy"
  // CF Property(Roles) = ['aws_iam_role.firehose_role_aa67_c190.arn']
}


resource "aws_kinesis_firehose_delivery_stream" "cl_firehose" {
  kinesis_source_configuration = {
    KeyType = "AWS_OWNED_CMK"
  }
  name = "CL-Firehose"
  type = "DirectPut"
  elasticsearch_configuration = {
    CloudWatchLoggingOptions = {
      Enabled = "True"
      LogGroupName = "/aws/kinesisfirehose/CL-Firehose"
      LogStreamName = aws_cloudwatch_log_stream.firehose_es_log_stream_c35_dd04_e.arn
    }
    DomainARN = aws_elasticsearch_domain.es_domain_b45006_da.arn
    IndexName = "cwl"
    IndexRotationPeriod = "OneDay"
    RoleARN = aws_iam_role.firehose_role_aa67_c190.arn
    S3BackupMode = "AllDocuments"
    S3Configuration = {
      BucketARN = aws_s3_bucket.cl_bucket116_f9_f6_b.arn
      CloudWatchLoggingOptions = {
        Enabled = "True"
        LogGroupName = "/aws/kinesisfirehose/CL-Firehose"
        LogStreamName = aws_cloudwatch_log_stream.firehose_s3_log_stream_b4_dcf7_b1.arn
      }
      RoleARN = aws_iam_role.firehose_role_aa67_c190.arn
    }
    VpcConfiguration = {
      RoleARN = aws_iam_role.firehose_role_aa67_c190.arn
      SecurityGroupIds = ['aws_security_group.essge420_b5_a1.id']
      SubnetIds = ['aws_subnet.esvpces_isolated_subnet_subnet1_subnet_bc48_a527.id', 'aws_subnet.esvpces_isolated_subnet_subnet2_subnet_f8_d4_db34.id']
    }
  }
}


resource "aws_iam_role" "cw_destination_role20_a8055_f" {
  assume_role_policy = {
    Statement = [{'Effect': '"Allow"', 'Principal': {'Service': '"logs.amazonaws.com"'}, "Action": '"sts:AssumeRole"'}]
    Version = "2012-10-17"
  }
}


resource "aws_iam_policy" "cw_dest_policy3_dd10_f82" {
  policy = {
    Statement = [{"Action": '"kinesis:PutRecord"', 'Effect': '"Allow"', 'Resource': 'aws_kinesis_stream.cl_data_stream4_dfb5423.arn'}]
    Version = "2012-10-17"
  }
  name = "CWDestPolicy3DD10F82"
  // CF Property(Roles) = ['aws_iam_role.cw_destination_role20_a8055_f.arn']
}


resource "aws_iam_policy" "helper_role_policy285_d208_f4" {
  policy = {
    Statement = [{"Action": '"iam:PassRole"', 'Effect': '"Allow"', 'Resource': 'aws_iam_role.cw_destination_role20_a8055_f.arn'}]
    Version = "2012-10-17"
  }
  name = "HelperRolePolicy285D208F4"
  // CF Property(Roles) = ['aws_iam_role.helper_role_d1833_f54.arn']
}


resource "aws_cloudwatch_log_destination" "cw_destination" {
  // CF Property(ServiceToken) = aws_lambda_function.helper_providerframeworkon_event1079_de9_d.arn
  // CF Property(Regions) = var.spoke_regions
  name = join("", ["CL-Destination-", aws_shield_protection.create_uuid.id])
  role_arn = aws_iam_role.cw_destination_role20_a8055_f.arn
  // CF Property(DataStream) = aws_kinesis_stream.cl_data_stream4_dfb5423.arn
  // CF Property(SpokeAccounts) = var.spoke_accounts
}


resource "aws_security_group" "cl_jumpbox_jumpbox_sgd93_e94_fc" {
  description = "CL-PrimaryStack/CL-Jumpbox/JumpboxSG"
  egress = [{'cidr_blocks': '"0.0.0.0/0"', 'description': '"allow outbound https"', 'from_port': '"80"', 'protocol': '"tcp"', 'to_port': '"80"'}, {'cidr_blocks': '"0.0.0.0/0"', 'description': '"allow outbound https"', 'from_port': '"443"', 'protocol': '"tcp"', 'to_port': '"443"'}]
  vpc_id = aws_vpc.esvpc3_cead2_a7.arn
}


resource "aws_iam_role" "cl_jumpbox_jumpbox_ec2_instance_role92_dda704" {
  assume_role_policy = {
    Statement = [{"Action": '"sts:AssumeRole"', 'Effect': '"Allow"', 'Principal': {'Service': 'join("", ["ec2.", data.aws_partition.current.dns_suffix])'}}]
    Version = "2012-10-17"
  }
  tags = [{'Key': '"Name"', 'Value': '"CL-PrimaryStack/CL-Jumpbox/JumpboxEC2"'}]
}


resource "aws_iam_instance_profile" "cl_jumpbox_jumpbox_ec2_instance_profile10_a8921_d" {
  role = ['aws_iam_role.cl_jumpbox_jumpbox_ec2_instance_role92_dda704.arn']
}


resource "aws_instance" "cl_jumpbox_jumpbox_ec210_de4297" {
  availability_zone = element(data.aws_availability_zones.available.names, 0)
  iam_instance_profile = aws_iam_instance_profile.cl_jumpbox_jumpbox_ec2_instance_profile10_a8921_d.arn
  private_ip = var.windows_ami
  instance_type = "t3.micro"
  key_name = var.jumpbox_key
  vpc_security_group_ids = ['aws_security_group.cl_jumpbox_jumpbox_sgd93_e94_fc.id']
  subnet_id = aws_subnet.esvpces_public_subnet_subnet1_subnet12560704.id
  tags = [{'Key': '"Name"', 'Value': '"CL-PrimaryStack/CL-Jumpbox/JumpboxEC2"'}]
  user_data = base64encode(<powershell></powershell>)
}


resource "aws_cloudformation_stack" "cl_demo_stack_nested_stack_cl_demo_stack_nested_stack_resource3_db21482" {
  template_url = "https://solutions-reference.s3.amazonaws.com/centralized-logging/v4.0.1/aws-centralized-logging-demo.template"
  parameters = {
    CWDestinationParm = join("", ["arn:", data.aws_region.current.name, ":logs:", data.aws_region.current.name, ":", data.aws_region.current.name, ":destination:CL-Destination-", aws_shield_protection.create_uuid.id])
  }
}


resource "aws_ecs_task_set" "cdk_metadata" {
  // CF Property(Analytics) = "v2:deflate64:H4sIAAAAAAAA/2VTXW/bMAz8LX1X1CUdsNel2VoM2DAv6fquyEzCxhY9fTgIDP/3UZLteOuTjifS5J3opVw+rOSHu8/q4ha6PN93mizIbueVPovNwRTKqho82Bj8UE2D5hjhhkyJHsmItXPgOf+Ybsg4b4P2YhOcp3oLjoLVEEsmPCenRj+Db4LvRRykQ1XLbktVrotnQRXqa5poQt+4lzIaCksHrKAXlar3pZLdUzA6zcZJE/7agvG71Him4z3bC/ewUFGUk0kbx7J7DPoM/lE5EBnG4gHl4zbXPO6FpqNBT7L77cAWRFVMmfAIvlCt0Myv3jPxTLpLnhn9dfzYPI5mrT2beqqZZEvo6GT3nY7PlkITsyfMYOctqHpgc9AL0CvZvTY60q/FRhQWW+VhF/Ymy76hLQUPL2qfHyrzN47dI40quV+EPdvxX2V+RF4uJp+5xUVdh6ZDdFMiniq68JDpSQe4Ax0s656k/UuM6zFfFVZXKedRO1BWn2R3czkjfv0/bNivACEVJsCkYfKFGkyuZMBinLbYjJs2j/nZKwrlRfnYZF0pm1xOoBdnNODQxd9s9H80f7g6oIUTOZBxMKiwBXsdU3T6sxZ2+Iuc5P1vsQTbC0MlyDd33y4/yuUnubp7c4gLG3g9apDbfP4F2FLoQfQDAAA="
}


output "destination_subscription_command" {
  description = "Command to run in spoke accounts/regions"
  value = join("", ["aws logs put-subscription-filter       --destination-arn arn:", data.aws_region.current.name, ":logs:<region>:", data.aws_region.current.name, ":destination:CL-Destination-", aws_shield_protection.create_uuid.id, "       --log-group-name <MyLogGroup>       --filter-name <MyFilterName>       --filter-pattern <MyFilterPattern>       --profile <MyAWSProfile> "])
}


output "unique_id" {
  description = "UUID for Centralized Logging Stack"
  value = aws_shield_protection.create_uuid.id
}


output "admin_email" {
  description = "Admin Email address"
  value = var.admin_email
}


output "domain_name" {
  description = "ES Domain Name"
  value = var.domain_name
}


output "kibana_url" {
  description = "Kibana URL"
  value = join("", ["https://", aws_elasticsearch_domain.es_domain_b45006_da.endpoint, "/_plugin/kibana/"])
}


output "cluster_size" {
  description = "ES Cluster Size"
  value = var.cluster_size
}


output "demo_deployment" {
  description = "Demo data deployed?"
  value = var.demo_template
}