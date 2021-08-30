######################################
# DATA
######################################
provider "aws" {
  profile = "default"
  region  = var.default_region
}

data "aws_caller_identity" "current" {}

######################################
# RESOURCES
######################################

# IAM - CloudWatch Logs Role
resource "aws_iam_role" "cloudwatch_logs_role" {
    name = "${var.customer_prefix}-cloudwatch-logs-role"
    description = "IAM role used by CloudTrail to use CloudWatch Logs"
    assume_role_policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
        "Effect": "Allow",
        "Principal": {
            "Service": "cloudtrail.amazonaws.com"
        },
        "Action": "sts:AssumeRole"
        }
    ]
}
EOF
}

resource "aws_iam_policy" "cloudwatch_logs_policy" {
    name = "${var.customer_prefix}-cloudwatch-logs-policy"
    description = "IAM Policy allowing access to cloudtrail and cloudwatch log group"
    policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "CloudTrailFullAccess",
            "Effect": "Allow",
            "Action": [
                "cloudtrail:*"
            ],
            "Resource": "*"
        },
        {
            "Sid": "AwsOrgsAccess",
            "Effect": "Allow",
            "Action": [
                "organizations:DescribeAccount",
                "organizations:DescribeOrganization",
                "organizations:ListAccounts",
                "organizations:ListAWSServiceAccessForOrganization"
            ],
            "Resource": [
                "*"
            ]
        },
        {
            "Sid": "LogsAccess",
            "Effect": "Allow",
            "Action": "logs:*",
            "Resource" : "${aws_cloudwatch_log_group.cloudtrail_log_group.arn}:*"
        }
    ]
}
EOF    
}

# IAM - Attach policy to CloudWatch logs role
resource "aws_iam_role_policy_attachment" "attach_cloudtrail_policy" {
    role = aws_iam_role.cloudwatch_logs_role.name
    policy_arn = aws_iam_policy.cloudwatch_logs_policy.arn
}

# Cloudwatch - Unauthorized API Calls Metric Filter
resource "aws_cloudwatch_log_metric_filter" "unauthorized_api_calls" {
    name = "UnauthorizedAPICalls"
    log_group_name = aws_cloudwatch_log_group.cloudtrail_log_group.name
    metric_transformation {
      name = "unauthorized_api_calls"
      namespace = "LogMetrics"
      value = "1"
    }
    pattern = <<EOF
{($.errorCode="*UnauthorizedOperation") || ($.errorCode="AccessDenied*")}
EOF
}

# Cloudwatch - Management Console sign-in without MFA Metric Filter
resource "aws_cloudwatch_log_metric_filter" "sign_in_without_mfa" {
    name = "SignInWithoutMFA"
    log_group_name = aws_cloudwatch_log_group.cloudtrail_log_group.name
    metric_transformation {
      name = "sign_in_without_mfa"
      namespace = "LogMetrics"
      value = "1"
    }
    pattern = <<EOF
{($.eventName="ConsoleLogin") && ($.additionalEventData.MFAUsed !="Yes")}
EOF
}

# Cloudwatch - Usage of the root account Metric Filter
resource "aws_cloudwatch_log_metric_filter" "usage_of_root_account" {
    name = "UsageOfRootAccount"
    log_group_name = aws_cloudwatch_log_group.cloudtrail_log_group.name
    metric_transformation {
      name = "usage_of_root_account"
      namespace = "LogMetrics"
      value = "1"
    }
    pattern = <<EOF
{$.userIdentity.type="Root" && $.userIdentity.invokedBy NOT EXISTS && $.eventType !="AwsServiceEvent"}
EOF
}

# Cloudwatch - Unauthorized API Calls alarm
resource "aws_cloudwatch_metric_alarm" "unatuhorized_api_calls_alarm" {
    alarm_name = "unauthorized-api-calls-alarm"
    alarm_description = "This metric monitors for Unauthorized API Calls"
    comparison_operator = "GreaterThanOrEqualToThreshold"
    metric_name = aws_cloudwatch_log_metric_filter.unauthorized_api_calls.name
    namespace = aws_cloudwatch_log_metric_filter.unauthorized_api_calls.metric_transformation[0].namespace
    threshold = "1"
    statistic = "Sum"
    period = "300"
    evaluation_periods = "1"
    alarm_actions = [aws_sns_topic.security_alert_topic.arn]
}

# Cloudwatch - Management Console sign-in without MFA alarm
resource "aws_cloudwatch_metric_alarm" "sign_in_without_mfa_alarm" {
    alarm_name = "sign-in-without-mfa-alarm"
    alarm_description = "This metric monitors for anyone signing in without MFA"
    comparison_operator = "GreaterThanOrEqualToThreshold"
    metric_name = aws_cloudwatch_log_metric_filter.sign_in_without_mfa.name
    namespace = aws_cloudwatch_log_metric_filter.sign_in_without_mfa.metric_transformation[0].namespace
    threshold = "1"
    statistic = "Sum"
    period = "300"
    evaluation_periods = "1"
    alarm_actions = [aws_sns_topic.security_alert_topic.arn]
}

# Cloudwatch - Usage of the root account alarm
resource "aws_cloudwatch_metric_alarm" "usage_of_root_account_alarm" {
    alarm_name = "susage-of-root-account-alarm"
    alarm_description = "This metric monitors for the usage of the root account"
    comparison_operator = "GreaterThanOrEqualToThreshold"
    metric_name = aws_cloudwatch_log_metric_filter.usage_of_root_account.name
    namespace = aws_cloudwatch_log_metric_filter.usage_of_root_account.metric_transformation[0].namespace
    threshold = "1"
    statistic = "Sum"
    period = "300"
    evaluation_periods = "1"
    alarm_actions = [aws_sns_topic.security_alert_topic.arn]
}

# Cloudwatch - Cloudtrail Log
resource "aws_cloudwatch_log_group" "cloudtrail_log_group" {
    name = "${var.customer_prefix}-cloudtrail-logs"
  
}

# Cloudtrail - Account Cloudtrail
resource "aws_cloudtrail" "account_cloudtrail" {
    name                        = "${var.customer_prefix}-cloudtrail"
    s3_bucket_name              = aws_s3_bucket.cloudtrail_bucket.id
    is_multi_region_trail       = "true"
    enable_log_file_validation  = "true"
    include_global_service_events = "true"
    cloud_watch_logs_group_arn = "${aws_cloudwatch_log_group.cloudtrail_log_group.arn}:*"
    cloud_watch_logs_role_arn = aws_iam_role.cloudwatch_logs_role.arn
}

# S3 - Logging Bucket
resource "aws_s3_bucket" "logging_bucket" {
    bucket = "${var.customer_prefix}-logging-bucket"
    acl = "log-delivery-write"
    server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        kms_master_key_id = aws_kms_key.s3_kms_key.arn
        sse_algorithm     = "aws:kms"
      }
    }
    }
  
}

# S3 - Cloudtrail Bucket
resource "aws_s3_bucket" "cloudtrail_bucket" {
    bucket = "${var.customer_prefix}-cloudtrail-bucket"
    acl = "private"
    logging {
      target_bucket = aws_s3_bucket.logging_bucket.id
      target_prefix = "AccessLogs/"
    }
    server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        kms_master_key_id = aws_kms_key.s3_kms_key.arn
        sse_algorithm     = "aws:kms"
      }
    }
    }
    policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AWSCloudTrailAclCheck",
            "Effect": "Allow",
            "Principal": {
              "Service": "cloudtrail.amazonaws.com"
            },
            "Action": "s3:GetBucketAcl",
            "Resource": "arn:aws:s3:::${var.customer_prefix}-cloudtrail-bucket"
        },
        {
            "Sid": "AWSCloudTrailWrite",
            "Effect": "Allow",
            "Principal": {
              "Service": "cloudtrail.amazonaws.com"
            },
            "Action": "s3:PutObject",
            "Resource": "arn:aws:s3:::${var.customer_prefix}-cloudtrail-bucket/AWSLogs/${data.aws_caller_identity.current.account_id}/*",
            "Condition": {
                "StringEquals": {
                    "s3:x-amz-acl": "bucket-owner-full-control"
                }
            }
        }
    ]
}
EOF
}

# S3 - Cloudtrail Bucket public access block
resource "aws_s3_bucket_public_access_block" "cloudtrail_bucket_public_block" {
    bucket = aws_s3_bucket.cloudtrail_bucket.id
    block_public_acls = "true"
    block_public_policy = "true"
    ignore_public_acls = "true"
    restrict_public_buckets = "true"
}

# KMS - S3 Key
resource "aws_kms_key" "s3_kms_key" {
    description = "KMS Key used to encrypt S3 Buckets"
    tags = {
      "Name" = "${var.customer_prefix}-s3-kms-key"
    }
}

# KMS - SNS Topic
resource "aws_kms_key" "sns_kms_key" {
    description = "KMS Key used to encrypt SNS topics"
    tags = {
      "Name" = "${var.customer_prefix}-sns-kms-key"
    }
}

# KMS - Cloudtrail Key 
/*
resource "aws_kms_key" "cloudtrail_kms_key" {
    description = "KMS Key used to encrypt cloudtrail logs"
    tags = {
      "Name" = "${var.customer_prefix}-cloudtrail-kms-key"
    }
}
*/

# SNS - Alert Topic
resource "aws_sns_topic" "security_alert_topic" {
    name = "security-alert-topic"
    kms_master_key_id = aws_kms_key.sns_kms_key.id
}

# SNS - Topic Subscription
resource "aws_sns_topic_subscription" "security_alert_subscription" {
    topic_arn = aws_sns_topic.security_alert_topic.arn
    protocol = "email"
    endpoint = var.alert_email_address
}

