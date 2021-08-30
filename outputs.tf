output "cloudwatch_log_group_name" {
    description = "Cloudwatch log group used for cloudtrail"
    value = aws_cloudwatch_log_group.cloudtrail_log_group.name
}

output "s3_logging_bucket_name" {
    description = "Logging S3 Bucket Name"
    value = aws_s3_bucket.logging_bucket.bucket
}

output "s3_cloudtrail_bucket_name" {
    description = "Cloudtrail S3 Bucket Name"
    value = aws_s3_bucket.cloudtrail_bucket.bucket
}

output "sns_alert_topic_name" {
    description = "Alert SNS topic"
    value = aws_sns_topic.security_alert_topic.name  
}

output "iam_role_name" {
    description = "IAM role used by CloudTraik"
    value = aws_iam_role.cloudwatch_logs_role.name
}

output "cloudtrail_name" {
    description = "CloudTrail Name"
    value = aws_cloudtrail.account_cloudtrail.name
  
}