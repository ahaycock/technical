# Account Security Hardening
Terraform repository which will security harden the AWS Account.

## CloudTrail Requirements
[x] Enable CloudTrail 
[x] Ensure CloudTrail is enabled in all regions 
[x] Ensure CloudTrail log file validation is enabled. 
[x] Ensure that both management and global events are captured within CloudTrail. 
[] Ensure CloudTrail logs are encrypted at rest using KMS customer managed CMKs. 

[x] Ensure CloudTrail logs are stored within an S3 bucket. 
[x] Ensure controls are in place to block public access to the bucket. 
[x] Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket. 

[x] Ensure CloudTrail trails are integrated with CloudWatch Logs.

## CloudWatch Filters and Alarms Requirements
[x] Unauthorized API calls 
[x] Management Console sign-in without MFA 
[x] Usage of the "root" account

## Removing Default VPCs Requirements
[] Remove the default VPC within every region of the account.