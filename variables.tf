variable "default_region" {
    description = "Default region to be used"
    type        = string
    default     = "eu-west-2"
}

variable "customer_prefix" {
  description = "Value of the Name for CloudTrail"
  type        = string
}

variable "alert_email_address" {
    description = "Email address where Alerts will go to"
    type = string
}