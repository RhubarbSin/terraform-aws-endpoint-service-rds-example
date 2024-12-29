variable "name" {
  type    = string
  default = "AWS Endpoint Service"

  validation {
    condition     = can(regex("^[A-Za-z][0-9A-Za-z ]{0,62}$", var.name))
    error_message = "The value of name variable must a string no longer than 63 characters containing only alphanumeric characters and spaces and must begin with a letter."
  }
}

variable "region" {
  type     = string
  nullable = false
  default  = "us-east-2"
}

variable "rds_preferred_instance_classes" {
  type     = list(string)
  nullable = false
  default  = ["db.t4g.micro", "db.t3.micro", "db.t4g.small", "db.t3.small"]
}

variable "rds_allocated_storage" {
  type    = number
  default = 20

  validation {
    condition = alltrue(
      [
        var.rds_allocated_storage >= 20,
        var.rds_allocated_storage <= 65536,
      ]
    )
    error_message = "The value of rds_allocated_storage variable must be an integer from 20 to 65536."
  }
}

variable "rds_username" {
  type     = string
  nullable = false
  default  = "admin"
}

variable "ssm_parameter_name" {
  type     = string
  nullable = false
  default  = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-arm64"
}
