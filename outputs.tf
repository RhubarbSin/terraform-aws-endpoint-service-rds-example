output "instance_public_ip" {
  value = aws_instance.this.public_ip

  description = "The public IP address of the EC2 instance"
}

output "region" {
  value = var.region

  description = "The region in which the resources reside"
}

output "ssh_key_file_name" {
  value = basename(local_sensitive_file.this.filename)

  description = "The name of the file that contains the private SSH key used by the EC2 instance"
}

output "rds_username" {
  value = aws_db_instance.this.username

  description = "The username for the master DB user"
}

output "rds_password" {
  value = nonsensitive(aws_db_instance.this.password)

  description = "The password for the master DB user"
}

output "vpc_endpoint_dns_cname_record" {
  value = aws_route53_record.this.name

  description = "The value of the CNAME record for the VPC interface endpoint"
}
