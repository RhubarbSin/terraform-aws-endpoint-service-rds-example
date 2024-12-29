provider "aws" {
  region = var.region

  default_tags {
    tags = { Name : var.name }
  }
}

locals {
  keys        = ["provider", "consumer"]
  name_prefix = format("%s-", lower(replace(var.name, " ", "-")))
}

resource "random_integer" "this" {
  min = 0
  max = 254
}

resource "aws_vpc" "this" {
  for_each = { for key in local.keys : key => index(local.keys, key) }

  cidr_block = "192.168.${random_integer.this.result + each.value}.0/24"

  enable_dns_hostnames = true

  tags = { Name : format("${var.name} %s", title(each.key)) }
}

resource "aws_default_security_group" "this" {
  for_each = aws_vpc.this

  vpc_id = each.value.id

  tags = { Name : "${each.value.tags.Name} Default" }
}

resource "aws_default_route_table" "this" {
  for_each = aws_vpc.this

  default_route_table_id = each.value.default_route_table_id

  tags = { Name : each.value.tags.Name }
}

resource "aws_internet_gateway" "this" {
  tags = { Name : "${var.name} Consumer" }
}

resource "aws_internet_gateway_attachment" "this" {
  internet_gateway_id = aws_internet_gateway.this.id
  vpc_id              = aws_vpc.this["consumer"].id
}

resource "aws_route" "this" {
  route_table_id         = aws_default_route_table.this["consumer"].id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.this.id

  depends_on = [aws_internet_gateway_attachment.this]
}

data "aws_availability_zones" "this" {
  state = "available"
}

resource "random_shuffle" "this" {
  input = data.aws_availability_zones.this.names

  result_count = 2
}

locals {
  subnet = {
    for tuple in setproduct(keys(aws_vpc.this), range(random_shuffle.this.result_count)) :
    "${tuple.0}_${tuple.1}" => {
      vpc_id : aws_vpc.this[tuple.0].id,
      availability_zone : random_shuffle.this.result[tuple.1],
      cidr_block : cidrsubnet(aws_vpc.this[tuple.0].cidr_block, 1, tuple.1),
      name_tag : "${aws_vpc.this[tuple.0].tags.Name} ${random_shuffle.this.result[tuple.1]}",
    }
  }
}

resource "aws_subnet" "this" {
  for_each = local.subnet

  vpc_id = each.value.vpc_id

  availability_zone                   = each.value.availability_zone
  cidr_block                          = each.value.cidr_block
  private_dns_hostname_type_on_launch = "resource-name"

  tags = { Name : each.value.name_tag }
}

resource "aws_route_table_association" "this" {
  for_each = aws_subnet.this

  subnet_id = each.value.id
  route_table_id = one(
    [
      for k, v in aws_vpc.this :
      aws_default_route_table.this[k].id
      if each.value.vpc_id == v.id
    ]
  )
}

locals {
  security_group = {
    provider : ["rds", "nlb"],
    consumer : ["ec2", "vpce"],
  }
}

resource "aws_security_group" "this" {
  for_each = transpose(local.security_group)

  name_prefix = format("${var.name} %s %s ", title(each.value.0), upper(each.key))
  vpc_id      = aws_vpc.this[each.value.0].id

  tags = { Name : format("${var.name} %s %s", title(each.value.0), upper(each.key)) }
}

resource "aws_vpc_security_group_egress_rule" "default_all_all" {
  for_each = aws_vpc.this

  security_group_id = aws_default_security_group.this[each.key].id

  cidr_ipv4   = "0.0.0.0/0"
  ip_protocol = -1
}

resource "aws_vpc_security_group_egress_rule" "nlb_rds_tcp_3306" {
  security_group_id = aws_security_group.this["nlb"].id

  referenced_security_group_id = aws_security_group.this["rds"].id
  from_port                    = 3306
  to_port                      = 3306
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "nlb_rds_tcp_3306" {
  security_group_id = aws_security_group.this["rds"].id

  referenced_security_group_id = aws_security_group.this["nlb"].id
  from_port                    = 3306
  to_port                      = 3306
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "vpce_nlb_tcp_10000" {
  security_group_id = aws_security_group.this["nlb"].id

  cidr_ipv4   = aws_vpc.this["consumer"].cidr_block
  from_port   = 10000
  to_port     = 10000
  ip_protocol = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "ec2_vpce_tcp_10000" {
  security_group_id = aws_security_group.this["vpce"].id

  referenced_security_group_id = aws_security_group.this["ec2"].id
  from_port                    = 10000
  to_port                      = 10000
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "all_ec2_tcp_22" {
  security_group_id = aws_security_group.this["ec2"].id

  cidr_ipv4   = "0.0.0.0/0"
  from_port   = 22
  to_port     = 22
  ip_protocol = "tcp"
}

data "aws_rds_engine_version" "this" {
  engine = "mariadb"

  default_only = true
  latest       = true
}

data "aws_rds_orderable_db_instance" "this" {
  engine = "mariadb"

  engine_version             = data.aws_rds_engine_version.this.version_actual
  license_model              = "general-public-license"
  storage_type               = "gp3"
  preferred_instance_classes = var.rds_preferred_instance_classes
}

resource "aws_db_subnet_group" "this" {
  subnet_ids = [for k, v in aws_subnet.this : v.id if v.vpc_id == aws_vpc.this["provider"].id]

  name_prefix = local.name_prefix
}

resource "aws_db_parameter_group" "this" {
  family = data.aws_rds_engine_version.this.parameter_group_family

  name_prefix = local.name_prefix

  parameter {
    name  = "max_connect_errors"
    value = "4294967295"
  }

  parameter {
    name  = "log_warnings"
    value = "1"
  }
}

resource "random_password" "this" {
  length = 8

  special = false
}

resource "aws_db_instance" "this" {
  allocated_storage = var.rds_allocated_storage
  storage_type      = "gp3"
  engine            = "mariadb"
  instance_class    = data.aws_rds_orderable_db_instance.this.instance_class

  apply_immediately      = true
  availability_zone      = random_shuffle.this.result.0
  db_subnet_group_name   = aws_db_subnet_group.this.id
  identifier_prefix      = local.name_prefix
  engine_version         = data.aws_rds_engine_version.this.version_actual
  username               = var.rds_username
  password               = random_password.this.result
  parameter_group_name   = aws_db_parameter_group.this.name
  skip_final_snapshot    = true
  vpc_security_group_ids = [aws_security_group.this["rds"].id]
}

locals {
  subnet_id = {
    rds : [
      for subnet in aws_subnet.this :
      subnet.id
      if subnet.availability_zone == aws_db_instance.this.availability_zone
      && subnet.vpc_id == aws_vpc.this["provider"].id
    ].0,
    ec2 : [
      for subnet in aws_subnet.this :
      subnet.id
      if subnet.availability_zone == aws_db_instance.this.availability_zone
      && subnet.vpc_id == aws_vpc.this["consumer"].id
    ].0,
  }
}

data "aws_network_interfaces" "this" {
  filter {
    name   = "vpc-id"
    values = [aws_vpc.this["provider"].id]
  }

  filter {
    name   = "subnet-id"
    values = [local.subnet_id.rds]
  }

  filter {
    name   = "description"
    values = ["RDSNetworkInterface"]
  }

  depends_on = [aws_db_instance.this]
}

data "aws_network_interface" "this" {
  id = one(data.aws_network_interfaces.this.ids)
}

resource "aws_lb" "this" {
  name_prefix        = substr(local.name_prefix, 0, 6)
  internal           = true
  load_balancer_type = "network"
  security_groups    = [aws_security_group.this["nlb"].id]
  subnets            = [local.subnet_id.rds]
}

resource "aws_lb_target_group" "this" {
  port        = 3306
  protocol    = "TCP"
  target_type = "ip"
  name        = aws_lb.this.name
  vpc_id      = aws_vpc.this["provider"].id

  health_check {
    protocol = "TCP"
    interval = 300
  }
}

resource "aws_lb_target_group_attachment" "this" {
  target_group_arn = aws_lb_target_group.this.arn
  target_id        = data.aws_network_interface.this.private_ip
}

resource "aws_lb_listener" "this" {
  load_balancer_arn = aws_lb.this.arn

  port     = 10000
  protocol = "TCP"

  default_action {
    type = "forward"

    target_group_arn = aws_lb_target_group.this.arn
  }
}

data "aws_caller_identity" "this" {}

resource "aws_vpc_endpoint_service" "this" {
  acceptance_required = false

  network_load_balancer_arns = [aws_lb.this.arn]
  allowed_principals         = ["arn:aws:iam::${data.aws_caller_identity.this.account_id}:root"]
}

resource "aws_vpc_endpoint" "this" {
  service_name = aws_vpc_endpoint_service.this.service_name
  vpc_id       = aws_vpc.this["consumer"].id

  vpc_endpoint_type  = "Interface"
  security_group_ids = [aws_security_group.this["vpce"].id]
  subnet_ids         = [local.subnet_id.ec2]
}

resource "aws_route53_zone" "this" {
  name = "${aws_lb.this.name}.example"

  vpc {
    vpc_id = aws_vpc_endpoint.this.vpc_id
  }
}

resource "aws_route53_record" "this" {
  zone_id = aws_route53_zone.this.zone_id
  name    = "${aws_db_instance.this.engine}.${aws_route53_zone.this.name}"
  type    = "CNAME"
  ttl     = 3600
  records = [aws_vpc_endpoint.this.dns_entry.0.dns_name]
}

data "aws_ssm_parameter" "this" {
  name = var.ssm_parameter_name

  with_decryption = false
}

data "aws_ami" "this" {
  filter {
    name   = "image-id"
    values = [data.aws_ssm_parameter.this.value]
  }
}

data "aws_ec2_instance_types" "this" {
  filter {
    name   = "burstable-performance-supported"
    values = ["true"]
  }

  filter {
    name   = "current-generation"
    values = ["true"]
  }

  filter {
    name   = "memory-info.size-in-mib"
    values = ["512"]
  }

  filter {
    name   = "processor-info.supported-architecture"
    values = [data.aws_ami.this.architecture]
  }
}

data "aws_iam_policy_document" "this" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "this" {
  assume_role_policy = data.aws_iam_policy_document.this.json

  name_prefix = replace(var.name, " ", "")
}

data "aws_iam_policy" "this" {
  name = "AmazonSSMManagedInstanceCore"
}

resource "aws_iam_role_policy_attachment" "this" {
  role       = aws_iam_role.this.name
  policy_arn = data.aws_iam_policy.this.arn
}

resource "aws_iam_instance_profile" "this" {
  name = aws_iam_role.this.name
  role = aws_iam_role.this.name
}

resource "tls_private_key" "this" {
  algorithm = "ED25519"
}

resource "random_pet" "this" {}

resource "local_file" "this" {
  content  = tls_private_key.this.public_key_openssh
  filename = "${path.module}/${random_pet.this.id}.pub"
}

resource "local_sensitive_file" "this" {
  content  = tls_private_key.this.private_key_openssh
  filename = "${path.module}/${random_pet.this.id}"
}

resource "aws_key_pair" "this" {
  key_name   = random_pet.this.id
  public_key = tls_private_key.this.public_key_openssh
}

locals {
  my_dot_cnf = <<-EOF
    [client]
    host = ${aws_route53_record.this.fqdn}
    port = 10000
    user = ${aws_db_instance.this.username}
    password = ${aws_db_instance.this.password}
    EOF
  user_data = {
    packages : [
      "mariadb105",
      "nmap-ncat",
      "telnet",
    ],
    write_files : [
      {
        path : "/home/ec2-user/.my.cnf",
        permissions : "0600",
        owner : "ec2-user:ec2-user",
        defer : true,
        content : local.my_dot_cnf,
      },
    ],
  }
}

data "cloudinit_config" "this" {
  part {
    content = yamlencode(local.user_data)

    content_type = "text/cloud-config"
  }
}

resource "aws_instance" "this" {
  ami                         = data.aws_ami.this.id
  associate_public_ip_address = true
  iam_instance_profile        = aws_iam_role.this.name
  instance_type               = data.aws_ec2_instance_types.this.instance_types.0
  key_name                    = aws_key_pair.this.key_name
  subnet_id                   = local.subnet_id.ec2
  user_data                   = data.cloudinit_config.this.rendered
  vpc_security_group_ids = [
    aws_default_security_group.this["consumer"].id,
    aws_security_group.this["ec2"].id,
  ]

  root_block_device {
    encrypted   = true
    volume_type = "gp3"
  }

  depends_on = [aws_internet_gateway_attachment.this]
}
