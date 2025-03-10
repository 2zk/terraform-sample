provider "aws" {
  region = "ap-northeast-1"
  default_tags {
    tags = {
      Managed = "terraform"
    }
  }
}


locals {
  env      = "test"
  svc_name = "Ec2Win"
  vpc_cidr = "192.168.0.0/16"

  public_subnet_cidr = {
    "ap-northeast-1a" = "192.168.0.0/24"
  }

  # RDP の接続元制限するために利用
  permitted_cidr_blocks_v4 = [
    "xx.xx.xx.xx/32" # 利用環境の IPv4 アドレス
  ]
  # permitted_cidr_blocks_v6 = [
  #   "zzzz:zzzz:zzzz:zzzz::/56"   # 利用環境の IPv6 アドレス
  # ]

  #####
  # インスタンスサイズはお好みで
  win_server_instance_type = "t3a.large" // 2vCPU, 8GB Mem

  #####
  # + 注意点
  #   https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/create-key-pairs.html
  #   --> ED25519 keys are not supported for Windows instances.
  #   --> SSH private key file format must be PEM or PPK
  #   --> (RSA only) Base64 encoded DER format
  #   --> (RSA only) SSH public key file format as specified in RFC 4716
  #   --> Supported lengths: 1024, 2048, and 4096.
  #
  #   example : ssh-keygen -t rsa -m PEM -b 4096 -f test-ec2-win.pem
  ssh_pem_file_path = "~/.ssh/test-ec2-win.pem"
  ssh_pub_file_path = "~/.ssh/test-ec2-win.pem.pub"

  #####
  # Microsoft Windows Server 2016 with Desktop Experience Locale English AMI provided by Amazon / 64-bit (x86)
  # ami_amazon_win_server = "ami-0eab37501ca6f9075"
  # Microsoft Windows Server 2019 with Desktop Experience Locale English AMI provided by Amazon / 64-bit (x86)
  # ami_amazon_win_server = "ami-0d4e1dc285dc7f5e1"
  # Microsoft Windows Server 2012 R2 RTM 64-bit Locale English AMI provided by Amazon /  64-bit (x86)
  # ami_amazon_win_server = "ami-08f0cb9c56a7cc8cd"
  # Microsoft Windows Server 2022 Full Locale English AMI provided by Amazon /  64-bit (x86)
  # ami_amazon_win_server = "ami-05f53c2def3a51a08"

  # Microsoft Windows Server 2025 Full Locale English AMI provided by Amazon /  64-bit (x86)
  ami_amazon_win_server = "ami-0b51a1c68e86976b6"

}

#######################################################################################
# VPC 関係
#######################################################################################
resource "aws_vpc" "base" {
  cidr_block                       = local.vpc_cidr
  enable_dns_hostnames             = true
  enable_dns_support               = true
  assign_generated_ipv6_cidr_block = true

  tags = {
    Name = "${local.svc_name}-vpc-${local.env}"
  }
}

resource "aws_internet_gateway" "base" {
  vpc_id = aws_vpc.base.id
  tags = {
    Name = "${local.svc_name}-igw-${local.env}"
  }
}

resource "aws_route_table" "base_public_rt" {
  vpc_id = aws_vpc.base.id

  tags = {
    Name = "${local.svc_name}-public-route00-${local.env}"
  }
}
resource "aws_route" "base_public_rt_igw_rt" {
  route_table_id         = aws_route_table.base_public_rt.id
  gateway_id             = aws_internet_gateway.base.id
  destination_cidr_block = "0.0.0.0/0"
}

resource "aws_route" "base_public_rt_igw_rt_v6" {
  route_table_id              = aws_route_table.base_public_rt.id
  gateway_id                  = aws_internet_gateway.base.id
  destination_ipv6_cidr_block = "::/0"
}

resource "aws_subnet" "base_public_subnet00" {
  vpc_id                          = aws_vpc.base.id
  availability_zone               = "ap-northeast-1a"
  cidr_block                      = local.public_subnet_cidr["ap-northeast-1a"]
  ipv6_cidr_block                 = cidrsubnet(aws_vpc.base.ipv6_cidr_block, 8, 0)
  map_public_ip_on_launch         = true
  assign_ipv6_address_on_creation = true
  tags = {
    Name = "${local.svc_name}-public-subnet00-${local.env}"
  }
}

resource "aws_route_table_association" "base_public_rt00_assoc" {
  subnet_id      = aws_subnet.base_public_subnet00.id
  route_table_id = aws_route_table.base_public_rt.id
}

#######################################################################################
# EC2 関係
#######################################################################################
resource "aws_iam_role" "win_sv00_role" {
  description = "Allows EC2 instances to call AWS services on your behalf."
  name        = "win-sv00-role"
  assume_role_policy = jsonencode(
    {
      Statement = [
        {
          Action = "sts:AssumeRole"
          Effect = "Allow"
          Principal = {
            Service = "ec2.amazonaws.com"
          }
        },
      ]
      Version = "2008-10-17"
    }
  )
}

resource "aws_iam_role_policy_attachment" "ssm_managed_instance_core" {
  role       = aws_iam_role.win_sv00_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_role_policy_attachment" "cloudwatch_agent_server_policy" {
  role       = aws_iam_role.win_sv00_role.name
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
}

resource "aws_iam_role_policy_attachment" "cloudwatch_agent_admin_policy" {
  role       = aws_iam_role.win_sv00_role.name
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentAdminPolicy"
}

resource "aws_iam_instance_profile" "iam_instance_profile_win_sv00" {
  name = "iam-instance-profile-win-sv00"
  role = aws_iam_role.win_sv00_role.name
}

resource "aws_key_pair" "ssh_key" {
  key_name   = "test-ec2-win.pem.pub"
  public_key = file(local.ssh_pub_file_path)
}

resource "aws_security_group" "ec2_sec" {
  name        = "${local.svc_name}-sg-${local.env}"
  description = "only from permitted cidr blocks"
  vpc_id      = aws_vpc.base.id

  ingress {
    description = "Allow ICMP (IPv4)"
    from_port   = -1
    to_port     = -1
    protocol    = "icmp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    description      = "Allow ICMP (IPv6)"
    from_port        = -1
    to_port          = -1
    protocol         = "icmpv6"
    ipv6_cidr_blocks = ["::/0"]
  }
  ingress {
    description = "Allow RDP (IPv4/v6 TCP)"
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = local.permitted_cidr_blocks_v4
    //ipv6_cidr_blocks = local.permitted_cidr_blocks_v6
  }
  egress {
    description      = "Allow all IPv4/v6"
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }
  tags = {
    Name = "${local.svc_name}-sg-${local.env}"
  }
}

resource "aws_network_interface" "win_sv00_nw_if" {
  description     = "Network Interface 00"
  subnet_id       = aws_subnet.base_public_subnet00.id
  ipv6_addresses  = [cidrhost(aws_subnet.base_public_subnet00.ipv6_cidr_block, 10)]
  security_groups = [aws_security_group.ec2_sec.id]
  tags = {
    Name = "${local.svc_name}-nw-if00-${local.env}"
  }
}

resource "aws_eip" "eip00" {
  network_interface = aws_network_interface.win_sv00_nw_if.id
  tags = {
    Name = "${local.svc_name}-eip00-${local.env}"
  }
}

resource "aws_instance" "win_sv00" {
  ami                     = local.ami_amazon_win_server
  iam_instance_profile    = aws_iam_instance_profile.iam_instance_profile_win_sv00.name
  instance_type           = local.win_server_instance_type
  disable_api_termination = false
  key_name                = aws_key_pair.ssh_key.key_name
  get_password_data       = true
  network_interface {
    network_interface_id = aws_network_interface.win_sv00_nw_if.id
    device_index         = 0
  }
  root_block_device {
    volume_type           = "gp2"
    volume_size           = 32
    delete_on_termination = true
    encrypted             = true
  }

  tags = {
    Name = "${local.svc_name}-win-sv00-${local.env}"
  }
}

#######################################################################################
# 実行後にコンソールへ出力
#######################################################################################
output "public_ip" {
  value = aws_eip.eip00.public_ip
}

output "Administrator_pass" {
  value = [rsadecrypt(aws_instance.win_sv00.password_data, file(local.ssh_pem_file_path))]
}