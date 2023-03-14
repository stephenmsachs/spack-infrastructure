resource "aws_instance" "windows-node" {
  # AMI for "Windows Server 2019 English Core with Containers" (us-east-1)
  ami               = "ami-0c86aa220cfc66a3b"
  instance_type     = "t2.small"
  availability_zone = "us-east-2a"
}
