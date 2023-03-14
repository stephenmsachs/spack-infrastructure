packer {
  required_plugins {
    amazon = {
      version = ">= 0.0.2"
      source  = "github.com/hashicorp/amazon"
    }
  }
}

locals {
  timestamp = regex_replace(timestamp(), "[- TZ:]", "")
}

source "amazon-ebs" "windows-runner" {
  # AMI for "Windows Server 2019 English Core with Containers"
  # in us-east-1
  source_ami    = "ami-0c86aa220cfc66a3b"
  region        = "us-east-1"
  instance_type = "t2.micro"
  ami_name      = "spack-windows-runner-${local.timestamp}"

  # This user data file sets up winrm and configures it so that the connection
  # from Packer is allowed. Without this file being set, Packer will not
  # connect to the instance.
  user_data_file = "./winrm_bootstrap.txt"
  communicator   = "winrm"
  winrm_username = "Administrator"
  winrm_use_ssl  = true
  winrm_insecure = true

}

build {
  name    = "windows-runner"
  sources = ["source.amazon-ebs.windows-runner"]

  # Install chocolatey
  provisioner "powershell" {
    inline = [
      "Set-ExecutionPolicy Bypass -Scope Process -Force",
      "[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072",
      "iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))",
    ]
  }

  # Install file and gpg
  provisioner "powershell" {
    inline = [
      "choco install -y file",
      "choco install -y gpg4win",
    ]
  }
}
