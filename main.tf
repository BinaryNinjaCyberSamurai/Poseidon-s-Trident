# Provider configuration
provider "aws" {
  region = "us-west-2"
}

# EC2 instance resource
resource "aws_instance" "example" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t2.micro"

  tags = {
    Name = "poseidonstrident-instance"
  }
}
