# Specify the AWS provider
provider "aws" {
  region = "us-west-2"  # Choose the appropriate AWS region

  #Set access and secret keys (recommended to use environment variables)
  access_key = var.aws_access_key
  secret_key = var.aws_secret_key

  #Customize the retryable error codes
  retryable_errors = ["ThrottlingException", "RequestLimitExceeded"]

  #Enable detailed AWS API request logging
  # Uncomment the following lines if needed
  # endpoints {
  #   ec2 = "http://localhost:4566"  # Localstack for testing
  # }

  #Configure IAM role for the EC2 instances
  # Uncomment and customize as needed
  # assume_role {
  #   role_arn = "arn:aws:iam::123456789012:role/my-ec2-role"
  # }

  #Enable S3 bucket versioning
  # Uncomment if you're using S3 buckets
  # s3_force_path_style = true
}

#Define custom tags for resources
resource "aws_instance" "trident_instance" {
  ami           = "ami-0c55b159cbfafe1f0"  # Specify the AMI ID
  instance_type = "t2.micro"  # Choose an appropriate instance type

  tags = {
    Name        = "Poseidon-Trident-Instance"
    Environment = "Production"
    Project     = "Cybersecurity"
  }
}

#Create an S3 bucket for data storage
resource "aws_s3_bucket" "trident_data_bucket" {
  bucket = "poseidon-trident-data"
  acl    = "private"  # Set appropriate ACL (private, public-read, etc.)

  #Enable versioning for data retention
  versioning {
    enabled = true
  }
}

#Define security group rules
resource "aws_security_group" "trident_sg" {
  name        = "trident-security-group"
  description = "Security group for Poseidon's Trident"

  # Define ingress rules (allow traffic from specific IPs or CIDR blocks)
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # Restrict to specific IPs for production
  }

  # Add more ingress rules as needed
}

#Create an IAM role for Trident services
resource "aws_iam_role" "trident_role" {
  name = "trident-service-role"

  # Attach policies to the role (e.g., S3 read/write, CloudWatch logs)
  # Customize based on your requirements
  # ...

  #Trust relationship policy (e.g., allow EC2 instances to assume this role)
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Action = "sts:AssumeRole",
      Effect = "Allow",
      Principal = {
        Service = "ec2.amazonaws.com"
      }
    }]
  })
}

#Create an RDS MySQL database
resource "aws_db_instance" "trident_db" {
  allocated_storage    = 20
  storage_type         = "gp2"
  engine               = "mysql"
  engine_version       = "5.7"
  instance_class       = "db.t2.micro"
  name                 = "poseidon_trident_db"
  username             = "trident_user"
  password             = "supersecret"
  parameter_group_name = "default.mysql5.7"
  skip_final_snapshot  = true
}

#Create an S3 bucket for logs
resource "aws_s3_bucket" "trident_logs_bucket" {
  bucket = "poseidon-trident-logs"
  acl    = "private"
}

#Create CloudWatch alarms for monitoring
resource "aws_cloudwatch_metric_alarm" "trident_cpu_alarm" {
  alarm_name          = "TridentCPUAlarm"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 3
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 300
  statistic           = "Average"
  threshold           = 80
  alarm_description   = "High CPU utilization on Trident instance"
  alarm_actions       = [aws_sns_topic.trident_alerts.arn]
}

#Create an SNS topic for alerts
resource "aws_sns_topic" "trident_alerts" {
