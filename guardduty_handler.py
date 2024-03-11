import boto3

def lambda_handler(event, context):
    # Extract relevant details from the GuardDuty event
    finding_type = event['detail']['type']
    resource_arn = event['detail']['resource']['resourceArn']

    if finding_type == 'UnauthorizedAccess:IAMUser/ConsoleLogin':
        # Respond to unauthorized console login attempts
        revoke_access(resource_arn)
        notify_security_team(resource_arn)

    elif finding_type == 'Recon:EC2/PortProbeUnprotectedPort':
        # Respond to port scanning attempts
        block_ip(resource_arn)
        notify_security_team(resource_arn)

    # Add more response actions based on other GuardDuty findings

def revoke_access(resource_arn):
    # Revoke IAM access keys, update security groups, etc.
    pass

def block_ip(resource_arn):
    # Update security groups or network ACLs to block the IP
    pass

def notify_security_team(resource_arn):
    # Send alerts to the security team via SNS or other channels
    pass
