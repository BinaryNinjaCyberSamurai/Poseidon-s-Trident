#!/bin/bash

# Assume the AWS role
output=$(aws sts assume-role --role-arn "arn:aws:iam::<account-id>:role/<rolename>" --role-session-name AWSCLI-Session)

# Extract credentials
access_key_id=$(echo "$output" | jq -r '.Credentials.AccessKeyId')
secret_access_key=$(echo "$output" | jq -r '.Credentials.SecretAccessKey')
session_token=$(echo "$output" | jq -r '.Credentials.SessionToken')

# Set environment variables
export AWS_ACCESS_KEY_ID="$access_key_id"
export AWS_SECRET_ACCESS_KEY="$secret_access_key"
export AWS_SESSION_TOKEN="$session_token"
