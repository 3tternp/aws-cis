#!/bin/bash

# CIS AWS Foundations Benchmark v5.0.0 Compliance Checker
# Automatically installs dependencies, checks automated CIS controls, and generates JSON/HTML reports
# Requires read-only IAM user with SecurityAudit policy
# Manual checks are listed for review in the report

# Function to install dependencies
install_dependencies() {
    echo "Checking and installing dependencies..."
    if ! command -v aws &> /dev/null; then
        echo "Installing AWS CLI..."
        if [[ "$OSTYPE" == "darwin"* ]]; then
            brew install awscli || { echo "Error: Failed to install AWS CLI"; exit 1; }
        else
            curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
            unzip awscliv2.zip
            sudo ./aws/install
            rm -rf awscliv2.zip aws
        fi
    fi
    if ! command -v jq &> /dev/null; then
        echo "Installing jq..."
        if [[ "$OSTYPE" == "darwin"* ]]; then
            brew install jq || { echo "Error: Failed to install jq"; exit 1; }
        else
            sudo apt-get update && sudo apt-get install -y jq || { echo "Error: Failed to install jq"; exit 1; }
        fi
    fi
}

# Function to append results to JSON file
append_result() {
    local check_id=$1
    local status=$2
    local message=$3
    local details=$4
    local risk=$5
    local remediation=$6
    jq ". += [{\"check_id\": \"$check_id\", \"status\": \"$status\", \"message\": \"$message\", \"details\": \"$details\", \"risk\": \"$risk\", \"remediation\": \"$remediation\"}]" "$JSON_OUTPUT" > tmp.json && mv tmp.json "$JSON_OUTPUT"
}

# Function to check if AWS CLI command was successful
check_aws_command() {
    if [ $? -ne 0 ]; then
        echo "Error: AWS CLI command failed. Check credentials and permissions."
        exit 1
    fi
}

# Function to generate HTML report
generate_html_report() {
    cat <<EOF > "$HTML_OUTPUT"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>CIS AWS Benchmark v5.0.0 Compliance Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        table { width: 100%; border-collapse: collapse; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        tr:nth-child(even) { background-color: #f9f9f9; }
        .pass { color: green; }
        .fail { color: red; }
        .critical { background-color: #ffcccc; }
        .high { background-color: #ffebcc; }
        .medium { background-color: #fff4cc; }
        .low { background-color: #e6f3ff; }
    </style>
</head>
<body>
    <h1>CIS AWS Foundations Benchmark v5.0.0 Compliance Report</h1>
    <p>Generated on: $(date)</p>
    <p>Region: $AWS_REGION</p>
    <table>
        <tr>
            <th>Check ID</th>
            <th>Issue Name</th>
            <th>Risk Rating</th>
            <th>Status</th>
            <th>Details</th>
            <th>Remediation Steps</th>
        </tr>
EOF
    jq -r '.[] | "<tr class=\"\(.risk | ascii_downcase)\"><td>\(.check_id)</td><td>\(.message)</td><td>\(.risk)</td><td class=\"\(.status | ascii_downcase)\">\(.status)</td><td>\(.details)</td><td>\(.remediation | gsub("\n"; "<br>"))</td></tr>"' "$JSON_OUTPUT" >> "$HTML_OUTPUT"
    cat <<EOF >> "$HTML_OUTPUT"
    </table>
</body>
</html>
EOF
}

# Install dependencies
install_dependencies

# Prompt for AWS credentials
read -p "Enter AWS Access Key ID: " AWS_ACCESS_KEY_ID
read -p "Enter AWS Secret Access Key: " AWS_SECRET_ACCESS_KEY
read -p "Enter AWS Region (default: us-east-1): " AWS_REGION
AWS_REGION=${AWS_REGION:-us-east-1}

# Export credentials for AWS CLI
export AWS_ACCESS_KEY_ID
export AWS_SECRET_ACCESS_KEY
export AWS_DEFAULT_REGION=$AWS_REGION

# Output files
JSON_OUTPUT="cis_aws_benchmark_5.0.0_report_$(date +%Y%m%d_%H%M%S).json"
HTML_OUTPUT="cis_aws_benchmark_5.0.0_report_$(date +%Y%m%d_%H%M%S).html"
echo "[]" > "$JSON_OUTPUT"

echo "Starting CIS AWS Foundations Benchmark v5.0.0 Compliance Check..."
echo "Region: $AWS_REGION"
echo "Results will be saved to: $JSON_OUTPUT (JSON) and $HTML_OUTPUT (HTML)"

# Manual checks (listed for review)
append_result "1.1" "INFO" "Maintain current contact details (Manual)" "This check requires manual verification of contact details in the AWS Console under Billing and Cost Management." "High" "1. Sign in to AWS Management Console and open Billing and Cost Management console at https://console.aws.amazon.com/billing/home#/.\n2. Verify and update contact email and telephone details."
append_result "1.2" "INFO" "Ensure security contact information is registered (Manual)" "This check requires manual verification of security contact details in the AWS Console." "High" "1. Sign in to AWS Management Console and open Account settings.\n2. Run: aws account put-alternate-contact --alternate-contact-type SECURITY --email-address <email> --name <name> --phone-number <phone>."
append_result "1.5" "INFO" "Ensure hardware MFA is enabled for the 'root' user account (Manual)" "This check requires manual verification of hardware MFA for the root user in the AWS Console." "Critical" "1. Sign in as root user.\n2. Go to IAM > My Security Credentials.\n3. Enable a hardware MFA device (e.g., YubiKey) as per AWS documentation."
append_result "1.6" "INFO" "Eliminate use of the 'root' user for administrative and daily tasks (Manual)" "This check requires manual review of root user activity logs." "Critical" "1. Review CloudTrail logs for root user activity.\n2. Use IAM roles/users for daily tasks instead of root."
append_result "1.10" "INFO" "Do not create access keys during initial setup for IAM users with a console password (Manual)" "This check requires manual review of IAM user creation processes." "High" "1. Review IAM user creation policies.\n2. Ensure access keys are not created by default for console users."
append_result "1.20" "INFO" "Ensure IAM users are managed centrally via identity federation or AWS Organizations (Manual)" "This check requires manual verification of identity federation or AWS Organizations setup." "High" "1. Verify AWS Organizations or SSO configuration.\n2. Ensure no individual IAM users are created directly."
append_result "1.21" "INFO" "Ensure access to AWSCloudShellFullAccess is restricted (Manual)" "This check requires manual review of AWSCloudShellFullAccess policy attachments." "High" "1. Run: aws iam list-entities-for-policy --policy-arn arn:aws:iam::aws:policy/AWSCloudShellFullAccess\n2. Ensure PolicyRoles is empty."
append_result "2.1.2" "INFO" "Ensure MFA Delete is enabled on S3 buckets (Manual)" "This check requires manual verification of MFA Delete settings on S3 buckets." "Medium" "1. Run: aws s3api get-bucket-versioning --bucket <bucket_name>\n2. Enable MFA Delete using AWS CLI with root credentials."
append_result "2.1.3" "INFO" "Ensure all data in Amazon S3 has been discovered, classified, and secured (Manual)" "This check requires manual verification using AWS Macie." "Medium" "1. Enable AWS Macie in the console.\n2. Set up a repository for sensitive data discovery results."
append_result "4.1" "INFO" "Ensure unauthorized API calls are monitored (Manual)" "This check requires manual setup of CloudTrail and CloudWatch monitoring." "Medium" "1. Set up CloudTrail with CloudWatch integration.\n2. Create metric filters and alarms for unauthorized API calls."
append_result "4.2" "INFO" "Ensure management console sign-in without MFA is monitored (Manual)" "This check requires manual setup of CloudTrail and CloudWatch monitoring." "High" "1. Set up CloudTrail with CloudWatch integration.\n2. Create metric filters and alarms for non-MFA sign-ins."
append_result "4.3" "INFO" "Ensure usage of the 'root' account is monitored (Manual)" "This check requires manual setup of CloudTrail and CloudWatch monitoring." "Critical" "1. Set up CloudTrail with CloudWatch integration.\n2. Create metric filters and alarms for root account activity."
append_result "4.4" "INFO" "Ensure IAM policy changes are monitored (Manual)" "This check requires manual setup of CloudTrail and CloudWatch monitoring." "High" "1. Set up CloudTrail with CloudWatch integration.\n2. Create metric filters and alarms for IAM policy changes."
append_result "4.5" "INFO" "Ensure CloudTrail configuration changes are monitored (Manual)" "This check requires manual setup of CloudTrail and CloudWatch monitoring." "High" "1. Set up CloudTrail with CloudWatch integration.\n2. Create metric filters and alarms for CloudTrail changes."
append_result "4.6" "INFO" "Ensure AWS Management Console authentication failures are monitored (Manual)" "This check requires manual setup of CloudTrail and CloudWatch monitoring." "Medium" "1. Set up CloudTrail with CloudWatch integration.\n2. Create metric filters and alarms for console authentication failures."
append_result "4.7" "INFO" "Ensure disabling or scheduled deletion of customer created CMKs is monitored (Manual)" "This check requires manual setup of CloudTrail and CloudWatch monitoring." "Medium" "1. Set up CloudTrail with CloudWatch integration.\n2. Create metric filters and alarms for CMK changes."
append_result "4.8" "INFO" "Ensure S3 bucket policy changes are monitored (Manual)" "This check requires manual setup of CloudTrail and CloudWatch monitoring." "High" "1. Set up CloudTrail with CloudWatch integration.\n2. Create metric filters and alarms for S3 bucket policy changes."
append_result "4.9" "INFO" "Ensure AWS Config configuration changes are monitored (Manual)" "This check requires manual setup of CloudTrail and CloudWatch monitoring." "Medium" "1. Set up CloudTrail with CloudWatch integration.\n2. Create metric filters and alarms for AWS Config changes."
append_result "4.10" "INFO" "Ensure security group changes are monitored (Manual)" "This check requires manual setup of CloudTrail and CloudWatch monitoring." "Medium" "1. Set up CloudTrail with CloudWatch integration.\n2. Create metric filters and alarms for security group changes."
append_result "4.11" "INFO" "Ensure Network Access Control List (NACL) changes are monitored (Manual)" "This check requires manual setup of CloudTrail and CloudWatch monitoring." "Medium" "1. Set up CloudTrail with CloudWatch integration.\n2. Create metric filters and alarms for NACL changes."
append_result "4.12" "INFO" "Ensure changes to network gateways are monitored (Manual)" "This check requires manual setup of CloudTrail and CloudWatch monitoring." "High" "1. Set up CloudTrail with CloudWatch integration.\n2. Create metric filters and alarms for network gateway changes."
append_result "4.13" "INFO" "Ensure route table changes are monitored (Manual)" "This check requires manual setup of CloudTrail and CloudWatch monitoring." "High" "1. Set up CloudTrail with CloudWatch integration.\n2. Create metric filters and alarms for route table changes."
append_result "4.14" "INFO" "Ensure VPC changes are monitored (Manual)" "This check requires manual setup of CloudTrail and CloudWatch monitoring." "High" "1. Set up CloudTrail with CloudWatch integration.\n2. Create metric filters and alarms for VPC changes."
append_result "4.15" "INFO" "Ensure AWS Organizations changes are monitored (Manual)" "This check requires manual setup of CloudTrail and CloudWatch monitoring." "High" "1. Set up CloudTrail with CloudWatch integration.\n2. Create metric filters and alarms for AWS Organizations changes."
append_result "5.6" "INFO" "Ensure routing tables for VPC peering are 'least access' (Manual)" "This check requires manual review of VPC peering routing tables." "Medium" "1. Run: aws ec2 describe-route-tables\n2. Verify routes are restricted to necessary CIDR blocks."

# Automated checks
# 1.3: Ensure no 'root' user account access key exists
echo "Checking CIS 1.3: No 'root' user access key..."
root_keys=$(aws iam get-account-summary --query 'SummaryMap.AccountAccessKeysPresent' --output text 2>/dev/null)
check_aws_command
if [ "$root_keys" -eq 0 ]; then
    append_result "1.3" "PASS" "Ensure no 'root' user account access key exists" "No root access keys found." "Critical" "No action needed."
else
    append_result "1.3" "FAIL" "Ensure no 'root' user account access key exists" "Root access keys detected." "Critical" "1. Sign in as root user.\n2. Go to IAM > My Security Credentials > Access Keys.\n3. Delete any active keys."
fi

# 1.4: Ensure MFA is enabled for the 'root' user account
echo "Checking CIS 1.4: MFA enabled for 'root' user..."
mfa_enabled=$(aws iam get-account-summary --query 'SummaryMap.AccountMFAEnabled' --output text 2>/dev/null)
check_aws_command
if [ "$mfa_enabled" -eq 1 ]; then
    append_result "1.4" "PASS" "Ensure MFA is enabled for the 'root' user account" "Root MFA is enabled." "Critical" "No action needed."
else
    append_result "1.4" "FAIL" "Ensure MFA is enabled for the 'root' user account" "Root MFA is not enabled." "Critical" "1. Sign in as root user.\n2. Go to IAM > My Security Credentials.\n3. Enable MFA (virtual or hardware)."
fi

# 1.7: Ensure IAM password policy requires minimum length of 14 or greater
echo "Checking CIS 1.7: IAM password policy minimum length..."
password_policy=$(aws iam get-account-password-policy --query 'PasswordPolicy.MinimumPasswordLength' --output text 2>/dev/null)
check_aws_command
if [ "$password_policy" -ge 14 ] 2>/dev/null; then
    append_result "1.7" "PASS" "Ensure IAM password policy requires minimum length of 14 or greater" "Password policy meets minimum length requirement." "High" "No action needed."
else
    append_result "1.7" "FAIL" "Ensure IAM password policy requires minimum length of 14 or greater" "Password policy length is less than 14 or not set." "High" "1. Go to IAM > Account Settings.\n2. Set 'Minimum password length' to 14 or greater."
fi

# 1.8: Ensure IAM password policy prevents password reuse
echo "Checking CIS 1.8: IAM password policy prevents reuse..."
password_reuse=$(aws iam get-account-password-policy --query 'PasswordPolicy.PasswordReusePrevention' --output text 2>/dev/null)
check_aws_command
if [ "$password_reuse" -ge 24 ] 2>/dev/null; then
    append_result "1.8" "PASS" "Ensure IAM password policy prevents password reuse" "Password reuse prevention is set to 24 or greater." "High" "No action needed."
else
    append_result "1.8" "FAIL" "Ensure IAM password policy prevents password reuse" "Password reuse prevention is less than 24 or not set." "High" "1. Run: aws iam update-account-password-policy --password-reuse-prevention 24"
fi

# 1.9: Ensure MFA is enabled for all IAM users with console password
echo "Checking CIS 1.9: MFA for IAM users with console access..."
users=$(aws iam list-users --query 'Users[].UserName' --output json 2>/dev/null)
check_aws_command
non_mfa_users=""
while IFS= read -r user; do
    user=$(echo "$user" | tr -d '"')
    has_password=$(aws iam list-login-profiles --user-name "$user" --query 'LoginProfile' --output json 2>/dev/null)
    if [ -n "$has_password" ] && [ "$has_password" != "null" ]; then
        mfa_devices=$(aws iam list-mfa-devices --user-name "$user" --query 'MFADevices' --output json 2>/dev/null)
        if [ "$mfa_devices" == "[]" ]; then
            non_mfa_users="$non_mfa_users$user\n"
        fi
    fi
done <<< "$(echo "$users" | jq -c '.[]')"
if [ -z "$non_mfa_users" ]; then
    append_result "1.9" "PASS" "Ensure MFA is enabled for all IAM users with console password" "All IAM users with console access have MFA enabled." "High" "No action needed."
else
    append_result "1.9" "FAIL" "Ensure MFA is enabled for all IAM users with console password" "IAM users with console access without MFA: $non_mfa_users" "High" "1. Go to IAM > Users.\n2. For each user, enable MFA under Security Credentials."
fi

# 1.11: Ensure credentials unused for 45 days or more are disabled
echo "Checking CIS 1.11: Credentials unused for 45 days..."
aws iam generate-credential-report >/dev/null
credential_report=$(aws iam get-credential-report --query 'Content' --output text | base64 -d 2>/dev/null)
check_aws_command
inactive_users=""
while IFS= read -r line; do
    user=$(echo "$line" | cut -d, -f1)
    password_last_used=$(echo "$line" | cut -d, -f5)
    access_key_1_last_used=$(echo "$line" | cut -d, -f10)
    access_key_2_last_used=$(echo "$line" | cut -d, -f15)
    if [ "$password_last_used" != "N/A" ] && [ "$password_last_used" != "no_information" ]; then
        last_used_epoch=$(date -d "$password_last_used" +%s 2>/dev/null || date -j -f "%Y-%m-%dT%H:%M:%SZ" "$password_last_used" +%s 2>/dev/null)
        current_epoch=$(date +%s)
        age_days=$(( (current_epoch - last_used_epoch) / 86400 ))
        if [ "$age_days" -gt 45 ]; then
            inactive_users="$inactive_users$user (password unused for $age_days days)\n"
        fi
    fi
    for key_last_used in "$access_key_1_last_used" "$access_key_2_last_used"; do
        if [ "$key_last_used" != "N/A" ] && [ "$key_last_used" != "no_information" ]; then
            key_last_used_epoch=$(date -d "$key_last_used" +%s 2>/dev/null || date -j -f "%Y-%m-%dT%H:%M:%SZ" "$key_last_used" +%s 2>/dev/null)
            key_age_days=$(( (current_epoch - key_last_used_epoch) / 86400 ))
            if [ "$key_age_days" -gt 45 ]; then
                inactive_users="$inactive_users$user (access key unused for $key_age_days days)\n"
            fi
        fi
    done
done <<< "$(echo "$credential_report" | tail -n +2)"
if [ -z "$inactive_users" ]; then
    append_result "1.11" "PASS" "Ensure credentials unused for 45 days or more are disabled" "No credentials unused for 45+ days." "High" "No action needed."
else
    append_result "1.11" "FAIL" "Ensure credentials unused for 45 days or more are disabled" "Inactive credentials: $inactive_users" "High" "1. Run: aws iam generate-credential-report\n2. Disable or delete unused credentials in IAM console."
fi

# 1.12: Ensure there is only one active access key for any single IAM user
echo "Checking CIS 1.12: One active access key per IAM user..."
multiple_keys=""
while IFS= read -r user; do
    user=$(echo "$user" | tr -d '"')
    active_keys=$(aws iam list-access-keys --user-name "$user" --query 'AccessKeyMetadata[?Status==`Active`].AccessKeyId' --output json 2>/dev/null | jq length)
    if [ "$active_keys" -gt 1 ]; then
        multiple_keys="$multiple_keys$user ($active_keys active keys)\n"
    fi
done <<< "$(echo "$users" | jq -c '.[]')"
if [ -z "$multiple_keys" ]; then
    append_result "1.12" "PASS" "Ensure there is only one active access key for any single IAM user" "All IAM users have at most one active access key." "High" "No action needed."
else
    append_result "1.12" "FAIL" "Ensure there is only one active access key for any single IAM user" "Users with multiple active keys: $multiple_keys" "High" "1. Go to IAM > Users > Security Credentials.\n2. Deactivate or delete excess keys."
fi

# 1.13: Ensure access keys are rotated every 90 days or less
echo "Checking CIS 1.13: Access key rotation (90 days or less)..."
non_compliant_keys=""
while IFS= read -r user; do
    user=$(echo "$user" | tr -d '"')
    access_keys=$(aws iam list-access-keys --user-name "$user" --query 'AccessKeyMetadata[].{AccessKeyId:AccessKeyId,CreateDate:CreateDate}' --output json 2>/dev/null)
    while IFS= read -r key; do
        create_date=$(echo "$key" | jq -r '.CreateDate')
        key_id=$(echo "$key" | jq -r '.AccessKeyId')
        create_epoch=$(date -d "$create_date" +%s 2>/dev/null || date -j -f "%Y-%m-%dT%H:%M:%SZ" "$create_date" +%s 2>/dev/null)
        current_epoch=$(date +%s)
        age_days=$(( (current_epoch - create_epoch) / 86400 ))
        if [ "$age_days" -gt 90 ]; then
            non_compliant_keys="$non_compliant_keys$user: $key_id ($age_days days)\n"
        fi
    done <<< "$(echo "$access_keys" | jq -c '.[]')"
done <<< "$(echo "$users" | jq -c '.[]')"
if [ -z "$non_compliant_keys" ]; then
    append_result "1.13" "PASS" "Ensure access keys are rotated every 90 days or less" "All access keys are rotated within 90 days." "High" "No action needed."
else
    append_result "1.13" "FAIL" "Ensure access keys are rotated every 90 days or less" "Access keys older than 90 days: $non_compliant_keys" "High" "1. Go to IAM > Users > Security Credentials.\n2. Rotate keys older than 90 days."
fi

# 1.14: Ensure IAM users receive permissions only through groups
echo "Checking CIS 1.14: IAM users receive permissions only through groups..."
direct_policies=""
while IFS= read -r user; do
    user=$(echo "$user" | tr -d '"')
    policies=$(aws iam list-attached-user-policies --user-name "$user" --query 'AttachedPolicies[].PolicyName' --output json 2>/dev/null)
    if [ "$policies" != "[]" ]; then
        direct_policies="$direct_policies$user: $(echo "$policies" | jq -r '.[]' | tr '\n' ',')\n"
    fi
done <<< "$(echo "$users" | jq -c '.[]')"
if [ -z "$direct_policies" ]; then
    append_result "1.14" "PASS" "Ensure IAM users receive permissions only through groups" "No IAM users have directly attached policies." "High" "No action needed."
else
    append_result "1.14" "FAIL" "Ensure IAM users receive permissions only through groups" "Users with direct policies: $direct_policies" "High" "1. Go to IAM > Users.\n2. Move permissions to groups and attach groups to users."
fi

# 1.15: Ensure IAM policies that allow full "*:*" administrative privileges are not attached
echo "Checking CIS 1.15: No full admin IAM policies..."
iam_policies=$(aws iam list-policies --scope Local --query 'Policies[?PolicyName!=`AWSServiceRole*`].{Name:PolicyName,Arn:Arn}' --output json 2>/dev/null)
check_aws_command
full_admin_policies=""
while IFS= read -r policy; do
    policy_arn=$(echo "$policy" | jq -r '.Arn')
    policy_version=$(aws iam get-policy-version --policy-arn "$policy_arn" --version-id $(aws iam get-policy --policy-arn "$policy_arn" --query 'Policy.DefaultVersionId' --output text) --query 'PolicyVersion.Document' --output json 2>/dev/null)
    if echo "$policy_version" | grep -q '"Effect":"Allow","Action":"*","Resource":"*"'; then
        full_admin_policies="$full_admin_policies$(echo "$policy" | jq -r '.Name')\n"
    fi
done <<< "$(echo "$iam_policies" | jq -c '.[]')"
if [ -z "$full_admin_policies" ]; then
    append_result "1.15" "PASS" "Ensure IAM policies that allow full '*:*' administrative privileges are not attached" "No full admin policies found." "High" "No action needed."
else
    append_result "1.15" "FAIL" "Ensure IAM policies that allow full '*:*' administrative privileges are not attached" "Full admin policies: $full_admin_policies" "High" "1. Go to IAM > Policies.\n2. Detach or modify policies with full admin privileges."
fi

# 1.16: Ensure a support role has been created
echo "Checking CIS 1.16: Support role exists..."
support_role=$(aws iam list-entities-for-policy --policy-arn arn:aws:iam::aws:policy/AWSSupportAccess --query 'PolicyRoles' --output json 2>/dev/null)
check_aws_command
if [ "$support_role" != "[]" ]; then
    append_result "1.16" "PASS" "Ensure a support role has been created" "AWSSupportAccess policy is attached to at least one role." "High" "No action needed."
else
    append_result "1.16" "FAIL" "Ensure a support role has been created" "No roles with AWSSupportAccess policy found." "High" "1. Create a role in IAM.\n2. Attach AWSSupportAccess policy."
fi

# 1.17: Ensure IAM instance roles are used for AWS resource access from instances
echo "Checking CIS 1.17: IAM instance roles for EC2..."
instances=$(aws ec2 describe-instances --query 'Reservations[].Instances[].{InstanceId:InstanceId,IamInstanceProfile:IamInstanceProfile.Arn}' --output json 2>/dev/null)
check_aws_command
no_role_instances=""
while IFS= read -r instance; do
    instance_id=$(echo "$instance" | jq -r '.InstanceId')
    profile=$(echo "$instance" | jq -r '.IamInstanceProfile')
    if [ "$profile" == "null" ]; then
        no_role_instances="$no_role_instances$instance_id\n"
    fi
done <<< "$(echo "$instances" | jq -c '.[]')"
if [ -z "$no_role_instances" ]; then
    append_result "1.17" "PASS" "Ensure IAM instance roles are used for AWS resource access from instances" "All EC2 instances have IAM roles attached." "Medium" "No action needed."
else
    append_result "1.17" "FAIL" "Ensure IAM instance roles are used for AWS resource access from instances" "Instances without IAM roles: $no_role_instances" "Medium" "1. Go to EC2 > Instances.\n2. Attach IAM roles to listed instances."
fi

# 1.18: Ensure that all expired SSL/TLS certificates stored in AWS IAM are removed
echo "Checking CIS 1.18: No expired SSL/TLS certificates in IAM..."
certificates=$(aws iam list-server-certificates --query 'ServerCertificateMetadataList[].{Name:ServerCertificateName,Expiration:Expiration}' --output json 2>/dev/null)
check_aws_command
expired_certs=""
current_date=$(date -u +%Y-%m-%dT%H:%M:%SZ)
while IFS= read -r cert; do
    name=$(echo "$cert" | jq -r '.Name')
    expiration=$(echo "$cert" | jq -r '.Expiration')
    if [[ "$expiration" < "$current_date" ]]; then
        expired_certs="$expired_certs$name (expired $expiration)\n"
    fi
done <<< "$(echo "$certificates" | jq -c '.[]')"
if [ -z "$expired_certs" ]; then
    append_result "1.18" "PASS" "Ensure that all expired SSL/TLS certificates stored in AWS IAM are removed" "No expired certificates found." "High" "No action needed."
else
    append_result "1.18" "FAIL" "Ensure that all expired SSL/TLS certificates stored in AWS IAM are removed" "Expired certificates: $expired_certs" "High" "1. Run: aws iam delete-server-certificate --server-certificate-name <name>"
fi

# 1.19: Ensure IAM External Access Analyzer is enabled for all regions
echo "Checking CIS 1.19: IAM External Access Analyzer enabled..."
analyzer_status=$(aws accessanalyzer list-analyzers --query 'analyzers[?status==`ACTIVE`].name' --output json 2>/dev/null)
check_aws_command
if [ "$analyzer_status" != "[]" ]; then
    append_result "1.19" "PASS" "Ensure IAM External Access Analyzer is enabled for all regions" "Access Analyzer is active." "High" "No action needed."
else
    append_result "1.19" "FAIL" "Ensure IAM External Access Analyzer is enabled for all regions" "No active Access Analyzer found." "High" "1. Run: aws accessanalyzer create-analyzer --analyzer-name <name> --type ACCOUNT"
fi

# 2.1.1: Ensure S3 bucket policy denies HTTP requests
echo "Checking CIS 2.1.1: S3 bucket policy denies HTTP..."
buckets=$(aws s3api list-buckets --query 'Buckets[].Name' --output json 2>/dev/null)
check_aws_command
non_secure_buckets=""
while IFS= read -r bucket; do
    bucket=$(echo "$bucket" | tr -d '"')
    policy=$(aws s3api get-bucket-policy --bucket "$bucket" --query 'Policy' --output text 2>/dev/null)
    if [ $? -eq 0 ]; then
        if ! echo "$policy" | grep -q '"aws:SecureTransport": "false"'; then
            non_secure_buckets="$non_secure_buckets$bucket\n"
        fi
    else
        non_secure_buckets="$non_secure_buckets$bucket (no policy denying HTTP)\n"
    fi
done <<< "$(echo "$buckets" | jq -c '.[]')"
if [ -z "$non_secure_buckets" ]; then
    append_result "2.1.1" "PASS" "Ensure S3 bucket policy is set to deny HTTP requests" "All S3 buckets deny HTTP requests." "Medium" "No action needed."
else
    append_result "2.1.1" "FAIL" "Ensure S3 bucket policy is set to deny HTTP requests" "Buckets not denying HTTP: $non_secure_buckets" "Medium" "1. Go to S3 > Bucket > Permissions > Bucket Policy.\n2. Add policy to deny HTTP requests."
fi

# 2.1.4: Ensure S3 is configured with 'Block Public Access' enabled
echo "Checking CIS 2.1.4: S3 block public access..."
non_compliant_buckets=""
while IFS= read -r bucket; do
    bucket=$(echo "$bucket" | tr -d '"')
    public_access=$(aws s3api get-public-access-block --bucket "$bucket" --query 'PublicAccessBlockConfiguration' --output json 2>/dev/null)
    if [ $? -eq 0 ]; then
        block_all=$(echo "$public_access" | jq -r '.BlockPublicAcls and .IgnorePublicAcls and .BlockPublicPolicy and .RestrictPublicBuckets')
        if [ "$block_all" != "true" ]; then
            non_compliant_buckets="$non_compliant_buckets$bucket\n"
        fi
    else
        non_compliant_buckets="$non_compliant_buckets$bucket (no public access block)\n"
    fi
done <<< "$(echo "$buckets" | jq -c '.[]')"
if [ -z "$non_compliant_buckets" ]; then
    append_result "2.1.4" "PASS" "Ensure S3 is configured with 'Block Public Access' enabled" "All S3 buckets have block public access enabled." "High" "No action needed."
else
    append_result "2.1.4" "FAIL" "Ensure S3 is configured with 'Block Public Access' enabled" "Buckets without block public access: $non_compliant_buckets" "High" "1. Go to S3 > Bucket > Permissions.\n2. Enable Block Public Access settings."
fi

# 2.2.1: Ensure encryption-at-rest is enabled for RDS instances
echo "Checking CIS 2.2.1: RDS encryption-at-rest..."
rds_instances=$(aws rds describe-db-instances --query 'DBInstances[].{DBInstanceIdentifier:DBInstanceIdentifier,StorageEncrypted:StorageEncrypted}' --output json 2>/dev/null)
check_aws_command
unencrypted_rds=""
while IFS= read -r instance; do
    id=$(echo "$instance" | jq -r '.DBInstanceIdentifier')
    encrypted=$(echo "$instance" | jq -r '.StorageEncrypted')
    if [ "$encrypted" == "false" ]; then
        unencrypted_rds="$unencrypted_rds$id\n"
    fi
done <<< "$(echo "$rds_instances" | jq -c '.[]')"
if [ -z "$unencrypted_rds" ]; then
    append_result "2.2.1" "PASS" "Ensure encryption-at-rest is enabled for RDS instances" "All RDS instances are encrypted." "High" "No action needed."
else
    append_result "2.2.1" "FAIL" "Ensure encryption-at-rest is enabled for RDS instances" "Unencrypted RDS instances: $unencrypted_rds" "High" "1. Create an encrypted snapshot of the instance.\n2. Restore from the encrypted snapshot."
fi

# 2.2.2: Ensure Auto Minor Version Upgrade is enabled for RDS instances
echo "Checking CIS 2.2.2: RDS Auto Minor Version Upgrade..."
no_auto_upgrade_rds=""
while IFS= read -r instance; do
    id=$(echo "$instance" | jq -r '.DBInstanceIdentifier')
    auto_upgrade=$(aws rds describe-db-instances --db-instance-identifier "$id" --query 'DBInstances[].AutoMinorVersionUpgrade' --output text 2>/dev/null)
    if [ "$auto_upgrade" == "False" ]; then
        no_auto_upgrade_rds="$no_auto_upgrade_rds$id\n"
    fi
done <<< "$(echo "$rds_instances" | jq -c '.[]')"
if [ -z "$no_auto_upgrade_rds" ]; then
    append_result "2.2.2" "PASS" "Ensure Auto Minor Version Upgrade is enabled for RDS instances" "All RDS instances have auto minor version upgrade enabled." "High" "No action needed."
else
    append_result "2.2.2" "FAIL" "Ensure Auto Minor Version Upgrade is enabled for RDS instances" "RDS instances without auto upgrade: $no_auto_upgrade_rds" "High" "1. Go to RDS > Databases.\n2. Enable Auto Minor Version Upgrade for listed instances."
fi

# 2.2.3: Ensure RDS instances are not publicly accessible
echo "Checking CIS 2.2.3: RDS instances not publicly accessible..."
public_rds=""
while IFS= read -r instance; do
    id=$(echo "$instance" | jq -r '.DBInstanceIdentifier')
    public=$(aws rds describe-db-instances --db-instance-identifier "$id" --query 'DBInstances[].PubliclyAccessible' --output text 2>/dev/null)
    if [ "$public" == "True" ]; then
        public_rds="$public_rds$id\n"
    fi
done <<< "$(echo "$rds_instances" | jq -c '.[]')"
if [ -z "$public_rds" ]; then
    append_result "2.2.3" "PASS" "Ensure RDS instances are not publicly accessible" "No publicly accessible RDS instances found." "High" "No action needed."
else
    append_result "2.2.3" "FAIL" "Ensure RDS instances are not publicly accessible" "Publicly accessible RDS instances: $public_rds" "High" "1. Go to RDS > Databases > Connectivity & Security.\n2. Set Publicly Accessible to 'Not publicly accessible'."
fi

# 2.3.1: Ensure encryption is enabled for EFS file systems
echo "Checking CIS 2.3.1: EFS encryption..."
efs_systems=$(aws efs describe-file-systems --query 'FileSystems[].{FileSystemId:FileSystemId,Encrypted:Encrypted}' --output json 2>/dev/null)
check_aws_command
unencrypted_efs=""
while IFS= read -r efs; do
    id=$(echo "$efs" | jq -r '.FileSystemId')
    encrypted=$(echo "$efs" | jq -r '.Encrypted')
    if [ "$encrypted" == "false" ]; then
        unencrypted_efs="$unencrypted_efs$id\n"
    fi
done <<< "$(echo "$efs_systems" | jq -c '.[]')"
if [ -z "$unencrypted_efs" ]; then
    append_result "2.3.1" "PASS" "Ensure encryption is enabled for EFS file systems" "All EFS file systems are encrypted." "High" "No action needed."
else
    append_result "2.3.1" "FAIL" "Ensure encryption is enabled for EFS file systems" "Unencrypted EFS file systems: $unencrypted_efs" "High" "1. Create a new encrypted EFS file system.\n2. Migrate data to the encrypted file system."
fi

# 3.1: Ensure CloudTrail is enabled in all regions
echo "Checking CIS 3.1: CloudTrail enabled in all regions..."
cloudtrail_status=$(aws cloudtrail describe-trails --query 'trailList[?IsMultiRegionTrail==`true`].{Name:Name,HomeRegion:HomeRegion}' --output json 2>/dev/null)
check_aws_command
if [ -n "$cloudtrail_status" ] && [ "$cloudtrail_status" != "[]" ]; then
    append_result "3.1" "PASS" "Ensure CloudTrail is enabled in all regions" "Multi-region CloudTrail is enabled." "High" "No action needed."
else
    append_result "3.1" "FAIL" "Ensure CloudTrail is enabled in all regions" "No multi-region CloudTrail detected." "High" "1. Go to CloudTrail > Trails.\n2. Create a multi-region trail."
fi

# 3.2: Ensure CloudTrail log file validation is enabled
echo "Checking CIS 3.2: CloudTrail log file validation..."
trails=$(aws cloudtrail describe-trails --query 'trailList[].{Name:Name,LogFileValidationEnabled:LogFileValidationEnabled}' --output json 2>/dev/null)
check_aws_command
no_validation_trails=""
while IFS= read -r trail; do
    name=$(echo "$trail" | jq -r '.Name')
    validation=$(echo "$trail" | jq -r '.LogFileValidationEnabled')
    if [ "$validation" == "false" ]; then
        no_validation_trails="$no_validation_trails$name\n"
    fi
done <<< "$(echo "$trails" | jq -c '.[]')"
if [ -z "$no_validation_trails" ]; then
    append_result "3.2" "PASS" "Ensure CloudTrail log file validation is enabled" "All CloudTrail trails have log file validation enabled." "Medium" "No action needed."
else
    append_result "3.2" "FAIL" "Ensure CloudTrail log file validation is enabled" "Trails without log file validation: $no_validation_trails" "Medium" "1. Run: aws cloudtrail update-trail --name <trail_name> --enable-log-file-validation"
fi

# 3.3: Ensure AWS Config is enabled in all regions
echo "Checking CIS 3.3: AWS Config enabled..."
config_recorders=$(aws configservice describe-configuration-recorders --query 'ConfigurationRecorders[].recordingGroup.allSupported' --output json 2>/dev/null)
check_aws_command
if echo "$config_recorders" | grep -q "true"; then
    append_result "3.3" "PASS" "Ensure AWS Config is enabled in all regions" "AWS Config is enabled with allSupported true." "Medium" "No action needed."
else
    append_result "3.3" "FAIL" "Ensure AWS Config is enabled in all regions" "AWS Config is not enabled or not fully configured." "Medium" "1. Go to AWS Config > Settings.\n2. Enable AWS Config with all resources recording."
fi

# 3.5: Ensure CloudTrail logs are encrypted at rest using KMS CMKs
echo "Checking CIS 3.5: CloudTrail logs encrypted with KMS..."
unencrypted_trails=""
while IFS= read -r trail; do
    name=$(echo "$trail" | jq -r '.Name')
    kms_key=$(aws cloudtrail describe-trails --trail-name-list "$name" --query 'trailList[].KmsKeyId' --output text 2>/dev/null)
    if [ -z "$kms_key" ]; then
        unencrypted_trails="$unencrypted_trails$name\n"
    fi
done <<< "$(echo "$trails" | jq -c '.[]')"
if [ -z "$unencrypted_trails" ]; then
    append_result "3.5" "PASS" "Ensure CloudTrail logs are encrypted at rest using KMS CMKs" "All CloudTrail trails use KMS encryption." "Medium" "No action needed."
else
    append_result "3.5" "FAIL" "Ensure CloudTrail logs are encrypted at rest using KMS CMKs" "Trails without KMS encryption: $unencrypted_trails" "Medium" "1. Run: aws cloudtrail update-trail --name <trail_name> --kms-key-id <kms_key_id>"
fi

# 3.6: Ensure rotation for customer-created symmetric CMKs is enabled
echo "Checking CIS 3.6: KMS key rotation..."
kms_keys=$(aws kms list-keys --query 'Keys[].KeyId' --output json 2>/dev/null)
check_aws_command
no_rotation_keys=""
while IFS= read -r key_id; do
    key_id=$(echo "$key_id" | tr -d '"')
    rotation=$(aws kms get-key-rotation-status --key-id "$key_id" --query 'KeyRotationEnabled' --output text 2>/dev/null)
    key_spec=$(aws kms describe-key --key-id "$key_id" --query 'KeyMetadata.KeySpec' --output text 2>/dev/null)
    if [ "$key_spec" == "SYMMETRIC_DEFAULT" ] && [ "$rotation" == "False" ]; then
        no_rotation_keys="$no_rotation_keys$key_id\n"
    fi
done <<< "$(echo "$kms_keys" | jq -c '.[]')"
if [ -z "$no_rotation_keys" ]; then
    append_result "3.6" "PASS" "Ensure rotation for customer-created symmetric CMKs is enabled" "All symmetric CMKs have rotation enabled." "Medium" "No action needed."
else
    append_result "3.6" "FAIL" "Ensure rotation for customer-created symmetric CMKs is enabled" "Keys without rotation: $no_rotation_keys" "Medium" "1. Run: aws kms enable-key-rotation --key-id <key_id>"
fi

# 3.7: Ensure VPC flow logging is enabled in all VPCs
echo "Checking CIS 3.7: VPC flow logging..."
vpcs=$(aws ec2 describe-vpcs --query 'Vpcs[].VpcId' --output json 2>/dev/null)
check_aws_command
no_flow_log_vpcs=""
while IFS= read -r vpc; do
    vpc=$(echo "$vpc" | tr -d '"')
    flow_logs=$(aws ec2 describe-flow-logs --filter Name=resource-id,Values="$vpc" --query 'FlowLogs[].FlowLogId' --output json 2>/dev/null)
    if [ "$flow_logs" == "[]" ]; then
        no_flow_log_vpcs="$no_flow_log_vpcs$vpc\n"
    fi
done <<< "$(echo "$vpcs" | jq -c '.[]')"
if [ -z "$no_flow_log_vpcs" ]; then
    append_result "3.7" "PASS" "Ensure VPC flow logging is enabled in all VPCs" "All VPCs have flow logging enabled." "Medium" "No action needed."
else
    append_result "3.7" "FAIL" "Ensure VPC flow logging is enabled in all VPCs" "VPCs without flow logging: $no_flow_log_vpcs" "Medium" "1. Go to VPC > Flow Logs.\n2. Create flow logs for listed VPCs."
fi

# 3.8: Ensure object-level logging for write events is enabled for S3 buckets
echo "Checking CIS 3.8: S3 object-level write logging..."
no_write_logging=""
while IFS= read -r trail; do
    name=$(echo "$trail" | jq -r '.Name')
    selectors=$(aws cloudtrail get-event-selectors --trail-name "$name" --query 'EventSelectors[].DataResources[?Type==`AWS::S3::Object`].Values' --output json 2>/dev/null)
    if ! echo "$selectors" | grep -q "arn:aws:s3:::"; then
        no_write_logging="$no_write_logging$name\n"
    fi
done <<< "$(echo "$trails" | jq -c '.[]')"
if [ -z "$no_write_logging" ]; then
    append_result "3.8" "PASS" "Ensure object-level logging for write events is enabled for S3 buckets" "All trails have S3 write event logging enabled." "Medium" "No action needed."
else
    append_result "3.8" "FAIL" "Ensure object-level logging for write events is enabled for S3 buckets" "Trails without S3 write logging: $no_write_logging" "Medium" "1. Go to CloudTrail > Trails.\n2. Enable S3 data event logging for write events."
fi

# 3.9: Ensure object-level logging for read events is enabled for S3 buckets
echo "Checking CIS 3.9: S3 object-level read logging..."
no_read_logging=""
while IFS= read -r trail; do
    name=$(echo "$trail" | jq -r '.Name')
    selectors=$(aws cloudtrail get-event-selectors --trail-name "$name" --query 'EventSelectors[].DataResources[?Type==`AWS::S3::Object`].Values' --output json 2>/dev/null)
    if ! echo "$selectors" | grep -q "arn:aws:s3:::"; then
        no_read_logging="$no_read_logging$name\n"
    fi
done <<< "$(echo "$trails" | jq -c '.[]')"
if [ -z "$no_read_logging" ]; then
    append_result "3.9" "PASS" "Ensure object-level logging for read events is enabled for S3 buckets" "All trails have S3 read event logging enabled." "Medium" "No action needed."
else
    append_result "3.9" "FAIL" "Ensure object-level logging for read events is enabled for S3 buckets" "Trails without S3 read logging: $no_read_logging" "Medium" "1. Go to CloudTrail > Trails.\n2. Enable S3 data event logging for read events."
fi

# 4.16: Ensure AWS Security Hub is enabled
echo "Checking CIS 4.16: AWS Security Hub enabled..."
security_hub=$(aws securityhub describe-hub --query 'SubscribedAt' --output text 2>/dev/null)
check_aws_command
if [ -n "$security_hub" ]; then
    append_result "4.16" "PASS" "Ensure AWS Security Hub is enabled" "Security Hub is enabled." "Medium" "No action needed."
else
    append_result "4.16" "FAIL" "Ensure AWS Security Hub is enabled" "Security Hub is not enabled." "Medium" "1. Go to Security Hub > Enable Security Hub."
fi

# 5.1.1: Ensure EBS volume encryption is enabled
echo "Checking CIS 5.1.1: EBS volume encryption..."
ebs_encryption=$(aws ec2 get-ebs-encryption-by-default --query 'EbsEncryptionByDefault' --output text 2>/dev/null)
check_aws_command
if [ "$ebs_encryption" == "True" ]; then
    append_result "5.1.1" "PASS" "Ensure EBS volume encryption is enabled in all regions" "EBS encryption is enabled by default." "High" "No action needed."
else
    append_result "5.1.1" "FAIL" "Ensure EBS volume encryption is enabled in all regions" "EBS encryption is not enabled by default." "High" "1. Go to EC2 > Account Attributes > EBS Encryption.\n2. Enable default encryption."
fi

# 5.1.2: Ensure CIFS access is restricted
echo "Checking CIS 5.1.2: CIFS access restricted..."
security_groups=$(aws ec2 describe-security-groups --query 'SecurityGroups[].{GroupId:GroupId,IpPermissions:IpPermissions[?ToPort==`445`].IpRanges[].CidrIp}' --output json 2>/dev/null)
check_aws_command
unrestricted_cifs=""
while IFS= read -r group; do
    group_id=$(echo "$group" | jq -r '.GroupId')
    cidrs=$(echo "$group" | jq -r '.IpPermissions[]')
    if echo "$cidrs" | grep -q "0.0.0.0/0"; then
        unrestricted_cifs="$unrestricted_cifs$group_id\n"
    fi
done <<< "$(echo "$security_groups" | jq -c '.[]')"
if [ -z "$unrestricted_cifs" ]; then
    append_result "5.1.2" "PASS" "Ensure CIFS access is restricted to trusted networks" "No security groups allow CIFS from 0.0.0.0/0." "High" "No action needed."
else
    append_result "5.1.2" "FAIL" "Ensure CIFS access is restricted to trusted networks" "Security groups allowing CIFS from 0.0.0.0/0: $unrestricted_cifs" "High" "1. Go to VPC > Security Groups.\n2. Remove or restrict rules allowing port 445 from 0.0.0.0/0."
fi

# 5.2: Ensure no Network ACLs allow ingress from 0.0.0.0/0 to remote server administration ports
echo "Checking CIS 5.2: No NACLs allow ingress to admin ports..."
nacls=$(aws ec2 describe-network-acls --query 'NetworkAcls[].{NetworkAclId:NetworkAclId,Entries:Entries[?Egress==`false` && (PortRange.To==`22` || PortRange.To==`3389`)].CidrBlock}' --output json 2>/dev/null)
check_aws_command
unrestricted_nacls=""
while IFS= read -r nacl; do
    nacl_id=$(echo "$nacl" | jq -r '.NetworkAclId')
    cidrs=$(echo "$nacl" | jq -r '.Entries[]')
    if echo "$cidrs" | grep -q "0.0.0.0/0"; then
        unrestricted_nacls="$unrestricted_nacls$nacl_id\n"
    fi
done <<< "$(echo "$nacls" | jq -c '.[]')"
if [ -z "$unrestricted_nacls" ]; then
    append_result "5.2" "PASS" "Ensure no Network ACLs allow ingress from 0.0.0.0/0 to remote server administration ports" "No NACLs allow ingress to ports 22/3389 from 0.0.0.0/0." "High" "No action needed."
else
    append_result "5.2" "FAIL" "Ensure no Network ACLs allow ingress from 0.0.0.0/0 to remote server administration ports" "NACLs allowing ingress to admin ports: $unrestricted_nacls" "High" "1. Go to VPC > Network ACLs.\n2. Remove rules allowing ports 22/3389 from 0.0.0.0/0."
fi

# 5.3: Ensure no security groups allow ingress from 0.0.0.0/0 to remote server administration ports
echo "Checking CIS 5.3: No security groups allow ingress to admin ports..."
unrestricted_sgs=""
while IFS= read -r group; do
    group_id=$(echo "$group" | jq -r '.GroupId')
    cidrs=$(echo "$group" | jq -r '.IpPermissions[?ToPort==`22` || ToPort==`3389`].IpRanges[].CidrIp')
    if echo "$cidrs" | grep -q "0.0.0.0/0"; then
        unrestricted_sgs="$unrestricted_sgs$group_id\n"
    fi
done <<< "$(echo "$security_groups" | jq -c '.[]')"
if [ -z "$unrestricted_sgs" ]; then
    append_result "5.3" "PASS" "Ensure no security groups allow ingress from 0.0.0.0/0 to remote server administration ports" "No security groups allow ingress to ports 22/3389 from 0.0.0.0/0." "High" "No action needed."
else
    append_result "5.3" "FAIL" "Ensure no security groups allow ingress from 0.0.0.0/0 to remote server administration ports" "Security groups allowing admin ports: $unrestricted_sgs" "High" "1. Go to VPC > Security Groups.\n2. Remove rules allowing ports 22/3389 from 0.0.0.0/0."
fi

# 5.4: Ensure no security groups allow ingress from ::/0 to remote server administration ports
echo "Checking CIS 5.4: No security groups allow IPv6 ingress to admin ports..."
unrestricted_ipv6_sgs=""
while IFS= read -r group; do
    group_id=$(echo "$group" | jq -r '.GroupId')
    ipv6_cidrs=$(echo "$group" | jq -r '.IpPermissions[?ToPort==`22` || ToPort==`3389`].Ipv6Ranges[].CidrIpv6')
    if echo "$ipv6_cidrs" | grep -q "::/0"; then
        unrestricted_ipv6_sgs="$unrestricted_ipv6_sgs$group_id\n"
    fi
done <<< "$(echo "$security_groups" | jq -c '.[]')"
if [ -z "$unrestricted_ipv6_sgs" ]; then
    append_result "5.4" "PASS" "Ensure no security groups allow ingress from ::/0 to remote server administration ports" "No security groups allow IPv6 ingress to ports 22/3389 from ::/0." "High" "No action needed."
else
    append_result "5.4" "FAIL" "Ensure no security groups allow ingress from ::/0 to remote server administration ports" "Security groups allowing IPv6 admin ports: $unrestricted_ipv6_sgs" "High" "1. Go to VPC > Security Groups.\n2. Remove rules allowing ports 22/3389 from ::/0."
fi

# 5.5: Ensure the default security group of every VPC restricts all traffic
echo "Checking CIS 5.5: Default security group restricts all traffic..."
default_sgs=$(aws ec2 describe-security-groups --filters Name=group-name,Values=default --query 'SecurityGroups[].{GroupId:GroupId,IpPermissions:IpPermissions,IpPermissionsEgress:IpPermissionsEgress}' --output json 2>/dev/null)
check_aws_command
unrestricted_default_sgs=""
while IFS= read -r sg; do
    group_id=$(echo "$sg" | jq -r '.GroupId')
    ingress=$(echo "$sg" | jq -r '.IpPermissions[]')
    egress=$(echo "$sg" | jq -r '.IpPermissionsEgress[]')
    if [ -n "$ingress" ] || [ -n "$egress" ]; then
        unrestricted_default_sgs="$unrestricted_default_sgs$group_id\n"
    fi
done <<< "$(echo "$default_sgs" | jq -c '.[]')"
if [ -z "$unrestricted_default_sgs" ]; then
    append_result "5.5" "PASS" "Ensure the default security group of every VPC restricts all traffic" "All default security groups restrict all traffic." "High" "No action needed."
else
    append_result "5.5" "FAIL" "Ensure the default security group of every VPC restricts all traffic" "Default security groups with open rules: $unrestricted_default_sgs" "High" "1. Go to VPC > Security Groups.\n2. Remove all inbound/outbound rules from default security groups."
fi

# 5.7: Ensure EC2 Metadata Service only allows IMDSv2
echo "Checking CIS 5.7: EC2 Metadata Service uses IMDSv2..."
instances=$(aws ec2 describe-instances --query 'Reservations[].Instances[].{InstanceId:InstanceId,MetadataOptions:MetadataOptions.HttpTokens}' --output json 2>/dev/null)
check_aws_command
non_imdsv2_instances=""
while IFS= read -r instance; do
    instance_id=$(echo "$instance" | jq -r '.InstanceId')
    http_tokens=$(echo "$instance" | jq -r '.MetadataOptions.HttpTokens')
    if [ "$http_tokens" != "required" ]; then
        non_imdsv2_instances="$non_imdsv2_instances$instance_id\n"
    fi
done <<< "$(echo "$instances" | jq -c '.[]')"
if [ -z "$non_imdsv2_instances" ]; then
    append_result "5.7" "PASS" "Ensure EC2 Metadata Service only allows IMDSv2" "All EC2 instances use IMDSv2." "High" "No action needed."
else
    append_result "5.7" "FAIL" "Ensure EC2 Metadata Service only allows IMDSv2" "Instances not using IMDSv2: $non_imdsv2_instances" "High" "1. Run: aws ec2 modify-instance-metadata-options --instance-id <instance_id> --http-tokens required"
fi

# Generate HTML report
generate_html_report

# Display summary
echo -e "\nCompliance Check Summary:"
jq -r '.[] | "\(.check_id): \(.status) - \(.message) (\(.risk))"' "$JSON_OUTPUT"
echo -e "\nDetailed reports saved to: $JSON_OUTPUT (JSON) and $HTML_OUTPUT (HTML)"

# Clean up environment variables
unset AWS_ACCESS_KEY_ID
unset AWS_SECRET_ACCESS_KEY
unset AWS_DEFAULT_REGION

echo "Compliance check completed."
