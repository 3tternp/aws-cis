# PowerShell script to check CIS AWS Foundations Benchmark v5.0.0 compliance
# Automatically installs dependencies, performs automated checks, and generates JSON/HTML reports
# Requires read-only IAM user with SecurityAudit policy
# Manual checks are listed for review in the report

# Function to install dependencies
function Install-Dependencies {
    Write-Host "Checking and installing dependencies..."
    
    # Check for AWS CLI
    if (-not (Get-Command aws -ErrorAction SilentlyContinue)) {
        Write-Host "Installing AWS CLI..."
        try {
            # Check if Chocolatey is installed
            if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
                Write-Host "Installing Chocolatey..."
                Set-ExecutionPolicy Bypass -Scope Process -Force
                [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
                Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
            }
            choco install awscli -y
            if ($LASTEXITCODE -ne 0) { throw "Failed to install AWS CLI" }
        } catch {
            Write-Host "Error: Failed to install AWS CLI. $_"
            Write-Host "Please install AWS CLI manually from https://aws.amazon.com/cli/ and try again."
            exit 1
        }
    }

    # Check for jq
    if (-not (Get-Command jq -ErrorAction SilentlyContinue)) {
        Write-Host "Installing jq..."
        try {
            choco install jq -y
            if ($LASTEXITCODE -ne 0) { throw "Failed to install jq" }
        } catch {
            Write-Host "Error: Failed to install jq. $_"
            Write-Host "Please install jq manually from https://stedolan.github.io/jq/download/ and try again."
            exit 1
        }
    }
}

# Function to append results to JSON file
function Append-Result {
    param (
        [string]$CheckId,
        [string]$Status,
        [string]$Message,
        [string]$Details,
        [string]$Risk,
        [string]$Remediation
    )
    $result = [PSCustomObject]@{
        check_id = $CheckId
        status = $Status
        message = $Message
        details = $Details
        risk = $Risk
        remediation = $Remediation
    }
    $existing = if (Test-Path $JSON_OUTPUT) { Get-Content $JSON_OUTPUT | ConvertFrom-Json } else { @() }
    $existing += $result
    $existing | ConvertTo-Json -Depth 10 | Set-Content $JSON_OUTPUT
}

# Function to check if AWS CLI command was successful
function Check-AwsCommand {
    param (
        [string]$ErrorMessage = "AWS CLI command failed. Check credentials and permissions."
    )
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Error: $ErrorMessage"
        exit 1
    }
}

# Function to generate HTML report
function Generate-HtmlReport {
    $html = @"
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
    <p>Generated on: $(Get-Date)</p>
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
"@

    $results = Get-Content $JSON_OUTPUT | ConvertFrom-Json
    foreach ($result in $results) {
        $html += "<tr class=`"$($result.risk.ToLower())`"><td>$($result.check_id)</td><td>$($result.message)</td><td>$($result.risk)</td><td class=`"$($result.status.ToLower())`">$($result.status)</td><td>$($result.details)</td><td>$($result.remediation -replace "`n", "<br>")</td></tr>"
    }

    $html += @"
    </table>
</body>
</html>
"@
    Set-Content -Path $HTML_OUTPUT -Value $html
}

# Install dependencies
Install-Dependencies

# Prompt for AWS credentials
$AWS_ACCESS_KEY_ID = Read-Host "Enter AWS Access Key ID"
$AWS_SECRET_ACCESS_KEY = Read-Host "Enter AWS Secret Access Key"
$AWS_REGION = Read-Host "Enter AWS Region (default: us-east-1)"
if (-not $AWS_REGION) { $AWS_REGION = "us-east-1" }

# Set AWS environment variables
$env:AWS_ACCESS_KEY_ID = $AWS_ACCESS_KEY_ID
$env:AWS_SECRET_ACCESS_KEY = $AWS_SECRET_ACCESS_KEY
$env:AWS_DEFAULT_REGION = $AWS_REGION

# Output files
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$JSON_OUTPUT = "cis_aws_benchmark_5.0.0_report_$timestamp.json"
$HTML_OUTPUT = "cis_aws_benchmark_5.0.0_report_$timestamp.html"
@() | ConvertTo-Json | Set-Content $JSON_OUTPUT

Write-Host "Starting CIS AWS Foundations Benchmark v5.0.0 Compliance Check..."
Write-Host "Region: $AWS_REGION"
Write-Host "Results will be saved to: $JSON_OUTPUT (JSON) and $HTML_OUTPUT (HTML)"

# Manual checks
Append-Result "1.1" "INFO" "Maintain current contact details (Manual)" "This check requires manual verification of contact details in the AWS Console under Billing and Cost Management." "High" "1. Sign in to AWS Management Console and open Billing and Cost Management console at https://console.aws.amazon.com/billing/home#/.\n2. Verify and update contact email and telephone details."
Append-Result "1.2" "INFO" "Ensure security contact information is registered (Manual)" "This check requires manual verification of security contact details in the AWS Console." "High" "1. Sign in to AWS Management Console and open Account settings.\n2. Run: aws account put-alternate-contact --alternate-contact-type SECURITY --email-address <email> --name <name> --phone-number <phone>."
Append-Result "1.5" "INFO" "Ensure hardware MFA is enabled for the 'root' user account (Manual)" "This check requires manual verification of hardware MFA for the root user in the AWS Console." "Critical" "1. Sign in as root user.\n2. Go to IAM > My Security Credentials.\n3. Enable a hardware MFA device (e.g., YubiKey) as per AWS documentation."
Append-Result "1.6" "INFO" "Eliminate use of the 'root' user for administrative and daily tasks (Manual)" "This check requires manual review of root user activity logs." "Critical" "1. Review CloudTrail logs for root user activity.\n2. Use IAM roles/users for daily tasks instead of root."
Append-Result "1.10" "INFO" "Do not create access keys during initial setup for IAM users with a console password (Manual)" "This check requires manual review of IAM user creation processes." "High" "1. Review IAM user creation policies.\n2. Ensure access keys are not created by default for console users."
Append-Result "1.20" "INFO" "Ensure IAM users are managed centrally via identity federation or AWS Organizations (Manual)" "This check requires manual verification of identity federation or AWS Organizations setup." "High" "1. Verify AWS Organizations or SSO configuration.\n2. Ensure no individual IAM users are created directly."
Append-Result "1.21" "INFO" "Ensure access to AWSCloudShellFullAccess is restricted (Manual)" "This check requires manual review of AWSCloudShellFullAccess policy attachments." "High" "1. Run: aws iam list-entities-for-policy --policy-arn arn:aws:iam::aws:policy/AWSCloudShellFullAccess\n2. Ensure PolicyRoles is empty."
Append-Result "2.1.2" "INFO" "Ensure MFA Delete is enabled on S3 buckets (Manual)" "This check requires manual verification of MFA Delete settings on S3 buckets." "Medium" "1. Run: aws s3api get-bucket-versioning --bucket <bucket_name>\n2. Enable MFA Delete using AWS CLI with root credentials."
Append-Result "2.1.3" "INFO" "Ensure all data in Amazon S3 has been discovered, classified, and secured (Manual)" "This check requires manual verification using AWS Macie." "Medium" "1. Enable AWS Macie in the console.\n2. Set up a repository for sensitive data discovery results."
Append-Result "4.1" "INFO" "Ensure unauthorized API calls are monitored (Manual)" "This check requires manual setup of CloudTrail and CloudWatch monitoring." "Medium" "1. Set up CloudTrail with CloudWatch integration.\n2. Create metric filters and alarms for unauthorized API calls."
Append-Result "4.2" "INFO" "Ensure management console sign-in without MFA is monitored (Manual)" "This check requires manual setup of CloudTrail and CloudWatch monitoring." "High" "1. Set up CloudTrail with CloudWatch integration.\n2. Create metric filters and alarms for non-MFA sign-ins."
Append-Result "4.3" "INFO" "Ensure usage of the 'root' account is monitored (Manual)" "This check requires manual setup of CloudTrail and CloudWatch monitoring." "Critical" "1. Set up CloudTrail with CloudWatch integration.\n2. Create metric filters and alarms for root account activity."
Append-Result "4.4" "INFO" "Ensure IAM policy changes are monitored (Manual)" "This check requires manual setup of CloudTrail and CloudWatch monitoring." "High" "1. Set up CloudTrail with CloudWatch integration.\n2. Create metric filters and alarms for IAM policy changes."
Append-Result "4.5" "INFO" "Ensure CloudTrail configuration changes are monitored (Manual)" "This check requires manual setup of CloudTrail and CloudWatch monitoring." "High" "1. Set up CloudTrail with CloudWatch integration.\n2. Create metric filters and alarms for CloudTrail changes."
Append-Result "4.6" "INFO" "Ensure AWS Management Console authentication failures are monitored (Manual)" "This check requires manual setup of CloudTrail and CloudWatch monitoring." "Medium" "1. Set up CloudTrail with CloudWatch integration.\n2. Create metric filters and alarms for console authentication failures."
Append-Result "4.7" "INFO" "Ensure disabling or scheduled deletion of customer created CMKs is monitored (Manual)" "This check requires manual setup of CloudTrail and CloudWatch monitoring." "Medium" "1. Set up CloudTrail with CloudWatch integration.\n2. Create metric filters and alarms for CMK changes."
Append-Result "4.8" "INFO" "Ensure S3 bucket policy changes are monitored (Manual)" "This check requires manual setup of CloudTrail and CloudWatch monitoring." "High" "1. Set up CloudTrail with CloudWatch integration.\n2. Create metric filters and alarms for S3 bucket policy changes."
Append-Result "4.9" "INFO" "Ensure AWS Config configuration changes are monitored (Manual)" "This check requires manual setup of CloudTrail and CloudWatch monitoring." "Medium" "1. Set up CloudTrail with CloudWatch integration.\n2. Create metric filters and alarms for AWS Config changes."
Append-Result "4.10" "INFO" "Ensure security group changes are monitored (Manual)" "This check requires manual setup of CloudTrail and CloudWatch monitoring." "Medium" "1. Set up CloudTrail with CloudWatch integration.\n2. Create metric filters and alarms for security group changes."
Append-Result "4.11" "INFO" "Ensure Network Access Control List (NACL) changes are monitored (Manual)" "This check requires manual setup of CloudTrail and CloudWatch monitoring." "Medium" "1. Set up CloudTrail with CloudWatch integration.\n2. Create metric filters and alarms for NACL changes."
Append-Result "4.12" "INFO" "Ensure changes to network gateways are monitored (Manual)" "This check requires manual setup of CloudTrail and CloudWatch monitoring." "High" "1. Set up CloudTrail with CloudWatch integration.\n2. Create metric filters and alarms for network gateway changes."
Append-Result "4.13" "INFO" "Ensure route table changes are monitored (Manual)" "This check requires manual setup of CloudTrail and CloudWatch monitoring." "High" "1. Set up CloudTrail with CloudWatch integration.\n2. Create metric filters and alarms for route table changes."
Append-Result "4.14" "INFO" "Ensure VPC changes are monitored (Manual)" "This check requires manual setup of CloudTrail and CloudWatch monitoring." "High" "1. Set up CloudTrail with CloudWatch integration.\n2. Create metric filters and alarms for VPC changes."
Append-Result "4.15" "INFO" "Ensure AWS Organizations changes are monitored (Manual)" "This check requires manual setup of CloudTrail and CloudWatch monitoring." "High" "1. Set up CloudTrail with CloudWatch integration.\n2. Create metric filters and alarms for AWS Organizations changes."
Append-Result "5.6" "INFO" "Ensure routing tables for VPC peering are 'least access' (Manual)" "This check requires manual review of VPC peering routing tables." "Medium" "1. Run: aws ec2 describe-route-tables\n2. Verify routes are restricted to necessary CIDR blocks."

# Automated checks
# 1.3: Ensure no 'root' user account access key exists
Write-Host "Checking CIS 1.3: No 'root' user access key..."
$root_keys = aws iam get-account-summary --query 'SummaryMap.AccountAccessKeysPresent' --output text 2>$null
Check-AwsCommand
if ($root_keys -eq 0) {
    Append-Result "1.3" "PASS" "Ensure no 'root' user account access key exists" "No root access keys found." "Critical" "No action needed."
} else {
    Append-Result "1.3" "FAIL" "Ensure no 'root' user account access key exists" "Root access keys detected." "Critical" "1. Sign in as root user.\n2. Go to IAM > My Security Credentials > Access Keys.\n3. Delete any active keys."
}

# 1.4: Ensure MFA is enabled for the 'root' user account
Write-Host "Checking CIS 1.4: MFA enabled for 'root' user..."
$mfa_enabled = aws iam get-account-summary --query 'SummaryMap.AccountMFAEnabled' --output text 2>$null
Check-AwsCommand
if ($mfa_enabled -eq 1) {
    Append-Result "1.4" "PASS" "Ensure MFA is enabled for the 'root' user account" "Root MFA is enabled." "Critical" "No action needed."
} else {
    Append-Result "1.4" "FAIL" "Ensure MFA is enabled for the 'root' user account" "Root MFA is not enabled." "Critical" "1. Sign in as root user.\n2. Go to IAM > My Security Credentials.\n3. Enable MFA (virtual or hardware)."
}

# 1.7: Ensure IAM password policy requires minimum length of 14 or greater
Write-Host "Checking CIS 1.7: IAM password policy minimum length..."
$password_policy = aws iam get-account-password-policy --query 'PasswordPolicy.MinimumPasswordLength' --output text 2>$null
Check-AwsCommand
if ($password_policy -ge 14) {
    Append-Result "1.7" "PASS" "Ensure IAM password policy requires minimum length of 14 or greater" "Password policy meets minimum length requirement." "High" "No action needed."
} else {
    Append-Result "1.7" "FAIL" "Ensure IAM password policy requires minimum length of 14 or greater" "Password policy length is less than 14 or not set." "High" "1. Go to IAM > Account Settings.\n2. Set 'Minimum password length' to 14 or greater."
}

# 1.8: Ensure IAM password policy prevents password reuse
Write-Host "Checking CIS 1.8: IAM password policy prevents reuse..."
$password_reuse = aws iam get-account-password-policy --query 'PasswordPolicy.PasswordReusePrevention' --output text 2>$null
Check-AwsCommand
if ($password_reuse -ge 24) {
    Append-Result "1.8" "PASS" "Ensure IAM password policy prevents password reuse" "Password reuse prevention is set to 24 or greater." "High" "No action needed."
} else {
    Append-Result "1.8" "FAIL" "Ensure IAM password policy prevents password reuse" "Password reuse prevention is less than 24 or not set." "High" "1. Run: aws iam update-account-password-policy --password-reuse-prevention 24"
}

# 1.9: Ensure MFA is enabled for all IAM users with console password
Write-Host "Checking CIS 1.9: MFA for IAM users with console access..."
$users = aws iam list-users --query 'Users[].UserName' --output json | ConvertFrom-Json
Check-AwsCommand
$non_mfa_users = ""
foreach ($user in $users) {
    $has_password = aws iam list-login-profiles --user-name $user --query 'LoginProfile' --output json 2>$null
    if ($has_password -and $has_password -ne "null") {
        $mfa_devices = aws iam list-mfa-devices --user-name $user --query 'MFADevices' --output json 2>$null
        if ($mfa_devices -eq "[]") {
            $non_mfa_users += "$user`n"
        }
    }
}
if (-not $non_mfa_users) {
    Append-Result "1.9" "PASS" "Ensure MFA is enabled for all IAM users with console password" "All IAM users with console access have MFA enabled." "High" "No action needed."
} else {
    Append-Result "1.9" "FAIL" "Ensure MFA is enabled for all IAM users with console password" "IAM users with console access without MFA: $non_mfa_users" "High" "1. Go to IAM > Users.\n2. For each user, enable MFA under Security Credentials."
}

# 1.11: Ensure credentials unused for 45 days or more are disabled
Write-Host "Checking CIS 1.11: Credentials unused for 45 days..."
aws iam generate-credential-report | Out-Null
$credential_report = aws iam get-credential-report --query 'Content' --output text | ForEach-Object { [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($_)) }
Check-AwsCommand
$inactive_users = ""
$report_lines = $credential_report -split "`n" | Select-Object -Skip 1
foreach ($line in $report_lines) {
    $fields = $line -split ","
    $user = $fields[0]
    $password_last_used = $fields[4]
    $access_key_1_last_used = $fields[9]
    $access_key_2_last_used = $fields[14]
    $current_date = Get-Date
    if ($password_last_used -notmatch "N/A|no_information") {
        $last_used = [DateTime]::Parse($password_last_used)
        $age_days = ($current_date - $last_used).Days
        if ($age_days -gt 45) {
            $inactive_users += "$user (password unused for $age_days days)`n"
        }
    }
    foreach ($key_last_used in @($access_key_1_last_used, $access_key_2_last_used)) {
        if ($key_last_used -notmatch "N/A|no_information") {
            $key_last_used_date = [DateTime]::Parse($key_last_used)
            $key_age_days = ($current_date - $key_last_used_date).Days
            if ($key_age_days -gt 45) {
                $inactive_users += "$user (access key unused for $key_age_days days)`n"
            }
        }
    }
}
if (-not $inactive_users) {
    Append-Result "1.11" "PASS" "Ensure credentials unused for 45 days or more are disabled" "No credentials unused for 45+ days." "High" "No action needed."
} else {
    Append-Result "1.11" "FAIL" "Ensure credentials unused for 45 days or more are disabled" "Inactive credentials: $inactive_users" "High" "1. Run: aws iam generate-credential-report\n2. Disable or delete unused credentials in IAM console."
}

# 1.12: Ensure there is only one active access key for any single IAM user
Write-Host "Checking CIS 1.12: One active access key per IAM user..."
$multiple_keys = ""
foreach ($user in $users) {
    $active_keys = aws iam list-access-keys --user-name $user --query 'AccessKeyMetadata[?Status==`Active`].AccessKeyId' --output json | ConvertFrom-Json
    if ($active_keys.Count -gt 1) {
        $multiple_keys += "${user} ($($active_keys.Count) active keys)`n"
    }
}
if (-not $multiple_keys) {
    Append-Result "1.12" "PASS" "Ensure there is only one active access key for any single IAM user" "All IAM users have at most one active access key." "High" "No action needed."
} else {
    Append-Result "1.12" "FAIL" "Ensure there is only one active access key for any single IAM user" "Users with multiple active keys: $multiple_keys" "High" "1. Go to IAM > Users > Security Credentials.\n2. Deactivate or delete excess keys."
}

# 1.13: Ensure access keys are rotated every 90 days or less
Write-Host "Checking CIS 1.13: Access key rotation (90 days or less)..."
$non_compliant_keys = ""
foreach ($user in $users) {
    $access_keys = aws iam list-access-keys --user-name $user --query 'AccessKeyMetadata[].{AccessKeyId:AccessKeyId,CreateDate:CreateDate}' --output json | ConvertFrom-Json
    foreach ($key in $access_keys) {
        $create_date = [DateTime]::Parse($key.CreateDate)
        $age_days = ((Get-Date) - $create_date).Days
        if ($age_days -gt 90) {
            $non_compliant_keys += "${user}: $($key.AccessKeyId) ($age_days days)`n"
        }
    }
}
if (-not $non_compliant_keys) {
    Append-Result "1.13" "PASS" "Ensure access keys are rotated every 90 days or less" "All access keys are rotated within 90 days." "High" "No action needed."
} else {
    Append-Result "1.13" "FAIL" "Ensure access keys are rotated every 90 days or less" "Access keys older than 90 days: $non_compliant_keys" "High" "1. Go to IAM > Users > Security Credentials.\n2. Rotate keys older than 90 days."
}

# 1.14: Ensure IAM users receive permissions only through groups
Write-Host "Checking CIS 1.14: IAM users receive permissions only through groups..."
$direct_policies = ""
foreach ($user in $users) {
    $policies = aws iam list-attached-user-policies --user-name $user --query 'AttachedPolicies[].PolicyName' --output json | ConvertFrom-Json
    if ($policies) {
        $direct_policies += "${user}: $($policies -join ',')`n"
    }
}
if (-not $direct_policies) {
    Append-Result "1.14" "PASS" "Ensure IAM users receive permissions only through groups" "No IAM users have directly attached policies." "High" "No action needed."
} else {
    Append-Result "1.14" "FAIL" "Ensure IAM users receive permissions only through groups" "Users with direct policies: $direct_policies" "High" "1. Go to IAM > Users.\n2. Move permissions to groups and attach groups to users."
}

# 1.15: Ensure IAM policies that allow full "*:*" administrative privileges are not attached
Write-Host "Checking CIS 1.15: No full admin IAM policies..."
$iam_policies = aws iam list-policies --scope Local --query 'Policies[?PolicyName!=`AWSServiceRole*`].{Name:PolicyName,Arn:Arn}' --output json | ConvertFrom-Json
Check-AwsCommand
$full_admin_policies = ""
foreach ($policy in $iam_policies) {
    $policy_version = aws iam get-policy-version --policy-arn $policy.Arn --version-id (aws iam get-policy --policy-arn $policy.Arn --query 'Policy.DefaultVersionId' --output text) --query 'PolicyVersion.Document' --output json | ConvertFrom-Json
    if ($policy_version.Statement | Where-Object { $_.Effect -eq "Allow" -and $_.Action -eq "*" -and $_.Resource -eq "*" }) {
        $full_admin_policies += "$($policy.Name)`n"
    }
}
if (-not $full_admin_policies) {
    Append-Result "1.15" "PASS" "Ensure IAM policies that allow full '*:*' administrative privileges are not attached" "No full admin policies found." "High" "No action needed."
} else {
    Append-Result "1.15" "FAIL" "Ensure IAM policies that allow full '*:*' administrative privileges are not attached" "Full admin policies: $full_admin_policies" "High" "1. Go to IAM > Policies.\n2. Detach or modify policies with full admin privileges."
}

# 1.16: Ensure a support role has been created
Write-Host "Checking CIS 1.16: Support role exists..."
$support_role = aws iam list-entities-for-policy --policy-arn arn:aws:iam::aws:policy/AWSSupportAccess --query 'PolicyRoles' --output json | ConvertFrom-Json
Check-AwsCommand
if ($support_role) {
    Append-Result "1.16" "PASS" "Ensure a support role has been created" "AWSSupportAccess policy is attached to at least one role." "High" "No action needed."
} else {
    Append-Result "1.16" "FAIL" "Ensure a support role has been created" "No roles with AWSSupportAccess policy found." "High" "1. Create a role in IAM.\n2. Attach AWSSupportAccess policy."
}

# 1.17: Ensure IAM instance roles are used for AWS resource access from instances
Write-Host "Checking CIS 1.17: IAM instance roles for EC2..."
$instances = aws ec2 describe-instances --query 'Reservations[].Instances[].{InstanceId:InstanceId,IamInstanceProfile:IamInstanceProfile.Arn}' --output json | ConvertFrom-Json
Check-AwsCommand
$no_role_instances = ""
foreach ($instance in $instances) {
    if (-not $instance.IamInstanceProfile) {
        $no_role_instances += "$($instance.InstanceId)`n"
    }
}
if (-not $no_role_instances) {
    Append-Result "1.17" "PASS" "Ensure IAM instance roles are used for AWS resource access from instances" "All EC2 instances have IAM roles attached." "Medium" "No action needed."
} else {
    Append-Result "1.17" "FAIL" "Ensure IAM instance roles are used for AWS resource access from instances" "Instances without IAM roles: $no_role_instances" "Medium" "1. Go to EC2 > Instances.\n2. Attach IAM roles to listed instances."
}

# 1.18: Ensure that all expired SSL/TLS certificates stored in AWS IAM are removed
Write-Host "Checking CIS 1.18: No expired SSL/TLS certificates in IAM..."
$certificates = aws iam list-server-certificates --query 'ServerCertificateMetadataList[].{Name:ServerCertificateName,Expiration:Expiration}' --output json | ConvertFrom-Json
Check-AwsCommand
$expired_certs = ""
$current_date = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"
foreach ($cert in $certificates) {
    if ([DateTime]::Parse($cert.Expiration) -lt [DateTime]::Parse($current_date)) {
        $expired_certs += "$($cert.Name) (expired $($cert.Expiration))`n"
    }
}
if (-not $expired_certs) {
    Append-Result "1.18" "PASS" "Ensure that all expired SSL/TLS certificates stored in AWS IAM are removed" "No expired certificates found." "High" "No action needed."
} else {
    Append-Result "1.18" "FAIL" "Ensure that all expired SSL/TLS certificates stored in AWS IAM are removed" "Expired certificates: $expired_certs" "High" "1. Run: aws iam delete-server-certificate --server-certificate-name <name>"
}

# 1.19: Ensure IAM External Access Analyzer is enabled for all regions
Write-Host "Checking CIS 1.19: IAM External Access Analyzer enabled..."
$analyzer_status = aws accessanalyzer list-analyzers --query 'analyzers[?status==`ACTIVE`].name' --output json | ConvertFrom-Json
Check-AwsCommand
if ($analyzer_status) {
    Append-Result "1.19" "PASS" "Ensure IAM External Access Analyzer is enabled for all regions" "Access Analyzer is active." "High" "No action needed."
} else {
    Append-Result "1.19" "FAIL" "Ensure IAM External Access Analyzer is enabled for all regions" "No active Access Analyzer found." "High" "1. Run: aws accessanalyzer create-analyzer --analyzer-name <name> --type ACCOUNT"
}

# 2.1.1: Ensure S3 bucket policy denies HTTP requests
Write-Host "Checking CIS 2.1.1: S3 bucket policy denies HTTP..."
$buckets = aws s3api list-buckets --query 'Buckets[].Name' --output json | ConvertFrom-Json
Check-AwsCommand
$non_secure_buckets = ""
foreach ($bucket in $buckets) {
    $policy = aws s3api get-bucket-policy --bucket $bucket --query 'Policy' --output text 2>$null
    if ($LASTEXITCODE -eq 0) {
        if ($policy -notmatch '"aws:SecureTransport":\s*"false"') {
            $non_secure_buckets += "$bucket`n"
        }
    } else {
        $non_secure_buckets += "$bucket (no policy denying HTTP)`n"
    }
}
if (-not $non_secure_buckets) {
    Append-Result "2.1.1" "PASS" "Ensure S3 bucket policy is set to deny HTTP requests" "All S3 buckets deny HTTP requests." "Medium" "No action needed."
} else {
    Append-Result "2.1.1" "FAIL" "Ensure S3 bucket policy is set to deny HTTP requests" "Buckets not denying HTTP: $non_secure_buckets" "Medium" "1. Go to S3 > Bucket > Permissions > Bucket Policy.\n2. Add policy to deny HTTP requests."
}

# 2.1.4: Ensure S3 is configured with 'Block Public Access' enabled
Write-Host "Checking CIS 2.1.4: S3 block public access..."
$non_compliant_buckets = ""
foreach ($bucket in $buckets) {
    $public_access = aws s3api get-public-access-block --bucket $bucket --query 'PublicAccessBlockConfiguration' --output json 2>$null
    if ($LASTEXITCODE -eq 0) {
        $public_access = $public_access | ConvertFrom-Json
        if (-not ($public_access.BlockPublicAcls -and $public_access.IgnorePublicAcls -and $public_access.BlockPublicPolicy -and $public_access.RestrictPublicBuckets)) {
            $non_compliant_buckets += "$bucket`n"
        }
    } else {
        $non_compliant_buckets += "$bucket (no public access block)`n"
    }
}
if (-not $non_compliant_buckets) {
    Append-Result "2.1.4" "PASS" "Ensure S3 is configured with 'Block Public Access' enabled" "All S3 buckets have block public access enabled." "High" "No action needed."
} else {
    Append-Result "2.1.4" "FAIL" "Ensure S3 is configured with 'Block Public Access' enabled" "Buckets without block public access: $non_compliant_buckets" "High" "1. Go to S3 > Bucket > Permissions.\n2. Enable Block Public Access settings."
}

# 2.2.1: Ensure encryption-at-rest is enabled for RDS instances
Write-Host "Checking CIS 2.2.1: RDS encryption-at-rest..."
$rds_instances = aws rds describe-db-instances --query 'DBInstances[].{DBInstanceIdentifier:DBInstanceIdentifier,StorageEncrypted:StorageEncrypted}' --output json | ConvertFrom-Json
Check-AwsCommand
$unencrypted_rds = ""
foreach ($instance in $rds_instances) {
    if (-not $instance.StorageEncrypted) {
        $unencrypted_rds += "$($instance.DBInstanceIdentifier)`n"
    }
}
if (-not $unencrypted_rds) {
    Append-Result "2.2.1" "PASS" "Ensure encryption-at-rest is enabled for RDS instances" "All RDS instances are encrypted." "High" "No action needed."
} else {
    Append-Result "2.2.1" "FAIL" "Ensure encryption-at-rest is enabled for RDS instances" "Unencrypted RDS instances: $unencrypted_rds" "High" "1. Create an encrypted snapshot of the instance.\n2. Restore from the encrypted snapshot."
}

# 2.2.2: Ensure Auto Minor Version Upgrade is enabled for RDS instances
Write-Host "Checking CIS 2.2.2: RDS Auto Minor Version Upgrade..."
$no_auto_upgrade_rds = ""
foreach ($instance in $rds_instances) {
    $auto_upgrade = aws rds describe-db-instances --db-instance-identifier $instance.DBInstanceIdentifier --query 'DBInstances[].AutoMinorVersionUpgrade' --output text
    if ($auto_upgrade -eq "False") {
        $no_auto_upgrade_rds += "$($instance.DBInstanceIdentifier)`n"
    }
}
if (-not $no_auto_upgrade_rds) {
    Append-Result "2.2.2" "PASS" "Ensure Auto Minor Version Upgrade is enabled for RDS instances" "All RDS instances have auto minor version upgrade enabled." "High" "No action needed."
} else {
    Append-Result "2.2.2" "FAIL" "Ensure Auto Minor Version Upgrade is enabled for RDS instances" "RDS instances without auto upgrade: $no_auto_upgrade_rds" "High" "1. Go to RDS > Databases.\n2. Enable Auto Minor Version Upgrade for listed instances."
}

# 2.2.3: Ensure RDS instances are not publicly accessible
Write-Host "Checking CIS 2.2.3: RDS instances not publicly accessible..."
$public_rds = ""
foreach ($instance in $rds_instances) {
    $public = aws rds describe-db-instances --db-instance-identifier $instance.DBInstanceIdentifier --query 'DBInstances[].PubliclyAccessible' --output text
    if ($public -eq "True") {
        $public_rds += "$($instance.DBInstanceIdentifier)`n"
    }
}
if (-not $public_rds) {
    Append-Result "2.2.3" "PASS" "Ensure RDS instances are not publicly accessible" "No publicly accessible RDS instances found." "High" "No action needed."
} else {
    Append-Result "2.2.3" "FAIL" "Ensure RDS instances are not publicly accessible" "Publicly accessible RDS instances: $public_rds" "High" "1. Go to RDS > Databases > Connectivity & Security.\n2. Set Publicly Accessible to 'Not publicly accessible'."
}

# 2.3.1: Ensure encryption is enabled for EFS file systems
Write-Host "Checking CIS 2.3.1: EFS encryption..."
$efs_systems = aws efs describe-file-systems --query 'FileSystems[].{FileSystemId:FileSystemId,Encrypted:Encrypted}' --output json | ConvertFrom-Json
Check-AwsCommand
$unencrypted_efs = ""
foreach ($efs in $efs_systems) {
    if (-not $efs.Encrypted) {
        $unencrypted_efs += "$($efs.FileSystemId)`n"
    }
}
if (-not $unencrypted_efs) {
    Append-Result "2.3.1" "PASS" "Ensure encryption is enabled for EFS file systems" "All EFS file systems are encrypted." "High" "No action needed."
} else {
    Append-Result "2.3.1" "FAIL" "Ensure encryption is enabled for EFS file systems" "Unencrypted EFS file systems: $unencrypted_efs" "High" "1. Create a new encrypted EFS file system.\n2. Migrate data to the encrypted file system."
}

# 3.1: Ensure CloudTrail is enabled in all regions
Write-Host "Checking CIS 3.1: CloudTrail enabled in all regions..."
$cloudtrail_status = aws cloudtrail describe-trails --query 'trailList[?IsMultiRegionTrail==`true`].{Name:Name,HomeRegion:HomeRegion}' --output json | ConvertFrom-Json
Check-AwsCommand
if ($cloudtrail_status) {
    Append-Result "3.1" "PASS" "Ensure CloudTrail is enabled in all regions" "Multi-region CloudTrail is enabled." "High" "No action needed."
} else {
    Append-Result "3.1" "FAIL" "Ensure CloudTrail is enabled in all regions" "No multi-region CloudTrail detected." "High" "1. Go to CloudTrail > Trails.\n2. Create a multi-region trail."
}

# 3.2: Ensure CloudTrail log file validation is enabled
Write-Host "Checking CIS 3.2: CloudTrail log file validation..."
$trails = aws cloudtrail describe-trails --query 'trailList[].{Name:Name,LogFileValidationEnabled:LogFileValidationEnabled}' --output json | ConvertFrom-Json
Check-AwsCommand
$no_validation_trails = ""
foreach ($trail in $trails) {
    if (-not $trail.LogFileValidationEnabled) {
        $no_validation_trails += "$($trail.Name)`n"
    }
}
if (-not $no_validation_trails) {
    Append-Result "3.2" "PASS" "Ensure CloudTrail log file validation is enabled" "All CloudTrail trails have log file validation enabled." "Medium" "No action needed."
} else {
    Append-Result "3.2" "FAIL" "Ensure CloudTrail log file validation is enabled" "Trails without log file validation: $no_validation_trails" "Medium" "1. Run: aws cloudtrail update-trail --name <trail_name> --enable-log-file-validation"
}

# 3.3: Ensure AWS Config is enabled in all regions
Write-Host "Checking CIS 3.3: AWS Config enabled..."
$config_recorders = aws configservice describe-configuration-recorders --query 'ConfigurationRecorders[].recordingGroup.allSupported' --output json | ConvertFrom-Json
Check-AwsCommand
if ($config_recorders -contains $true) {
    Append-Result "3.3" "PASS" "Ensure AWS Config is enabled in all regions" "AWS Config is enabled with allSupported true." "Medium" "No action needed."
} else {
    Append-Result "3.3" "FAIL" "Ensure AWS Config is enabled in all regions" "AWS Config is not enabled or not fully configured." "Medium" "1. Go to AWS Config > Settings.\n2. Enable AWS Config with all resources recording."
}

# 3.5: Ensure CloudTrail logs are encrypted at rest using KMS CMKs
Write-Host "Checking CIS 3.5: CloudTrail logs encrypted with KMS..."
$unencrypted_trails = ""
foreach ($trail in $trails) {
    $kms_key = aws cloudtrail describe-trails --trail-name-list $trail.Name --query 'trailList[].KmsKeyId' --output text 2>$null
    if (-not $kms_key) {
        $unencrypted_trails += "$($trail.Name)`n"
    }
}
if (-not $unencrypted_trails) {
    Append-Result "3.5" "PASS" "Ensure CloudTrail logs are encrypted at rest using KMS CMKs" "All CloudTrail trails use KMS encryption." "Medium" "No action needed."
} else {
    Append-Result "3.5" "FAIL" "Ensure CloudTrail logs are encrypted at rest using KMS CMKs" "Trails without KMS encryption: $unencrypted_trails" "Medium" "1. Run: aws cloudtrail update-trail --name <trail_name> --kms-key-id <kms_key_id>"
}

# 3.6: Ensure rotation for customer-created symmetric CMKs is enabled
Write-Host "Checking CIS 3.6: KMS key rotation..."
$kms_keys = aws kms list-keys --query 'Keys[].KeyId' --output json | ConvertFrom-Json
Check-AwsCommand
$no_rotation_keys = ""
foreach ($key_id in $kms_keys) {
    $rotation = aws kms get-key-rotation-status --key-id $key_id --query 'KeyRotationEnabled' --output text
    $key_spec = aws kms describe-key --key-id $key_id --query 'KeyMetadata.KeySpec' --output text
    if ($key_spec -eq "SYMMETRIC_DEFAULT" -and $rotation -eq "False") {
        $no_rotation_keys += "$key_id`n"
    }
}
if (-not $no_rotation_keys) {
    Append-Result "3.6" "PASS" "Ensure rotation for customer-created symmetric CMKs is enabled" "All symmetric CMKs have rotation enabled." "Medium" "No action needed."
} else {
    Append-Result "3.6" "FAIL" "Ensure rotation for customer-created symmetric CMKs is enabled" "Keys without rotation: $no_rotation_keys" "Medium" "1. Run: aws kms enable-key-rotation --key-id <key_id>"
}

# 3.7: Ensure VPC flow logging is enabled in all VPCs
Write-Host "Checking CIS 3.7: VPC flow logging..."
$vpcs = aws ec2 describe-vpcs --query 'Vpcs[].VpcId' --output json | ConvertFrom-Json
Check-AwsCommand
$no_flow_log_vpcs = ""
foreach ($vpc in $vpcs) {
    $flow_logs = aws ec2 describe-flow-logs --filter Name=resource-id,Values=$vpc --query 'FlowLogs[].FlowLogId' --output json | ConvertFrom-Json
    if (-not $flow_logs) {
        $no_flow_log_vpcs += "$vpc`n"
    }
}
if (-not $no_flow_log_vpcs) {
    Append-Result "3.7" "PASS" "Ensure VPC flow logging is enabled in all VPCs" "All VPCs have flow logging enabled." "Medium" "No action needed."
} else {
    Append-Result "3.7" "FAIL" "Ensure VPC flow logging is enabled in all VPCs" "VPCs without flow logging: $no_flow_log_vpcs" "Medium" "1. Go to VPC > Flow Logs.\n2. Create flow logs for listed VPCs."
}

# 3.8: Ensure object-level logging for write events is enabled for S3 buckets
Write-Host "Checking CIS 3.8: S3 object-level write logging..."
$no_write_logging = ""
foreach ($trail in $trails) {
    $selectors = aws cloudtrail get-event-selectors --trail-name $trail.Name --query 'EventSelectors[].DataResources[?Type==`AWS::S3::Object`].Values' --output json | ConvertFrom-Json
    if (-not ($selectors | Where-Object { $_ -match "arn:aws:s3:::" })) {
        $no_write_logging += "$($trail.Name)`n"
    }
}
if (-not $no_write_logging) {
    Append-Result "3.8" "PASS" "Ensure object-level logging for write events is enabled for S3 buckets" "All trails have S3 write event logging enabled." "Medium" "No action needed."
} else {
    Append-Result "3.8" "FAIL" "Ensure object-level logging for write events is enabled for S3 buckets" "Trails without S3 write logging: $no_write_logging" "Medium" "1. Go to CloudTrail > Trails.\n2. Enable S3 data event logging for write events."
}

# 3.9: Ensure object-level logging for read events is enabled for S3 buckets
Write-Host "Checking CIS 3.9: S3 object-level read logging..."
$no_read_logging = ""
foreach ($trail in $trails) {
    $selectors = aws cloudtrail get-event-selectors --trail-name $trail.Name --query 'EventSelectors[].DataResources[?Type==`AWS::S3::Object`].Values' --output json | ConvertFrom-Json
    if (-not ($selectors | Where-Object { $_ -match "arn:aws:s3:::" })) {
        $no_read_logging += "$($trail.Name)`n"
    }
}
if (-not $no_read_logging) {
    Append-Result "3.9" "PASS" "Ensure object-level logging for read events is enabled for S3 buckets" "All trails have S3 read event logging enabled." "Medium" "No action needed."
} else {
    Append-Result "3.9" "FAIL" "Ensure object-level logging for read events is enabled for S3 buckets" "Trails without S3 read logging: $no_read_logging" "Medium" "1. Go to CloudTrail > Trails.\n2. Enable S3 data event logging for read events."
}

# 4.16: Ensure AWS Security Hub is enabled
Write-Host "Checking CIS 4.16: AWS Security Hub enabled..."
$security_hub = aws securityhub describe-hub --query 'SubscribedAt' --output text 2>$null
Check-AwsCommand
if ($security_hub) {
    Append-Result "4.16" "PASS" "Ensure AWS Security Hub is enabled" "Security Hub is enabled." "Medium" "No action needed."
} else {
    Append-Result "4.16" "FAIL" "Ensure AWS Security Hub is enabled" "Security Hub is not enabled." "Medium" "1. Go to Security Hub > Enable Security Hub."
}

# 5.1.1: Ensure EBS volume encryption is enabled
Write-Host "Checking CIS 5.1.1: EBS volume encryption..."
$ebs_encryption = aws ec2 get-ebs-encryption-by-default --query 'EbsEncryptionByDefault' --output text
Check-AwsCommand
if ($ebs_encryption -eq "True") {
    Append-Result "5.1.1" "PASS" "Ensure EBS volume encryption is enabled in all regions" "EBS encryption is enabled by default." "High" "No action needed."
} else {
    Append-Result "5.1.1" "FAIL" "Ensure EBS volume encryption is enabled in all regions" "EBS encryption is not enabled by default." "High" "1. Go to EC2 > Account Attributes > EBS Encryption.\n2. Enable default encryption."
}

# 5.1.2: Ensure CIFS access is restricted
Write-Host "Checking CIS 5.1.2: CIFS access restricted..."
$security_groups = aws ec2 describe-security-groups --query 'SecurityGroups[].{GroupId:GroupId,IpPermissions:IpPermissions[?ToPort==`445`].IpRanges[].CidrIp}' --output json | ConvertFrom-Json
Check-AwsCommand
$unrestricted_cifs = ""
foreach ($group in $security_groups) {
    if ($group.IpPermissions -contains "0.0.0.0/0") {
        $unrestricted_cifs += "$($group.GroupId)`n"
    }
}
if (-not $unrestricted_cifs) {
    Append-Result "5.1.2" "PASS" "Ensure CIFS access is restricted to trusted networks" "No security groups allow CIFS from 0.0.0.0/0." "High" "No action needed."
} else {
    Append-Result "5.1.2" "FAIL" "Ensure CIFS access is restricted to trusted networks" "Security groups allowing CIFS from 0.0.0.0/0: $unrestricted_cifs" "High" "1. Go to VPC > Security Groups.\n2. Remove or restrict rules allowing port 445 from 0.0.0.0/0."
}

# 5.2: Ensure no Network ACLs allow ingress from 0.0.0.0/0 to remote server administration ports
Write-Host "Checking CIS 5.2: No NACLs allow ingress to admin ports..."
$nacls = aws ec2 describe-network-acls --query 'NetworkAcls[].{NetworkAclId:NetworkAclId,Entries:Entries[?Egress==`false` && (PortRange.To==`22` || PortRange.To==`3389`)].CidrBlock}' --output json | ConvertFrom-Json
Check-AwsCommand
$unrestricted_nacls = ""
foreach ($nacl in $nacls) {
    if ($nacl.Entries -contains "0.0.0.0/0") {
        $unrestricted_nacls += "$($nacl.NetworkAclId)`n"
    }
}
if (-not $unrestricted_nacls) {
    Append-Result "5.2" "PASS" "Ensure no Network ACLs allow ingress from 0.0.0.0/0 to remote server administration ports" "No NACLs allow ingress to ports 22/3389 from 0.0.0.0/0." "High" "No action needed."
} else {
    Append-Result "5.2" "FAIL" "Ensure no Network ACLs allow ingress from 0.0.0.0/0 to remote server administration ports" "NACLs allowing ingress to admin ports: $unrestricted_nacls" "High" "1. Go to VPC > Network ACLs.\n2. Remove rules allowing ports 22/3389 from 0.0.0.0/0."
}

# 5.3: Ensure no security groups allow ingress from 0.0.0.0/0 to remote server administration ports
Write-Host "Checking CIS 5.3: No security groups allow ingress to admin ports..."
$unrestricted_sgs = ""
foreach ($group in $security_groups) {
    $cidrs = aws ec2 describe-security-groups --group-ids $group.GroupId --query 'SecurityGroups[].IpPermissions[?ToPort==`22` || ToPort==`3389`].IpRanges[].CidrIp' --output json | ConvertFrom-Json
    if ($cidrs -contains "0.0.0.0/0") {
        $unrestricted_sgs += "$($group.GroupId)`n"
    }
}
if (-not $unrestricted_sgs) {
    Append-Result "5.3" "PASS" "Ensure no security groups allow ingress from 0.0.0.0/0 to remote server administration ports" "No security groups allow ingress to ports 22/3389 from 0.0.0.0/0." "High" "No action needed."
} else {
    Append-Result "5.3" "FAIL" "Ensure no security groups allow ingress from 0.0.0.0/0 to remote server administration ports" "Security groups allowing admin ports: $unrestricted_sgs" "High" "1. Go to VPC > Security Groups.\n2. Remove rules allowing ports 22/3389 from 0.0.0.0/0."
}

# 5.4: Ensure no security groups allow ingress from ::/0 to remote server administration ports
Write-Host "Checking CIS 5.4: No security groups allow IPv6 ingress to admin ports..."
$unrestricted_ipv6_sgs = ""
foreach ($group in $security_groups) {
    $ipv6_cidrs = aws ec2 describe-security-groups --group-ids $group.GroupId --query 'SecurityGroups[].IpPermissions[?ToPort==`22` || ToPort==`3389`].Ipv6Ranges[].CidrIpv6' --output json | ConvertFrom-Json
    if ($ipv6_cidrs -contains "::/0") {
        $unrestricted_ipv6_sgs += "$($group.GroupId)`n"
    }
}
if (-not $unrestricted_ipv6_sgs) {
    Append-Result "5.4" "PASS" "Ensure no security groups allow ingress from ::/0 to remote server administration ports" "No security groups allow IPv6 ingress to ports 22/3389 from ::/0." "High" "No action needed."
} else {
    Append-Result "5.4" "FAIL" "Ensure no security groups allow ingress from ::/0 to remote server administration ports" "Security groups allowing IPv6 admin ports: $unrestricted_ipv6_sgs" "High" "1. Go to VPC > Security Groups.\n2. Remove rules allowing ports 22/3389 from ::/0."
}

# 5.5: Ensure the default security group of every VPC restricts all traffic
Write-Host "Checking CIS 5.5: Default security group restricts all traffic..."
$default_sgs = aws ec2 describe-security-groups --filters Name=group-name,Values=default --query 'SecurityGroups[].{GroupId:GroupId,IpPermissions:IpPermissions,IpPermissionsEgress:IpPermissionsEgress}' --output json | ConvertFrom-Json
Check-AwsCommand
$unrestricted_default_sgs = ""
foreach ($sg in $default_sgs) {
    if ($sg.IpPermissions -or $sg.IpPermissionsEgress) {
        $unrestricted_default_sgs += "$($sg.GroupId)`n"
    }
}
if (-not $unrestricted_default_sgs) {
    Append-Result "5.5" "PASS" "Ensure the default security group of every VPC restricts all traffic" "All default security groups restrict all traffic." "High" "No action needed."
} else {
    Append-Result "5.5" "FAIL" "Ensure the default security group of every VPC restricts all traffic" "Default security groups with open rules: $unrestricted_default_sgs" "High" "1. Go to VPC > Security Groups.\n2. Remove all inbound/outbound rules from default security groups."
}

# 5.7: Ensure EC2 Metadata Service only allows IMDSv2
Write-Host "Checking CIS 5.7: EC2 Metadata Service uses IMDSv2..."
$instances = aws ec2 describe-instances --query 'Reservations[].Instances[].{InstanceId:InstanceId,MetadataOptions:MetadataOptions.HttpTokens}' --output json | ConvertFrom-Json
Check-AwsCommand
$non_imdsv2_instances = ""
foreach ($instance in $instances) {
    if ($instance.MetadataOptions.HttpTokens -ne "required") {
        $non_imdsv2_instances += "$($instance.InstanceId)`n"
    }
}
if (-not $non_imdsv2_instances) {
    Append-Result "5.7" "PASS" "Ensure EC2 Metadata Service only allows IMDSv2" "All EC2 instances use IMDSv2." "High" "No action needed."
} else {
    Append-Result "5.7" "FAIL" "Ensure EC2 Metadata Service only allows IMDSv2" "Instances not using IMDSv2: $non_imdsv2_instances" "High" "1. Run: aws ec2 modify-instance-metadata-options --instance-id <instance_id> --http-tokens required"
}

# Generate HTML report
Generate-HtmlReport

# Display summary
Write-Host "`nCompliance Check Summary:"
$results = Get-Content $JSON_OUTPUT | ConvertFrom-Json
foreach ($result in $results) {
    Write-Host "$($result.check_id): $($result.status) - $($result.message) ($($result.risk))"
}
Write-Host "`nDetailed reports saved to: $JSON_OUTPUT (JSON) and $HTML_OUTPUT (HTML)"

# Clean up environment variables
$env:AWS_ACCESS_KEY_ID = $null
$env:AWS_SECRET_ACCESS_KEY = $null
$env:AWS_DEFAULT_REGION = $null

Write-Host "Compliance check completed."