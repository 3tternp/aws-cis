# aws-cis
This repository contains a Bash script (cis_aws_benchmark_5.0.0_checker.sh) designed to automate compliance checks against the CIS AWS Foundations Benchmark v5.0.0. The script verifies AWS configurations using read-only permissions, generates detailed reports in JSON and HTML formats, and provides remediation steps for non-compliant resources. Manual checks are listed for review where automation is not possible due to permission or console-based requirements.

Features





Automated Checks: Covers CIS controls that can be verified with read-only permissions (e.g., IAM, S3, RDS, CloudTrail, EBS, etc.).



Manual Checks: Lists controls requiring manual verification (e.g., root MFA, CloudWatch monitoring) with remediation guidance.



Dependencies: Automatically installs aws-cli and jq for Linux/macOS environments.



Reports: Generates a JSON file for raw data and an HTML file with a formatted table including issue name, risk rating (Critical, High, Medium), status (Pass/Fail), details, and remediation steps.



Risk Ratings: Assigned based on CIS Level 1 (High), Level 2 (Medium), or critical impact (e.g., root account issues).

Prerequisites





AWS Account: An IAM user with read-only permissions (recommended: SecurityAudit policy).



Operating System: Linux (e.g., Ubuntu) or macOS. Windows users can use WSL (Windows Subsystem for Linux).



Dependencies:





curl, unzip (for installing aws-cli on Linux).



apt-get (Linux) or brew (macOS) for package management.



Internet access to download dependencies.



AWS Credentials: AWS Access Key ID and Secret Access Key for the IAM user.

Installation





Clone the Repository:

git clone https://github.com/<your-username>/cis-aws-benchmark-checker.git
cd cis-aws-benchmark-checker



Make the Script Executable:

chmod +x cis_aws_benchmark_5.0.0_checker.sh

Usage





Run the Script:

./cis_aws_benchmark_5.0.0_checker.sh



Provide Inputs:





AWS Access Key ID: Enter the IAM user's access key.



AWS Secret Access Key: Enter the corresponding secret key.



AWS Region: Enter the AWS region (e.g., us-east-1). Press Enter for default (us-east-1).



Review Output:





The script installs dependencies (aws-cli, jq) if not present.



It performs automated checks and lists manual checks for review.



Results are saved to:





JSON: cis_aws_benchmark_5.0.0_report_YYYYMMDD_HHMMSS.json



HTML: cis_aws_benchmark_5.0.0_report_YYYYMMDD_HHMMSS.html



A summary is printed to the console.

Output





JSON Report: Contains raw results with fields:





check_id: CIS benchmark control ID (e.g., 1.3).



status: PASS, FAIL, or INFO (for manual checks).



message: Description of the check.



details: Specific findings (e.g., non-compliant resources).



risk: Critical, High, or Medium.



remediation: Steps to fix non-compliance.



HTML Report: A formatted table with columns for Check ID, Issue Name, Risk Rating, Status, Details, and Remediation Steps. Color-coded for readability (green for PASS, red for FAIL, etc.).



Console Summary: Lists each check’s ID, status, message, and risk rating.

Checks Performed





Automated Checks (36 controls): Includes IAM (e.g., root MFA, password policy), S3 (e.g., block public access), RDS (e.g., encryption), CloudTrail (e.g., multi-region), EBS (e.g., encryption), and more.



Manual Checks (18 controls): Includes root MFA setup, contact details, CloudWatch monitoring (4.1–4.15), and VPC peering routes. These are flagged as "INFO" with remediation steps.



Risk Ratings:





Critical: Root account issues (1.3, 1.4, 1.5, 1.6, 4.3).



High: Level 1 controls (e.g., IAM, S3, RDS, security groups).



Medium: Level 2 controls (e.g., CloudTrail, KMS, AWS Config).

Notes





Permissions: The script assumes read-only access (SecurityAudit policy). Manual checks require console access or write permissions.



Limitations:





Some controls (e.g., 2.2.4, 3.4) are not included due to read-only constraints or incomplete benchmark details.



Designed for Linux/macOS. Windows users should use WSL or modify the dependency installation logic.



Dependencies: Automatically installs aws-cli and jq. Ensure curl, unzip, and package managers (apt-get or brew) are available.



Error Handling: The script exits if AWS CLI commands fail (e.g., invalid credentials). Verify IAM permissions before running.
