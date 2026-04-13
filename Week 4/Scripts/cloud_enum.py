#!/usr/bin/env python3
"""
cloud_enum.py
-------------
AWS cloud asset enumeration script using boto3.
Performs passive reconnaissance on S3 buckets, IAM users/policies,
EC2 instances, and CloudTrail configuration.

For use in authorised security assessments and CloudGoat labs only.

Requirements:
    pip install boto3 colorama

Usage:
    python3 cloud_enum.py --profile dev-user
    python3 cloud_enum.py --profile dev-user --region us-east-1
    python3 cloud_enum.py --profile dev-user --output report.json

ATT&CK Techniques:
    T1580  - Cloud Infrastructure Discovery
    T1538  - Cloud Service Dashboard
    T1069.003 - Permission Groups Discovery: Cloud Groups
"""

import argparse
import json
import sys
from datetime import datetime
from typing import Optional

try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError
    BOTO3_OK = True
except ImportError:
    BOTO3_OK = False
    print("[!] boto3 not installed: pip install boto3")


# ─── S3 Enumeration ────────────────────────────────────────────────────────────

def enum_s3_buckets(session: "boto3.Session") -> list[dict]:
    """
    Enumerate all S3 buckets accessible with current credentials.
    Checks ACL, versioning, logging, and public access settings.

    ATT&CK: T1580 (Cloud Infrastructure Discovery), T1530

    Args:
        session: boto3 Session with target credentials

    Returns:
        List of bucket info dicts
    """
    s3 = session.client("s3")
    buckets: list[dict] = []

    print("\n[*] Enumerating S3 buckets...")
    try:
        response = s3.list_buckets()
    except (ClientError, NoCredentialsError) as e:
        print(f"[!] S3 list failed: {e}")
        return []

    for b in response.get("Buckets", []):
        name = b["Name"]
        info: dict = {"name": name, "created": str(b.get("CreationDate", "")),
                      "public": False, "public_write": False, "issues": []}

        # Check public access block
        try:
            pab = s3.get_public_access_block(Bucket=name)
            cfg = pab.get("PublicAccessBlockConfiguration", {})
            if not cfg.get("BlockPublicAcls") or not cfg.get("BlockPublicPolicy"):
                info["issues"].append("Public access block not fully enabled")
        except ClientError:
            info["issues"].append("No public access block configured")

        # Check ACL
        try:
            acl = s3.get_bucket_acl(Bucket=name)
            for grant in acl.get("Grants", []):
                grantee = grant.get("Grantee", {})
                if grantee.get("URI") == "http://acs.amazonaws.com/groups/global/AllUsers":
                    perm = grant.get("Permission", "")
                    if "READ" in perm:
                        info["public"] = True
                        info["issues"].append("PUBLIC READ access enabled")
                        print(f"  [!] {name}: PUBLIC READ")
                    if "WRITE" in perm:
                        info["public_write"] = True
                        info["issues"].append("PUBLIC WRITE access enabled")
                        print(f"  [!!] {name}: PUBLIC WRITE — critical!")
        except ClientError:
            pass

        # Check versioning
        try:
            ver = s3.get_bucket_versioning(Bucket=name)
            if ver.get("Status") != "Enabled":
                info["issues"].append("Versioning disabled")
        except ClientError:
            pass

        # Check logging
        try:
            log = s3.get_bucket_logging(Bucket=name)
            if "LoggingEnabled" not in log:
                info["issues"].append("Access logging disabled")
        except ClientError:
            pass

        severity = "CRITICAL" if info["public_write"] else "HIGH" if info["public"] else "LOW"
        info["severity"] = severity
        buckets.append(info)
        status = f"[{severity}]" if info["issues"] else "[OK]"
        print(f"  {status} {name} — {len(info['issues'])} issue(s)")

    print(f"[*] {len(buckets)} buckets enumerated")
    return buckets


# ─── IAM Enumeration ───────────────────────────────────────────────────────────

def enum_iam(session: "boto3.Session") -> dict:
    """
    Enumerate IAM users, groups, roles, and attached policies.
    Identifies privilege escalation paths via PassRole + Lambda/EC2.

    ATT&CK: T1069.003, T1078.004

    Args:
        session: boto3 Session

    Returns:
        Dict with users, roles, policies, and privesc paths
    """
    iam = session.client("iam")
    result: dict = {"users": [], "roles": [], "privesc_paths": [], "issues": []}

    print("\n[*] Enumerating IAM configuration...")

    # Current identity
    try:
        sts = session.client("sts")
        identity = sts.get_caller_identity()
        print(f"  Identity: {identity.get('Arn', 'unknown')}")
        result["identity"] = identity.get("Arn", "")
    except ClientError as e:
        print(f"  [!] STS failed: {e}")

    # List users
    try:
        paginator = iam.get_paginator("list_users")
        for page in paginator.paginate():
            for user in page.get("Users", []):
                uname = user["UserName"]
                result["users"].append(uname)
        print(f"  [*] {len(result['users'])} IAM users found")
    except ClientError as e:
        print(f"  [!] IAM list_users failed: {e}")

    # Check for PassRole (privesc indicator)
    try:
        my_policies = iam.list_attached_user_policies(
            UserName=identity.get("Arn", "").split("/")[-1]
        )
        for policy in my_policies.get("AttachedPolicies", []):
            if "PassRole" in policy.get("PolicyName", ""):
                result["privesc_paths"].append({
                    "path": "iam:PassRole detected",
                    "risk": "Can attach roles to Lambda/EC2 for privilege escalation",
                    "severity": "HIGH"
                })
                print(f"  [!] iam:PassRole permission detected — privesc path possible")
    except ClientError:
        pass

    # Check MFA on users
    try:
        for uname in result["users"][:10]:
            devices = iam.list_mfa_devices(UserName=uname)
            if not devices.get("MFADevices"):
                result["issues"].append(f"{uname}: No MFA device configured")
    except ClientError:
        pass

    return result


# ─── EC2 Enumeration ───────────────────────────────────────────────────────────

def enum_ec2(session: "boto3.Session", region: str = "us-east-1") -> list[dict]:
    """
    Enumerate EC2 instances, security groups, and instance metadata settings.

    Args:
        session: boto3 Session
        region:  AWS region to enumerate

    Returns:
        List of instance info dicts
    """
    ec2 = session.client("ec2", region_name=region)
    instances: list[dict] = []

    print(f"\n[*] Enumerating EC2 instances in {region}...")
    try:
        response = ec2.describe_instances()
        for reservation in response.get("Reservations", []):
            for inst in reservation.get("Instances", []):
                iid   = inst.get("InstanceId", "")
                state = inst.get("State", {}).get("Name", "")
                itype = inst.get("InstanceType", "")
                ip    = inst.get("PublicIpAddress", "N/A")
                issues: list[str] = []

                # Check IMDSv1 (metadata service without token)
                meta = inst.get("MetadataOptions", {})
                if meta.get("HttpTokens") != "required":
                    issues.append("IMDSv1 enabled — SSRF → credential theft risk")

                # Check security groups for 0.0.0.0/0
                for sg in inst.get("SecurityGroups", []):
                    sg_detail = ec2.describe_security_groups(GroupIds=[sg["GroupId"]])
                    for rule in sg_detail["SecurityGroups"][0].get("IpPermissions", []):
                        for ip_range in rule.get("IpRanges", []):
                            if ip_range.get("CidrIp") == "0.0.0.0/0":
                                port = rule.get("FromPort", "all")
                                issues.append(f"0.0.0.0/0 access on port {port}")

                info = {"id": iid, "type": itype, "state": state,
                        "public_ip": ip, "issues": issues}
                instances.append(info)
                if issues:
                    print(f"  [!] {iid} ({ip}): {len(issues)} issue(s)")
                else:
                    print(f"  [OK] {iid} ({ip}): no issues")

    except ClientError as e:
        print(f"  [!] EC2 enum failed: {e}")

    return instances


# ─── CloudTrail Check ──────────────────────────────────────────────────────────

def check_cloudtrail(session: "boto3.Session") -> dict:
    """
    Check CloudTrail configuration — whether audit logging is enabled
    in all regions and whether log file validation is active.

    Args:
        session: boto3 Session

    Returns:
        Dict with trail info and issues
    """
    ct = session.client("cloudtrail")
    result: dict = {"trails": [], "issues": []}

    print("\n[*] Checking CloudTrail configuration...")
    try:
        trails = ct.describe_trails(includeShadowTrails=False)
        for trail in trails.get("trailList", []):
            name    = trail.get("Name", "")
            multi   = trail.get("IsMultiRegionTrail", False)
            log_val = trail.get("LogFileValidationEnabled", False)
            issues  = []

            if not multi:
                issues.append("Single-region trail — blind spots in other regions")
            if not log_val:
                issues.append("Log file validation disabled — logs can be tampered")

            result["trails"].append({"name": name, "multi_region": multi,
                                     "log_validation": log_val, "issues": issues})
            status = "[!]" if issues else "[OK]"
            print(f"  {status} {name} — {len(issues)} issue(s)")

        if not trails.get("trailList"):
            result["issues"].append("No CloudTrail configured — zero audit logging!")
            print("  [!!] NO CLOUDTRAIL CONFIGURED — critical finding!")

    except ClientError as e:
        print(f"  [!] CloudTrail check failed: {e}")

    return result


# ─── Report ────────────────────────────────────────────────────────────────────

def save_report(data: dict, output_path: str) -> None:
    """Save all enumeration results to a JSON report."""
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str)
    print(f"\n[+] Report saved → {output_path}")


def print_summary(data: dict) -> None:
    """Print a formatted summary to stdout."""
    print("\n" + "="*60)
    print("  AWS Cloud Enumeration Summary")
    print("="*60)
    buckets   = data.get("s3", [])
    public_bk = [b for b in buckets if b.get("public")]
    iam_data  = data.get("iam", {})
    ec2_list  = data.get("ec2", [])

    print(f"  S3 Buckets total   : {len(buckets)}")
    print(f"  S3 Public buckets  : {len(public_bk)}")
    print(f"  IAM Users          : {len(iam_data.get('users', []))}")
    print(f"  PrivEsc paths      : {len(iam_data.get('privesc_paths', []))}")
    print(f"  EC2 Instances      : {len(ec2_list)}")
    print(f"  CloudTrail issues  : {len(data.get('cloudtrail', {}).get('issues', []))}")
    print("="*60)


# ─── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="AWS Cloud Asset Enumeration (authorised assessments only)"
    )
    parser.add_argument("--profile", "-p", default="default",
                        help="AWS CLI profile name (default: default)")
    parser.add_argument("--region",  "-r", default="us-east-1",
                        help="AWS region (default: us-east-1)")
    parser.add_argument("--output",  "-o", default="cloud_enum_report.json",
                        help="JSON output report path")
    parser.add_argument("--s3-only",       action="store_true",
                        help="Only enumerate S3")
    parser.add_argument("--iam-only",      action="store_true",
                        help="Only enumerate IAM")
    args = parser.parse_args()

    if not BOTO3_OK:
        print("[!] boto3 required: pip install boto3")
        sys.exit(1)

    print("="*60)
    print("  AWS Cloud Enumeration Tool")
    print("  AUTHORISED USE ONLY")
    print("="*60)
    print(f"  Profile: {args.profile} | Region: {args.region}")
    print()

    session = boto3.Session(profile_name=args.profile, region_name=args.region)

    report: dict = {"timestamp": datetime.now().isoformat(), "profile": args.profile}

    if args.s3_only:
        report["s3"] = enum_s3_buckets(session)
    elif args.iam_only:
        report["iam"] = enum_iam(session)
    else:
        report["s3"]         = enum_s3_buckets(session)
        report["iam"]        = enum_iam(session)
        report["ec2"]        = enum_ec2(session, args.region)
        report["cloudtrail"] = check_cloudtrail(session)

    print_summary(report)
    save_report(report, args.output)


if __name__ == "__main__":
    main()
