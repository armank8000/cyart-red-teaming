# Week 4 — Advanced C2, Cloud Attacks, Adversary Emulation & Reporting

> All activities performed in an isolated lab environment. No external systems targeted.

## Overview

Week 4 covers advanced red team operations across five domains:

| # | Topic | ATT&CK Phase | Key Tools |
|---|-------|-------------|-----------|
| 1 | Advanced C2 Frameworks | Command & Control | PoshC2, Cobalt Strike (concepts) |
| 2 | Cloud Environment Attacks | Discovery, Exfiltration | Pacu, awscli, CloudGoat, ScoutSuite |
| 3 | Adversary Emulation | All phases (APT29) | CALDERA, Evilginx2, Metasploit |
| 4 | Native Tool Abuse / Evasion | Defense Evasion | PowerShell, WMI, msfvenom, certutil |
| 5 | Comprehensive Reporting | — | PTES, CVSS, Draw.io |

---

## Repository Structure

```
Week 4/
├── README.md
├── Documentation/
│   ├── Week4_RedTeam_Report.md     ← Full PTES-compliant engagement report
│   ├── Cloud_Attack_Notes.md        ← AWS/IAM attack reference
│   └── MITRE_ATT&CK_Mapping.md     ← Full TTP mapping with Navigator JSON
├── Screenshots/
│   ├── 01_c2_infrastructure.png
│   ├── 02_cloud_attack_lab.png
│   ├── 03_adversary_emulation.png
│   ├── 04_lolbins_evasion.png
│   ├── 05_capstone_report.png
│   └── 06_cloud_privilege_abuse.png
├── Scripts/
│   ├── cloud_enum.py               ← AWS asset enumeration (boto3)
│   └── README.md                   ← Tool reference & commands
└── Workflow/
    └── STEPS.md                    ← Phase-by-phase lab steps
```

---

## Lab Environment

| Component | Details |
|-----------|---------|
| Attacker | Kali Linux 2024.1 — 192.168.1.50 |
| C2 Server | Ubuntu 22.04 (PoshC2) — 192.168.1.50:443 |
| Windows Victim 1 | Windows 10 Pro — 192.168.1.110 |
| Windows Victim 2 | Windows 10 Pro — 192.168.1.111 |
| Windows Server | Windows Server 2019 — 192.168.1.120 |
| Cloud Target | AWS CloudGoat Lab (isolated) |

---

## Key Results

### C2 Operations
- 3 PoshC2 sessions established (SID001–SID003)
- Stageless PowerShell + dropper EXE payloads generated
- HTTPS beacon with 5s interval ±20% jitter — mimics browser traffic

### Cloud Attacks
- 3 S3 buckets with public access — 142MB sensitive data exfiltrated
- IAM privilege escalation: `dev-intern` → `AdministratorAccess` via Lambda PassRole
- ScoutSuite found 19 misconfigurations across IAM, S3, EC2, CloudTrail

### Adversary Emulation (APT29)
- All 8 CALDERA phases completed
- Wazuh detected 9/10 attack phases (90% detection rate)
- DNS tunnelling and certutil LOLBIN evaded default rules

### Evasion Results
| Technique | Tool | AV Detection |
|-----------|------|-------------|
| No encoding (baseline) | msfvenom | 52/70 |
| shikata_ga_nai ×3 | msfvenom | 28/70 |
| shikata_ga_nai ×5 | msfvenom | 14/70 |
| XOR+b64 custom | Custom | 8/70 |
| LOLBIN certutil | certutil | 0/70 |

---

## MITRE ATT&CK Techniques

| ID | Technique | Tool |
|----|-----------|------|
| T1071 | Application Layer Protocol (C2) | PoshC2 HTTPS |
| T1580 | Cloud Infrastructure Discovery | Pacu, awscli |
| T1078.004 | Valid Accounts: Cloud | Pacu IAM exploit |
| T1537 | Transfer Data to Cloud Account | awscli S3 |
| T1566.001 | Spearphishing Attachment | Evilginx2 |
| T1059.001 | PowerShell | PoshC2, PowerSploit |
| T1055 | Process Injection | PowerShell VirtualAlloc |
| T1027 | Obfuscated Files | msfvenom shikata_ga_nai |
| T1218 | System Binary Proxy Execution | certutil -decode |
| T1090 | Proxy | proxychains + Tor |
| T1003 | OS Credential Dumping | Mimikatz |
| T1583 | Acquire Infrastructure | Lab C2 server |
