# Week 3 — Advanced Red Team Operations

> **Scope:** All activities documented here were performed in an isolated lab environment (VMware host-only network). No external systems were targeted. All techniques are for educational purposes.

## Overview

Week 3 covers the full red team engagement lifecycle across five domains:

| # | Topic | ATT&CK Phase | Key Tools |
|---|-------|-------------|-----------|
| 1 | OSINT & Reconnaissance | Reconnaissance | Recon-ng, Shodan, Maltego |
| 2 | Initial Access | Initial Access | Evilginx2, Gophish, SET |
| 3 | Exploitation & Vuln Research | Execution | Metasploit, OWASP ZAP |
| 4 | Lateral Movement & Persistence | Lateral Movement | Impacket, psexec.py |
| 5 | Evasion Techniques | Defense Evasion | msfvenom, proxychains |

---

## Repository Structure

```
Week 3/
├── README.md                    ← This file
├── Documentation/
│   ├── Week3_RedTeam_Report.md  ← Full engagement report
│   └── MITRE_Mapping.md         ← ATT&CK technique mapping
├── Screenshots/
│   ├── 01_osint_recon_lab.png
│   ├── 02_phishing_simulation.png
│   ├── 03_vulnerability_exploitation.png
│   ├── 04_lateral_movement.png
│   ├── 05_attack_flowchart.png
│   └── 06_post_exploitation.png
├── Scripts/
│   ├── osint_recon.py           ← Subdomain enum + Shodan + WHOIS
│   ├── payload_generator.py     ← XOR/b64 evasion payload builder
│   └── lateral_movement.py      ← Impacket PtH + persistence helper
└── Workflow/
    └── STEPS.md                 ← Step-by-step lab workflow
```

---

## Lab Environment

| Component | Details |
|-----------|---------|
| Attacker | Kali Linux 2024.1 — 192.168.1.50 |
| Target 1 | Metasploitable3 (Ubuntu) — 192.168.1.110 |
| Target 2 | Windows 10 VM — 192.168.1.120 |
| Target 3 | Windows Server 2019 (DC) — 192.168.1.130 |
| Network | VMware Host-Only — 192.168.1.0/24 |
| Hypervisor | VMware Workstation 17 |

---

## Quick Start — Lab Setup

```bash
# 1. Install Kali tools
sudo apt update && sudo apt install -y \
  metasploit-framework nmap wireshark \
  impacket-scripts recon-ng maltego

# 2. Python dependencies
pip3 install requests shodan python-whois dnspython \
             impacket scapy pyshark matplotlib

# 3. Run OSINT recon
python3 Scripts/osint_recon.py --target example.com

# 4. Generate evasion payload (dry run)
python3 Scripts/payload_generator.py --lhost 192.168.1.50 --lport 4444

# 5. Simulate lateral movement (dry run)
python3 Scripts/lateral_movement.py \
  --targets 192.168.1.120 192.168.1.130 \
  --username Administrator \
  --hash 31d6cfe0d16ae931b73c59d7e0c089c0 \
  --dry-run
```

---

## MITRE ATT&CK Techniques Covered

| ID | Technique | Phase | Tool |
|----|-----------|-------|------|
| T1595.002 | Active Scanning | Reconnaissance | Nmap, Shodan |
| T1590 | Gather Victim Network Info | Reconnaissance | Recon-ng, WHOIS |
| T1593 | Search Open Websites | Reconnaissance | Maltego, Google |
| T1566.001 | Spearphishing Attachment | Initial Access | Gophish |
| T1078 | Valid Accounts | Initial Access | Evilginx2 |
| T1190 | Exploit Public-Facing App | Execution | Metasploit |
| T1068 | Exploitation for Priv Esc | Privilege Escalation | GTFOBins |
| T1021 | Remote Services | Lateral Movement | psexec.py |
| T1550.002 | Pass the Hash | Lateral Movement | Impacket |
| T1053.005 | Scheduled Task | Persistence | schtasks |
| T1547.001 | Registry Run Keys | Persistence | reg.exe |
| T1027 | Obfuscated Files | Defense Evasion | msfvenom |
| T1090 | Proxy | Defense Evasion | proxychains |
| T1003.001 | LSASS Memory Dump | Credential Access | Mimikatz |
| T1048 | Exfil over Alt Protocol | Exfiltration | DNS tunnel |

---

## Key Findings Summary

### Vulnerabilities Exploited
- **CVE-2017-5638** (Apache Struts RCE) — CVSS 9.8 — Remote code execution on Metasploitable3
- **CVE-2020-1234** (SQL Injection in web app) — CVSS 9.1 — Full database access obtained
- **Weak SSH credentials** — password spraying with Hydra → root access

### Credentials Harvested
| Source | Count |
|--------|-------|
| Evilginx2 phishing | 12 |
| Mimikatz LSASS dump | 4 NTLM hashes |
| Secretsdump (SAM) | 3 accounts per host |
| Cleartext (wdigest) | 2 admin passwords |

### Hosts Compromised
1. `192.168.1.110` — Metasploitable3 (Struts RCE → root)
2. `192.168.1.120` — Windows 10 (PtH psexec → SYSTEM)
3. `192.168.1.130` — Windows Server (DCSync → krbtgt hash)

---

## Ethical & Legal Disclaimer

All activities documented in this repository were performed:
- In a **private, isolated lab** environment
- With **no connection to external networks**
- Purely for **educational and skill development** purposes
- In compliance with applicable laws and ethical guidelines

**Never** use these techniques against systems you do not own or have explicit written permission to test.
