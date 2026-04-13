# MITRE ATT&CK Mapping — Week 3 Red Team Engagement

All techniques documented here were exercised in an isolated lab environment.

## Tactic Coverage Matrix

| Tactic | # Techniques | Coverage |
|--------|-------------|----------|
| Reconnaissance | 3 | T1595, T1590, T1593 |
| Initial Access | 2 | T1566.001, T1078 |
| Execution | 2 | T1190, T1059 |
| Privilege Escalation | 1 | T1068 |
| Credential Access | 3 | T1003.001, T1003.002, T1110 |
| Lateral Movement | 2 | T1021.002, T1550.002 |
| Persistence | 4 | T1053.005, T1547.001, T1136.001, T1546.003 |
| Defense Evasion | 3 | T1027, T1090, T1036 |
| Collection | 1 | T1005 |
| Exfiltration | 2 | T1048, T1041 |

---

## Detailed Technique Index

### Reconnaissance
| ID | Name | Tool | Notes |
|----|------|------|-------|
| T1595.002 | Active Scanning: Vulnerability Scanning | Nmap, OWASP ZAP | Port/service scan on lab targets |
| T1590 | Gather Victim Network Information | Recon-ng, dig | DNS records, NS, MX enumeration |
| T1593 | Search Open Websites/Domains | Shodan, Google | Exposed hosts and banner grabbing |

### Initial Access
| ID | Name | Tool | Notes |
|----|------|------|-------|
| T1566.001 | Phishing: Spearphishing Attachment | Gophish | 247 emails, 12 creds captured |
| T1078 | Valid Accounts | Evilginx2 | Session token capture bypasses MFA |

### Execution
| ID | Name | Tool | Notes |
|----|------|------|-------|
| T1190 | Exploit Public-Facing Application | Metasploit | Apache Struts CVE-2017-5638 |
| T1059.001 | Command and Scripting: PowerShell | msfvenom | PS stager for initial execution |

### Privilege Escalation
| ID | Name | Tool | Notes |
|----|------|------|-------|
| T1068 | Exploitation for Privilege Escalation | GTFOBins | SUID find → root shell |

### Credential Access
| ID | Name | Tool | Notes |
|----|------|------|-------|
| T1003.001 | OS Cred Dump: LSASS Memory | Mimikatz | sekurlsa::logonpasswords |
| T1003.002 | OS Cred Dump: SAM | Impacket secretsdump | SAM + LSA secrets |
| T1110.003 | Brute Force: Password Spraying | Hydra | SSH brute force |

### Lateral Movement
| ID | Name | Tool | Notes |
|----|------|------|-------|
| T1021.002 | Remote Services: SMB/Windows Admin | Impacket psexec | ADMIN$ share execution |
| T1550.002 | Use Alt Auth Material: PtH | Impacket psexec | No cleartext needed |

### Persistence
| ID | Name | Tool | Notes |
|----|------|------|-------|
| T1053.005 | Scheduled Task/Job | schtasks.exe | Daily 02:00 execution |
| T1547.001 | Registry Run Keys | reg.exe | HKCU Run key on login |
| T1136.001 | Create Account: Local | net user | svchost$ hidden admin |
| T1546.003 | WMI Event Subscription | wmic | EventFilter + Consumer |

### Defense Evasion
| ID | Name | Tool | Notes |
|----|------|------|-------|
| T1027 | Obfuscated Files or Information | msfvenom | shikata_ga_nai ×5 |
| T1090 | Proxy | proxychains + Tor | C2 traffic masking |
| T1036 | Masquerading | Manual | svchost$ account name |

### Exfiltration
| ID | Name | Tool | Notes |
|----|------|------|-------|
| T1048 | Exfiltration Over Alternative Protocol | iodine | DNS tunnel |
| T1041 | Exfiltration Over C2 Channel | Meterpreter | Encrypted Meterpreter |

---

## Navigator Layer

The following ATT&CK techniques were exercised (suitable for import into MITRE ATT&CK Navigator):

```json
{
  "name": "Week 3 Red Team Coverage",
  "versions": {"attack": "14", "navigator": "4.9"},
  "techniques": [
    {"techniqueID": "T1595.002", "color": "#e74c3c", "comment": "Nmap + Shodan"},
    {"techniqueID": "T1590",     "color": "#e74c3c", "comment": "Recon-ng"},
    {"techniqueID": "T1593",     "color": "#e74c3c", "comment": "Maltego"},
    {"techniqueID": "T1566.001", "color": "#f18f01", "comment": "Gophish campaign"},
    {"techniqueID": "T1078",     "color": "#f18f01", "comment": "Evilginx2 tokens"},
    {"techniqueID": "T1190",     "color": "#e74c3c", "comment": "Struts CVE-2017-5638"},
    {"techniqueID": "T1068",     "color": "#c0392b", "comment": "SUID find escalation"},
    {"techniqueID": "T1003.001", "color": "#8e44ad", "comment": "Mimikatz LSASS"},
    {"techniqueID": "T1003.002", "color": "#8e44ad", "comment": "secretsdump SAM"},
    {"techniqueID": "T1110.003", "color": "#8e44ad", "comment": "Hydra SSH spray"},
    {"techniqueID": "T1021.002", "color": "#d35400", "comment": "psexec ADMIN$"},
    {"techniqueID": "T1550.002", "color": "#d35400", "comment": "Pass-the-Hash"},
    {"techniqueID": "T1053.005", "color": "#d35400", "comment": "schtasks persistence"},
    {"techniqueID": "T1547.001", "color": "#d35400", "comment": "Registry Run key"},
    {"techniqueID": "T1027",     "color": "#2ecc71", "comment": "msfvenom encoding"},
    {"techniqueID": "T1090",     "color": "#2ecc71", "comment": "Tor proxychains"},
    {"techniqueID": "T1048",     "color": "#c0392b", "comment": "DNS tunnel iodine"},
    {"techniqueID": "T1041",     "color": "#c0392b", "comment": "Meterpreter C2"}
  ]
}
```
