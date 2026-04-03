# Incident Response Report — Phishing Attack Simulation
**Classification:** Internal / Training Exercise  
**Report Date:** 2025-08-18  
**Prepared By:** CYART Apprentice  
**Incident ID:** IR-2025-001  

---

## Executive Summary

On 2025-08-18 at approximately 09:45 UTC, a simulated phishing attack was detected targeting the mock organization's employee accounts. A crafted phishing email containing a malicious link was delivered to a test mailbox. Upon clicking, the payload established a reverse shell connection to an attacker-controlled IP (192.168.1.100). The incident was detected by Wazuh within 4 minutes, contained within 22 minutes, and fully eradicated within 2 hours. No real data was exfiltrated. This exercise revealed gaps in email filtering and endpoint monitoring that are documented with recommendations below.

---

## Incident Timeline

| Timestamp (UTC) | Phase | Event |
|----------------|-------|-------|
| 09:45:00 | Detection | Phishing email delivered to test mailbox |
| 09:47:30 | Detection | User clicked malicious link (simulated) |
| 09:49:12 | Detection | Wazuh alert triggered — suspicious process spawned |
| 09:51:00 | Containment | SOC analyst notified, began triage |
| 10:07:00 | Containment | Affected endpoint isolated from network |
| 10:15:00 | Eradication | Malicious process terminated, persistence removed |
| 10:30:00 | Eradication | Endpoint reimaged from clean backup |
| 11:45:00 | Recovery | Endpoint restored, user credentials reset |
| 12:00:00 | Recovery | Systems verified clean, monitoring increased |

---

## Indicators of Compromise (IOCs)

| IOC Type | Value | Notes |
|----------|-------|-------|
| IP Address | 192.168.1.100 | C2 server (attacker VM) |
| Domain | malicious-sim.local | Phishing landing page |
| File Hash (MD5) | d41d8cd98f00b204e9800998ecf8427e | Dropper payload |
| Process | powershell.exe -EncodedCommand ... | Encoded payload execution |
| Registry Key | HKCU\Software\Microsoft\Windows\CurrentVersion\Run | Persistence mechanism |

---

## MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Observed Behavior |
|--------|-------------|---------------|------------------|
| Initial Access | T1566.001 | Spearphishing Attachment | Phishing email with link |
| Execution | T1059.001 | PowerShell | Encoded PowerShell payload |
| Persistence | T1547.001 | Registry Run Keys | Added to HKCU Run key |
| Command & Control | T1071.001 | Web Protocols | HTTP beacon to 192.168.1.100 |
| Exfiltration | T1041 | Exfiltration Over C2 | Simulated data staging |

---

## Containment Actions

1. Isolated endpoint at network switch level (VLAN change)
2. Blocked attacker IP (192.168.1.100) via CrowdSec firewall rule
3. Disabled compromised user account in Active Directory
4. Preserved forensic image before remediation

---

## Eradication Steps

1. Terminated malicious process (PID 4821 — powershell.exe)
2. Removed persistence registry key
3. Deleted dropper file from `%TEMP%` directory
4. Scanned all network shares for similar indicators

---

## Recovery Steps

1. Reimaged endpoint from verified clean golden image
2. Reset all credentials for affected user account
3. Enabled enhanced logging (Sysmon + Wazuh) on affected subnet
4. Notified simulated stakeholders per IR communications plan

---

## Lessons Learned & Recommendations

| Finding | Risk | Recommendation | Priority |
|---------|------|---------------|----------|
| No email sandbox in place | HIGH | Deploy Proofpoint or Mimecast email sandbox | P1 |
| Encoded PowerShell not alerted promptly | HIGH | Tune Sigma rules to flag -EncodedCommand immediately | P1 |
| No MFA on test accounts | HIGH | Enforce MFA across all accounts | P1 |
| Slow manual containment | MEDIUM | Automate SOAR playbook for network isolation | P2 |
| No deception technology | LOW | Deploy honeypots on internal network | P3 |

---

## Incident Response Flowchart

```
[Phishing Email Received]
         |
         v
[User Clicks Link] ──► [Wazuh Alert Triggered]
         |                       |
         v                       v
[Payload Executes]      [SOC Analyst Triages]
         |                       |
         v                       v
[C2 Connection]         [Endpoint Isolated]
         |                       |
         v                       v
[Data Staged]           [Process Killed + IOCs Collected]
                                 |
                                 v
                        [Endpoint Reimaged]
                                 |
                                 v
                        [Credentials Reset]
                                 |
                                 v
                        [Monitoring Enhanced]
                                 |
                                 v
                        [Report Filed — CLOSED]
```

---

*Report generated as part of Week 2 CYART Red Teaming Apprenticeship training exercise.*
