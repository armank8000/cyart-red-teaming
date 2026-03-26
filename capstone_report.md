# Capstone Project Report — Full Incident Response Cycle
**Incident ID:** CAP-2025-001  
**Tools Used:** Metasploit, Wazuh, CrowdSec, Velociraptor  
**Date:** 2025-08-18  

---

## Attack Simulation

### Exploit Used
```
msf6 > use exploit/unix/ftp/vsftpd_234_backdoor
msf6 exploit(vsftpd_234_backdoor) > set RHOSTS 192.168.1.200
msf6 exploit(vsftpd_234_backdoor) > set RPORT 21
msf6 exploit(vsftpd_234_backdoor) > run
```

**Result:** Remote shell obtained on Metasploitable2 (192.168.1.200) with root privileges.  
**MITRE Technique:** T1190 — Exploit Public-Facing Application

---

## Detection — Wazuh Alerts

| Timestamp | Source IP | Destination IP | Alert Description | MITRE Technique |
|-----------|-----------|---------------|------------------|-----------------|
| 2025-08-18 11:00:12 | 192.168.1.100 | 192.168.1.200 | FTP connection on port 21 | T1190 |
| 2025-08-18 11:00:14 | 192.168.1.100 | 192.168.1.200 | VSFTPD 2.3.4 backdoor trigger | T1190 |
| 2025-08-18 11:00:16 | 192.168.1.200 | 192.168.1.100 | Outbound shell on port 6200 | T1059 |
| 2025-08-18 11:00:20 | 192.168.1.100 | 192.168.1.200 | Root shell command execution | T1068 |

---

## Artifact Collection — Velociraptor Queries

```sql
-- Collect running processes
SELECT Pid, Name, Exe, CommandLine, Username
FROM processes
WHERE Username = "root"

-- Collect network connections
SELECT Pid, FamilyString, TypeString, Status,
       Laddr.IP, Laddr.Port, Raddr.IP, Raddr.Port
FROM netstat
WHERE Status = "ESTABLISHED"
```

**Key Artifacts Found:**

| Artifact | Value | Significance |
|----------|-------|-------------|
| Listening Port | 6200/TCP | VSFTPD backdoor shell |
| Remote IP | 192.168.1.100 | Attacker machine |
| Process | /bin/sh | Shell spawned by exploit |
| User | root | Full privilege escalation confirmed |

---

## Containment — CrowdSec

```bash
# Block attacker IP with CrowdSec
sudo cscli decisions add --ip 192.168.1.100 --duration 24h --reason "VSFTPD exploit attempt"

# Verify block
sudo cscli decisions list

# Verify with ping test from target
ping 192.168.1.100  # Expected: Request timeout — connection blocked
```

**Result:** Attacker IP blocked at firewall level. All subsequent connection attempts dropped.

---

## 200-Word Incident Summary

On 2025-08-18 at 11:00 UTC, a simulated cyberattack was conducted against a Metasploitable2 virtual machine (192.168.1.200) to test the full incident response lifecycle. The attacker (192.168.1.100) exploited the VSFTPD 2.3.4 backdoor vulnerability (CVE-2011-2523) using Metasploit's `vsftpd_234_backdoor` module, successfully obtaining a root-level remote shell via port 6200. This maps to MITRE ATT&CK technique T1190 (Exploit Public-Facing Application).

Wazuh detected the intrusion within 8 seconds, generating four high-severity alerts covering the FTP connection, backdoor trigger, shell spawning, and command execution. Velociraptor was immediately deployed to collect forensic artifacts, confirming the active root shell and identifying the attacker's IP and process lineage.

Containment was executed via CrowdSec, which applied a 24-hour IP block on 192.168.1.100, verified by a failed ping test from the target machine. The vulnerable VSFTPD service was then patched and the service restarted with a secure configuration.

**Key Recommendations:** Immediately patch VSFTPD to a non-vulnerable version or disable the FTP service. Implement network segmentation to prevent direct internet-facing exposure of legacy services. Deploy continuous vulnerability scanning to detect known CVEs before exploitation occurs.

---

## Remediation Plan

| Vulnerability | CVSS | Fix | Priority |
|--------------|------|-----|---------|
| VSFTPD 2.3.4 Backdoor (CVE-2011-2523) | 10.0 | Upgrade to vsftpd 3.x or disable FTP | CRITICAL |
| Anonymous FTP enabled | 7.5 | Disable anonymous FTP in vsftpd.conf | HIGH |
| No network segmentation | 6.0 | Isolate legacy VMs in separate VLAN | HIGH |
| No patch management policy | 5.0 | Implement automated patch scanning | MEDIUM |
