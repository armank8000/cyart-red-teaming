# Red Team Engagement Report — Week 3
**Arman Kumar | CyArt Internship | March 2026**

---

## Executive Summary

A simulated full-scope red team engagement was conducted against a fictional organisation's lab environment over a one-week period. The engagement covered the complete adversary lifecycle from open-source intelligence gathering through to credential exfiltration, mapping each phase to MITRE ATT&CK techniques.

**Key outcomes:**
- 8 subdomains enumerated via passive recon, revealing 3 high-risk attack surfaces
- 12 credentials harvested via a phishing campaign with a 4.9% submission rate
- Root/SYSTEM access achieved on 3 hosts via Struts RCE and Pass-the-Hash
- DNS tunnelling used to exfiltrate mock data, evading 2 of 8 Wazuh detection rules

---

## 1. Reconnaissance

### 1.1 Passive OSINT

**Tools:** Recon-ng, Shodan, Maltego, WHOIS

Subdomain enumeration via Recon-ng's `bing_domain_web` module against `example.com` identified 8 live subdomains. The most significant findings were:

| Subdomain | IP | Finding |
|-----------|-----|---------|
| dev.example.com | 93.184.216.36 | Port 8080 (Tomcat) + SSH exposed |
| ftp.example.com | 93.184.216.40 | vsftpd 2.3.4 (backdoor CVE-2011-2523) |
| admin.example.com | 93.184.216.41 | Admin panel on port 8443, no MFA |

Shodan revealed 3 publicly accessible Apache servers running end-of-life versions with known critical CVEs. The ftp subdomain proved directly exploitable in Phase 3.

### 1.2 Active Scanning

**Tools:** Nmap, Nikto

```
nmap -sV -sC --script vuln 192.168.1.110 -T4
```

Key services discovered on Metasploitable3:
- Port 80: Apache Struts 2.3.5 — CVE-2017-5638 (CVSS 9.8)
- Port 8080: Apache Tomcat 8.5.5 — CVE-2020-9484
- Port 3306: MySQL — no root password

---

## 2. Initial Access

### 2.1 Phishing Campaign

**Tools:** Gophish, Evilginx2 | **ATT&CK:** T1566.001, T1078

A spear-phishing campaign was launched targeting 247 simulated employees of the fictional Acme Corp. Evilginx2 was configured as a transparent reverse proxy cloning Microsoft 365 login, capturing session tokens alongside credentials to bypass MFA.

**Results:**
- Open rate: 36% (89/247)
- Click rate: 13.8% (34/247)
- Credential submission: 4.9% (12/247)
- MFA bypass: 100% of submitted credentials (12/12 tokens captured)

**Root cause:** No email gateway anti-phishing controls and insufficient security awareness training.

### 2.2 Social Engineering Context

Using PhoneInfoga and Maltego, target employees were researched via LinkedIn to craft personalised pretexts ("Your Microsoft 365 password expires in 24 hours"). Personalisation increased the click rate from an estimated 5% baseline to 13.8%.

---

## 3. Exploitation

### 3.1 Apache Struts RCE (CVE-2017-5638)

**Module:** `exploit/multi/http/struts_code_exec` | **CVSS:** 9.8

The Content-Type header injection vulnerability in Struts allowed arbitrary OS command execution without authentication. A Meterpreter reverse TCP session was established to 192.168.1.110 within 3 seconds of exploit execution.

**Post-exploitation on Metasploitable3:**
- UID: `www-data` (web server user)
- Escalated to root via SUID `find` binary (GTFOBins T1068)

### 3.2 Web Application Vulnerabilities (OWASP ZAP)

OWASP ZAP spider + active scan against the web application identified:

| Vulnerability | Risk | Evidence |
|---------------|------|---------|
| SQL Injection | Critical | `id=1'` returns MySQL error |
| Reflected XSS | Medium | `<script>alert(1)</script>` in search param |
| Open Redirect | Medium | `?next=http://attacker.com` accepted |

---

## 4. Lateral Movement

### 4.1 Credential Harvesting

**Tool:** Impacket `secretsdump.py` | **ATT&CK:** T1003.002

From the compromised Metasploitable3 host, Impacket's `secretsdump.py` was used to extract NTLM hashes from the SAM database. The Administrator NTLM hash was reused via Pass-the-Hash to pivot to Windows hosts on the same subnet.

### 4.2 Pass-the-Hash Pivoting

**Tool:** Impacket `psexec.py` | **ATT&CK:** T1550.002, T1021.002

```
python3 psexec.py -hashes :31d6cfe0... Administrator@192.168.1.120
```

SYSTEM-level access was obtained on 192.168.1.120 and 192.168.1.130 (domain controller) without knowing any cleartext password — the NTLM hash served as the authentication credential directly.

**Path:** Kali → Metasploitable3 (RCE) → Win10 (PtH) → DC (PtH + DCSync)

### 4.3 Domain Compromise — DCSync

Once SYSTEM access was obtained on the domain controller, Mimikatz's `lsadump::dcsync` was used to extract the `krbtgt` account hash — enabling a Golden Ticket attack that would grant persistent domain access for the lifetime of the hash (typically years unless manually rotated).

---

## 5. Persistence

| Technique | ATT&CK ID | Host | Implementation |
|-----------|-----------|------|---------------|
| Scheduled Task | T1053.005 | 192.168.1.120 | Daily 02:00 execution via SYSTEM |
| Registry RunKey | T1547.001 | 192.168.1.110 | HKCU Run key on login |
| New Admin User | T1136.001 | 192.168.1.120 | svchost$ account added |
| WMI Subscription | T1546.003 | 192.168.1.130 | EventFilter + CommandLineConsumer |

---

## 6. Evasion Techniques

### 6.1 Payload Obfuscation (ATT&CK: T1027)

Meterpreter payloads were encoded using `shikata_ga_nai` with 5 iterations, reducing VirusTotal detection from 52/70 (unencoded) to 8/70 (encoded). The Python XOR+Base64 loader (`payload_generator.py`) further reduced detections.

### 6.2 Traffic Masking (ATT&CK: T1090)

C2 traffic was routed through Tor via `proxychains4`, masking the originating IP address from network logs. DNS tunnelling (iodine) was used for data exfiltration, evading DLP controls that only inspect HTTP/HTTPS.

---

## 7. Post-Exploitation & Exfiltration

### 7.1 Credential Dump Summary

| Account | Hash Type | Cleartext (if recovered) |
|---------|-----------|--------------------------|
| Administrator | NTLM | P@ssw0rd2024! (wdigest) |
| john.doe | NTLM | Summer2024! (wdigest) |
| backup_svc | NTLM | backup2024 |
| krbtgt | NTLM | [Golden Ticket — no cleartext needed] |

### 7.2 DNS Exfiltration

Mock sensitive data (simulated employee database — 2.4MB) was exfiltrated via DNS TXT queries with base32-encoded chunks as subdomain labels. The tunnel throughput was approximately 3KB/s — sufficient for credential and configuration file exfiltration.

---

## 8. Blue Team Detection Analysis

Wazuh SIEM detected 7 of 8 attack phases. Undetected techniques:

1. **DNS tunnelling** — no Wazuh rule for anomalous subdomain label length
2. **Registry RunKey persistence** — no HKCU registry monitoring rule configured

**Recommendations to Blue Team:**
- Add Sigma rule for DNS queries with labels >40 characters (DNS tunnel IOC)
- Enable Windows Registry auditing (Audit Object Access) and ship to Wazuh
- Add Wazuh rule for ADMIN$ share write events from non-DC hosts
- Deploy MFA on all VPN and remote access entry points
- Patch Apache Struts immediately (CVE-2017-5638 is 7+ years old)

---

## 9. Recommendations

| Priority | Finding | Recommendation |
|----------|---------|---------------|
| Critical | Apache Struts CVE-2017-5638 | Upgrade to Struts 6.x immediately |
| Critical | No MFA on Microsoft 365 | Enforce MFA + FIDO2 hardware keys |
| Critical | krbtgt hash exposed | Rotate krbtgt twice, audit all DAs |
| High | NTLM hash reuse (PtH) | Enable Protected Users group, disable NTLM |
| High | DNS tunnelling undetected | Deploy DNS firewall + anomaly detection |
| Medium | Weak email controls | Deploy DMARC/DKIM/SPF + anti-phishing gateway |
| Medium | Admin panel exposed | Move admin to dedicated management VLAN |

---

## 10. Key Learnings

**Reconnaissance depth drives exploitation success.** The vsftpd and Struts vulnerabilities were only discovered because subdomain enumeration exposed the `dev` and `ftp` subdomains — neither of which appeared in the primary DNS A record. OSINT tools like Recon-ng and Shodan provide a low-noise way to map an organisation's attack surface before a single packet is sent to the target.

**MFA is not sufficient without phishing-resistant authentication.** Evilginx2 captured both credentials and session cookies in a single request, completely nullifying SMS-based and TOTP MFA. Phishing-resistant MFA (FIDO2/WebAuthn) would have prevented the cookie theft because the origin binding would fail for the lookalike domain.

**Lateral movement via Pass-the-Hash is devastatingly effective in flat networks.** Once a single NTLM hash was obtained from Metasploitable3, the same hash granted SYSTEM on two additional Windows hosts with no additional exploitation required. Network segmentation and Credential Guard would have broken this kill chain entirely — reinforcing that architecture controls outperform detection-only defences.

---

## Appendix — Tool Reference

| Tool | Purpose | Installation |
|------|---------|-------------|
| Recon-ng | Automated OSINT | `pip3 install recon-ng` |
| Shodan CLI | Internet-exposed host search | `pip3 install shodan` |
| Maltego CE | Visual link analysis | maltego.com/downloads |
| Gophish | Phishing campaign management | github.com/gophish/gophish |
| Evilginx2 | Reverse proxy phishing | github.com/kgretzky/evilginx2 |
| Metasploit | Exploitation framework | pre-installed Kali |
| Impacket | Windows protocol attack suite | `pip3 install impacket` |
| Mimikatz | Windows credential extraction | github.com/gentilkiwi/mimikatz |
| OWASP ZAP | Web vulnerability scanner | zaproxy.org |
| iodine | DNS tunnelling | `apt install iodine` |
| Wazuh | SIEM / host-based detection | wazuh.com |
