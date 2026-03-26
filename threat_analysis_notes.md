# Advanced Threat Analysis — Study Notes

## 1. STRIDE Threat Modeling

STRIDE is used to identify threats by mapping a system's assets, data flows, and trust boundaries.

| Category | Threat | Mitigation |
|----------|--------|-----------|
| **S**poofing | Attacker impersonates users | MFA, strong authentication |
| **T**ampering | Data modification in transit | TLS, digital signatures, HMAC |
| **R**epudiation | Denying actions | Audit logs, non-repudiation controls |
| **I**nformation Disclosure | Unauthorized data access | Encryption, access controls |
| **D**enial of Service | Disrupting availability | Rate limiting, redundancy |
| **E**levation of Privilege | Gaining higher access | Least privilege, RBAC |

### Applying STRIDE to a Web Application

**Asset:** User authentication system  
**Entry Point:** Login form (HTTP POST)  
**Trust Boundary:** Public internet → Web server → Database

| STRIDE Category | Identified Threat | Mitigation |
|----------------|------------------|-----------|
| Spoofing | Fake login form (phishing) | MFA, HSTS headers |
| Tampering | Session token manipulation | Signed JWT tokens, HTTPS |
| Repudiation | No login audit trail | Log all auth events to SIEM |
| Info Disclosure | Error messages leaking DB info | Generic error messages |
| DoS | Brute force login attempts | Account lockout, CAPTCHA |
| Elevation | SQL injection gaining admin access | Parameterized queries |

**Tool:** OWASP Threat Dragon — https://threatdragon.github.io

---

## 2. MITRE ATT&CK Framework

The framework organizes adversary behaviors into **14 Tactics** and hundreds of **Techniques**.

### Key Tactics

| Tactic | ID | Description |
|--------|----|-------------|
| Initial Access | TA0001 | Getting into the target network |
| Execution | TA0002 | Running malicious code |
| Persistence | TA0003 | Maintaining access |
| Privilege Escalation | TA0004 | Gaining higher permissions |
| Defense Evasion | TA0005 | Avoiding detection |
| Credential Access | TA0006 | Stealing credentials |
| Discovery | TA0007 | Mapping the environment |
| Lateral Movement | TA0008 | Moving through the network |
| Collection | TA0009 | Gathering target data |
| Command and Control | TA0011 | Communicating with compromised systems |
| Exfiltration | TA0010 | Stealing data out |
| Impact | TA0040 | Disrupting operations |

### Phishing Attack Mapped to ATT&CK

```
Phase 1: Initial Access    → T1566.001 (Spearphishing Link)
Phase 2: Execution         → T1059.001 (PowerShell)
Phase 3: Persistence       → T1547.001 (Registry Run Keys)
Phase 4: C2 Communication  → T1071.001 (Web Protocols - HTTP)
Phase 5: Exfiltration      → T1041 (Exfiltration Over C2 Channel)
```

---

## 3. Advanced Attack Vectors

### Advanced Persistent Threats (APTs)
- Long-term, targeted campaigns (weeks to years)
- Nation-state or sophisticated criminal groups
- Example: APT29 (Cozy Bear) — Russian SVR-linked group
- **Goal:** Espionage, IP theft, infrastructure disruption

### Supply Chain Attacks
- Compromise trusted third-party software/hardware
- **SolarWinds 2020:** Attackers inserted backdoor into Orion software update
  - 18,000+ organizations affected including US Government agencies
  - Technique: T1195.002 (Compromise Software Supply Chain)
  - Detection was delayed 9 months

### Zero-Day Exploits
- Vulnerabilities unknown to the vendor
- No patch available at time of exploitation
- Example: EternalBlue (MS17-010) — used in WannaCry
- **Detection challenge:** No signature exists; requires behavioral detection
- **Resources:** Exploit-DB (exploit-db.com), NVD (nvd.nist.gov)
