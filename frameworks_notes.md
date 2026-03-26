# Security Frameworks — Study Notes

## 1. NIST Cybersecurity Framework (CSF)

The NIST CSF provides a policy framework of computer security guidance for organizations.

### Five Core Functions

| Function | Purpose | Key Activities |
|----------|---------|---------------|
| **IDENTIFY** | Understand the environment | Asset inventory, risk assessment, governance |
| **PROTECT** | Safeguard critical services | Access control, encryption, training, maintenance |
| **DETECT** | Discover cybersecurity events | Monitoring, anomaly detection, logging |
| **RESPOND** | Act on detected incidents | IR planning, communications, analysis, mitigation |
| **RECOVER** | Restore capabilities | Recovery planning, improvements, communications |

### Implementation Tiers

| Tier | Name | Description |
|------|------|-------------|
| Tier 1 | Partial | Ad hoc, reactive, limited awareness |
| Tier 2 | Risk-Informed | Risk-aware but not organization-wide policy |
| Tier 3 | Repeatable | Formal policy, consistent across organization |
| Tier 4 | Adaptive | Continuously improving, real-time adaptation |

### WannaCry Mapped to NIST CSF

| NIST Function | Action Taken |
|--------------|-------------|
| Identify | Catalog unpatched Windows systems |
| Protect | Apply MS17-010 patch, disable SMBv1 |
| Detect | Monitor for EternalBlue exploit signatures |
| Respond | Isolate infected machines, activate IR plan |
| Recover | Restore from backups, verify clean state |

---

## 2. ISO 27001 Controls

ISO 27001 defines 114 controls across 14 domains in Annex A.

### Key Controls Relevant to Week 2

| Control ID | Domain | Description | Ransomware Application |
|-----------|--------|-------------|----------------------|
| A.8.2.1 | Asset Classification | Classify data by sensitivity | Identify critical data for extra protection |
| A.12.3.1 | Backup | Regular tested backups | Restore capability after ransomware |
| A.12.4.1 | Event Logging | Log all security events | Detect ransomware early via log anomalies |
| A.12.6.1 | Vulnerability Management | Timely patch management | Patch exploited vulnerabilities like MS17-010 |
| A.14.2.1 | Security in Dev | Secure development policy | Prevent vulnerable software from shipping |
| A.16.1.1 | IR Management | Formal IR procedure | Structured response to ransomware incident |

### Ransomware Mitigation Using ISO 27001

1. **A.8.2.1** — Classify data to prioritize what needs backup
2. **A.12.3.1** — 3-2-1 backup rule (3 copies, 2 media, 1 offsite)
3. **A.12.4.1** — Log anomalous file encryption activity
4. **A.12.6.1** — Patch OS and applications within SLA
5. **A.16.1.1** — Execute documented IR playbook

---

## 3. CIS Controls vs NIST CSF Mapping

| CIS Control | CIS Name | NIST CSF Function |
|-------------|---------|------------------|
| CIS 1 | Inventory of Enterprise Assets | IDENTIFY |
| CIS 2 | Inventory of Software Assets | IDENTIFY |
| CIS 3 | Data Protection | PROTECT |
| CIS 4 | Secure Configuration | PROTECT |
| CIS 6 | Access Control Management | PROTECT |
| CIS 8 | Audit Log Management | DETECT |
| CIS 13 | Network Monitoring and Defense | DETECT |
| CIS 17 | Incident Response Management | RESPOND |
