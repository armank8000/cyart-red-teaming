# Incident Response Fundamentals — Study Notes

## Incident Lifecycle (SANS Model)

```
1. PREPARATION  →  2. DETECTION  →  3. CONTAINMENT  →  4. ERADICATION  →  5. RECOVERY  →  6. LESSONS LEARNED
```

| Phase | Key Activities | Tools |
|-------|---------------|-------|
| Preparation | IR policy, playbooks, team roles, toolkits | Wazuh, Velociraptor |
| Detection | Alert triage, log analysis, IOC hunting | SIEM, Elastic, Suricata |
| Containment | Isolate systems, block IPs, preserve evidence | CrowdSec, firewall rules |
| Eradication | Remove malware, patch vulnerability, reset credentials | EDR, AV, patching tools |
| Recovery | Restore systems, monitor for recurrence | Backups, monitoring |
| Lessons Learned | Document findings, update playbooks | Google Docs, Confluence |

## SOC Workflow

```
Alert Generated (SIEM)
       ↓
Tier 1 Analyst — Initial Triage (false positive check)
       ↓ (if real)
Tier 2 Analyst — Deep Investigation
       ↓ (if critical)
Tier 3 / IR Team — Full Incident Response
       ↓
Incident Report + Lessons Learned
```

## Incident Prioritization (Severity Levels)

| Severity | Criteria | Response SLA |
|----------|---------|-------------|
| P1 - Critical | Active breach, data exfiltration | 15 minutes |
| P2 - High | Malware detected, C2 communication | 1 hour |
| P3 - Medium | Suspicious activity, policy violation | 4 hours |
| P4 - Low | Minor anomaly, informational | 24 hours |
