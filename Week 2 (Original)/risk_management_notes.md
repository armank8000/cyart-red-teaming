# Risk Management Advanced Concepts — Study Notes

## Quantitative vs Qualitative Risk Assessment

| Aspect | Quantitative | Qualitative |
|--------|-------------|-------------|
| Measurement | Numerical ($, %) | Descriptive (High/Med/Low) |
| Formula | ALE = SLE × ARO | Risk Matrix (Likelihood × Impact) |
| Precision | High | Low-Medium |
| Use Case | Financial reporting, insurance | Initial risk surveys |
| Example | "Ransomware = $2,000/year ALE" | "Ransomware = HIGH risk" |

## Key Formulas

```
SLE  = Asset Value (AV) × Exposure Factor (EF)
ARO  = Expected frequency per year
ALE  = SLE × ARO

Example:
  AV  = $50,000 (server value)
  EF  = 0.20    (20% of server destroyed in incident)
  SLE = $50,000 × 0.20 = $10,000
  ARO = 0.2     (once every 5 years)
  ALE = $10,000 × 0.2  = $2,000/year
```

## Business Impact Analysis (BIA)

BIA identifies critical business functions and the impact of disruption.

| BIA Metric | Definition |
|-----------|-----------|
| **RTO** | Recovery Time Objective — max acceptable downtime |
| **RPO** | Recovery Point Objective — max acceptable data loss |
| **MTTR** | Mean Time to Recovery — average time to restore |
| **MTBF** | Mean Time Between Failures — reliability measure |

## FAIR Risk Model (Factor Analysis of Information Risk)

FAIR provides a quantitative framework for cyber risk:

```
Risk = Probable Frequency × Probable Magnitude

Threat Event Frequency (TEF)
  × Vulnerability (Vuln)
  = Loss Event Frequency (LEF)
    × Primary Loss Magnitude (PLM)
    = Risk ($)
```

**Resource:** FAIR Institute — fairinstitute.org
