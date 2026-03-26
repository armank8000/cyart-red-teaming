# Risk Assessment — ALE Calculation & Risk Matrix

## Scenario: Ransomware Attack on Organization

---

## Formulas

| Term | Definition | Formula |
|------|-----------|---------|
| **SLE** | Single Loss Expectancy — cost of one incident | Asset Value × Exposure Factor |
| **ARO** | Annual Rate of Occurrence — how often per year | Historical data / industry average |
| **ALE** | Annualized Loss Expectancy — expected yearly loss | SLE × ARO |

---

## Calculation

```
Given:
  SLE (Single Loss Expectancy)      = $10,000
  ARO (Annual Rate of Occurrence)   = 0.2  (once every 5 years)

ALE = SLE × ARO
ALE = $10,000 × 0.2
ALE = $2,000 per year
```

**Interpretation:** The organization can expect an average annual loss of **$2,000** from ransomware incidents.

---

## Google Sheets Formula

```
Cell A1: SLE         → 10000
Cell B1: ARO         → 0.2
Cell C1: ALE         → =A1*B1    → Result: 2000

Cell D1: Label       → "ALE = $2,000/year"
```

---

## 5x5 Risk Matrix

```
         │  1-Negligible │ 2-Minor  │ 3-Moderate │ 4-Major  │ 5-Critical
─────────┼───────────────┼──────────┼────────────┼──────────┼───────────
5-Almost │      5        │    10    │     15     │    20    │    25
Certain  │               │          │            │          │
─────────┼───────────────┼──────────┼────────────┼──────────┼───────────
4-Likely │      4        │     8    │     12     │    16    │    20
         │               │          │            │          │
─────────┼───────────────┼──────────┼────────────┼──────────┼───────────
3-Possible│     3        │     6    │      9     │    12    │    15
         │               │          │            │          │
─────────┼───────────────┼──────────┼────────────┼──────────┼───────────
2-Unlikely│     2        │     4    │      6     │     8    │    10
         │               │          │            │          │
─────────┼───────────────┼──────────┼────────────┼──────────┼───────────
1-Rare   │      1        │     2    │      3     │     4    │     5
         │               │          │            │          │
```

**Legend:**  1–4 = LOW (Green)  |  5–9 = MEDIUM (Yellow)  |  10–16 = HIGH (Orange)  |  17–25 = CRITICAL (Red)

---

## Ransomware Risk Scoring

| Risk Factor | Score | Justification |
|------------|-------|---------------|
| Likelihood | 2 (Unlikely) | Organization has basic backups and AV |
| Impact | 4 (Major) | Could affect 60% of business operations |
| **Risk Score** | **8 (HIGH)** | Requires immediate mitigation planning |

---

## Recommended Controls

1. **Preventive:** Deploy EDR solution, enforce MFA on all accounts
2. **Detective:** Enable file integrity monitoring, log anomalous encryption activity
3. **Corrective:** Maintain offline backups (3-2-1 rule), test restoration quarterly
4. **Cost Justification:** Spending up to $2,000/year on controls is break-even; spending less provides net positive ROI
