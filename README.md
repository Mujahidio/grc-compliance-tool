# GRC Compliance Checklist Tool

A Python CLI tool that maps security controls to **SAMA CSF** (Saudi Central Bank Cybersecurity Framework) and **NCA ECC** (National Cybersecurity Authority Essential Cybersecurity Controls).

Built for cybersecurity GRC professionals operating in Saudi Arabia's regulated financial sector.

---

## Features

- Interactive compliance assessment across SAMA CSF and NCA ECC domains
- Per-control status tracking: Compliant / Partially Compliant / Non-Compliant / Not Applicable
- Evidence and notes capture per control
- Critical gap identification and summary report
- Export results to **JSON** or **CSV**
- Demo mode for testing and presentations

---

## Frameworks Covered

| Framework | Domains Covered |
|-----------|----------------|
| SAMA CSF  | Governance, Risk Management, Operations & Technology, IAM, Third-Party Security |
| NCA ECC   | Governance, Defense, Resilience, Technology Acquisition |

---

## Requirements

- Python 3.8+
- No external dependencies (standard library only)

---

## Usage

```bash
python grc_checker.py
```

You will be prompted to:
1. Select a framework (SAMA CSF, NCA ECC, or both)
2. Rate each control's compliance status
3. Add optional notes/evidence
4. Export the final report

### Demo Mode

Run the tool and select option **4** to auto-generate a sample report without manual input — useful for testing or demonstrations.

---

## Output Example

```
=================================================================
  ASSESSMENT SUMMARY
=================================================================
  Total Controls Assessed : 32
  Compliant               : 18 (56.2%)
  Partially Compliant     : 7
  Non-Compliant           : 5
  Not Applicable          : 2

  [!] CRITICAL GAPS REQUIRING IMMEDIATE ACTION (3):
      - [SAMA-3.1] SIEM solution is deployed and monitored 24/7...
      - [SAMA-4.2] Multi-factor authentication (MFA) is enforced...
      - [ECC-3.3] Incident response plan is defined, tested...
```

---

## Author

**Mujahid Ahmed** — Cybersecurity GRC Specialist  
[LinkedIn](https://linkedin.com) | [GitHub](https://github.com)
