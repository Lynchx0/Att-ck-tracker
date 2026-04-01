# 🏦 ATT&CK Tracker

> A Python-based threat hunting toolkit that automatically maps MITRE ATT&CK techniques used by APT groups targeting the **Financial Services** sector — and generates ready-to-use hunting playbooks for SOC analysts.

![Python](https://img.shields.io/badge/Python-3.7+-blue)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red)
![Sector](https://img.shields.io/badge/Sector-Financial%20Services-green)
![No Dependencies](https://img.shields.io/badge/Dependencies-None-brightgreen)

---

## 📌 What is this?

**ATT&CK Tracker** is a Threat Intelligence toolkit built for SOC analysts and IR teams working in banking and financial institutions.

It automatically:
- 🔍 Pulls the latest MITRE ATT&CK data and detects all APT groups targeting Finance
- 📄 Generates a structured hunting playbook for each technique (Splunk, QRadar, Elastic)
- 📊 Builds a coverage matrix showing what you have and what gaps remain

No API keys. No external dependencies. Just Python.

**Built for:** SOC Analysts, Threat Hunters, IR teams in Banking & Financial institutions.

---

## 🎯 Tracked Finance-Targeting APT Groups

| Group ID | Name | Known For |
|---|---|---|
| G0046 | FIN7 | POS malware, spear-phishing banks |
| G0008 | Carbanak | SWIFT fraud, bank heists |
| G0032 | Lazarus Group | SWIFT attacks, crypto theft |
| G0037 | FIN6 | Payment card theft |
| G0038 | Silence | ATM cashout attacks |
| G0080 | Cobalt Group | ATM jackpotting |
| G0048 | RTM | Banking trojan campaigns |
| G0085 | FIN4 | Financial insider trading |
| G0083 | SilverTerrier | BEC against finance |

> ⚡ Groups are **auto-detected** from MITRE STIX data — new APTs added by MITRE will appear automatically on the next run.

---

## 🚀 Quick Start

```bash
# 1. Clone the repo
git clone https://github.com/YOUR_USERNAME/ATT-CK-Tracker.git
cd ATT-CK-Tracker

# 2. No dependencies needed — uses Python stdlib only
python3 --version  # Python 3.7+ required

# 3. Phase 1 — Fetch Finance techniques from MITRE
python3 scripts/ATT\&CK_Tracker.py

# 4. Phase 2 — Generate hunting playbooks
python3 scripts/generate_playbooks.py

# 5. Phase 3 — Build coverage matrix
python3 scripts/coverage_matrix.py
```

---

## 📄 Playbook Format

Each technique gets a dedicated Markdown playbook with:

```
T1566.001 — Spearphishing Attachment
├── Overview       (technique ID, tactic, platforms, APT groups)
├── Hunting Queries
│   ├── Splunk
│   ├── QRadar (AQL)
│   └── Elastic (EQL/KQL)
├── Log Sources Required
├── Finance Groups Using This Technique
└── Response Steps
```

**Example hunting query (Splunk):**
```spl
index=email_logs attachment_name IN ("*.doc","*.xls","*.js","*.vbs","*.hta")
| stats count by src_user, attachment_name, subject
```

---

## 📊 Coverage Matrix Output

After running Phase 3, you get a full coverage report:

```
✅ Initial Access      ████████████░░░  80%  (8/10)
✅ Execution           ██████████░░░░░  65%  (5/8)
⚠️  Persistence        ██████░░░░░░░░░  40%  (3/8)
❌ Reconnaissance     ░░░░░░░░░░░░░░░   0%  (0/5) ← GAP

Overall Coverage: 62%  |  Techniques: 45 covered / 73 total
```

The report highlights:
- ✅ Tactics with good coverage (60%+)
- ⚠️ Tactics needing more playbooks (30-59%)
- ❌ Gaps with zero coverage

---

## 🔗 References

- [MITRE ATT&CK Enterprise](https://attack.mitre.org/)
- [MITRE CTI GitHub](https://github.com/mitre/cti)
- [FS-ISAC Threat Intelligence](https://www.fsisac.com/)
- [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)

---

## 📄 License

MIT License — free to use, modify, and share.
