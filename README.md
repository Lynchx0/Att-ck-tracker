# ATT&CK_Tracker
# 🏦 Financial Sector Threat Hunting Playbooks (MITRE ATT&CK)

> Threat hunting playbooks mapped to MITRE ATT&CK techniques used by APT groups targeting the **Financial Services** sector.

---

## 📌 What is this?

This project automatically pulls all MITRE ATT&CK techniques used by known finance-targeting threat groups (FIN7, Carbanak, Lazarus, Silence, Cobalt Group, etc.) and builds structured hunting playbooks for each one.

**Built for:** SOC Analysts, Threat Hunters, IR teams in Banking & Financial institutions.

---

## 🎯 Tracked Finance-Targeting Groups

| Group ID | Name | Known For |
|----------|------|-----------|
| G0046 | FIN7 | POS malware, spear-phishing banks |
| G0008 | Carbanak | SWIFT fraud, bank heists |
| G0032 | Lazarus Group | SWIFT attacks, crypto theft |
| G0037 | FIN6 | Payment card theft |
| G0038 | Silence | ATM cashout attacks |
| G0080 | Cobalt Group | ATM jackpotting |
| G0048 | RTM | Banking trojan campaigns |
| G0085 | FIN4 | Financial insider trading |
| G0083 | SilverTerrier | BEC against finance |

---

## 🗂 Project Structure

```
finance-hunting-playbooks/
├── scripts/
│   ├── fetch_finance_techniques.py   # Step 1: Pull techniques from MITRE
│   └── generate_playbooks.py         # Step 2: Generate playbook per technique (coming soon)
├── playbooks/
│   └── <TXXXX>_<technique_name>.md  # Auto-generated playbooks
├── output/
│   ├── finance_techniques.json       # Raw technique data
│   └── finance_techniques.csv        # Spreadsheet-friendly view
└── README.md
```

---

## 🚀 Quick Start

```bash
# 1. Clone the repo
git clone https://github.com/YOUR_USERNAME/finance-hunting-playbooks.git
cd finance-hunting-playbooks

# 2. Install dependencies (none required — uses stdlib only)
python3 --version  # requires Python 3.7+

# 3. Fetch Finance techniques from MITRE
python3 scripts/fetch_finance_techniques.py

# 4. Check output
cat output/finance_techniques.csv
```

---

## 📊 Sample Output

```
technique_id  name                          tactics           finance_groups
T1566.001     Spearphishing Attachment      Initial Access    FIN7, Carbanak, Lazarus Group
T1055         Process Injection             Defense Evasion   FIN7, Silence, Cobalt Group
T1078         Valid Accounts                Persistence       Carbanak, FIN6, Lazarus Group
T1003         OS Credential Dumping         Credential Access FIN7, Cobalt Group, Silence
```

---

## 🛡 Playbook Format (coming in next phase)

Each technique gets a playbook with:

```markdown
## T1566.001 — Spearphishing Attachment

### 🎯 Hypothesis
Threat actor sends malicious email attachments to gain initial access

### 🔍 Hunting Queries
**Splunk:**  index=email_logs attachment_type IN ("doc","xls","js","vbs")
**KQL:**     EmailAttachmentInfo | where FileType in ("doc","xls","js")

### 📋 Log Sources Required
- Email gateway logs
- Endpoint EDR logs

### ✅ Response Steps
1. Isolate affected endpoint
2. Extract attachment for sandbox analysis
3. Search for lateral movement from same host
```

---

## 🔗 References

- [MITRE ATT&CK Enterprise](https://attack.mitre.org/)
- [FS-ISAC Threat Intelligence](https://www.fsisac.com/)
- [MITRE CTI GitHub](https://github.com/mitre/cti)

---

## 📄 License

MIT License — free to use, modify, and share.
