"""
infrastructure_filter.py
=========================
Reads my_infrastructure.yaml and finance_techniques.json,
then filters and prioritizes techniques relevant to YOUR environment.

Depends on:
- my_infrastructure.yaml      (fill this with your environment details)
- output/finance_techniques.json  (from Phase 1)

Output:
- output/my_prioritized_techniques.md    → prioritized report for your env
- output/my_prioritized_techniques.json  → machine-readable
"""

import json
import os
from datetime import datetime

# ──────────────────────────────────────────────
# PATHS
# ──────────────────────────────────────────────

BASE_DIR       = os.path.join(os.path.dirname(__file__), "..")
INPUT_FILE     = os.path.join(BASE_DIR, "output", "finance_techniques.json")
INFRA_FILE     = os.path.join(BASE_DIR, "my_infrastructure.yaml")
OUTPUT_DIR     = os.path.join(BASE_DIR, "output")
os.makedirs(OUTPUT_DIR, exist_ok=True)


# ──────────────────────────────────────────────
# TACTIC RISK SCORES
# Higher = more critical tactic
# ──────────────────────────────────────────────

TACTIC_RISK = {
    "Initial Access":        10,
    "Execution":             9,
    "Credential Access":     9,
    "Privilege Escalation":  8,
    "Defense Evasion":       8,
    "Lateral Movement":      8,
    "Persistence":           7,
    "Collection":            7,
    "Exfiltration":          9,
    "Command And Control":   8,
    "Discovery":             5,
    "Impact":                10,
    "Reconnaissance":        4,
    "Resource Development":  3,
}

# ──────────────────────────────────────────────
# SERVICE → TECHNIQUE MAPPING
# Which techniques are relevant per service
# ──────────────────────────────────────────────

SERVICE_TECHNIQUE_MAP = {
    "Active Directory": [
        "T1078", "T1003", "T1558", "T1550", "T1482",
        "T1087", "T1021", "T1110", "T1547",
    ],
    "MSSQL": [
        "T1190", "T1505", "T1078", "T1552",
    ],
    "Exchange": [
        "T1114", "T1566", "T1078", "T1048",
    ],
    "IIS": [
        "T1190", "T1505", "T1059",
    ],
    "Linux": [
        "T1053", "T1059", "T1548", "T1055",
    ],
    # ── Network Devices ──────────────────────
    "Firewall": [
        "T1562", "T1190", "T1048", "T1572", "T1071",
    ],
    "Wireless Access Points": [
        "T1557", "T1040", "T1078", "T1110",
    ],
    "Aruba": [
        "T1557", "T1040", "T1078", "T1110",
    ],
    "Cisco": [
        "T1557", "T1040", "T1078", "T1562", "T1190",
    ],
    "Printers": [
        "T1078", "T1110", "T1190", "T1040",
    ],
}


# ──────────────────────────────────────────────
# STEP 1 — Simple YAML parser (no dependencies)
# ──────────────────────────────────────────────

def parse_yaml(path: str) -> dict:
    """
    Minimal YAML parser — handles only the structure used
    in my_infrastructure.yaml (lists and key:value pairs).
    No external libraries needed.
    """
    if not os.path.exists(path):
        print(f"[!] ERROR: {path} not found!")
        print("[!] Please create my_infrastructure.yaml first.")
        return {}

    config = {}
    current_key = None

    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            # Skip comments and empty lines
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            # List item
            if stripped.startswith("- "):
                value = stripped[2:].strip()
                if current_key and isinstance(config.get(current_key), list):
                    config[current_key].append(value)

            # Key: value pair
            elif ":" in stripped:
                key, _, value = stripped.partition(":")
                key   = key.strip()
                value = value.strip()
                if value:
                    config[key] = value
                    current_key = key
                else:
                    config[key] = []
                    current_key = key

    return config


# ──────────────────────────────────────────────
# STEP 2 — Load techniques
# ──────────────────────────────────────────────

def load_techniques(path: str) -> list:
    if not os.path.exists(path):
        print(f"[!] ERROR: {path} not found!")
        print("[!] Please run ATT&CK_Tracker.py first.")
        return []
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


# ──────────────────────────────────────────────
# STEP 3 — Filter & score techniques
# ──────────────────────────────────────────────

def filter_and_score(techniques: list, config: dict) -> list:
    """
    Score each technique based on:
    - Platform match        (+40 if technique targets your OS)
    - Service match         (+30 if technique targets your services)
    - Network device match  (+20 if technique targets your network devices)
    - Group count           (+up to 20 based on how many APTs use it)
    - Tactic risk           (+up to 10 based on tactic severity)
    """
    platforms       = [p.lower() for p in config.get("platforms", [])]
    services        = config.get("services", [])
    network_devices = config.get("network_devices", [])

    # Build set of technique IDs relevant to services
    service_relevant = set()
    for svc in services:
        for tech_id in SERVICE_TECHNIQUE_MAP.get(svc, []):
            service_relevant.add(tech_id)

    # Build set of technique IDs relevant to network devices
    network_relevant = set()
    for device in network_devices:
        for tech_id in SERVICE_TECHNIQUE_MAP.get(device, []):
            network_relevant.add(tech_id)

    scored = []

    for tech in techniques:
        tech_id        = tech.get("technique_id", "")
        tech_platforms = [p.lower() for p in tech.get("platforms", [])]
        tactics        = tech.get("tactics", [])
        group_count    = tech.get("group_count", 0)
        score          = 0
        reasons        = []
        parent_id      = tech_id.split(".")[0]

        # Platform match
        if any(p in tech_platforms for p in platforms):
            score += 40
            reasons.append("platform match")

        # Service match
        if tech_id in service_relevant or parent_id in service_relevant:
            score += 30
            reasons.append("targets your services")

        # Network device match
        if tech_id in network_relevant or parent_id in network_relevant:
            score += 20
            reasons.append("targets your network devices")

        # Group count score (max 20)
        group_score = min(group_count * 3, 20)
        score += group_score
        if group_count > 3:
            reasons.append(f"{group_count} APT groups use this")

        # Tactic risk score (max 10)
        tactic_score = max(
            (TACTIC_RISK.get(t, 0) for t in tactics), default=0
        )
        score += tactic_score
        if tactic_score >= 8:
            reasons.append("high-risk tactic")

        scored.append({
            **tech,
            "score":   score,
            "reasons": reasons,
        })

    # Sort by score descending
    scored.sort(key=lambda x: x["score"], reverse=True)
    return scored


# ──────────────────────────────────────────────
# STEP 4 — Risk label
# ──────────────────────────────────────────────

def risk_label(score: int) -> str:
    if score >= 80:
        return "🔴 Critical"
    elif score >= 60:
        return "🟠 High"
    elif score >= 40:
        return "🟡 Medium"
    else:
        return "🟢 Low"


# ──────────────────────────────────────────────
# STEP 5 — Generate Markdown report
# ──────────────────────────────────────────────

def generate_report(scored: list, config: dict) -> str:
    date            = datetime.now().strftime("%Y-%m-%d")
    platforms       = ", ".join(config.get("platforms", []))
    services        = ", ".join(config.get("services", []))
    network_devices = ", ".join(config.get("network_devices", []))
    siem            = config.get("siem", "N/A")
    network         = config.get("network_type", "N/A")

    # Top 20 only
    top = scored[:20]

    rows = []
    for i, tech in enumerate(top, 1):
        tech_id = tech.get("technique_id", "")
        name    = tech.get("name", "")
        tactics = ", ".join(tech.get("tactics", []))
        groups  = ", ".join(f"`{g}`" for g in tech.get("finance_groups", []))
        score   = tech.get("score", 0)
        risk    = risk_label(score)
        rows.append(f"| {i} | `{tech_id}` | {name} | {tactics} | {risk} | {groups} |")

    rows_md = "\n".join(rows)

    return f"""# 🎯 ATT&CK Tracker — Prioritized Techniques for Your Environment

> Generated: {date}

---

## 🏗 Your Infrastructure Profile

| Field | Value |
|---|---|
| **Platforms** | {platforms} |
| **Services** | {services} |
| **Network Devices** | {network_devices} |
| **SIEM** | {siem} |
| **Network** | {network} |

---

## 🔴 Top 20 Techniques Relevant to Your Environment

> Ranked by: platform match + service exposure + APT group usage + tactic risk

| # | Technique | Name | Tactic | Risk | Finance Groups |
|---|---|---|---|---|---|
{rows_md}

---

## 📖 Risk Legend

| Level | Score | Meaning |
|---|---|---|
| 🔴 Critical | 80+ | Directly targets your platform & services — immediate focus |
| 🟠 High | 60-79 | High APT usage or critical tactic — high priority |
| 🟡 Medium | 40-59 | Moderate relevance to your environment |
| 🟢 Low | below 40 | Lower relevance but still worth monitoring |

---

## ✅ Recommended Next Steps

1. Start hunting for **Critical** techniques first
2. Make sure you have playbooks for all **Critical** and **High** techniques
3. Run `coverage_matrix.py` to check your current playbook coverage
4. Update `my_infrastructure.yaml` whenever your environment changes

---

*Generated by [ATT&CK Tracker](https://github.com/YOUR_USERNAME/ATT-CK-Tracker)*
"""


# ──────────────────────────────────────────────
# STEP 6 — Save outputs
# ──────────────────────────────────────────────

def save_markdown(content: str, path: str):
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"[+] Saved Markdown → {path}")


def save_json(data: list, config: dict, path: str):
    output = {
        "generated":       datetime.now().strftime("%Y-%m-%d %H:%M"),
        "infrastructure":  config,
        "top_techniques":  [
            {
                "rank":         i + 1,
                "technique_id": t.get("technique_id"),
                "name":         t.get("name"),
                "tactics":      t.get("tactics"),
                "score":        t.get("score"),
                "risk":         risk_label(t.get("score", 0)),
                "finance_groups": t.get("finance_groups"),
                "reasons":      t.get("reasons"),
            }
            for i, t in enumerate(data[:20])
        ]
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    print(f"[+] Saved JSON   → {path}")


# ──────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────

def main():
    print("=" * 55)
    print("  ATT&CK Tracker — Infrastructure Filter")
    print("  Phase 5: Prioritizing Techniques for Your Env")
    print("=" * 55)

    # Load infrastructure config
    config = parse_yaml(INFRA_FILE)
    if not config:
        return

    print(f"\n[+] Infrastructure profile loaded:")
    print(f"    Platforms       : {config.get('platforms', [])}")
    print(f"    Services        : {config.get('services', [])}")
    print(f"    Network Devices : {config.get('network_devices', [])}")
    print(f"    SIEM            : {config.get('siem', 'N/A')}")

    # Load techniques
    techniques = load_techniques(INPUT_FILE)
    if not techniques:
        return
    print(f"\n[+] Loaded {len(techniques)} finance techniques")

    # Filter and score
    scored = filter_and_score(techniques, config)
    print(f"[+] Scored and ranked all techniques")

    # Print top 10 to terminal
    print(f"\n🎯 Top 10 Techniques for YOUR Environment:")
    print("-" * 55)
    for i, tech in enumerate(scored[:10], 1):
        risk = risk_label(tech["score"])
        print(f"  #{i:<3} {tech['technique_id']:<12} {tech['name']:<35} {risk}")

    # Save outputs
    md_path   = os.path.join(OUTPUT_DIR, "my_prioritized_techniques.md")
    json_path = os.path.join(OUTPUT_DIR, "my_prioritized_techniques.json")

    content = generate_report(scored, config)
    save_markdown(content, md_path)
    save_json(scored, config, json_path)

    print(f"\n{'=' * 55}")
    print(f"✅ Done!")
    print(f"   🎯 my_prioritized_techniques.md  → full report")
    print(f"   📄 my_prioritized_techniques.json → machine-readable")
    print(f"{'=' * 55}")


if __name__ == "__main__":
    main()