"""
ATT&CK_Tracker.py
============================
Fetches all MITRE ATT&CK techniques used by threat groups
that target the Financial Services sector.

🔄 DYNAMIC MODE:
- Auto-detects finance-targeting groups directly from MITRE STIX data
  by scanning group descriptions for finance-related keywords.
- Manual override list handles groups that target finance but aren't
  explicitly labelled as such in MITRE descriptions.
- Every time you run this script, it pulls the latest MITRE data —
  so any new APT group MITRE adds will appear automatically.

Output:
- finance_techniques.json  → raw data
- finance_techniques.csv   → for spreadsheet viewing
- finance_groups_found.txt → log of all detected groups this run
"""

import json
import csv
import os
import urllib.request
from collections import defaultdict

# CONFIG
# ──────────────────────────────────────────────

MITRE_STIX_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)

# Keywords used to auto-detect finance-targeting groups
# from their MITRE description text
FINANCE_KEYWORDS = [
    "financial", "finance", "banking", "bank",
    "swift", "atm", "payment", "cryptocurrency",
    "wire transfer", "stock", "trading", "fintech",
    "credit card", "pos terminal", "money",
]

# Manual override — groups known to target Finance
# but not explicitly described as such in MITRE STIX.
# This list is a safety net, NOT the primary detection method.
MANUAL_FINANCE_GROUPS = {
    "G0046": "FIN7",           # POS malware, restaurant/hotel/finance
    "G0008": "Carbanak",       # Bank heists via SWIFT
    "G0032": "Lazarus Group",  # SWIFT attacks, crypto theft
    "G0037": "FIN6",           # Payment card theft
    "G0085": "FIN4",           # Financial insider trading
    "G0038": "Silence",        # ATM cashout attacks
    "G0083": "SilverTerrier",  # BEC targeting finance
    "G0080": "Cobalt Group",   # ATM jackpotting
    "G0048": "RTM",            # Banking trojan campaigns
}

OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "..", "output")
os.makedirs(OUTPUT_DIR, exist_ok=True)


# ──────────────────────────────────────────────
# STEP 1 — Download MITRE STIX bundle
# ──────────────────────────────────────────────

def download_stix(url: str) -> dict:
    print("[*] Downloading latest MITRE ATT&CK STIX data...")
    with urllib.request.urlopen(url, timeout=30) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    print(f"[+] Downloaded {len(data['objects'])} STIX objects")
    return data


# ──────────────────────────────────────────────
# STEP 2 — Parse objects into lookup dicts
# ──────────────────────────────────────────────

def parse_stix(bundle: dict):
    techniques = {}   # stix_id → technique info
    groups     = {}   # stix_id → group info
    relations  = []   # list of (group_stix_id, technique_stix_id)

    for obj in bundle["objects"]:
        obj_type = obj.get("type", "")

        # ── Techniques ──────────────────────────
        if obj_type == "attack-pattern":
            ext = obj.get("external_references", [])
            mitre_ref = next(
                (r for r in ext if r.get("source_name") == "mitre-attack"), {}
            )
            tech_id  = mitre_ref.get("external_id", "")
            tech_url = mitre_ref.get("url", "")

            tactics = [
                phase["phase_name"].replace("-", " ").title()
                for phase in obj.get("kill_chain_phases", [])
                if phase.get("kill_chain_name") == "mitre-attack"
            ]

            techniques[obj["id"]] = {
                "technique_id":    tech_id,
                "name":            obj.get("name", ""),
                "description":     obj.get("description", "")[:300],
                "tactics":         tactics,
                "url":             tech_url,
                "platforms":       obj.get("x_mitre_platforms", []),
                "data_sources":    obj.get("x_mitre_data_sources", []),
                "is_subtechnique": obj.get("x_mitre_is_subtechnique", False),
            }

        # ── Groups ──────────────────────────────
        elif obj_type == "intrusion-set":
            ext = obj.get("external_references", [])
            mitre_ref = next(
                (r for r in ext if r.get("source_name") == "mitre-attack"), {}
            )
            groups[obj["id"]] = {
                "group_id":    mitre_ref.get("external_id", ""),
                "name":        obj.get("name", ""),
                "aliases":     obj.get("aliases", []),
                "description": obj.get("description", "").lower(),
            }

        # ── Relationships (group → technique) ───
        elif obj_type == "relationship":
            if obj.get("relationship_type") == "uses":
                relations.append((
                    obj.get("source_ref", ""),
                    obj.get("target_ref", ""),
                ))

    print(f"[+] Parsed: {len(techniques)} techniques | "
          f"{len(groups)} groups | {len(relations)} relationships")
    return techniques, groups, relations


# ──────────────────────────────────────────────
# STEP 3 — Auto-detect Finance groups (DYNAMIC)
# ──────────────────────────────────────────────

def detect_finance_groups(groups: dict) -> dict:
    """
    Returns {stix_id: group_name} for all finance-targeting groups.

    Detection logic (two layers):
    1. DYNAMIC  — scan MITRE description for finance keywords
    2. MANUAL   — override list for groups not explicitly labelled
    """
    finance_stix_ids = {}   # stix_id → group name
    detected_log     = []   # for the log file

    print("\n[*] Scanning all MITRE groups for finance indicators...")

    for stix_id, info in groups.items():
        group_id   = info["group_id"]
        group_name = info["name"]
        desc       = info["description"]

        # Layer 1: Dynamic keyword match
        matched_keywords = [kw for kw in FINANCE_KEYWORDS if kw in desc]

        # Layer 2: Manual override
        is_manual = group_id in MANUAL_FINANCE_GROUPS

        if matched_keywords or is_manual:
            source = []
            if matched_keywords:
                source.append(f"keywords: {matched_keywords}")
            if is_manual:
                source.append("manual override")

            finance_stix_ids[stix_id] = group_name
            log_entry = (
                f"{group_id:<8} {group_name:<25} "
                f"[{' | '.join(source)}]"
            )
            detected_log.append(log_entry)
            print(f"  [✓] {log_entry}")

    print(f"\n[+] Total finance-targeting groups detected: {len(finance_stix_ids)}")

    # Save detection log
    log_path = os.path.join(OUTPUT_DIR, "finance_groups_found.txt")
    with open(log_path, "w", encoding="utf-8") as f:
        f.write("ATT&CK Tracker — Finance Groups Detection Log\n")
        f.write("=" * 60 + "\n\n")
        f.write(f"Total groups found: {len(detected_log)}\n\n")
        f.write("GROUP ID  NAME                      DETECTION SOURCE\n")
        f.write("-" * 60 + "\n")
        f.write("\n".join(detected_log))
    print(f"[+] Detection log saved → {log_path}")

    return finance_stix_ids


# ──────────────────────────────────────────────
# STEP 4 — Extract TTPs for Finance groups
# ──────────────────────────────────────────────

def extract_finance_ttps(techniques, finance_stix_ids, relations):
    tech_to_groups = defaultdict(set)

    for src, tgt in relations:
        if src in finance_stix_ids and tgt in techniques:
            tech_to_groups[tgt].add(finance_stix_ids[src])

    results = []
    for tech_stix_id, using_groups in tech_to_groups.items():
        tech = techniques[tech_stix_id]
        results.append({
            **tech,
            "finance_groups": sorted(using_groups),
            "group_count":    len(using_groups),
        })

    results.sort(key=lambda x: x["group_count"], reverse=True)
    print(f"[+] Found {len(results)} techniques used by finance-targeting groups")
    return results


# ──────────────────────────────────────────────
# STEP 5 — Save outputs
# ──────────────────────────────────────────────

def save_json(data, path):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    print(f"[+] Saved JSON → {path}")


def save_csv(data, path):
    if not data:
        return
    fieldnames = [
        "technique_id", "name", "tactics", "finance_groups",
        "group_count", "platforms", "data_sources", "url"
    ]
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in data:
            writer.writerow({
                **row,
                "tactics":        ", ".join(row.get("tactics", [])),
                "finance_groups": ", ".join(row.get("finance_groups", [])),
                "platforms":      ", ".join(row.get("platforms", [])),
                "data_sources":   ", ".join(row.get("data_sources", [])),
            })
    print(f"[+] Saved CSV  → {path}")


# MAIN
# ──────────────────────────────────────────────

def main():
    print("=" * 55)
    print("  ATT&CK Tracker — Finance Sector Techniques Fetcher")
    print("  🔄 Dynamic Mode: auto-detects groups from MITRE")
    print("=" * 55)

    bundle = download_stix(MITRE_STIX_URL)
    techniques, groups, relations = parse_stix(bundle)

    # Dynamic detection — no more hard-coded list!
    finance_stix_ids = detect_finance_groups(groups)

    finance_ttps = extract_finance_ttps(techniques, finance_stix_ids, relations)

    json_path = os.path.join(OUTPUT_DIR, "finance_techniques.json")
    csv_path  = os.path.join(OUTPUT_DIR, "finance_techniques.csv")

    save_json(finance_ttps, json_path)
    save_csv(finance_ttps,  csv_path)

    # Quick summary
    print("\n📊 Top 10 Most-Used Techniques in Finance Sector:")
    print("-" * 55)
    for t in finance_ttps[:10]:
        tactic     = t["tactics"][0] if t["tactics"] else "N/A"
        groups_str = ", ".join(t["finance_groups"])
        print(f"  {t['technique_id']:<12} {t['name']:<40}")
        print(f"             Tactic: {tactic}")
        print(f"             Groups: {groups_str}\n")

    print("✅ Done! Check the output/ folder.")


if __name__ == "__main__":
    main()