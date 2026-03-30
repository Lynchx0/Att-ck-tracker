"""
coverage_matrix.py
===================
Reads the playbooks/ folder (output of generate_playbooks.py)
and builds a coverage matrix showing which MITRE ATT&CK tactics
and techniques have playbooks and which are still gaps.

Depends on:
- output/finance_techniques.json  (from Phase 1)
- playbooks/                      (from Phase 2)

Output:
- output/coverage_matrix.md   → full human-readable report
- output/coverage_summary.json → machine-readable summary
"""

import json
import os
from datetime import datetime

# PATHS
# ──────────────────────────────────────────────

BASE_DIR      = os.path.join(os.path.dirname(__file__), "..")
INPUT_FILE    = os.path.join(BASE_DIR, "output", "finance_techniques.json")
PLAYBOOKS_DIR = os.path.join(BASE_DIR, "playbooks")
OUTPUT_DIR    = os.path.join(BASE_DIR, "output")
os.makedirs(OUTPUT_DIR, exist_ok=True)


# ──────────────────────────────────────────────
# ALL 14 MITRE ATT&CK TACTICS (ordered)
# ──────────────────────────────────────────────

ALL_TACTICS = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command And Control",
    "Exfiltration",
    "Impact",
]

# Coverage thresholds
GOOD_THRESHOLD = 0.6   # 60%+ = good coverage   ✅
WARN_THRESHOLD = 0.3   # 30%+ = partial coverage ⚠️
                       # below 30% = gap         ❌


# ──────────────────────────────────────────────
# STEP 1 — Load finance techniques
# ──────────────────────────────────────────────

def load_techniques(path: str) -> list:
    if not os.path.exists(path):
        print(f"[!] ERROR: {path} not found!")
        print("[!] Please run ATT&CK_Tracker.py first.")
        return []
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


# ──────────────────────────────────────────────
# STEP 2 — Check which techniques have playbooks
# ──────────────────────────────────────────────

def get_covered_techniques(playbooks_dir: str) -> set:
    """Return set of technique IDs that have a playbook file."""
    covered = set()
    if not os.path.exists(playbooks_dir):
        return covered
    for fname in os.listdir(playbooks_dir):
        if fname.endswith(".md") and fname != "INDEX.md":
            # filename format: T1566.001_Spearphishing_Attachment.md
            tech_id = fname.split("_")[0]
            covered.add(tech_id)
    return covered


# ──────────────────────────────────────────────
# STEP 3 — Build coverage data per tactic
# ──────────────────────────────────────────────

def build_coverage(techniques: list, covered: set) -> dict:
    """
    Returns dict:
    {
      tactic_name: {
        "total":    int,
        "covered":  int,
        "percent":  float,
        "techniques": [
          {"id": "T1566.001", "name": "...", "covered": True/False, "groups": [...]}
        ]
      }
    }
    """
    data = {tactic: {"total": 0, "covered": 0, "techniques": []} for tactic in ALL_TACTICS}

    for tech in techniques:
        tech_id  = tech.get("technique_id", "")
        name     = tech.get("name", "")
        tactics  = tech.get("tactics", [])
        groups   = tech.get("finance_groups", [])
        is_covered = tech_id in covered

        for tactic in tactics:
            # Normalize tactic name
            normalized = tactic.title()
            if normalized not in data:
                data[normalized] = {"total": 0, "covered": 0, "techniques": []}

            data[normalized]["total"] += 1
            if is_covered:
                data[normalized]["covered"] += 1
            data[normalized]["techniques"].append({
                "id":      tech_id,
                "name":    name,
                "covered": is_covered,
                "groups":  groups,
            })

    # Calculate percentages
    for tactic in data:
        total = data[tactic]["total"]
        covered_count = data[tactic]["covered"]
        data[tactic]["percent"] = (covered_count / total * 100) if total > 0 else 0.0

    return data


# ──────────────────────────────────────────────
# STEP 4 — Generate coverage bar
# ──────────────────────────────────────────────

def make_bar(percent: float, width: int = 20) -> str:
    filled = int(percent / 100 * width)
    empty  = width - filled
    return "█" * filled + "░" * empty


def coverage_icon(percent: float) -> str:
    if percent >= GOOD_THRESHOLD * 100:
        return "✅"
    elif percent >= WARN_THRESHOLD * 100:
        return "⚠️"
    else:
        return "❌"


# ──────────────────────────────────────────────
# STEP 5 — Generate Markdown report
# ──────────────────────────────────────────────

def _format_summary_row(tactic: str, data: dict) -> str:
    total   = data["total"]
    covered = data["covered"]
    pct     = data["percent"]
    
    if total == 0:
        return f"| {tactic} | — | — | `░░░░░░░░░░░░░░░` | ➖ Not in Finance scope |"
    
    bar  = make_bar(pct, width=15)
    icon = coverage_icon(pct)
    return f"| {tactic} | {covered} | {total} | `{bar}` {pct:.0f}% | {icon} |"


def _build_summary_table(coverage_data: dict) -> str:
    summary_rows = []
    for tactic in ALL_TACTICS:
        d = coverage_data.get(tactic, {"total": 0, "covered": 0, "percent": 0.0})
        summary_rows.append(_format_summary_row(tactic, d))
    return "\n".join(summary_rows)


def _collect_techniques_by_status(coverage_data: dict, covered: bool) -> list:
    techniques = []
    for tactic in ALL_TACTICS:
        d = coverage_data.get(tactic, {})
        for tech in d.get("techniques", []):
            if tech["covered"] == covered:
                techniques.append((tactic, tech))
    return techniques


def _format_technique_row(tactic: str, tech: dict) -> str:
    groups = ", ".join(f"`{g}`" for g in tech["groups"])
    return f"| {tech['id']} | {tech['name']} | {tactic} | {groups} |"


def _build_technique_section(techniques: list, empty_msg: str) -> str:
    rows = [_format_technique_row(tactic, tech) for tactic, tech in techniques]
    return "\n".join(rows) if rows else f"| — | {empty_msg} | — | — |"


def generate_markdown(coverage_data: dict, total_techs: int, total_covered: int) -> str:
    date             = datetime.now().strftime("%Y-%m-%d")
    overall_percent  = (total_covered / total_techs * 100) if total_techs > 0 else 0
    overall_bar      = make_bar(overall_percent)
    overall_icon     = coverage_icon(overall_percent)

    summary_md = _build_summary_table(coverage_data)
    
    gaps       = _collect_techniques_by_status(coverage_data, covered=False)
    gaps_md    = _build_technique_section(gaps, "No gaps found! All techniques covered")
    
    covered    = _collect_techniques_by_status(coverage_data, covered=True)
    covered_rows = [_format_technique_row(tactic, tech) for tactic, tech in covered]

    covered_md = "\n".join(covered_rows) if covered_rows else "| — | No playbooks found | — | — |"

    return f"""# 📊 ATT&CK Tracker — Coverage Matrix

> **ATT&CK Tracker** | Financial Sector Coverage Report
> Generated: {date}

---

## 🎯 Overall Coverage

```
{overall_bar}  {overall_percent:.0f}%  {overall_icon}
Techniques with playbooks: {total_covered} / {total_techs}
```

**Legend:** ✅ Good (60%+)  |  ⚠️ Partial (30–59%)  |  ❌ Gap (below 30%)  |  ➖ Not in Finance scope

---

## 📋 Coverage by Tactic

| Tactic | Covered | Total | Progress | Status |
|---|---|---|---|---|
{summary_md}

---

## ❌ Gaps — Techniques Without Playbooks

> These techniques are used by finance-targeting APTs but have no hunting playbook yet.
> **Priority:** Add playbooks for these to improve your coverage.

| Technique ID | Name | Tactic | Finance Groups |
|---|---|---|---|
{gaps_md}

---

## ✅ Covered — Techniques With Playbooks

| Technique ID | Name | Tactic | Finance Groups |
|---|---|---|---|
{covered_md}

---

## 🔧 How to Improve Coverage

1. Pick a technique from the **Gaps** table above
2. Run `generate_playbooks.py` — it will create a generic playbook for it
3. Customize the hunting queries for your environment
4. Re-run `coverage_matrix.py` to see your updated coverage

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


def save_summary_json(coverage_data: dict, total: int, covered: int, path: str):
    summary = {
        "generated":       datetime.now().strftime("%Y-%m-%d %H:%M"),
        "total_techniques": total,
        "covered":          covered,
        "gaps":             total - covered,
        "overall_percent":  round((covered / total * 100) if total > 0 else 0, 1),
        "by_tactic": {}
    }
    for tactic in ALL_TACTICS:
        d = coverage_data.get(tactic, {"total": 0, "covered": 0, "percent": 0.0})
        if d["percent"] >= 60:
            status = "good"
        elif d["percent"] >= 30:
            status = "partial"
        elif d["total"] > 0:
            status = "gap"
        else:
            status = "not_in_scope"
        summary["by_tactic"][tactic] = {
            "total":   d["total"],
            "covered": d["covered"],
            "percent": round(d["percent"], 1),
            "status":  status,
        }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)
    print(f"[+] Saved JSON   → {path}")


# MAIN
# ──────────────────────────────────────────────

def main():
    print("=" * 55)
    print("  ATT&CK Tracker — Coverage Matrix")
    print("  Phase 3: Building Coverage Report")
    print("=" * 55)

    # Load techniques
    techniques = load_techniques(INPUT_FILE)
    if not techniques:
        return

    print(f"[+] Loaded {len(techniques)} finance techniques")

    # Check which ones have playbooks
    covered = get_covered_techniques(PLAYBOOKS_DIR)
    print(f"[+] Found {len(covered)} techniques with playbooks in {PLAYBOOKS_DIR}")

    if len(covered) == 0:
        print("[!] No playbooks found — please run generate_playbooks.py first")
        return

    # Build coverage data
    coverage_data = build_coverage(techniques, covered)

    total_covered = sum(1 for t in techniques if t.get("technique_id") in covered)
    total_techs   = len(techniques)

    # Print quick summary to terminal
    print("\n📊 Coverage Summary:")
    print("-" * 55)
    for tactic in ALL_TACTICS:
        d    = coverage_data.get(tactic, {"total": 0, "covered": 0, "percent": 0.0})
        if d["total"] == 0:
            continue
        icon = coverage_icon(d["percent"])
        bar  = make_bar(d["percent"], width=15)
        print(f"  {icon} {tactic:<25} {bar} {d['percent']:.0f}%  ({d['covered']}/{d['total']})")

    overall = (total_covered / total_techs * 100) if total_techs > 0 else 0
    print(f"\n  Overall: {overall:.0f}% ({total_covered}/{total_techs} techniques covered)")

    # Save outputs
    md_path   = os.path.join(OUTPUT_DIR, "coverage_matrix.md")
    json_path = os.path.join(OUTPUT_DIR, "coverage_summary.json")

    md_content = generate_markdown(coverage_data, total_techs, total_covered)
    save_markdown(md_content, md_path)
    save_summary_json(coverage_data, total_techs, total_covered, json_path)

    print("\n" + "=" * 55)
    print("✅ Done!")
    print("   📊 coverage_matrix.md   → full report")
    print("   📄 coverage_summary.json → machine-readable")
    print("=" * 55)


if __name__ == "__main__":
    main()