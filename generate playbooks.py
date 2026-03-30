"""
generate_playbooks.py
======================
Reads finance_techniques.json (output of ATT&CK_Tracker.py)
and generates a structured Markdown hunting playbook for each technique.

Output:
- playbooks/<TECHNIQUE_ID>_<technique_name>.md   (one file per technique)
- playbooks/INDEX.md                              (master index of all playbooks)

Run ATT&CK_Tracker.py first to generate finance_techniques.json
"""

import json
import os
import re
from datetime import datetime

# PATHS
# ──────────────────────────────────────────────

BASE_DIR      = os.path.join(os.path.dirname(__file__), "..")
INPUT_FILE    = os.path.join(BASE_DIR, "output", "finance_techniques.json")
PLAYBOOKS_DIR = os.path.join(BASE_DIR, "playbooks")
os.makedirs(PLAYBOOKS_DIR, exist_ok=True)

# COMMON STRINGS
# ──────────────────────────────────────────────

EDR_TELEMETRY = "EDR telemetry"


# ──────────────────────────────────────────────
# HUNTING QUERIES
# Splunk + QRadar + Elastic queries per technique
# ──────────────────────────────────────────────

HUNTING_QUERIES = {
    # ── Initial Access ───────────────────────
    "T1566.001": {
        "splunk":  'index=email_logs attachment_name IN ("*.doc","*.xls","*.js","*.vbs","*.hta","*.iso") | stats count by src_user, attachment_name, subject',
        "qradar":  'SELECT sourceip, username, filename, subject FROM events WHERE category=\'Email\' AND filename ILIKE \'%.doc\' OR filename ILIKE \'%.xls\' OR filename ILIKE \'%.js\' LAST 24 HOURS',
        "elastic": 'event.category:email AND file.extension:(doc OR xls OR js OR vbs OR hta OR iso)',
    },
    "T1566.002": {
        "splunk":  'index=proxy_logs url_category="newly_registered" OR url_category="phishing" | stats count by src_ip, url, user',
        "qradar":  'SELECT sourceip, username, url FROM events WHERE category=\'Web\' AND url ILIKE \'%phish%\' LAST 24 HOURS',
        "elastic": 'event.category:network AND threat.indicator.type:url AND url.domain:*',
    },
    "T1078": {
        "splunk":  'index=wineventlog EventCode=4624 Logon_Type=3 | rare limit=20 Account_Name | where count < 5',
        "qradar":  'SELECT username, sourceip, LOGSOURCENAME(logsourceid) FROM events WHERE eventid=4624 AND logontype=3 GROUP BY username, sourceip HAVING count(*) < 5 LAST 24 HOURS',
        "elastic": 'event.code:4624 AND winlog.event_data.LogonType:3',
    },
    "T1190": {
        "splunk":  'index=waf_logs action=blocked | stats count by src_ip, uri, attack_type | sort -count',
        "qradar":  'SELECT sourceip, url, category FROM events WHERE category=\'WAF\' AND action=\'blocked\' GROUP BY sourceip ORDER BY count(*) DESC LAST 24 HOURS',
        "elastic": 'event.category:network AND event.outcome:failure AND destination.port:(80 OR 443)',
    },

    # ── Execution ────────────────────────────
    "T1059.001": {
        "splunk":  'index=wineventlog EventCode=4104 | search ScriptBlockText IN ("*IEX*","*Invoke-Expression*","*DownloadString*","*EncodedCommand*") | stats count by ComputerName, ScriptBlockText',
        "qradar":  'SELECT hostname, username, payload FROM events WHERE eventid=4104 AND (payload ILIKE \'%IEX%\' OR payload ILIKE \'%Invoke-Expression%\' OR payload ILIKE \'%DownloadString%\') LAST 24 HOURS',
        "elastic": 'event.code:4104 AND winlog.event_data.ScriptBlockText:(IEX OR "Invoke-Expression" OR DownloadString OR EncodedCommand)',
    },
    "T1059.003": {
        "splunk":  'index=wineventlog EventCode=4688 New_Process_Name="*cmd.exe" | search Process_Command_Line IN ("*net user*","*whoami*","*systeminfo*","*/c powershell*") | stats count by ComputerName, Process_Command_Line',
        "qradar":  'SELECT hostname, username, payload FROM events WHERE eventid=4688 AND payload ILIKE \'%cmd.exe%\' AND (payload ILIKE \'%net user%\' OR payload ILIKE \'%whoami%\') LAST 24 HOURS',
        "elastic": 'event.code:4688 AND process.name:cmd.exe AND process.command_line:(whoami OR "net user" OR systeminfo)',
    },
    "T1204.002": {
        "splunk":  'index=wineventlog EventCode=4688 | where New_Process_Name IN ("*winword.exe","*excel.exe","*powerpnt.exe") AND Parent_Process_Name IN ("*cmd.exe","*powershell.exe","*wscript.exe") | stats count by ComputerName, New_Process_Name, Parent_Process_Name',
        "qradar":  'SELECT hostname, payload FROM events WHERE eventid=4688 AND (payload ILIKE \'%winword.exe%\' OR payload ILIKE \'%excel.exe%\') AND (payload ILIKE \'%cmd.exe%\' OR payload ILIKE \'%powershell.exe%\') LAST 24 HOURS',
        "elastic": 'event.code:4688 AND process.parent.name:(winword.exe OR excel.exe OR powerpnt.exe) AND process.name:(cmd.exe OR powershell.exe OR wscript.exe)',
    },

    # ── Persistence ──────────────────────────
    "T1547.001": {
        "splunk":  'index=wineventlog EventCode=13 TargetObject IN ("*\\Run\\*","*\\RunOnce\\*") | stats count by ComputerName, TargetObject, Details',
        "qradar":  'SELECT hostname, payload FROM events WHERE eventid=13 AND (payload ILIKE \'%\\Run\\%\' OR payload ILIKE \'%\\RunOnce\\%\') LAST 24 HOURS',
        "elastic": 'event.code:13 AND registry.path:(*\\Run\\* OR *\\RunOnce\\*)',
    },
    "T1053.005": {
        "splunk":  'index=wineventlog EventCode=4698 | stats count by ComputerName, Task_Name, Task_Content | sort -count',
        "qradar":  'SELECT hostname, username, payload FROM events WHERE eventid=4698 LAST 24 HOURS',
        "elastic": 'event.code:4698 AND winlog.event_data.TaskName:*',
    },

    # ── Defense Evasion ──────────────────────
    "T1055": {
        "splunk":  'index=wineventlog EventCode=8 | stats count by SourceImage, TargetImage | where SourceImage != TargetImage | sort -count',
        "qradar":  'SELECT hostname, payload FROM events WHERE eventid=8 AND payload NOT ILIKE \'%SourceImage%TargetImage%\' LAST 24 HOURS',
        "elastic": 'event.code:8 AND winlog.event_data.SourceImage:* AND NOT winlog.event_data.SourceImage:winlog.event_data.TargetImage',
    },
    "T1562.001": {
        "splunk":  'index=wineventlog EventCode=7036 Message="*Windows Defender*stopped*" OR EventCode=4689 Process_Name="*MsMpEng.exe" | stats count by ComputerName, _time',
        "qradar":  'SELECT hostname, payload FROM events WHERE (eventid=7036 AND payload ILIKE \'%Defender%stopped%\') OR (eventid=4689 AND payload ILIKE \'%MsMpEng%\') LAST 24 HOURS',
        "elastic": '(event.code:7036 AND message:*Defender*stopped*) OR (event.code:4689 AND process.name:MsMpEng.exe)',
    },
    "T1027": {
        "splunk":  'index=wineventlog EventCode=4104 | search ScriptBlockText="*[Convert]::FromBase64String*" OR ScriptBlockText="*::FromBase64*" | stats count by ComputerName, ScriptBlockText',
        "qradar":  'SELECT hostname, payload FROM events WHERE eventid=4104 AND (payload ILIKE \'%FromBase64String%\' OR payload ILIKE \'%::FromBase64%\') LAST 24 HOURS',
        "elastic": 'event.code:4104 AND winlog.event_data.ScriptBlockText:(FromBase64String OR "::FromBase64")',
    },

    # ── Credential Access ────────────────────
    "T1003.001": {
        "splunk":  'index=wineventlog EventCode=10 TargetImage="*lsass.exe" | stats count by SourceImage, ComputerName | sort -count',
        "qradar":  'SELECT hostname, payload FROM events WHERE eventid=10 AND payload ILIKE \'%lsass.exe%\' LAST 24 HOURS',
        "elastic": 'event.code:10 AND winlog.event_data.TargetImage:*lsass.exe',
    },
    "T1110.001": {
        "splunk":  'index=wineventlog EventCode=4625 | stats count by Account_Name, src_ip, Failure_Reason | where count > 10 | sort -count',
        "qradar":  'SELECT username, sourceip, count(*) AS fail_count FROM events WHERE eventid=4625 GROUP BY username, sourceip HAVING count(*) > 10 LAST 24 HOURS',
        "elastic": 'event.code:4625 | stats count by winlog.event_data.TargetUserName, source.ip | where count > 10',
    },
    "T1552.001": {
        "splunk":  'index=wineventlog EventCode=4663 Object_Name IN ("*.txt","*.config","*.xml","*.ini") | search Object_Name IN ("*password*","*credential*","*secret*") | stats count by ComputerName, Object_Name, Account_Name',
        "qradar":  'SELECT hostname, username, payload FROM events WHERE eventid=4663 AND (payload ILIKE \'%password%\' OR payload ILIKE \'%credential%\' OR payload ILIKE \'%secret%\') LAST 24 HOURS',
        "elastic": 'event.code:4663 AND winlog.event_data.ObjectName:(*password* OR *credential* OR *secret*)',
    },

    # ── Lateral Movement ─────────────────────
    "T1021.001": {
        "splunk":  'index=wineventlog EventCode=4624 Logon_Type=10 | stats count by Account_Name, src_ip, ComputerName | where count > 3 | sort -count',
        "qradar":  'SELECT username, sourceip, destinationip, count(*) FROM events WHERE eventid=4624 AND logontype=10 GROUP BY username, sourceip, destinationip HAVING count(*) > 3 LAST 24 HOURS',
        "elastic": 'event.code:4624 AND winlog.event_data.LogonType:10',
    },
    "T1021.002": {
        "splunk":  'index=wineventlog EventCode=5140 Share_Name="*$" | stats count by Account_Name, src_ip, Share_Name | sort -count',
        "qradar":  'SELECT username, sourceip, payload FROM events WHERE eventid=5140 AND payload ILIKE \'%$\' LAST 24 HOURS',
        "elastic": 'event.code:5140 AND winlog.event_data.ShareName:*$',
    },
    "T1550.002": {
        "splunk":  'index=wineventlog EventCode=4624 Logon_Type=3 | search Keywords="*pass the hash*" OR (Logon_Process="NtLmSsp" AND Account_Name!="ANONYMOUS LOGON") | stats count by Account_Name, src_ip',
        "qradar":  'SELECT username, sourceip FROM events WHERE eventid=4624 AND logontype=3 AND authpackage=\'NTLM\' AND username != \'ANONYMOUS LOGON\' LAST 24 HOURS',
        "elastic": 'event.code:4624 AND winlog.event_data.LogonType:3 AND winlog.event_data.AuthenticationPackageName:NTLM AND NOT winlog.event_data.TargetUserName:"ANONYMOUS LOGON"',
    },

    # ── Collection ───────────────────────────
    "T1114.001": {
        "splunk":  'index=exchange_logs OR index=o365 operation IN ("MailItemsAccessed","FolderBind") | stats count by UserId, ClientIP | where count > 100 | sort -count',
        "qradar":  'SELECT username, sourceip, count(*) FROM events WHERE category=\'Exchange\' AND (payload ILIKE \'%MailItemsAccessed%\' OR payload ILIKE \'%FolderBind%\') GROUP BY username, sourceip HAVING count(*) > 100 LAST 24 HOURS',
        "elastic": 'event.action:(MailItemsAccessed OR FolderBind) AND event.category:email',
    },
    "T1560.001": {
        "splunk":  'index=wineventlog EventCode=4688 New_Process_Name IN ("*7z.exe","*winrar.exe","*zip.exe") | stats count by ComputerName, Process_Command_Line | sort -count',
        "qradar":  'SELECT hostname, payload FROM events WHERE eventid=4688 AND (payload ILIKE \'%7z.exe%\' OR payload ILIKE \'%winrar.exe%\' OR payload ILIKE \'%zip.exe%\') LAST 24 HOURS',
        "elastic": 'event.code:4688 AND process.name:(7z.exe OR winrar.exe OR zip.exe)',
    },

    # ── Exfiltration ─────────────────────────
    "T1048": {
        "splunk":  'index=firewall action=allow dest_port IN (443,80,21,22) bytes_out > 10000000 | stats sum(bytes_out) by src_ip, dest_ip | sort -sum(bytes_out)',
        "qradar":  'SELECT sourceip, destinationip, sum(eventcount) AS total_bytes FROM events WHERE destinationport IN (443,80,21,22) GROUP BY sourceip, destinationip HAVING total_bytes > 10000000 LAST 24 HOURS',
        "elastic": 'event.category:network AND destination.port:(443 OR 80 OR 21 OR 22) AND network.bytes > 10000000',
    },
    "T1567.002": {
        "splunk":  'index=proxy_logs dest_host IN ("*dropbox.com","*drive.google.com","*onedrive.live.com","*mega.nz") bytes_out > 5000000 | stats sum(bytes_out) by src_ip, dest_host, user',
        "qradar":  'SELECT sourceip, username, url FROM events WHERE (url ILIKE \'%dropbox.com%\' OR url ILIKE \'%drive.google.com%\' OR url ILIKE \'%mega.nz%\') LAST 24 HOURS',
        "elastic": 'event.category:network AND url.domain:(dropbox.com OR drive.google.com OR mega.nz) AND network.bytes > 5000000',
    },

    # ── Command & Control ────────────────────
    "T1071.001": {
        "splunk":  'index=proxy_logs | stats count by dest_host | where count < 3 | join dest_host [search index=threat_intel] | table dest_host, count',
        "qradar":  'SELECT destinationip, url, count(*) FROM events WHERE category=\'Web\' GROUP BY destinationip, url HAVING count(*) < 3 LAST 24 HOURS',
        "elastic": 'event.category:network AND network.protocol:http AND NOT destination.domain:* | stats count by destination.ip | where count < 3',
    },
    "T1572": {
        "splunk":  'index=firewall dest_port IN (80,443) protocol=tcp | where bytes_in > 1000 AND bytes_out > 1000 | stats avg(bytes_in) as avg_in, avg(bytes_out) as avg_out by src_ip, dest_ip | where abs(avg_in - avg_out) < 100',
        "qradar":  'SELECT sourceip, destinationip, avg(eventcount) FROM events WHERE destinationport IN (80,443) GROUP BY sourceip, destinationip LAST 24 HOURS',
        "elastic": 'event.category:network AND destination.port:(80 OR 443) AND network.bytes > 1000',
    },
}

# Fallback generic query when technique has no specific query
GENERIC_QUERIES = {
    "splunk":  "| search index=wineventlog OR index=syslog | stats count by host, source, EventCode | sort -count",
    "qradar":  "SELECT hostname, category, count(*) FROM events GROUP BY hostname, category ORDER BY count(*) DESC LAST 24 HOURS",
    "elastic": "event.category:* | stats count by host.name, event.action | sort count desc",
}

# ──────────────────────────────────────────────
# LOG SOURCES per tactic
# ──────────────────────────────────────────────

TACTIC_LOG_SOURCES = {
    "Initial Access": [
        "Email gateway logs (O365, Exchange, Proofpoint)",
        "Web proxy / firewall logs",
        "VPN & remote access logs",
        "Windows Security Event Logs (EventCode 4624, 4625)",
    ],
    "Execution": [
        "Windows Security Event Logs (EventCode 4688, 4104)",
        "Sysmon logs (EventCode 1, 11)",
        f"{EDR_TELEMETRY} (process creation)",
        "PowerShell ScriptBlock logs",
    ],
    "Persistence": [
        "Windows Registry audit logs (EventCode 13)",
        "Scheduled Task logs (EventCode 4698, 4702)",
        "Windows Security Event Logs (EventCode 4720, 4732)",
        "Sysmon logs",
    ],
    "Privilege Escalation": [
        "Windows Security Event Logs (EventCode 4672, 4673)",
        "EDR telemetry",
        "Active Directory logs",
    ],
    "Defense Evasion": [
        "Sysmon logs (EventCode 8, 10)",
        "Windows Defender / AV logs",
        "Windows Security Event Logs (EventCode 7036)",
        EDR_TELEMETRY,
    ],
    "Credential Access": [
        "Windows Security Event Logs (EventCode 4625, 4648, 4768)",
        "Sysmon logs (EventCode 10 — lsass access)",
        "Active Directory logs",
        EDR_TELEMETRY,
    ],
    "Discovery": [
        "Windows Security Event Logs (EventCode 4688)",
        "Network flow logs",
        "Active Directory audit logs",
    ],
    "Lateral Movement": [
        "Windows Security Event Logs (EventCode 4624, 4648, 5140)",
        "Network flow / firewall logs",
        "SMB / RDP access logs",
        EDR_TELEMETRY,
    ],
    "Collection": [
        "File access audit logs (EventCode 4663)",
        "Exchange / O365 audit logs",
        "DLP logs",
        EDR_TELEMETRY,
    ],
    "Exfiltration": [
        "Proxy / firewall logs (outbound traffic)",
        "DLP logs",
        "Network flow logs (large outbound transfers)",
        "Cloud app access logs",
    ],
    "Command And Control": [
        "DNS logs",
        "Proxy / firewall logs",
        "Network flow logs",
        "Threat Intelligence feed matches",
    ],
    "Impact": [
        "Windows Security Event Logs",
        "File integrity monitoring logs",
        "Backup system logs",
        "Database audit logs",
    ],
}

# ──────────────────────────────────────────────
# RESPONSE STEPS per tactic
# ──────────────────────────────────────────────

TACTIC_RESPONSE_STEPS = {
    "Initial Access": [
        "Identify and block the malicious source (IP / domain / email sender)",
        "Quarantine affected endpoint immediately",
        "Preserve email headers and attachment for forensic analysis",
        "Search for lateral movement from the compromised host",
        "Reset credentials of affected user(s)",
        "Notify SOC team and escalate to IR if confirmed compromise",
    ],
    "Execution": [
        "Isolate the affected endpoint from the network",
        "Collect process tree and parent-child relationship",
        "Capture memory dump if malware is suspected",
        "Submit suspicious file/script to sandbox for analysis",
        "Search for persistence mechanisms on the same host",
        "Check for lateral movement to other systems",
    ],
    "Persistence": [
        "Identify and remove the persistence mechanism (registry key / scheduled task)",
        "Determine initial access vector that allowed persistence",
        "Search for additional persistence on same and related hosts",
        "Reset affected account passwords",
        "Check for privilege escalation attempts post-persistence",
    ],
    "Privilege Escalation": [
        "Identify the account that was escalated",
        "Revert unauthorized privilege changes immediately",
        "Audit all privileged account activity in the same timeframe",
        "Determine root cause (vulnerability / misconfiguration)",
        "Patch or remediate the exploited privilege escalation vector",
    ],
    "Defense Evasion": [
        "Re-enable any disabled security controls immediately",
        "Collect logs from the period security was bypassed",
        "Identify what activity occurred during the evasion window",
        "Determine how attacker gained ability to disable defenses",
        "Review and harden security tool configurations",
    ],
    "Credential Access": [
        "Reset passwords for all potentially compromised accounts",
        "Enable MFA on all affected accounts if not already enabled",
        "Audit all activity performed with the compromised credentials",
        "Search for lateral movement using the stolen credentials",
        "Check for persistence and new accounts created by attacker",
    ],
    "Discovery": [
        "Identify the scope of the reconnaissance (what was enumerated)",
        "Correlate discovery activity with other attack stages",
        "Determine if sensitive assets were identified by the attacker",
        "Increase monitoring on enumerated systems and accounts",
    ],
    "Lateral Movement": [
        "Identify all systems accessed via lateral movement",
        "Isolate compromised systems from the network",
        "Reset credentials used for lateral movement",
        "Map the full attack path from initial access to current position",
        "Search for persistence on each laterally moved-to system",
    ],
    "Collection": [
        "Identify what data was accessed or staged",
        "Determine if sensitive financial data was involved",
        "Preserve file access logs for forensic investigation",
        "Notify Data Protection Officer (DPO) if PII/financial data involved",
        "Check for exfiltration activity following collection",
    ],
    "Exfiltration": [
        "Block outbound connection to exfiltration destination immediately",
        "Calculate volume and type of data exfiltrated",
        "Notify legal and compliance teams — potential regulatory impact",
        "Engage incident response team for full forensic investigation",
        "Preserve all network logs for the exfiltration timeframe",
        "Assess breach notification obligations (GDPR, PCI-DSS, etc.)",
    ],
    "Command And Control": [
        "Block all identified C2 IPs and domains at firewall/proxy",
        "Isolate beaconing endpoint from the network",
        "Capture network traffic for forensic analysis",
        "Search for implants or RATs on the affected system",
        "Scan environment for other hosts communicating with same C2",
    ],
    "Impact": [
        "Activate Business Continuity Plan (BCP) if services are impacted",
        "Isolate affected systems to prevent further damage",
        "Initiate backup restoration procedure",
        "Assess financial and operational impact",
        "Preserve all evidence before remediation",
        "Notify senior management and legal team",
    ],
}


# ──────────────────────────────────────────────
# PLAYBOOK GENERATOR
# ──────────────────────────────────────────────

def sanitize_filename(name: str) -> str:
    """Convert technique name to safe filename."""
    name = name.replace(" ", "_").replace("/", "-")
    name = re.sub(r"[^\w\-]", "", name)
    return name[:50]


def get_queries(tech_id: str) -> dict:
    """Get Splunk + KQL queries for a technique, fallback to generic."""
    # Try exact match first, then parent technique
    parent_id = tech_id.split(".")[0]
    return HUNTING_QUERIES.get(tech_id) or HUNTING_QUERIES.get(parent_id) or GENERIC_QUERIES


def get_log_sources(tactics: list) -> list:
    """Get relevant log sources based on tactics."""
    sources = []
    for tactic in tactics:
        sources.extend(TACTIC_LOG_SOURCES.get(tactic, []))
    return list(dict.fromkeys(sources))  # deduplicate while preserving order


def get_response_steps(tactics: list) -> list:
    """Get response steps based on primary tactic."""
    for tactic in tactics:
        steps = TACTIC_RESPONSE_STEPS.get(tactic)
        if steps:
            return steps
    return ["Isolate affected system", "Collect logs and evidence", "Escalate to IR team"]


def generate_playbook(tech: dict) -> str:
    """Generate a full Markdown playbook for one technique."""
    tech_id    = tech.get("technique_id", "UNKNOWN")
    name       = tech.get("name", "Unknown Technique")
    desc       = tech.get("description", "No description available.")
    tactics    = tech.get("tactics", ["Unknown"])
    platforms  = tech.get("platforms", [])
    groups     = tech.get("finance_groups", [])
    url        = tech.get("url", "")
    queries    = get_queries(tech_id)
    log_srcs   = get_log_sources(tactics)
    resp_steps = get_response_steps(tactics)
    date       = datetime.now().strftime("%Y-%m-%d")
    is_custom  = tech_id in HUNTING_QUERIES or tech_id.split(".")[0] in HUNTING_QUERIES

    query_note = "✅ Custom query" if is_custom else "⚠️ Generic query — customize for your environment"

    groups_badges = " | ".join(f"`{g}`" for g in groups)
    tactics_str   = " | ".join(f"`{t}`" for t in tactics)
    platforms_str = " | ".join(f"`{p}`" for p in platforms) if platforms else "`Windows` `Linux`"

    log_sources_md   = "\n".join(f"- {s}" for s in log_srcs)
    response_steps_md = "\n".join(f"{i+1}. {s}" for i, s in enumerate(resp_steps))

    return f"""# 🎯 {tech_id} — {name}

> **ATT&CK Tracker** | Financial Sector Threat Hunting Playbook
> Last updated: {date} | [MITRE Reference]({url})

---

## 📋 Overview

| Field | Details |
|---|---|
| **Technique ID** | `{tech_id}` |
| **Tactic(s)** | {tactics_str} |
| **Platforms** | {platforms_str} |
| **Finance Groups** | {groups_badges} |

### Description
{desc}...

> 📖 Full description: [{url}]({url})

---

## 🔍 Hunting Queries

> {query_note}

### Splunk
```spl
{queries['splunk']}
```

### QRadar (AQL)
```sql
{queries['qradar']}
```

### Elastic (EQL / KQL)
```kql
{queries['elastic']}
```

---

## 📂 Log Sources Required

{log_sources_md}

---

## 🏦 Finance Groups Using This Technique

| Group | Sector Focus |
|---|---|
{"".join(f"| `{g}` | Financial Services |{chr(10)}" for g in groups)}

---

## ✅ Response Steps

{response_steps_md}

---

## 🔗 References

- [MITRE ATT&CK — {tech_id}]({url})
- [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
- [FS-ISAC Threat Intelligence](https://www.fsisac.com/)

---

*Generated by [ATT&CK Tracker](https://github.com/YOUR_USERNAME/ATT-CK-Tracker)*
"""


# ──────────────────────────────────────────────
# INDEX GENERATOR
# ──────────────────────────────────────────────

def generate_index(techniques: list, playbook_files: list) -> str:
    """Generate master INDEX.md listing all playbooks."""
    date = datetime.now().strftime("%Y-%m-%d")
    rows = []

    for tech, fname in zip(techniques, playbook_files):
        tech_id  = tech.get("technique_id", "")
        name     = tech.get("name", "")
        tactics  = ", ".join(tech.get("tactics", []))
        groups   = ", ".join(tech.get("finance_groups", []))
        has_q    = "✅" if (tech_id in HUNTING_QUERIES or tech_id.split(".")[0] in HUNTING_QUERIES) else "⚠️"
        rows.append(f"| [{tech_id}]({fname}) | {name} | {tactics} | {groups} | {has_q} |")

    rows_md = "\n".join(rows)

    return f"""# 📚 ATT&CK Tracker — Finance Sector Playbook Index

> Auto-generated on {date} | Total techniques: **{len(techniques)}**

---

## How to Use

1. Run `ATT&CK_Tracker.py` to fetch latest techniques from MITRE
2. Run `generate_playbooks.py` to regenerate all playbooks
3. Use the hunting queries in your SIEM (Splunk / QRadar / Elastic)
4. Follow response steps when a hunt confirms a hit

**Query Legend:** ✅ Custom query | ⚠️ Generic query (needs tuning)

---

## All Finance Sector Playbooks

| Technique | Name | Tactic | Finance Groups | Query |
|---|---|---|---|---|
{rows_md}

---

*Generated by [ATT&CK Tracker](https://github.com/YOUR_USERNAME/ATT-CK-Tracker)*
"""


# MAIN
# ──────────────────────────────────────────────

def main():
    print("=" * 55)
    print("  ATT&CK Tracker — Playbook Generator")
    print("  Phase 2: Generating Markdown Hunting Playbooks")
    print("=" * 55)

    # Load techniques from Phase 1 output
    if not os.path.exists(INPUT_FILE):
        print(f"\n[!] ERROR: {INPUT_FILE} not found!")
        print("[!] Please run ATT&CK_Tracker.py first.\n")
        return

    with open(INPUT_FILE, "r", encoding="utf-8") as f:
        techniques = json.load(f)

    print(f"[+] Loaded {len(techniques)} techniques from {INPUT_FILE}")
    print(f"[*] Generating playbooks in: {PLAYBOOKS_DIR}\n")

    playbook_files = []
    custom_count   = 0
    generic_count  = 0

    for i, tech in enumerate(techniques, 1):
        tech_id  = tech.get("technique_id", "UNKNOWN")
        name     = tech.get("name", "unknown")
        safe_name = sanitize_filename(name)
        filename  = f"{tech_id}_{safe_name}.md"
        filepath  = os.path.join(PLAYBOOKS_DIR, filename)

        content = generate_playbook(tech)

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)

        has_custom = tech_id in HUNTING_QUERIES or tech_id.split(".")[0] in HUNTING_QUERIES
        tag = "✅" if has_custom else "⚠️"
        if has_custom:
            custom_count += 1
        else:
            generic_count += 1

        print(f"  {tag} [{i:>3}/{len(techniques)}] {tech_id:<12} {name}")
        playbook_files.append(filename)

    # Generate INDEX.md
    index_content = generate_index(techniques, playbook_files)
    index_path    = os.path.join(PLAYBOOKS_DIR, "INDEX.md")
    with open(index_path, "w", encoding="utf-8") as f:
        f.write(index_content)

    print(f"\n{'=' * 55}")
    print("✅ Done!")
    print(f"   📄 Playbooks generated : {len(techniques)}")
    print(f"   ✅ Custom queries       : {custom_count}")
    print(f"   ⚠️  Generic queries      : {generic_count}")
    print(f"   📚 Index file           : {index_path}")
    print(f"{'=' * 55}")


if __name__ == "__main__":
    main()