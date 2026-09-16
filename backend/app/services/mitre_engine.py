"""
MITRE ATT&CK Enterprise Matrix Mapping Engine
Maps incoming network alerts and IDS signatures to tactics and techniques.
"""

from typing import Any, Dict, List
from ..core.database import get_sync_connection

MITRE_TACTICS = [
    {
        "id": "TA0043",
        "name": "Reconnaissance",
        "techniques": [
            {"id": "T1595", "name": "Active Scanning", "match_keywords": ["scan", "nmap", "sweep", "recon"]},
            {"id": "T1590", "name": "Gather Network Info", "match_keywords": ["dns", "zone transfer", "whois"]}
        ]
    },
    {
        "id": "TA0001",
        "name": "Initial Access",
        "techniques": [
            {"id": "T1190", "name": "Exploit Public-Facing App", "match_keywords": ["sql", "injection", "rce", "cve-", "uri", "http"]},
            {"id": "T1566", "name": "Phishing", "match_keywords": ["phish", "spear", "email", "attachment"]}
        ]
    },
    {
        "id": "TA0002",
        "name": "Execution",
        "techniques": [
            {"id": "T1059", "name": "Command and Scripting Interpreter", "match_keywords": ["powershell", "bash", "cmd", "wscript"]},
            {"id": "T1053", "name": "Scheduled Task / Job", "match_keywords": ["cron", "schtasks", "at"]}
        ]
    },
    {
        "id": "TA0004",
        "name": "Privilege Escalation",
        "techniques": [
            {"id": "T1068", "name": "Exploitation for Privilege Escalation", "match_keywords": ["escalat", "root", "cve", "privilege"]},
            {"id": "T1078", "name": "Valid Accounts", "match_keywords": ["shadow admin", "privilege"]}
        ]
    },
    {
        "id": "TA0006",
        "name": "Credential Access",
        "techniques": [
            {"id": "T1110", "name": "Brute Force", "match_keywords": ["brute", "hydra", "failed logins", "auth fail", "dictionary"]},
            {"id": "T1003", "name": "OS Credential Dumping", "match_keywords": ["mimikatz", "lsass", "sam", "dump"]}
        ]
    },
    {
        "id": "TA0007",
        "name": "Discovery",
        "techniques": [
            {"id": "T1046", "name": "Network Service Discovery", "match_keywords": ["port", "syn", "syn_stealth", "discovery"]},
            {"id": "T1087", "name": "Account Discovery", "match_keywords": ["net user", "enum", "ldap"]}
        ]
    },
    {
        "id": "TA0008",
        "name": "Lateral Movement",
        "techniques": [
            {"id": "T1021", "name": "Remote Services (SMB/RDP/SSH)", "match_keywords": ["smb", "rdp", "lateral", "psexec", "wmi"]},
            {"id": "T1550", "name": "Use Alternate Auth Material", "match_keywords": ["pass the hash", "ticket", "kerberos"]}
        ]
    },
    {
        "id": "TA0011",
        "name": "Command & Control",
        "techniques": [
            {"id": "T1071", "name": "Application Layer Protocol", "match_keywords": ["cobalt", "beacon", "c2", "malleable", "trojan"]},
            {"id": "T1105", "name": "Ingress Tool Transfer", "match_keywords": ["wget", "curl", "download", "drop"]}
        ]
    },
    {
        "id": "TA0040",
        "name": "Impact",
        "techniques": [
            {"id": "T1486", "name": "Data Encrypted for Impact", "match_keywords": ["ransom", "encrypt", "lockbit", "wiper"]},
            {"id": "T1489", "name": "Service Stop", "match_keywords": ["stop", "kill", "disable defense"]}
        ]
    },
    {
        "id": "TA0005",
        "name": "Defense Evasion",
        "techniques": [
            {"id": "T1070", "name": "Indicator Removal on Host", "match_keywords": ["log clear", "wevtutil", "rm -rf", "audit off"]},
            {"id": "T1027", "name": "Obfuscated / Encrypted Files", "match_keywords": ["base64", "xor", "obfuscat", "packer"]}
        ]
    },
    {
        "id": "TA0003",
        "name": "Persistence",
        "techniques": [
            {"id": "T1547", "name": "Boot or Logon Autostart", "match_keywords": ["registry run", "startup", "systemd service"]},
            {"id": "T1136", "name": "Create Account", "match_keywords": ["useradd", "net user /add", "new user"]}
        ]
    },
    {
        "id": "TA0009",
        "name": "Collection",
        "techniques": [
            {"id": "T1005", "name": "Data from Local System", "match_keywords": ["tar", "zip", "find", "dump", "grep secret"]},
            {"id": "T1113", "name": "Screen Capture / Keystrokes", "match_keywords": ["keylogger", "screenshot", "clipboard"]}
        ]
    },
    {
        "id": "TA0010",
        "name": "Exfiltration",
        "techniques": [
            {"id": "T1048", "name": "Exfiltration Over Alt Protocol", "match_keywords": ["dns tunnel", "icmp tunnel", "exfil"]},
            {"id": "T1567", "name": "Exfiltration Over Web Service", "match_keywords": ["mega.nz", "anonfiles", "rclone", "dropbox", "curl -T"]}
        ]
    }
]

class MITREEngine:
    def get_matrix_coverage(self) -> Dict[str, Any]:
        """
        Queries recent alerts and maps them against MITRE ATT&CK tactics and techniques.
        """
        with get_sync_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT id, signature, category, severity, risk_score, src_ip, dst_ip, timestamp
                    FROM alerts
                    ORDER BY timestamp DESC
                    LIMIT 200
                    """
                )
                alerts = cur.fetchall()

        tactic_results = []
        technique_counts = {}
        total_detections = 0

        for tactic in MITRE_TACTICS:
            tactic_data = {
                "id": tactic["id"],
                "name": tactic["name"],
                "total_hits": 0,
                "techniques": []
            }

            for tech in tactic["techniques"]:
                tech_hits = 0
                matching_alerts = []

                for alert in alerts:
                    sig = (alert.get("signature") or "").lower()
                    cat = (alert.get("category") or "").lower()

                    if any(k in sig or k in cat for k in tech["match_keywords"]):
                        tech_hits += 1
                        if len(matching_alerts) < 3:
                            matching_alerts.append({
                                "id": str(alert["id"]),
                                "signature": alert["signature"],
                                "severity": alert["severity"],
                                "src_ip": str(alert["src_ip"]),
                                "timestamp": alert["timestamp"].isoformat()
                            })

                tactic_data["total_hits"] += tech_hits
                total_detections += tech_hits
                technique_counts[tech["id"]] = tech_hits

                # Intensity 0 - 4
                intensity = min(4, tech_hits)
                tactic_data["techniques"].append({
                    "id": tech["id"],
                    "name": tech["name"],
                    "hit_count": tech_hits,
                    "intensity": intensity,
                    "recent_alerts": matching_alerts
                })

            tactic_results.append(tactic_data)

        return {
            "total_mapped_detections": total_detections,
            "tactics": tactic_results,
            "top_techniques": sorted(
                [{"id": k, "hits": v} for k, v in technique_counts.items() if v > 0],
                key=lambda x: x["hits"],
                reverse=True
            )[:5]
        }

mitre_engine = MITREEngine()
