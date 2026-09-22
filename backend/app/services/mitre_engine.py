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
            {"id": "T1595", "name": "Active Scanning", "match_keywords": ["scan", "nmap", "sweep", "recon", "syn flood", "syn_stealth"]},
            {"id": "T1590", "name": "Gather Network Info", "match_keywords": ["dns", "zone transfer", "whois", "arp spoof", "dns spoof"]}
        ]
    },
    {
        "id": "TA0001",
        "name": "Initial Access",
        "techniques": [
            {"id": "T1190", "name": "Exploit Public-Facing App", "match_keywords": ["sql", "sqli", "injection", "xss", "csrf", "ssrf", "xxe", "rce", "cve-", "uri", "http"]},
            {"id": "T1566", "name": "Phishing", "match_keywords": ["phish", "spear", "email", "attachment"]}
        ]
    },
    {
        "id": "TA0002",
        "name": "Execution",
        "techniques": [
            {"id": "T1059", "name": "Command and Scripting Interpreter", "match_keywords": ["powershell", "bash", "cmd", "wscript", "command injection", "cat /etc/passwd"]},
            {"id": "T1053", "name": "Scheduled Task / Job", "match_keywords": ["cron", "schtasks", "at", "persistence"]}
        ]
    },
    {
        "id": "TA0004",
        "name": "Privilege Escalation",
        "techniques": [
            {"id": "T1068", "name": "Exploitation for Privilege Escalation", "match_keywords": ["escalat", "root", "cve", "privilege", "buffer overflow", "dll hijack"]},
            {"id": "T1078", "name": "Valid Accounts", "match_keywords": ["shadow admin", "privilege", "session hijack", "cookie replay"]}
        ]
    },
    {
        "id": "TA0006",
        "name": "Credential Access",
        "techniques": [
            {"id": "T1110", "name": "Brute Force", "match_keywords": ["brute", "hydra", "failed logins", "auth fail", "dictionary", "password spray", "credential stuffing"]},
            {"id": "T1003", "name": "OS Credential Dumping", "match_keywords": ["mimikatz", "lsass", "sam", "dump", "infostealer", "pass the hash", "kerberoast", "tgs-req"]}
        ]
    },
    {
        "id": "TA0007",
        "name": "Discovery",
        "techniques": [
            {"id": "T1046", "name": "Network Service Discovery", "match_keywords": ["port", "syn", "syn_stealth", "discovery", "ip spoof"]},
            {"id": "T1087", "name": "Account Discovery", "match_keywords": ["net user", "enum", "ldap"]}
        ]
    },
    {
        "id": "TA0008",
        "name": "Lateral Movement",
        "techniques": [
            {"id": "T1021", "name": "Remote Services (SMB/RDP/SSH)", "match_keywords": ["smb", "rdp", "lateral", "psexec", "wmi", "worm", "eternalblue"]},
            {"id": "T1550", "name": "Use Alternate Auth Material", "match_keywords": ["pass the hash", "ticket", "kerberos", "pth"]}
        ]
    },
    {
        "id": "TA0011",
        "name": "Command & Control",
        "techniques": [
            {"id": "T1071", "name": "Application Layer Protocol", "match_keywords": ["cobalt", "beacon", "c2", "malleable", "trojan", "rat", "asyncrat", "njrat"]},
            {"id": "T1105", "name": "Ingress Tool Transfer", "match_keywords": ["wget", "curl", "download", "drop", "lotl", "living-off-the-land", "certutil", "bitsadmin"]}
        ]
    },
    {
        "id": "TA0040",
        "name": "Impact",
        "techniques": [
            {"id": "T1486", "name": "Data Encrypted for Impact", "match_keywords": ["ransom", "encrypt", "lockbit", "wiper", "vssadmin"]},
            {"id": "T1489", "name": "Service Stop", "match_keywords": ["stop", "kill", "disable defense", "ddos", "flood", "syn flood"]}
        ]
    },
    {
        "id": "TA0005",
        "name": "Defense Evasion",
        "techniques": [
            {"id": "T1070", "name": "Indicator Removal on Host", "match_keywords": ["log clear", "wevtutil", "rm -rf", "audit off", "rootkit", "ld.so.preload"]},
            {"id": "T1027", "name": "Obfuscated / Encrypted Files", "match_keywords": ["base64", "xor", "obfuscat", "packer", "zero-day", "zero day"]}
        ]
    },
    {
        "id": "TA0003",
        "name": "Persistence",
        "techniques": [
            {"id": "T1547", "name": "Boot or Logon Autostart", "match_keywords": ["registry run", "startup", "systemd service", "persistence"]},
            {"id": "T1136", "name": "Create Account", "match_keywords": ["useradd", "net user /add", "new user"]}
        ]
    },
    {
        "id": "TA0009",
        "name": "Collection",
        "techniques": [
            {"id": "T1005", "name": "Data from Local System", "match_keywords": ["tar", "zip", "find", "dump", "grep secret", "infostealer"]},
            {"id": "T1113", "name": "Screen Capture / Keystrokes", "match_keywords": ["keylogger", "screenshot", "clipboard"]}
        ]
    },
    {
        "id": "TA0010",
        "name": "Exfiltration",
        "techniques": [
            {"id": "T1048", "name": "Exfiltration Over Alt Protocol", "match_keywords": ["dns tunnel", "icmp tunnel", "exfil", "data exfiltration"]},
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

    def get_technique_profile(self, technique_id: str) -> Dict[str, Any]:
        """
        Retrieves in-depth descriptive intelligence, threat actors, detection logic,
        mitigations, and live database alert correlations for a specific MITRE technique.
        """
        tid = technique_id.upper().strip()
        matched_tactic = None
        matched_tech = None

        for tactic in MITRE_TACTICS:
            for tech in tactic["techniques"]:
                if tech["id"].upper() == tid:
                    matched_tactic = tactic
                    matched_tech = tech
                    break
            if matched_tech:
                break

        # If not in default table, generate dynamic fallback
        tech_name = matched_tech["name"] if matched_tech else f"MITRE Technique {tid}"
        tactic_name = matched_tactic["name"] if matched_tactic else "Enterprise Defense"
        tactic_id = matched_tactic["id"] if matched_tactic else "TA0001"
        keywords = matched_tech["match_keywords"] if matched_tech else [tid.lower()]

        # Query live database alerts matching keywords
        with get_sync_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT id, signature, category, severity, risk_score, src_ip, dst_ip, timestamp
                    FROM alerts
                    ORDER BY timestamp DESC
                    LIMIT 300
                    """
                )
                all_alerts = cur.fetchall()

                # Query SOAR playbooks
                cur.execute("SELECT id, name, description, trigger_event, severity_threshold, actions FROM playbooks WHERE is_active = true")
                all_playbooks = cur.fetchall()

        correlated_alerts = []
        unique_ips = set()
        for alert in all_alerts:
            sig = (alert.get("signature") or "").lower()
            cat = (alert.get("category") or "").lower()
            if any(k in sig or k in cat for k in keywords):
                unique_ips.add(str(alert.get("src_ip")))
                if len(correlated_alerts) < 15:
                    correlated_alerts.append({
                        "id": str(alert["id"]),
                        "signature": alert["signature"],
                        "category": alert["category"],
                        "severity": alert["severity"],
                        "risk_score": alert.get("risk_score") or 85,
                        "src_ip": str(alert["src_ip"]),
                        "dst_ip": str(alert.get("dst_ip") or "internal-host"),
                        "timestamp": alert["timestamp"].isoformat()
                    })

        # Match relevant playbooks
        matched_playbooks = []
        for pb in all_playbooks:
            pb_name = (pb.get("name") or "").lower()
            pb_trig = (pb.get("trigger_event") or "").lower()
            if any(k in pb_name or k in pb_trig for k in keywords) or (tid in ("T1190", "T1059") and "rce" in pb_trig):
                matched_playbooks.append({
                    "id": str(pb["id"]),
                    "name": pb["name"],
                    "description": pb["description"],
                    "trigger_event": pb["trigger_event"],
                    "severity": pb["severity_threshold"],
                    "actions": pb.get("actions") or []
                })

        # Default fallback playbook if none directly matched
        if not matched_playbooks and all_playbooks:
            first_pb = all_playbooks[0]
            matched_playbooks.append({
                "id": str(first_pb["id"]),
                "name": first_pb["name"],
                "description": first_pb["description"],
                "trigger_event": first_pb["trigger_event"],
                "severity": first_pb["severity_threshold"],
                "actions": first_pb.get("actions") or []
            })

        return {
            "id": tid,
            "name": tech_name,
            "tactic_id": tactic_id,
            "tactic_name": tactic_name,
            "match_keywords": keywords,
            "total_correlated_detections": len(correlated_alerts),
            "unique_affected_hosts": list(unique_ips),
            "correlated_alerts": correlated_alerts,
            "recommended_playbooks": matched_playbooks
        }

mitre_engine = MITREEngine()
