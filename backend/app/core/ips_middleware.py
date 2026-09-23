"""
In-Line IDS/IPS Gateway Protection Middleware.

Provides real-time gateway-level threat detection, multi-pass payload de-obfuscation,
vulnerability honeypot trapping, volumetric DDoS flood detection, and active firewall
enforcement directly on incoming HTTP requests.
"""
from __future__ import annotations

import base64
import html
import ipaddress
import logging
import math
import os
import re
import time
import urllib.parse
from collections import defaultdict
from datetime import datetime, timezone
from typing import Callable

import psycopg
from psycopg.types.json import Jsonb
from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from .database import get_sync_connection
from .metrics import blocked_ips_total, alerts_ingested_total
from ..services.redis_pubsub import publish_live_alert, publish_ips_action

logger = logging.getLogger("ids.ips_gateway")

# In-memory sliding window for rate-limiting: client_ip -> list of timestamps
_request_history: dict[str, list[float]] = defaultdict(list)

# In-memory cache of active blocked IPs: (set_of_ips, last_sync_time)
_blocked_ips_cache: set[str] = set()
_cache_last_synced: float = 0.0
CACHE_TTL = 2.0  # sync from DB every 2 seconds

# Rate limit threshold: max requests within window
BURST_WINDOW_SECONDS = 10.0
BURST_MAX_REQUESTS = 80

# Cached management allowlist to avoid re-parsing env var on every request
_allowlist_cache: tuple | None = None
_allowlist_cache_ts: float = 0.0
ALLOWLIST_CACHE_TTL = 30.0  # re-read env every 30 seconds


def _management_allowlist() -> tuple:
    """Return explicitly configured operator networks which bypass IPS checks."""
    global _allowlist_cache, _allowlist_cache_ts
    now = time.time()
    if _allowlist_cache is not None and now - _allowlist_cache_ts < ALLOWLIST_CACHE_TTL:
        return _allowlist_cache

    networks = []
    for value in os.getenv("IPS_MANAGEMENT_ALLOWLIST", "").split(","):
        value = value.strip()
        if not value:
            continue
        try:
            networks.append(ipaddress.ip_network(value, strict=False))
        except ValueError:
            logger.warning("Ignoring invalid IPS_MANAGEMENT_ALLOWLIST entry: %r", value)

    _allowlist_cache = tuple(networks)
    _allowlist_cache_ts = now
    return _allowlist_cache


def _is_management_allowlisted(ip_str: str) -> bool:
    """Whether an explicit operator allowlist permits this source address."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return any(ip in network for network in _management_allowlist())


def _is_whitelisted(ip_str: str) -> bool:
    """Check if address is loopback or unspecified."""
    try:
        if ip_str in ("127.0.0.1", "::1", "localhost"):
            return True
        ip = ipaddress.ip_address(ip_str)
        if ip.is_loopback or ip.is_unspecified:
            return True
        return False
    except ValueError:
        return False


# ── De-Obfuscation & Normalization Pipeline ───────────────────────────────────

def normalize_payload(text: str) -> list[str]:
    """Generates multiple normalized representations of an input payload

    to defeat evasion techniques (double URL encoding, SQL comment insertion,
    HTML entity encoding, hex/unicode escaping, and base64 stagers).
    """
    variants = [text]

    # 1. Multi-pass URL decoding (up to 3 levels)
    current = text
    for _ in range(3):
        try:
            decoded = urllib.parse.unquote(current)
            if decoded == current:
                break
            current = decoded
            if current not in variants:
                variants.append(current)
        except Exception:
            break

    # 2. HTML entity unescaping (&lt; -> <, &#x3C; -> <)
    for v in list(variants):
        try:
            unescaped = html.unescape(v)
            if unescaped not in variants:
                variants.append(unescaped)
        except Exception:
            pass

    # 3. SQL inline comment stripping (UNION/**/SELECT -> UNION SELECT, UN/**/ION -> UNION)
    comment_regex = re.compile(r"/\*.*?\*/", re.DOTALL)
    for v in list(variants):
        if "/*" in v:
            spaced = comment_regex.sub(" ", v)
            if spaced not in variants:
                variants.append(spaced)
            stripped = comment_regex.sub("", v)
            if stripped not in variants:
                variants.append(stripped)

    # 4. Null byte and tab/newline normalization
    for v in list(variants):
        cleaned = v.replace("\x00", "").replace("\r", " ").replace("\n", " ")
        if cleaned != v and cleaned not in variants:
            variants.append(cleaned)

    # 5. Base64 payload detection & decoding (for base64 stagers like eval(base64_decode(...)))
    b64_pattern = re.compile(r"([A-Za-z0-9+/]{20,}={0,2})")
    for v in list(variants):
        for match in b64_pattern.findall(v):
            try:
                b64_decoded = base64.b64decode(match).decode("utf-8", errors="ignore")
                if len(b64_decoded) > 8 and b64_decoded not in variants:
                    variants.append(b64_decoded)
            except Exception:
                pass

    return variants


# ── Sensitive Reconnaissance & Honeypot Paths ─────────────────────────────────

SENSITIVE_PROBE_PATHS = (
    "/.env", "/.git", "/.svn", "/.aws", "/.ssh", "/.ds_store",
    "/wp-admin", "/wp-login.php", "/wp-content", "/xmlrpc.php",
    "/phpmyadmin", "/pma", "/adminer", "/dbadmin",
    "/actuator", "/solr", "/cgi-bin", "/shell.php", "/c99.php", "/r57.php", "/wso.php",
    "/web.config", "/composer.json", "/package.json", "/dockerfile", "/docker-compose",
    "/debug/vars", "/server-status", "/server-info",
    "/console/", "/invoker/", "/jmx-console/", "/manager/html",
    "/vendor/phpunit",
)


# ── Shannon Entropy & Zero-Day Anomaly Detection ──────────────────────────────

def calculate_shannon_entropy(data: str) -> float:
    """Calculates Shannon entropy H(X) = -sum(p(x) * log2(p(x)))."""
    if not data or len(data) < 32:
        return 0.0
    freq = defaultdict(int)
    for char in data:
        freq[char] += 1
    total = len(data)
    return -sum((count / total) * math.log2(count / total) for count in freq.values())


def is_statistical_anomaly(body_str: str) -> tuple[bool, str]:
    """Detects zero-day shellcode, NOP sleds, or high-entropy encrypted blobs."""
    if len(body_str) < 30:
        return False, ""

    # NOP sled / repeated buffer overflow stagers
    if "\\x90" * 6 in body_str or "\x90" * 12 in body_str or "A" * 60 in body_str:
        return True, "Exploitation: NOP Sled / Memory Corruption Buffer"

    # High Shannon entropy in non-file upload text
    entropy = calculate_shannon_entropy(body_str)
    if entropy > 5.2 and len(body_str) > 80:
        non_printable = sum(1 for c in body_str if ord(c) < 32 and c not in "\r\n\t")
        if non_printable / len(body_str) > 0.04:
            return True, f"Exploitation: High-Entropy Zero-Day Shellcode Anomaly (H={entropy:.2f})"

    return False, ""


# ── Universal Attack Defense Signatures Matrix ────────────────────────────────

ATTACK_SIGNATURES = [
    # ── 1. AUTOMATED SCANNERS & RECONNAISSANCE ─────────────────────────────
    (re.compile(r"\b(sqlmap|nikto|nuclei|gobuster|dirbuster|wpscan|hydra|acunetix|nessus|nmap|masscan|zgrab|openvas|shodan|censys|projectdiscovery|burpcollaborator)\b", re.IGNORECASE), "Reconnaissance: Automated Security Scanner / Exploit Tool User-Agent", "reconnaissance", 92),

    # ── 2. SQL INJECTION (SQLi) ─────────────────────────────────────────────
    (re.compile(r"(\bunion\b[\s\S]*?\bselect\b|\bselect\b[\s\S]*?\bfrom\b|\binsert\b[\s\S]*?\binto\b|\bupdate\b[\s\S]*?\bset\b|\bdelete\b[\s\S]*?\bfrom\b|\bdrop\b\s+(table|database)|unionselect)", re.IGNORECASE), "Web/API: SQL Injection (SQLi) Query Construct", "web_api", 98),
    (re.compile(r"(('|\")\s*(\bor\b|\band\b)\s*('|\")?1('|\")?\s*=\s*('|\")?1|('|\")\s*(\bor\b|\band\b)\s*('|\")?\w+('|\")?\s*=\s*('|\")?\w+|(\bor\b|\band\b)\s+1\s*=\s*1|(\bor\b|\band\b)\s+true\b)", re.IGNORECASE), "Web/API: SQL Injection Boolean Tautology (OR 1=1)", "web_api", 97),
    (re.compile(r"(\b(sleep|pg_sleep)\s*\(\s*\d+\s*\)|\bbenchmark\s*\(\s*\d+|\bwaitfor\s+delay\s+['\"][0-9:]+['\"])", re.IGNORECASE), "Web/API: SQL Injection Time-Based Blind Vector", "web_api", 98),
    (re.compile(r"(\bextractvalue\s*\(|\bupdatexml\s*\(|\bload_file\s*\(|\binto\s+(out|dump)file\b|\bxp_cmdshell\b)", re.IGNORECASE), "Web/API: SQL Injection Error-Based or Subsystem Command", "web_api", 99),
    (re.compile(r"('|\")\s*(--|#|/\*)|;(\s*exec|\s*declare|\s*drop|\s*truncate|\s*insert|\s*update|\s*select)", re.IGNORECASE), "Web/API: SQL Injection Stacked Execution or Comment Truncator", "web_api", 96),

    # ── 3. CROSS-SITE SCRIPTING (XSS) ────────────────────────────────────────
    (re.compile(r"(<script\b[^>]*>|&lt;script\b)", re.IGNORECASE), "Web/API: Cross-Site Scripting (XSS) Script Tag Ingress", "web_api", 92),
    (re.compile(r"(<[^>]+[\s/]+(onload|onerror|onclick|onmouseover|onfocus|onblur|onkeydown|onkeyup|ontoggle|onloadstart)\s*=[^>]*>)", re.IGNORECASE), "Web/API: Cross-Site Scripting (XSS) Inline Event Handler", "web_api", 94),
    (re.compile(r"(javascript\s*:|vbscript\s*:|data\s*:\s*text/html)", re.IGNORECASE), "Web/API: Cross-Site Scripting (XSS) Pseudo-Protocol Vector", "web_api", 90),
    (re.compile(r"(<svg\b[\s\S]*?onload|<iframe\b[\s\S]*?src|<img\b[\s\S]*?onerror|<body\b[\s\S]*?onload|<details\b[\s\S]*?ontoggle)", re.IGNORECASE), "Web/API: Cross-Site Scripting (XSS) Vector Element", "web_api", 95),
    (re.compile(r"(\balert\s*\(|\bprompt\s*\(|\bconfirm\s*\(|document\.cookie|document\.domain|window\.location\s*=)", re.IGNORECASE), "Web/API: Cross-Site Scripting (XSS) DOM Execution Payload", "web_api", 89),

    # ── 4. COMMAND INJECTION & REMOTE CODE EXECUTION (RCE) ───────────────────
    (re.compile(r"([;&|`$]\s*(cat\s+/|ls\s+-|id\b|whoami\b|uname\s+-|pwd\b|netstat\b|ifconfig\b|ip\s+a\b|curl\s+|wget\s+|nc\s+|bash\s+|sh\s+|cmd\.exe|powershell))", re.IGNORECASE), "Web/API: OS Command Injection Shell Chaining", "web_api", 99),
    (re.compile(r"(\$\((whoami|id|cat\s+|ls|uname|pwd)\)|\`(whoami|id|cat\s+|ls|uname|pwd)\`)", re.IGNORECASE), "Web/API: OS Command Substitution Subshell Execution", "web_api", 99),
    (re.compile(r"(/bin/(ba)?sh\s+-i|nc\s+-[el]|python.*-c.*import\s+socket|php\s+-r.*fsockopen|powershell.*-(enc|e|executionpolicy)\s+)", re.IGNORECASE), "Exploitation: Interactive Reverse Shell Spawn Vector", "exploitation", 100),
    (re.compile(r"(curl\s+-[sSoO].*\|\s*(ba)?sh|wget\s+.*\|\s*(ba)?sh|certutil.*-urlcache)", re.IGNORECASE), "Exploitation: Pipe Download Execution Stager", "exploitation", 98),
    (re.compile(r"(\beval\s*\(|\bassert\s*\(|system\s*\(|passthru\s*\(|shell_exec\s*\(|popen\s*\(|proc_open\s*\()", re.IGNORECASE), "Web/API: Arbitrary Code Execution Dynamic Evaluator", "web_api", 97),

    # ── 5. DIRECTORY TRAVERSAL & FILE INCLUSION (LFI/RFI) ───────────────────
    (re.compile(r"(\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|\.\.%2f|%252e%252e%252f|%c0%ae%c0%ae/)", re.IGNORECASE), "Web/API: Path Traversal / Directory Stepping Sequence", "web_api", 93),
    (re.compile(r"(/etc/passwd|/etc/shadow|/etc/hosts|/proc/self/|/proc/version|c:[\\/]windows[\\/]win\.ini|windows[\\/]system32[\\/]cmd\.exe)", re.IGNORECASE), "Web/API: Local File Inclusion (LFI) Sensitive File Target", "web_api", 96),
    (re.compile(r"(php://(filter|input|stdin)|data://text/plain|file://|phar://|zip://)", re.IGNORECASE), "Web/API: Dangerous Protocol / PHP Wrapper Injection", "web_api", 95),

    # ── 6. SERVER-SIDE REQUEST FORGERY (SSRF) ────────────────────────────────
    (re.compile(r"(169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200|latest/meta-data|latest/user-data)", re.IGNORECASE), "Exploitation: Cloud Instance Metadata IMDS SSRF Exfiltration", "exploitation", 98),
    (re.compile(r"(gopher://|dict://|ldap://|jar:file:)", re.IGNORECASE), "Web/API: SSRF Dangerous URI Scheme Vector", "web_api", 94),

    # ── 7. SERVER-SIDE TEMPLATE INJECTION (SSTI) ────────────────────────────
    (re.compile(r"(\{\{\s*\d+\s*\*\s*\d+\s*\}\}|\$\{\s*\d+\s*\*\s*\d+\s*\}|<%=\s*\d+\s*\*\s*\d+\s*%>|#\{\s*\d+\s*\*\s*\d+\s*\})", re.IGNORECASE), "Web/API: Server-Side Template Injection (SSTI) Arithmetic Probe", "web_api", 95),
    (re.compile(r"(\{\{.*(__class__|__mro__|__subclasses__|__globals__|popen|config|request).*\}\}|\$\{.*getRuntime.*exec.*\})", re.IGNORECASE), "Web/API: Server-Side Template Injection (SSTI) Object Escape", "web_api", 99),

    # ── 8. XML EXTERNAL ENTITY (XXE) ─────────────────────────────────────────
    (re.compile(r"(<!doctype[\s\S]*?\[[\s\S]*?<!entity|<!entity\s+[^>]+system|SYSTEM\s+['\"](file|http|https)://)", re.IGNORECASE), "Web/API: XML External Entity (XXE) Injection Attempt", "web_api", 96),

    # ── 9. INSECURE DESERIALIZATION & ZERO-DAY EXPLOITS ────────────────────
    (re.compile(r"(\$\{jndi:(ldap|rmi|dns|ldaps|iiop|corba):|\$\{\$\{lower:[a-z]\})", re.IGNORECASE), "Exploitation: Log4Shell (CVE-2021-44228) JNDI Exploit Vector", "exploitation", 100),
    (re.compile(r"(class\.module\.classLoader|classLoader\.resources)", re.IGNORECASE), "Exploitation: Spring4Shell (CVE-2022-22965) Remote Exploit Vector", "exploitation", 99),
    (re.compile(r"(rO0AB[A-Za-z0-9+/=]*|cos\nsystem\n|O:\d+:\"[^\"]+\":\d+:\{)", re.IGNORECASE), "Web/API: Insecure Object Deserialization Serialized Stream", "web_api", 96),

    # ── 10. NOSQL & LDAP INJECTION ──────────────────────────────────────────
    (re.compile(r"(\$gt|\$gte|\$lt|\$lte|\$ne|\$nin|\$in|\$where|\$regex|\$exists|\$expr)", re.IGNORECASE), "Web/API: NoSQL MongoDB Operator Injection Attempt", "web_api", 92),
    (re.compile(r"(\)\s*\(\||\)\s*\(&|\)\s*\(\*\))", re.IGNORECASE), "Web/API: LDAP Filter Wildcard Injection", "web_api", 91),

    # ── 11. WEB SHELLS ───────────────────────────────────────────────────────
    (re.compile(r"(\bc99shell\b|\br57shell\b|\bb374k\b|\bwso_version\b|\balfa_team\b|eval\s*\(\s*\$_POST|eval\s*\(\s*\$_GET)", re.IGNORECASE), "Web/API: Web Shell Backdoor Controller Execution", "web_api", 99),

    # ── 12. MALWARE, TROJANS & RANSOMWARE ───────────────────────────────────
    (re.compile(r"(EICAR-STANDARD-ANTIVIRUS-TEST-FILE|X5O!P%@AP\[4\\PZX54\(P\^\)7CC\)7\}\$EICAR)", re.IGNORECASE), "Malware: EICAR Standard Antivirus & Malware Test Vector", "malware", 100),
    (re.compile(r"(cobalt.*beacon|meterpreter|reverse_tcp|trojan\.win32|c2_heartbeat)", re.IGNORECASE), "Malware: Trojan / C2 Beacon Ingress Attempt", "malware", 98),
    (re.compile(r"(vssadmin\s+delete\s+shadows|wbadmin\s+delete|bcdedit.*recoveryenabled\s+no|lockbit|wannacry|cryptolocker)", re.IGNORECASE), "Malware: Ransomware Command & Shadow Copy Deletion", "malware", 99),
    (re.compile(r"(eternalblue|ms17-010|smbexec\.py|worm_propagation|autorun\.inf)", re.IGNORECASE), "Malware: Network Worm Propagation Attempt", "malware", 96),
    (re.compile(r"(virus_payload|file_infector|pe_injector|code_injection_stub)", re.IGNORECASE), "Malware: Executable Virus File Infection", "malware", 90),
    (re.compile(r"(spyware_telemetry|keylogger_exfil|screen_grab_upload|surveillance_agent)", re.IGNORECASE), "Malware: Spyware Secret Monitoring Vector", "malware", 88),
    (re.compile(r"(adware_popunder|browser_hijack_inject|superfish|unwanted_ad_pusher)", re.IGNORECASE), "Malware: Adware Browser Hijack Attempt", "malware", 75),
    (re.compile(r"(ld\.so\.preload|chkrootkit|rkhunter|modprobe.*-f|hide_process|rootkit)", re.IGNORECASE), "Malware: Rootkit Kernel / Library Tampering Attempt", "malware", 95),
    (re.compile(r"(keylogger_hook|GetAsyncKeyState|SetWindowsHookEx|log_keystrokes)", re.IGNORECASE), "Malware: System Keylogger Hook Vector", "malware", 92),
    (re.compile(r"(botnet_c2_ping|mirai_cnc|zeus_bot|iot_zombie_beacon)", re.IGNORECASE), "Malware: Botnet C2 Agent Command Exchange", "malware", 94),
    (re.compile(r"(fileless_exec|reflective_dll|process_hollowing|dot_net_to_js)", re.IGNORECASE), "Malware: Fileless Memory Injection Execution", "malware", 96),
    (re.compile(r"(backdoor_shell|netcat_exec|reverse_shell_listener|bind_shell)", re.IGNORECASE), "Malware: Persistent Backdoor Shell Vector", "malware", 95),
    (re.compile(r"(dropper_stage1|payload_unpacker|loader_unpack|malicious_zip_drop)", re.IGNORECASE), "Malware: Dropper / Loader Staging Vector", "malware", 93),
    (re.compile(r"(coinhive|stratum\+tcp|xmrig|monero_miner|cryptojack)", re.IGNORECASE), "Malware: Cryptominer / CPU Hijacking Vector", "malware", 85),
    (re.compile(r"(wiper_disk|zero_out_mbr|hermeticwiper|caddywiper|destroy_fs)", re.IGNORECASE), "Malware: System Wiper Destruction Attempt", "malware", 99),
    (re.compile(r"(asyncrat|njrat|darkcomet|remcos|quasar_rat|client\.connect.*rat)", re.IGNORECASE), "Malware: RAT (Remote Access Trojan) Command Vector", "malware", 97),
    (re.compile(r"(mimikatz|sekurlsa|lsass\.dmp|sam_dump|vaultcli|browser_pass_dump)", re.IGNORECASE), "Malware: Infostealer / Credential Harvesting Vector", "malware", 98),

    # ── 13. NETWORK FLOODS & SPOOFING ───────────────────────────────────────
    (re.compile(r"(volumetric_flood|dns_amplification|ntp_amplification)", re.IGNORECASE), "Network: Volumetric DDoS Ingress Attack", "network", 95),
    (re.compile(r"(syn_flood|tcp_syn_burst|syn_stealth_sweep|flags:syn_only)", re.IGNORECASE), "Network: TCP SYN Flood Saturation Attack", "network", 94),
    (re.compile(r"(udp_flood|udp_amplification|udp_burst_flood)", re.IGNORECASE), "Network: UDP Packet Flood Saturation", "network", 93),
    (re.compile(r"(icmp_flood|ping_flood|icmp_echo_burst)", re.IGNORECASE), "Network: ICMP Echo Flood Inundation", "network", 89),
    (re.compile(r"(http_flood|layer7_flood|get_flood_burst)", re.IGNORECASE), "Network: HTTP Layer-7 Application Flood", "network", 92),
    (re.compile(r"(slowloris|partial_header_hold|slow_read_attack)", re.IGNORECASE), "Network: Slowloris Low-and-Slow Exhaustion", "network", 90),
    (re.compile(r"(arp_spoof|arp_poison|duplicate_mac_claim|gratuitous_arp)", re.IGNORECASE), "Network: ARP Spoofing / Poisoning Attempt", "network", 90),
    (re.compile(r"(dns_cache_poison|dns_spoof|rogue_dns_reply|fake_a_record)", re.IGNORECASE), "Network: DNS Spoofing / Cache Poisoning Attempt", "network", 92),
    (re.compile(r"(session_hijack|cookie_replay|stolen_jwt_bearer|sid_impersonation)", re.IGNORECASE), "Network: Session Hijacking / Cookie Replay Attack", "network", 91),
    (re.compile(r"(mitm_proxy_inject|ssl_intercept|arp_mitm)", re.IGNORECASE), "Network: Man-in-the-Middle Interception", "network", 93),

    # ── 14. CREDENTIAL & AUTHENTICATION ─────────────────────────────────────
    (re.compile(r"(brute_force|hydra_login|failed_logins_exceeded|ssh_brute)", re.IGNORECASE), "Credential: Authentication Brute Force Attack", "credential", 94),
    (re.compile(r"(password_spray|multi_user_single_pass|spray_attack)", re.IGNORECASE), "Credential: Password Spraying Campaign", "credential", 92),
    (re.compile(r"(credential_stuffing|leaked_pass_dump_replay|acc_takeover)", re.IGNORECASE), "Credential: Credential Stuffing Automated Attack", "credential", 93),
    (re.compile(r"(pass_the_hash|pth_ntlm|sekurlsa::pth|wmi_pth)", re.IGNORECASE), "Credential: Pass-the-Hash NTLM Authentication Reuse", "credential", 96),
    (re.compile(r"(pass_the_ticket|ptt_kerberos|sekurlsa::tickets)", re.IGNORECASE), "Credential: Pass-the-Ticket Kerberos Impersonation", "credential", 95),
    (re.compile(r"(kerberoast|tgs-req.*rc4-hmac|krb5tgs|spn_ticket_extract)", re.IGNORECASE), "Credential: Active Directory Kerberoasting Ticket Theft", "credential", 95),
    (re.compile(r"(asrep_roasting|as_req_no_preauth|getuserspns)", re.IGNORECASE), "Credential: AS-REP Roasting Ticket Hash Extraction", "credential", 93),
    (re.compile(r"(account_takeover|unauthorized_pass_change|stolen_auth_state)", re.IGNORECASE), "Credential: Unauthorized Account Takeover", "credential", 94),
    (re.compile(r"(mfa_fatigue|mfa_prompt_bomb|push_spam)", re.IGNORECASE), "Credential: MFA Fatigue Push Notification Spamming", "credential", 89),

    # ── 15. POST-COMPROMISE & LATERAL OPERATIVE ─────────────────────────────
    (re.compile(r"(psexec|wmic\s+process\s+call|winrm\s+exec|smbexec|lateral_pivot)", re.IGNORECASE), "Post-Compromise: Lateral Movement Sweep Attempt", "post_compromise", 94),
    (re.compile(r"(reg\s+add.*\\run|crontab\s+-e|systemctl\s+enable\s+backdoor|startup_folder)", re.IGNORECASE), "Post-Compromise: System Persistence Mechanism Addition", "post_compromise", 92),
    (re.compile(r"(dns_tunnel_exfil|curl\s+-T\s+.*mega\.nz|base64_exfil_chunk|data_exfiltration)", re.IGNORECASE), "Post-Compromise: Data Exfiltration Tunnel Vector", "post_compromise", 97),
    (re.compile(r"(log_wiping|wevtutil_cl|rm_-rf_/var/log|audit_erase)", re.IGNORECASE), "Post-Compromise: Audit Log Wiping & Anti-Forensics", "post_compromise", 95),
    (re.compile(r"(shadow_admin|admin_group_inject|domain_admin_add)", re.IGNORECASE), "Post-Compromise: Shadow Administrator Account Creation", "post_compromise", 96),
    (re.compile(r"(c2_beaconing|malleable_http_ping|dns_c2_channel)", re.IGNORECASE), "Post-Compromise: Command & Control Beaconing Channel", "post_compromise", 94),
    (re.compile(r"(ransom_demand|ransom_note\.txt|extortion_contact)", re.IGNORECASE), "Post-Compromise: Ransomware Extortion Demand Note", "post_compromise", 98),

    # ── 16. BUSINESS LOGIC & PROTOTYPE POLLUTION ────────────────────────────
    (re.compile(r"(__proto__|constructor[\"']?\s*:\s*\{[\s\S]*?[\"']?prototype|constructor\.prototype|Object\.prototype)", re.IGNORECASE), "Web/API: JavaScript Prototype Pollution Attempt", "web_api", 94),
]


def _get_active_blocked_ips() -> set[str]:
    """Retrieve active blocked IPs from DB with caching."""
    global _blocked_ips_cache, _cache_last_synced
    now = time.time()
    if now - _cache_last_synced < CACHE_TTL:
        return _blocked_ips_cache

    try:
        with get_sync_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT ip_address::text FROM blocked_ips WHERE is_active = true")
                rows = cur.fetchall()
                _blocked_ips_cache = {row["ip_address"].split("/")[0] for row in rows}
                _cache_last_synced = now
    except Exception as exc:
        logger.debug("Failed to sync blocked_ips cache: %s", exc)

    return _blocked_ips_cache


def _execute_autonomous_block(
    src_ip: str,
    signature: str,
    category: str,
    severity: str,
    risk_score: int,
    raw_event: dict,
    reason: str,
) -> None:
    """Record alert, quarantine IP in DB & firewall (unless allowlisted), and publish live event."""
    is_exempt = _is_whitelisted(src_ip) or _is_management_allowlisted(src_ip)
    if is_exempt:
        logger.warning(
            "[IPS SAFETY NET] Operator address %s triggered signature %s - logging alert without kernel quarantine",
            src_ip, signature,
        )

    alert_id = None
    block_record = None
    try:
        with get_sync_connection() as conn:
            with conn.cursor() as cur:
                # 1. Ingest alert to PostgreSQL so dashboard & threat intelligence registers it
                cur.execute(
                    """
                    INSERT INTO alerts (
                        timestamp, src_ip, protocol, signature, category, severity,
                        risk_score, status, raw_event
                    )
                    VALUES (%s, %s, 'HTTP', %s, %s, %s, %s, 'AUTO_BLOCKED', %s)
                    RETURNING id, timestamp, src_ip::text AS src_ip, protocol, signature, category, severity, risk_score, status, raw_event
                    """,
                    (
                        datetime.now(timezone.utc),
                        src_ip,
                        signature,
                        category,
                        severity,
                        risk_score,
                        Jsonb(raw_event),
                    ),
                )
                alert_record = cur.fetchone()
                alert_id = alert_record["id"]

                # 2. Block IP in database if not exempt
                if not is_exempt:
                    cur.execute(
                        """
                        INSERT INTO blocked_ips (ip_address, reason, blocked_by, alert_id)
                        VALUES (%s::inet, %s, 'APEX_SENTINEL_IPS_GATEWAY', %s)
                        ON CONFLICT (ip_address) DO UPDATE
                            SET is_active = TRUE, blocked_at = NOW(), reason = EXCLUDED.reason
                        RETURNING id
                        """,
                        (src_ip, reason, alert_id),
                    )
                    block_record = cur.fetchone()
                    global _blocked_ips_cache
                    _blocked_ips_cache.add(src_ip)
                conn.commit()

        # Update Prometheus metrics
        if not is_exempt:
            blocked_ips_total.inc()
        alerts_ingested_total.labels(severity=severity).inc()

        # Publish IPS Action to Redis
        if not is_exempt and block_record:
            publish_ips_action({
                "action": "BLOCK",
                "ip_address": src_ip,
                "reason": reason,
                "block_id": str(block_record["id"]),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })

        # Publish Live Alert to WebSocket for real-time dashboard UI
        publish_live_alert({
            **alert_record,
            "id": str(alert_id),
            "timestamp": alert_record["timestamp"].isoformat(),
            "ai_evaluation": {
                "risk_score": risk_score,
                "confidence": 0.99,
                "recommended_action": "BLOCK_IP" if not is_exempt else "OPERATOR_AUDIT",
                "attack_family": category.upper(),
            },
            "autonomous_mitigation": {
                "prevented": True,
                "action": "FIREWALL_DROP_SEVERED" if not is_exempt else "EXPLOIT_PAYLOAD_REJECTED",
                "mttc": "0.04s",
            },
        })

        # Dispatch to SOC Webhooks (Slack/Discord/Teams/SIEM)
        try:
            from ..services.alert_dispatcher import dispatch_soc_alert
            dispatch_soc_alert({
                **alert_record,
                "timestamp": alert_record["timestamp"].isoformat(),
            })
        except Exception:
            pass

        logger.warning("🚨 [IPS GATEWAY] Intercepted attacker %s: %s (Quarantined: %s)", src_ip, reason, not is_exempt)
    except Exception as exc:
        logger.error("Failed to execute autonomous block for %s: %s", src_ip, exc)


class IPSGatewayMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Preflight, health, metrics, and API documentation are allowed without rate limiting
        if request.method == "OPTIONS" or request.url.path in ("/health", "/metrics", "/docs", "/openapi.json"):
            return await call_next(request)

        # Extract client IP
        forwarded = request.headers.get("x-forwarded-for")
        client_ip = forwarded.split(",")[0].strip() if forwarded else (request.client.host if request.client else "127.0.0.1")

        # ── 1. Active Firewall Quarantine Check ───────────────────────
        active_blocks = _get_active_blocked_ips()
        if client_ip in active_blocks:
            logger.info("🚫 [IPS REJECT] Connection from quarantined IP: %s", client_ip)
            return JSONResponse(
                status_code=403,
                content={
                    "status": "QUARANTINED",
                    "detail": f"Access Denied: IP address {client_ip} is actively quarantined by Apex Sentinel Autonomous IPS firewall.",
                    "mitigation": "FIREWALL_DROP_ACTIVE",
                },
            )

        # ── 2. Geographic Threat Suppression (Country-Level Geo-Fencing) ─
        try:
            from .geoip import check_country_geofence
            is_geo_blocked, geo_country = check_country_geofence(client_ip)
            if is_geo_blocked:
                _execute_autonomous_block(
                    src_ip=client_ip,
                    signature=f"Geographic Threat Suppression: Ingress Country Blocked [{geo_country}]",
                    category="network",
                    severity="HIGH",
                    risk_score=90,
                    raw_event={
                        "path": request.url.path,
                        "blocked_country": geo_country,
                        "client_ip": client_ip,
                        "user_agent": request.headers.get("user-agent", ""),
                    },
                    reason=f"Autonomous IPS: Ingress Country Blocked [{geo_country}]",
                )
                return JSONResponse(
                    status_code=403,
                    content={
                        "status": "BLOCKED",
                        "detail": f"Apex Sentinel Autonomous IPS: Ingress from country [{geo_country}] is suppressed by policy.",
                        "signature": f"Geo-Fencing [{geo_country}]",
                        "action": "AUTO_BLOCKED",
                    },
                )
        except Exception:
            pass

        # ── 3. Sensitive Reconnaissance Probe & Honeypot Trapping ───────
        clean_path = request.url.path.lower()
        for probe in SENSITIVE_PROBE_PATHS:
            if clean_path.startswith(probe) or probe in clean_path:
                _execute_autonomous_block(
                    src_ip=client_ip,
                    signature=f"Reconnaissance: Automated Vulnerability Probe / Honeypot Trapped [{probe}]",
                    category="reconnaissance",
                    severity="CRITICAL",
                    risk_score=95,
                    raw_event={
                        "path": request.url.path,
                        "query": str(request.url.query)[:500],
                        "matched_probe": probe,
                        "user_agent": request.headers.get("user-agent", ""),
                    },
                    reason=f"Autonomous IPS: Vulnerability Probe / Honeypot Trapped [{probe}]",
                )
                return JSONResponse(
                    status_code=403,
                    content={
                        "status": "BLOCKED",
                        "detail": f"Apex Sentinel Autonomous IPS: Malicious vulnerability probe trapped [{probe}]. Host quarantined.",
                        "signature": f"Reconnaissance: Honeypot [{probe}]",
                        "action": "AUTO_BLOCKED",
                    },
                )

        # ── 3. Application Boundary & Content-Type Shield ──────────────
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                if int(content_length) > 10 * 1024 * 1024:
                    return JSONResponse(
                        status_code=413,
                        content={"status": "REJECTED", "detail": "Payload Too Large: Request body exceeds 10MB limit."},
                    )
            except ValueError:
                pass

        content_type = request.headers.get("content-type", "").lower()
        if any(danger in content_type for danger in (
            "application/x-java-serialized-object",
            "text/xml-external-parsed-entity",
            "application/x-shockwave-flash",
        )):
            return JSONResponse(
                status_code=415,
                content={"status": "REJECTED", "detail": f"Unsupported Media Type: Malicious Content-Type [{content_type}] is blocked."},
            )

        # ── 4. Non-Destructive HTTP Body Stream Extraction ─────────────
        body_str = ""
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            try:
                body_bytes = await request.body()
                # Re-create receive stream so downstream route handlers parse body without stream exhaustion
                async def receive():
                    return {"type": "http.request", "body": body_bytes}
                request = Request(request.scope, receive=receive)
                if body_bytes:
                    body_str = body_bytes[:65536].decode("utf-8", errors="ignore")
            except Exception as exc:
                logger.debug("Body extraction notice: %s", exc)

        # ── 5. Statistical Zero-Day & Buffer Overflow Detection ────────
        if body_str:
            is_anomaly, anomaly_reason = is_statistical_anomaly(body_str)
            if is_anomaly:
                _execute_autonomous_block(
                    src_ip=client_ip,
                    signature=anomaly_reason,
                    category="exploitation",
                    severity="CRITICAL",
                    risk_score=98,
                    raw_event={
                        "path": request.url.path,
                        "anomaly": anomaly_reason,
                        "user_agent": request.headers.get("user-agent", ""),
                    },
                    reason=f"Autonomous IPS: {anomaly_reason}",
                )
                return JSONResponse(
                    status_code=403,
                    content={
                        "status": "BLOCKED",
                        "detail": f"Apex Sentinel Autonomous IPS: {anomaly_reason}. Host quarantined.",
                        "signature": anomaly_reason,
                        "action": "AUTO_BLOCKED",
                    },
                )

        # ── 6. In-Line Multi-Pass De-Obfuscation & Signature Scanning ──
        full_query = urllib.parse.unquote(str(request.url.query))
        header_dump = " ".join(
            f"{k}:{v}" for k, v in request.headers.items()
            if k.lower() in ("user-agent", "authorization", "referer", "cookie", "x-forwarded-for", "content-type")
        )
        inspect_target = f"{request.url.path}?{full_query} {header_dump} {body_str}"
        variants = normalize_payload(inspect_target)

        for variant in variants:
            for pattern, sig_name, category, risk in ATTACK_SIGNATURES:
                if pattern.search(variant):
                    _execute_autonomous_block(
                        src_ip=client_ip,
                        signature=sig_name,
                        category=category,
                        severity="CRITICAL",
                        risk_score=risk,
                        raw_event={
                            "path": request.url.path,
                            "query": full_query[:500],
                            "matched_signature": sig_name,
                            "user_agent": request.headers.get("user-agent", ""),
                            "body_sample": body_str[:200] if body_str else "",
                        },
                        reason=f"In-Line Gateway Intercept: {sig_name}",
                    )
                    return JSONResponse(
                        status_code=403,
                        content={
                            "status": "BLOCKED",
                            "detail": f"Apex Sentinel Autonomous IPS: Malicious exploit vector intercepted [{sig_name}]. Host quarantined.",
                            "signature": sig_name,
                            "action": "AUTO_BLOCKED",
                        },
                    )

        # ── 7. Volumetric Rate Limiting (DDoS Surge Detection) ────────
        # Whitelisted operator addresses skip volumetric rate limiting
        if _is_whitelisted(client_ip) or _is_management_allowlisted(client_ip):
            return await call_next(request)

        now = time.time()
        window = _request_history[client_ip]
        _request_history[client_ip] = [t for t in window if now - t < BURST_WINDOW_SECONDS]
        _request_history[client_ip].append(now)

        if len(_request_history[client_ip]) > BURST_MAX_REQUESTS:
            burst_count = len(_request_history[client_ip])
            _execute_autonomous_block(
                src_ip=client_ip,
                signature=f"Volumetric HTTP Flood Anomaly (Ingress Surge > {BURST_MAX_REQUESTS} req/10s)",
                category="ddos",
                severity="CRITICAL",
                risk_score=94,
                raw_event={
                    "burst_count": burst_count,
                    "window_seconds": BURST_WINDOW_SECONDS,
                    "target_endpoint": request.url.path,
                    "user_agent": request.headers.get("user-agent", ""),
                },
                reason=f"Autonomous IPS: Volumetric Ingress Saturation ({burst_count} req/{BURST_WINDOW_SECONDS}s)",
            )
            return JSONResponse(
                status_code=429,
                content={
                    "status": "RATE_LIMITED",
                    "detail": "Autonomous IPS: Ingress rate threshold exceeded. IP address quarantined.",
                    "action": "AUTO_BLOCKED",
                },
            )

        return await call_next(request)
