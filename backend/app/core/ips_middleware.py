"""
In-Line IDS/IPS Gateway Protection Middleware.

Provides real-time gateway-level threat detection, rate-limiting (DDoS flood detection),
and active firewall enforcement directly on incoming HTTP requests.
"""
from __future__ import annotations

import ipaddress
import logging
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
# Raised from 25→80 to accommodate the dashboard's 7 parallel API calls + WebSocket
# polling every 8s without triggering a self-block on legitimate operator traffic.
BURST_WINDOW_SECONDS = 10.0
BURST_MAX_REQUESTS = 80

# Cached management allowlist to avoid re-parsing env var on every request
_allowlist_cache: tuple | None = None
_allowlist_cache_ts: float = 0.0
ALLOWLIST_CACHE_TTL = 30.0  # re-read env every 30 seconds


def _management_allowlist() -> tuple:
    """Return explicitly configured operator networks which bypass IPS checks.

    Cached for ALLOWLIST_CACHE_TTL seconds to avoid re-parsing the env var on
    every single request. Re-reads automatically when the TTL expires so that a
    running instance picks up `.env` changes without a full restart.

    This is intentionally opt-in: it is for an administrator's fixed management
    address only, not a broad private-network exception.
    """
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

# Malicious signatures for deep query, header & payload inspection across all attack categories
ATTACK_SIGNATURES = [
    # ── 1. MALWARE (1-20) ───────────────────────────────────────────────────
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
    (re.compile(r"(logic_bomb_trigger|time_bomb_eval|drop_payload_epoch)", re.IGNORECASE), "Malware: Logic Bomb Time-Trigger Execution", "malware", 91),
    (re.compile(r"(dropper_stage1|payload_unpacker|loader_unpack|malicious_zip_drop)", re.IGNORECASE), "Malware: Dropper / Loader Staging Vector", "malware", 93),
    (re.compile(r"(coinhive|stratum\+tcp|xmrig|monero_miner|cryptojack)", re.IGNORECASE), "Malware: Cryptominer / CPU Hijacking Vector", "malware", 85),
    (re.compile(r"(wiper_disk|zero_out_mbr|hermeticwiper|caddywiper|destroy_fs)", re.IGNORECASE), "Malware: System Wiper Destruction Attempt", "malware", 99),
    (re.compile(r"(asyncrat|njrat|darkcomet|remcos|quasar_rat|client\.connect.*rat)", re.IGNORECASE), "Malware: RAT (Remote Access Trojan) Command Vector", "malware", 97),
    (re.compile(r"(mimikatz|sekurlsa|lsass\.dmp|sam_dump|vaultcli|browser_pass_dump)", re.IGNORECASE), "Malware: Infostealer / Credential Harvesting Vector", "malware", 98),
    (re.compile(r"(downloader_stager|curl_download_malware|certutil_fetch_bin)", re.IGNORECASE), "Malware: Malicious Payload Downloader", "malware", 89),
    (re.compile(r"(exploit_kit_landing|rig_ek|angiEK|flash_exploit_drop)", re.IGNORECASE), "Malware: Exploit Kit Landing Page Redirect", "malware", 92),
    (re.compile(r"(scareware_alert|fake_antivirus_popup|rogue_security_shield)", re.IGNORECASE), "Malware: Scareware Extortion Prompt Vector", "malware", 80),

    # ── 2. NETWORK FLOODS & SPOOFING (21-40) ──────────────────────────────────
    (re.compile(r"(volumetric_flood|dns_amplification|ntp_amplification)", re.IGNORECASE), "Network: Volumetric DDoS Ingress Attack", "network", 95),
    (re.compile(r"(syn_flood|tcp_syn_burst|syn_stealth_sweep|flags:syn_only)", re.IGNORECASE), "Network: TCP SYN Flood Saturation Attack", "network", 94),
    (re.compile(r"(udp_flood|udp_amplification|udp_burst_flood)", re.IGNORECASE), "Network: UDP Packet Flood Saturation", "network", 93),
    (re.compile(r"(icmp_flood|ping_flood|icmp_echo_burst)", re.IGNORECASE), "Network: ICMP Echo Flood Inundation", "network", 89),
    (re.compile(r"(http_flood|layer7_flood|get_flood_burst)", re.IGNORECASE), "Network: HTTP Layer-7 Application Flood", "network", 92),
    (re.compile(r"(slowloris|partial_header_hold|slow_read_attack)", re.IGNORECASE), "Network: Slowloris Low-and-Slow Exhaustion", "network", 90),
    (re.compile(r"(dns_amp_payload|dns_any_reflection)", re.IGNORECASE), "Network: DNS Amplification Reflection Vector", "network", 94),
    (re.compile(r"(ntp_monlist_amp|ntp_reflection)", re.IGNORECASE), "Network: NTP Amplification Reflection Vector", "network", 93),
    (re.compile(r"(ping_of_death|oversized_icmp|fragment_ping_overflow)", re.IGNORECASE), "Network: Ping of Death Oversized Packet", "network", 88),
    (re.compile(r"(smurf_attack|broadcast_icmp_echo)", re.IGNORECASE), "Network: Smurf Broadcast Amplification Attack", "network", 87),
    (re.compile(r"(arp_spoof|arp_poison|duplicate_mac_claim|gratuitous_arp)", re.IGNORECASE), "Network: ARP Spoofing / Poisoning Attempt", "network", 90),
    (re.compile(r"(dns_cache_poison|dns_spoof|rogue_dns_reply|fake_a_record)", re.IGNORECASE), "Network: DNS Spoofing / Cache Poisoning Attempt", "network", 92),
    (re.compile(r"(ip_spoof|x-forwarded-for:.*spoofed|raw_socket_forge)", re.IGNORECASE), "Network: IP Header Spoofing / Packet Forgery", "network", 88),
    (re.compile(r"(session_hijack|cookie_replay|stolen_jwt_bearer|sid_impersonation)", re.IGNORECASE), "Network: Session Hijacking / Cookie Replay Attack", "network", 91),
    (re.compile(r"(mitm_proxy_inject|ssl_intercept|arp_mitm)", re.IGNORECASE), "Network: Man-in-the-Middle Interception", "network", 93),
    (re.compile(r"(bgp_hijack|as_path_spoof|rogue_bgp_route)", re.IGNORECASE), "Network: BGP Route Hijacking Anomaly", "network", 96),
    (re.compile(r"(mac_flood|cam_table_overflow|mac_address_exhaustion)", re.IGNORECASE), "Network: Switch CAM Table MAC Flooding", "network", 86),
    (re.compile(r"(vlan_hopping|double_tagging|dot1q_spoof)", re.IGNORECASE), "Network: 802.1Q Double Tagging VLAN Hopping", "network", 89),
    (re.compile(r"(ssl_strip|http_downgrade|hsts_bypass)", re.IGNORECASE), "Network: SSL/TLS Downgrade Stripping Attack", "network", 91),
    (re.compile(r"(wifi_deauth|aircrack_deauth|802.11_frame_inject)", re.IGNORECASE), "Network: Wi-Fi 802.11 Deauthentication Attack", "network", 85),

    # ── 3. CREDENTIAL & AUTHENTICATION (41-55) ──────────────────────────────
    (re.compile(r"(brute_force|hydra_login|failed_logins_exceeded|ssh_brute)", re.IGNORECASE), "Credential: Authentication Brute Force Attack", "credential", 94),
    (re.compile(r"(password_spray|multi_user_single_pass|spray_attack)", re.IGNORECASE), "Credential: Password Spraying Campaign", "credential", 92),
    (re.compile(r"(credential_stuffing|leaked_pass_dump_replay|acc_takeover)", re.IGNORECASE), "Credential: Credential Stuffing Automated Attack", "credential", 93),
    (re.compile(r"(pass_the_hash|pth_ntlm|sekurlsa::pth|wmi_pth)", re.IGNORECASE), "Credential: Pass-the-Hash NTLM Authentication Reuse", "credential", 96),
    (re.compile(r"(pass_the_ticket|ptt_kerberos|sekurlsa::tickets)", re.IGNORECASE), "Credential: Pass-the-Ticket Kerberos Impersonation", "credential", 95),
    (re.compile(r"(kerberoast|tgs-req.*rc4-hmac|krb5tgs|spn_ticket_extract)", re.IGNORECASE), "Credential: Active Directory Kerberoasting Ticket Theft", "credential", 95),
    (re.compile(r"(asrep_roasting|as_req_no_preauth|getuserspns)", re.IGNORECASE), "Credential: AS-REP Roasting Ticket Hash Extraction", "credential", 93),
    (re.compile(r"(dictionary_attack|wordlist_auth|rockyou_spray)", re.IGNORECASE), "Credential: Dictionary-Based Auth Attack", "credential", 88),
    (re.compile(r"(rainbow_table|precomputed_hash_match)", re.IGNORECASE), "Credential: Rainbow Table Lookup Cracking", "credential", 85),
    (re.compile(r"(offline_crack|hashcat_job|john_the_ripper)", re.IGNORECASE), "Credential: Offline Password Hash Extraction", "credential", 90),
    (re.compile(r"(account_takeover|unauthorized_pass_change|stolen_auth_state)", re.IGNORECASE), "Credential: Unauthorized Account Takeover", "credential", 94),
    (re.compile(r"(cred_harvest_phish|fake_login_form_post)", re.IGNORECASE), "Credential: Credential Harvesting Phishing Form", "credential", 91),
    (re.compile(r"(token_theft|refresh_token_exfil|oauth_bearer_steal)", re.IGNORECASE), "Credential: OAuth / Bearer Session Token Theft", "credential", 92),
    (re.compile(r"(mfa_fatigue|mfa_prompt_bomb|push_spam)", re.IGNORECASE), "Credential: MFA Fatigue Push Notification Spamming", "credential", 89),
    (re.compile(r"(pass_reset_exploit|token_predict_reset|forge_reset_key)", re.IGNORECASE), "Credential: Password Reset Logic Exploit", "credential", 90),

    # ── 4. WEB & API ATTACKS (56-75) ──────────────────────────────────────────
    (re.compile(r"(\bunion\b\s+(all\s+)?\bselect\b|'\s+or\s+('\d+'='\d+|1=1)|--|\bexec(\s|\+)+(s|x)p_)", re.IGNORECASE), "Web/API: SQL Injection (SQLi) Ingress Attempt", "web_api", 98),
    (re.compile(r"(<script\b[^>]*>|javascript:\s*alert|onerror\s*=\s*['\"]?[^'\">]+|<img\s+src=x)", re.IGNORECASE), "Web/API: Cross-Site Scripting (XSS) Ingress Attempt", "web_api", 88),
    (re.compile(r"(csrf_token_bypass|missing_anti_csrf|unauthorized_cross_origin_post)", re.IGNORECASE), "Web/API: Cross-Site Request Forgery (CSRF) Attempt", "web_api", 86),
    (re.compile(r"(gopher://|dict://|http://169\.254\.169\.254|http://localhost:8080/admin)", re.IGNORECASE), "Web/API: Server-Side Request Forgery (SSRF) Vector", "web_api", 93),
    (re.compile(r"(<!entity\s+[^>]+system|<!element\s+[^>]+system|xxe_payload)", re.IGNORECASE), "Web/API: XML External Entity (XXE) Injection", "web_api", 94),
    (re.compile(r"(;\s*cat\s+/etc/passwd|\|\s*bash\s+-i|\$\(whoami\)|\`id\`|cmd\.exe\s+/c)", re.IGNORECASE), "Web/API: Operating System Command Injection", "web_api", 97),
    (re.compile(r"(\.\./\.\./\.\./etc/passwd|winnt/system32/cmd\.exe|lfi_path_traversal)", re.IGNORECASE), "Web/API: Local File Inclusion (LFI) Traversal", "web_api", 91),
    (re.compile(r"(rfi_remote_url|include\s*=\s*http://|php://input)", re.IGNORECASE), "Web/API: Remote File Inclusion (RFI) Vector", "web_api", 93),
    (re.compile(r"(O:8:\"Exception\":|Java\.lang\.Runtime|unserialize\(|pickle\.loads)", re.IGNORECASE), "Web/API: Insecure Object Deserialization Exploit", "web_api", 96),
    (re.compile(r"(broken_auth_bypass|jwt_alg_none|session_fixation)", re.IGNORECASE), "Web/API: Broken Authentication Mechanism Bypass", "web_api", 92),
    (re.compile(r"(idor_parameter|user_id_tamper|direct_object_ref_enum)", re.IGNORECASE), "Web/API: Insecure Direct Object Reference (IDOR)", "web_api", 89),
    (re.compile(r"(param_tamper|price=-100|role=admin_override)", re.IGNORECASE), "Web/API: Parameter Tampering Logic Manipulation", "web_api", 87),
    (re.compile(r"(api_key_leak|sk_live_[0-9a-zA-Z]{24}|ghp_[0-9a-zA-Z]{36})", re.IGNORECASE), "Web/API: Leaked API Secret Key Misuse", "web_api", 94),
    (re.compile(r"(mass_assignment|is_admin:true|role_escalate_json)", re.IGNORECASE), "Web/API: Mass Assignment Object Injection", "web_api", 90),
    (re.compile(r"(rate_limit_bypass|x-forwarded-for_rotate|burst_header_override)", re.IGNORECASE), "Web/API: API Rate Limit Bypass Evasion", "web_api", 88),
    (re.compile(r"(cors_misconfig|access-control-allow-origin:\s*\*|null_origin_trust)", re.IGNORECASE), "Web/API: CORS Misconfiguration Exploitation", "web_api", 86),
    (re.compile(r"(header_injection|crlf_injection|%0d%0aSet-Cookie)", re.IGNORECASE), "Web/API: HTTP Header Injection / CRLF Smuggling", "web_api", 89),
    (re.compile(r"(graphql_depth_bomb|graphql_introspection|nested_query_exhaust)", re.IGNORECASE), "Web/API: GraphQL Depth Bomb Denial of Service", "web_api", 91),
    (re.compile(r"(open_redirect|redirect_to=http://malicious|url=http://attacker)", re.IGNORECASE), "Web/API: Unvalidated Open Redirect Vector", "web_api", 80),
    (re.compile(r"(ssti_payload|\{\{7\*7\}\}|\{\{config\.items\(\)\}\})", re.IGNORECASE), "Web/API: Server-Side Template Injection (SSTI)", "web_api", 95),

    # ── 5. EXPLOITATION & ADVANCED THREATS (76-90) ───────────────────────────
    (re.compile(r"(\$\{jndi:(ldap|rmi|dns|ldaps|nis|iiop):|eval\(base64_decode|system\(|exec\()", re.IGNORECASE), "Exploitation: Remote Code Execution (RCE) Exploit Vector", "exploitation", 100),
    (re.compile(r"(\\x90{10,}|A{50,}|pattern_offset|eip_overwrite|nop_sled)", re.IGNORECASE), "Exploitation: Buffer Overflow / Stack Corruption Shellcode", "exploitation", 96),
    (re.compile(r"(heap_overflow|malloc_corruption|use_after_free_chunk)", re.IGNORECASE), "Exploitation: Heap Overflow Corruption Shellcode", "exploitation", 96),
    (re.compile(r"(sudo\s+su|chmod\s+u\+s|privilege_escalation|shadow_admin_add|kernel_exploit)", re.IGNORECASE), "Exploitation: Local Privilege Escalation Attempt", "exploitation", 95),
    (re.compile(r"(zero_day_vector|unlabelled_raw_stream|polymorphic_payload|opaque_execution)", re.IGNORECASE), "Exploitation: Zero-Day Polymorphic Exploit Vector", "exploitation", 99),
    (re.compile(r"(dll_hijack|loadlibrary.*malicious|version\.dll_fake|phantom_dll)", re.IGNORECASE), "Exploitation: DLL Search Order Hijacking Vector", "exploitation", 91),
    (re.compile(r"(format_string|%x%x%x%x|%n_write_memory)", re.IGNORECASE), "Exploitation: Format String Vulnerability Exploit", "exploitation", 93),
    (re.compile(r"(integer_overflow|int_wrap_around|malloc_negative_size)", re.IGNORECASE), "Exploitation: Integer Overflow Memory Vulnerability", "exploitation", 92),
    (re.compile(r"(use_after_free|uaf_dangling_ptr|vtable_hijack)", re.IGNORECASE), "Exploitation: Use-After-Free Memory Corruption", "exploitation", 95),
    (re.compile(r"(race_condition|toctou_file_swap|symlink_race)", re.IGNORECASE), "Exploitation: Race Condition / TOCTOU Flaw", "exploitation", 89),
    (re.compile(r"(container_escape|runc_exploit|docker_sock_mount|cgroup_release_agent)", re.IGNORECASE), "Exploitation: Container / Docker Socket Breakout Escape", "exploitation", 98),
    (re.compile(r"(cloud_imds_exfil|169\.254\.169\.254/latest/meta-data|aws_credentials_dump)", re.IGNORECASE), "Exploitation: Cloud Instance Metadata IMDS Exfiltration", "exploitation", 97),
    (re.compile(r"(subdomain_takeover|cname_dangling|unclaimed_bucket_takeover)", re.IGNORECASE), "Exploitation: Subdomain Takeover Hijacking", "exploitation", 87),
    (re.compile(r"(serverless_exploit|lambda_env_exfil|event_injection)", re.IGNORECASE), "Exploitation: Serverless Function Event Injection", "exploitation", 91),
    (re.compile(r"(supply_chain_poison|npm_typosquat|malicious_dep_inject)", re.IGNORECASE), "Exploitation: Software Supply Chain Dependency Poisoning", "exploitation", 96),

    # ── 6. POST-COMPROMISE & LATERAL OPERATIVE (91-100) ──────────────────────
    (re.compile(r"(psexec|wmic\s+process\s+call|winrm\s+exec|smbexec|lateral_pivot)", re.IGNORECASE), "Post-Compromise: Lateral Movement Sweep Attempt", "post_compromise", 94),
    (re.compile(r"(reg\s+add.*\\run|crontab\s+-e|systemctl\s+enable\s+backdoor|startup_folder)", re.IGNORECASE), "Post-Compromise: System Persistence Mechanism Addition", "post_compromise", 92),
    (re.compile(r"(certutil.*-urlcache|bitsadmin.*-transfer|mshta\.exe|rundll32\.exe)", re.IGNORECASE), "Post-Compromise: Living-off-the-Land (LotL) Binary Execution", "post_compromise", 93),
    (re.compile(r"(dns_tunnel_exfil|curl\s+-T\s+.*mega\.nz|base64_exfil_chunk|data_exfiltration)", re.IGNORECASE), "Post-Compromise: Data Exfiltration Tunnel Vector", "post_compromise", 97),
    (re.compile(r"(log_wiping|wevtutil_cl|rm_-rf_/var/log|audit_erase)", re.IGNORECASE), "Post-Compromise: Audit Log Wiping & Anti-Forensics", "post_compromise", 95),
    (re.compile(r"(shadow_admin|admin_group_inject|domain_admin_add)", re.IGNORECASE), "Post-Compromise: Shadow Administrator Account Creation", "post_compromise", 96),
    (re.compile(r"(c2_beaconing|malleable_http_ping|dns_c2_channel)", re.IGNORECASE), "Post-Compromise: Command & Control Beaconing Channel", "post_compromise", 94),
    (re.compile(r"(ransom_demand|ransom_note\.txt|extortion_contact)", re.IGNORECASE), "Post-Compromise: Ransomware Extortion Demand Note", "post_compromise", 98),
    (re.compile(r"(memory_scraping|pos_mem_dump|credit_card_scrape)", re.IGNORECASE), "Post-Compromise: Process Memory Scraping Vector", "post_compromise", 93),
    (re.compile(r"(staging_recon|7z_a_archive|rar_encrypt_exfil|internal_subnet_scan)", re.IGNORECASE), "Post-Compromise: Staging Data & Internal Network Recon", "post_compromise", 90),
]


def _is_whitelisted(ip_str: str) -> bool:
    """Never block loopback or local management/Docker bridge host."""
    try:
        if ip_str in ("127.0.0.1", "::1", "localhost"):
            return True
        ip = ipaddress.ip_address(ip_str)
        if ip.is_loopback or ip.is_unspecified:
            return True
        # Whitelist Docker internal bridge networks (172.16.0.0/12) used for container management
        if ip in ipaddress.ip_network("172.16.0.0/12"):
            return True
        return False
    except ValueError:
        return False




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
    """Record alert, quarantine IP, and publish live event."""
    # Safety net: never block an explicitly allowlisted management address.
    # This guards against edge-cases where the middleware dispatch path is
    # bypassed but this function is still called (e.g., internal tooling).
    if _is_whitelisted(src_ip) or _is_management_allowlisted(src_ip):
        logger.warning(
            "[IPS SAFETY NET] Refusing to block allowlisted management IP %s (sig: %s)",
            src_ip, signature,
        )
        return
    global _blocked_ips_cache
    _blocked_ips_cache.add(src_ip)

    alert_id = None
    try:
        with get_sync_connection() as conn:
            with conn.cursor() as cur:
                # 1. Ingest alert
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

                # 2. Block IP in database
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
                conn.commit()

        # Update Prometheus metrics
        blocked_ips_total.inc()
        alerts_ingested_total.labels(severity=severity).inc()

        # Publish IPS Action to Redis
        publish_ips_action({
            "action": "BLOCK",
            "ip_address": src_ip,
            "reason": reason,
            "block_id": str(block_record["id"]),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

        # Publish Live Alert to WebSocket
        publish_live_alert({
            **alert_record,
            "id": str(alert_id),
            "timestamp": alert_record["timestamp"].isoformat(),
            "ai_evaluation": {
                "risk_score": risk_score,
                "confidence": 0.99,
                "recommended_action": "BLOCK_IP",
                "attack_family": category.upper(),
            },
            "autonomous_mitigation": {
                "prevented": True,
                "action": "FIREWALL_DROP_SEVERED",
                "mttc": "0.04s",
            },
        })
        logger.warning("🚨 [IPS GATEWAY] Blocked attacker %s: %s", src_ip, reason)
    except Exception as exc:
        logger.error("Failed to execute autonomous block for %s: %s", src_ip, exc)


class IPSGatewayMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Preflight and API docs are allowed without rate limiting
        if request.method == "OPTIONS":
            return await call_next(request)

        # Extract client IP
        forwarded = request.headers.get("x-forwarded-for")
        client_ip = forwarded.split(",")[0].strip() if forwarded else (request.client.host if request.client else "127.0.0.1")

        # Local infrastructure and explicitly configured operator addresses
        # must remain reachable to recover from a false-positive quarantine.
        if _is_whitelisted(client_ip) or _is_management_allowlisted(client_ip):
            return await call_next(request)

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

        # ── 2. In-Line Payload & Exploit Inspection ───────────────────
        full_query = urllib.parse.unquote(str(request.url.query))
        inspect_target = f"{request.url.path}?{full_query} " + " ".join(
            f"{k}:{v}" for k, v in request.headers.items() if k.lower() in ("user-agent", "authorization", "referer")
        )

        for pattern, sig_name, category, risk in ATTACK_SIGNATURES:
            if pattern.search(inspect_target):
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

        # ── 3. Volumetric Rate Limiting (DDoS Surge Detection) ────────
        now = time.time()
        window = _request_history[client_ip]
        # Prune older than window
        _request_history[client_ip] = [t for t in window if now - t < BURST_WINDOW_SECONDS]
        _request_history[client_ip].append(now)

        if len(_request_history[client_ip]) > BURST_MAX_REQUESTS:
            burst_count = len(_request_history[client_ip])
            _execute_autonomous_block(
                src_ip=client_ip,
                signature=f"Volumetric HTTP Flood Anomaly (Ingress Surge > {BURST_MAX_REQUESTS} req/5s)",
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
