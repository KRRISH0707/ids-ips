#!/usr/bin/env python3
"""
Enterprise SOAR Playbooks Seeder (55 Autonomous Playbooks)
Mapps real-world cyber threat vectors across MITRE ATT&CK Enterprise Matrix:
- Ransomware & Destructive Malware (PB-01 to PB-05)
- Denial of Service & Protocol Violations (PB-06 to PB-10)
- Lateral Movement & Active Directory Defense (PB-11 to PB-15)
- Cloud Infrastructure & IAM Identity (PB-16 to PB-20)
- Kubernetes & Container Mesh Defense (PB-21 to PB-25)
- Web Application & API Security (PB-26 to PB-30)
- Insider Threat & Data Exfiltration (PB-31 to PB-35)
- Email, Phishing & Social Engineering (PB-36 to PB-40)
- Endpoint Defense Evasion & Anti-Forensics (PB-41 to PB-45)
- Supply Chain, CI/CD & DevSecOps (PB-46 to PB-50)
- OT, SCADA, IoT & Emerging AI Threat Defense (PB-51 to PB-55)
"""

import os
import sys
import logging
from datetime import datetime, timezone, timedelta
import random
import psycopg
from psycopg.types.json import Jsonb

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("seed_playbooks")

PLAYBOOKS_55 = [
    # 1. Ransomware & Host Destruction
    {
        "name": "PB-01: Rapid Ransomware Containment & VSS Shadow Lock",
        "description": "Instantly halts ransomware mass encryption by quarantining endpoint, killing lateral SMB ports, locking Volume Shadow storage, and paging SOC.",
        "trigger_event": "RANSOMWARE",
        "severity_threshold": "CRITICAL",
        "actions": ["ISOLATE_HOST", "LOCK_SHADOW_COPIES", "BLOCK_LATERAL_SMB", "DISPATCH_PAGERDUTY_ALERT"],
    },
    {
        "name": "PB-02: Cobalt Strike Beaconing & Active C2 Severance",
        "description": "Sever active Command & Control beacon communication, ban external C2 IP at edge firewall, and capture volatile memory triage artifacts.",
        "trigger_event": "C2_BEACON",
        "severity_threshold": "CRITICAL",
        "actions": ["FIREWALL_DROP_EGRESS", "ISOLATE_COMPROMISED_HOST", "DUMP_PROCESS_MEMORY_ARTIFACTS", "SOC_HIGH_PRIORITY_INCIDENT"],
    },
    {
        "name": "PB-03: Credential Stuffing & SSH/RDP Brute Force Mitigation",
        "description": "Imposes 24-hour firewall ban on attacking botnet IP, invalidates active sessions, and triggers automated step-up MFA challenge.",
        "trigger_event": "BRUTE_FORCE",
        "severity_threshold": "HIGH",
        "actions": ["BLOCK_SOURCE_IP_24H", "FORCE_USER_SESSION_TERMINATION", "ENABLE_MFA_STEPUP", "WRITE_FORENSIC_AUDIT_LOG"],
    },
    {
        "name": "PB-04: Automated Network Reconnaissance & Port Scan Tarpit",
        "description": "Identifies adversarial network port sweeps and SYN reconnaissance, diverting malicious scanners into TCP tarpit honey-queues.",
        "trigger_event": "PORT_SCAN",
        "severity_threshold": "MEDIUM",
        "actions": ["TARPIT_ATTACKER_TCP", "DYNAMIC_IPTABLES_DROP", "NOTIFY_NETWORK_ADMIN"],
    },
    {
        "name": "PB-05: High Anomaly Behavioral & Entropy Isolation",
        "description": "Autonomously quarantines internal machines exhibiting severe behavioral deviations, Shannon entropy spikes, or abnormal process parents.",
        "trigger_event": "HIGH_ANOMALY",
        "severity_threshold": "CRITICAL",
        "actions": ["ISOLATE_HOST", "START_PROMISCUOUS_PCAP_CAPTURE", "ESCALATE_TO_TIER2_ANALYST"],
    },

    # 2. Denial of Service & Protocol Violations
    {
        "name": "PB-06: Volumetric DDoS & BGP Flowspec Scrubbing Shield",
        "description": "Mitigates multi-gigabit volumetric SYN, UDP, and ICMP saturation attacks by activating upstream BGP Flowspec scrubbing and kernel SYN cookies.",
        "trigger_event": "SYN_FLOOD",
        "severity_threshold": "CRITICAL",
        "actions": ["ACTIVATE_BGP_FLOWSPEC_SCRUBBING", "DYNAMIC_IPTABLES_DROP", "RATE_LIMIT_SYN_COOKIES", "BROADCAST_INCIDENT_WAR_ROOM"],
    },
    {
        "name": "PB-07: Remote Code Execution (RCE) & Web Shell Lockdown",
        "description": "Intercepts zero-day RCE exploits and web shell execution, terminating web worker child processes, banning attacker IP, and capturing PCAP streams.",
        "trigger_event": "RCE_EXPLOIT",
        "severity_threshold": "CRITICAL",
        "actions": ["TERMINATE_WEB_WORKER_PROCESS", "BLOCK_SOURCE_IP_24H", "INVALIDATE_SESSION_COOKIES", "CAPTURE_FORENSIC_PCAP_STREAM"],
    },
    {
        "name": "PB-08: Active Directory DCSync & Kerberoasting Quarantine",
        "description": "Halts unauthorized Active Directory domain credential harvesting, DCSync replication sweeps, and Kerberoasting ticket requests.",
        "trigger_event": "KERBEROASTING",
        "severity_threshold": "CRITICAL",
        "actions": ["SUSPEND_COMPROMISED_AD_ACCOUNT", "SEVER_SMB_RPC_TUNNELS", "TRIGGER_KRBTGT_PASSWORD_RESET", "DISPATCH_SOC_URGENT_PAGE"],
    },
    {
        "name": "PB-09: Covert DNS Tunneling & Data Exfiltration Interception",
        "description": "Detects high-entropy outbound DNS tunneling and covert data leakage, sinkholing attacker nameservers and severing active TCP/UDP sockets.",
        "trigger_event": "DNS_TUNNELING",
        "severity_threshold": "HIGH",
        "actions": ["SINKHOLE_MALICIOUS_NAMESERVER", "INJECT_TCP_RESET_STREAM", "ISOLATE_EXFILTRATING_HOST", "DUMP_ENDPOINT_NETWORK_SOCKETS"],
    },
    {
        "name": "PB-10: Cloud Container Escape & Kernel Cgroup Freeze",
        "description": "Enforces immediate cgroup freezing upon detecting container namespace breakouts or mount leaks, revoking ephemeral cloud IAM tokens.",
        "trigger_event": "CONTAINER_ESCAPE",
        "severity_threshold": "CRITICAL",
        "actions": ["FREEZE_CONTAINER_RUNTIME_CGROUP", "REVOKE_CLOUD_IAM_ROLE_TOKENS", "TERMINATE_KUBERNETES_POD", "NOTIFY_DEVSECOPS_LEAD"],
    },

    # 3. Lateral Movement & Active Directory Defense
    {
        "name": "PB-11: Pass-The-Hash & WMI Lateral Movement Quarantine",
        "description": "Contains internal lateral pivoting via Pass-The-Hash, WMI, or WinRM by enforcing microsegmentation boundaries around infected nodes.",
        "trigger_event": "LATERAL_MOVEMENT",
        "severity_threshold": "HIGH",
        "actions": ["ENFORCE_MICROSEGMENTATION_ISOLATION", "REVOKE_KERBEROS_TGT_TOKENS", "ENABLE_EXTENDED_SECURITY_AUDIT", "SOC_TIER2_ESCALATION"],
    },
    {
        "name": "PB-12: Zero-Day Protocol Anomaly & Dynamic eBPF Discard",
        "description": "Autonomously synthesizes dynamic eBPF drop filters and Suricata bytecode rules upon identifying malformed packet payloads or zero-day zero-byte exploits.",
        "trigger_event": "PROTOCOL_VIOLATION",
        "severity_threshold": "CRITICAL",
        "actions": ["INJECT_KERNEL_EBPF_DISCARD", "BLOCK_SOURCE_IP_24H", "GENERATE_SURICATA_SNORT_SIGNATURE", "DISPATCH_PAGERDUTY_ALERT"],
    },
    {
        "name": "PB-13: Golden / Silver Ticket Forgery Autonomous Purge",
        "description": "Detects forged Kerberos TGT/TGS tickets, forces dual KRBTGT password rollover on primary domain controller, and flushes domain KDC caches.",
        "trigger_event": "GOLDEN_TICKET",
        "severity_threshold": "CRITICAL",
        "actions": ["TRIGGER_KRBTGT_PASSWORD_RESET", "PURGE_DOMAIN_KDC_CACHE", "LOCK_COMPROMISED_SPN_ACCOUNTS", "NOTIFY_CISO_EXECUTIVE"],
    },
    {
        "name": "PB-14: LSASS Memory Dumping & Mimikatz Execution Kill",
        "description": "Detects unauthorized LSASS process access or MiniDumpWriteDump calls, terminates hostile dump utilities, and isolates host immediately.",
        "trigger_event": "LSASS_DUMP",
        "severity_threshold": "CRITICAL",
        "actions": ["KILL_LSASS_DUMP_PROCESS", "ISOLATE_HOST", "ENABLE_CREDENTIAL_GUARD", "DISPATCH_SOC_URGENT_PAGE"],
    },
    {
        "name": "PB-15: ZeroLogon & Netlogon Spoofing Host Containment",
        "description": "Neutralizes CVE-2020-1472 Netlogon cryptographic flaws, terminating insecure Netlogon RPC connections and resetting DC computer account passwords.",
        "trigger_event": "ZEROLOGON",
        "severity_threshold": "CRITICAL",
        "actions": ["SEVER_NETLOGON_SECURE_CHANNEL", "FORCE_DC_COMPUTER_PW_SYNC", "ISOLATE_HOST", "BROADCAST_INCIDENT_WAR_ROOM"],
    },

    # 4. Cloud Infrastructure & IAM Identity
    {
        "name": "PB-16: Cloud IAM Access Key Leakage & Instant Revocation",
        "description": "Detects public Git or pastebin exposure of AWS/Azure access keys, deactivates keys in cloud control plane, and attaches explicit deny policies.",
        "trigger_event": "IAM_KEY_LEAK",
        "severity_threshold": "CRITICAL",
        "actions": ["REVOKE_CLOUD_IAM_ROLE_TOKENS", "DEACTIVATE_COMPROMISED_ACCESS_KEY", "ATTACH_QUARANTINE_DENY_POLICY", "PAGE_CLOUD_ARCHITECT"],
    },
    {
        "name": "PB-17: Malicious S3 / Cloud Storage Public Exposure Remediation",
        "description": "Enforces automated S3 Block Public Access, removes public wildcard ACLs, and audits cloud object download logs for exfiltration.",
        "trigger_event": "S3_BUCKET_LEAK",
        "severity_threshold": "HIGH",
        "actions": ["ENFORCE_S3_BLOCK_PUBLIC_ACCESS", "REVOKE_PUBLIC_ACL_POLICIES", "AUDIT_BUCKET_ACCESS_LOGS", "NOTIFY_COMPLIANCE_OFFICER"],
    },
    {
        "name": "PB-18: AWS STS Ephemeral Session Credential Hijack Severance",
        "description": "Revokes stolen AssumeRole STS session credentials, terminates active cloud console sessions, and forces hardware MFA enrollment.",
        "trigger_event": "STS_ASSUME_ROLE_ABUSE",
        "severity_threshold": "HIGH",
        "actions": ["TERMINATE_ACTIVE_STS_SESSIONS", "REVOKE_CLOUD_IAM_ROLE_TOKENS", "ENABLE_MFA_STEPUP", "WRITE_FORENSIC_AUDIT_LOG"],
    },
    {
        "name": "PB-19: Azure AD Impossible Travel & Token Revocation",
        "description": "Detects anomalous geographically impossible logins, invalidates all OAuth refresh tokens, and prompts strict FIDO2 MFA challenge.",
        "trigger_event": "IMPOSSIBLE_TRAVEL",
        "severity_threshold": "HIGH",
        "actions": ["REVOKE_REFRESH_TOKENS", "FORCE_GLOBAL_SIGNOUT", "ENABLE_MFA_STEPUP", "NOTIFY_SECURITY_OPS"],
    },
    {
        "name": "PB-20: GCP Service Account Privilege Escalation Lockout",
        "description": "Disables compromised Google Cloud service accounts attempting unauthorized IAM role bindings or key generation.",
        "trigger_event": "GCP_PRIV_ESC",
        "severity_threshold": "CRITICAL",
        "actions": ["DISABLE_GCP_SERVICE_ACCOUNT", "REVOKE_CLOUD_IAM_ROLE_TOKENS", "ESCALATE_TO_TIER2_ANALYST", "DISPATCH_SOC_URGENT_PAGE"],
    },

    # 5. Kubernetes & Container Infrastructure
    {
        "name": "PB-21: Kubernetes Privileged Pod Injection & Kubelet Eviction",
        "description": "Evicts pods created with privileged flags, hostPID, or hostPath volume mounts, enforcing admission controller policy blocks.",
        "trigger_event": "PRIVILEGED_POD",
        "severity_threshold": "CRITICAL",
        "actions": ["TERMINATE_KUBERNETES_POD", "APPLY_RESTRICTED_POD_SECURITY_POLICY", "ISOLATE_HOST", "NOTIFY_DEVSECOPS_LEAD"],
    },
    {
        "name": "PB-22: Container Image Drift & Cryptomining Pod Teardown",
        "description": "Detects unauthorized binary execution inside container images (e.g. XMRig), terminates container pod, and blocks stratum mining pools.",
        "trigger_event": "CRYPTOMINING_POD",
        "severity_threshold": "HIGH",
        "actions": ["TERMINATE_KUBERNETES_POD", "BLOCK_MINING_POOL_IPS", "DYNAMIC_IPTABLES_DROP", "WRITE_FORENSIC_AUDIT_LOG"],
    },
    {
        "name": "PB-23: Kubernetes RBAC ClusterRoleBinding Backdoor Purge",
        "description": "Deletes unauthorized cluster-admin RoleBindings assigned to default service accounts, rolling Kube-API tokens immediately.",
        "trigger_event": "K8S_RBAC_BACKDOOR",
        "severity_threshold": "CRITICAL",
        "actions": ["DELETE_MALICIOUS_CLUSTER_ROLE_BINDING", "REVOKE_CLOUD_IAM_ROLE_TOKENS", "WRITE_FORENSIC_AUDIT_LOG", "DISPATCH_SOC_URGENT_PAGE"],
    },
    {
        "name": "PB-24: Ingress Controller API Abuse & Virtual WAF Rate-Limiting",
        "description": "Imposes aggressive rate limits on API endpoints under Layer-7 distributed HTTP flood attacks, injecting CAPTCHA challenges.",
        "trigger_event": "API_RATE_ABUSE",
        "severity_threshold": "MEDIUM",
        "actions": ["ENABLE_VIRTUAL_WAF_RULE", "ENFORCE_INGRESS_RATE_LIMIT", "BLOCK_SOURCE_IP_24H", "NOTIFY_NETWORK_ADMIN"],
    },
    {
        "name": "PB-25: Microservice East-West Mesh Injection Severance",
        "description": "Sever unauthorized inter-service traffic violating Istio/Linkerd mTLS authorization policies, isolating rogue microservice pods.",
        "trigger_event": "MESH_INJECTION",
        "severity_threshold": "HIGH",
        "actions": ["ENFORCE_MUTUAL_TLS_STRICT", "TERMINATE_KUBERNETES_POD", "ENFORCE_MICROSEGMENTATION_ISOLATION", "NOTIFY_DEVSECOPS_LEAD"],
    },

    # 6. Web Application & API Security
    {
        "name": "PB-26: SQL Injection & Automated Database Query Shielding",
        "description": "Identifies advanced blind/time-based SQLi patterns, applies automated virtual WAF regex filtering, and drops attacking IP sessions.",
        "trigger_event": "SQL_INJECTION",
        "severity_threshold": "CRITICAL",
        "actions": ["ENABLE_VIRTUAL_WAF_RULE", "BLOCK_SOURCE_IP_24H", "INVALIDATE_SESSION_COOKIES", "WRITE_FORENSIC_AUDIT_LOG"],
    },
    {
        "name": "PB-27: Server-Side Request Forgery (SSRF) Cloud Metadata Lock",
        "description": "Blocks internal requests directed at cloud metadata endpoints (169.254.169.254), enforcing IMDSv2 session token validation.",
        "trigger_event": "SSRF_EXPLOIT",
        "severity_threshold": "CRITICAL",
        "actions": ["BLOCK_METADATA_IP_ACCESS", "ENABLE_IMDSV2_STRICT", "BLOCK_SOURCE_IP_24H", "DISPATCH_PAGERDUTY_ALERT"],
    },
    {
        "name": "PB-28: Broken Object Level Authorization (BOLA/IDOR) Throttling",
        "description": "Halts sequential IDOR parameter fuzzing, revokes JWT tokens for attacker identity, and locks account from further API transactions.",
        "trigger_event": "BOLA_IDOR_ABUSE",
        "severity_threshold": "HIGH",
        "actions": ["SUSPEND_USER_ACCOUNT", "REVOKE_REFRESH_TOKENS", "ENABLE_VIRTUAL_WAF_RULE", "NOTIFY_SECURITY_OPS"],
    },
    {
        "name": "PB-29: GraphQL Depth Query / Introspection DoS Shield",
        "description": "Blocks nested circular GraphQL queries exceeding depth limits and shuts down schema introspection in production endpoints.",
        "trigger_event": "GRAPHQL_DOS",
        "severity_threshold": "MEDIUM",
        "actions": ["ENABLE_VIRTUAL_WAF_RULE", "BLOCK_SOURCE_IP_24H", "WRITE_FORENSIC_AUDIT_LOG", "NOTIFY_NETWORK_ADMIN"],
    },
    {
        "name": "PB-30: Malicious File Upload & Web Shell Execution Kill",
        "description": "Detects polyglot PHP/JSP web shells in media directories, permanently deletes uploaded files, and terminates parent web worker processes.",
        "trigger_event": "WEB_SHELL_UPLOAD",
        "severity_threshold": "CRITICAL",
        "actions": ["DELETE_UPLOADED_PAYLOAD", "TERMINATE_WEB_WORKER_PROCESS", "BLOCK_SOURCE_IP_24H", "DUMP_PROCESS_MEMORY_ARTIFACTS"],
    },

    # 7. Insider Threat & Data Exfiltration
    {
        "name": "PB-31: Mass Sensitive Data Exfiltration / Cloud Sync Severance",
        "description": "Terminates multi-gigabyte anomalous uploads to Mega, Google Drive, or personal Dropbox, freezing outbound network tunnels.",
        "trigger_event": "DATA_EXFIL",
        "severity_threshold": "CRITICAL",
        "actions": ["DROP_OUTBOUND_TUNNEL", "REVOKE_API_KEYS", "FREEZE_S3_EXFIL_TARGET", "PAGE_INCIDENT_COMMANDER"],
    },
    {
        "name": "PB-32: Unauthorized USB / Removable Media Storage Lock",
        "description": "Detects mass copy operations to unencrypted USB mass storage devices, disables USB ports via endpoint agent, and alerts DLP team.",
        "trigger_event": "USB_EXFIL",
        "severity_threshold": "HIGH",
        "actions": ["DISABLE_USB_STORAGE_PORTS", "ISOLATE_HOST", "FORCE_USER_SESSION_TERMINATION", "NOTIFY_COMPLIANCE_OFFICER"],
    },
    {
        "name": "PB-33: Rogue Local Administrator Account Creation Revert",
        "description": "Detects unauthorized additions to local Administrators / wheel groups, deletes backdoor accounts, and alerts SecOps.",
        "trigger_event": "ROGUE_ADMIN_USER",
        "severity_threshold": "CRITICAL",
        "actions": ["DELETE_ROGUE_ADMIN_USER", "ISOLATE_HOST", "ENABLE_EXTENDED_SECURITY_AUDIT", "BROADCAST_INCIDENT_WAR_ROOM"],
    },
    {
        "name": "PB-34: Off-Hours Bulk Database Query Throttling & Audit Freeze",
        "description": "Detects SELECT * dumps executed outside business hours, severs database connection, and freezes database user credentials.",
        "trigger_event": "OFF_HOURS_DB_DUMP",
        "severity_threshold": "HIGH",
        "actions": ["KILL_RUNNING_DB_QUERY", "REVOKE_API_KEYS", "CAPTURE_FORENSIC_PCAP_STREAM", "NOTIFY_SECURITY_OPS"],
    },
    {
        "name": "PB-35: Confidential Source Code Repository Bulk Clone Block",
        "description": "Detects anomalous cloning of 20+ enterprise Git repositories in minutes, revokes SSH deployment keys, and suspends SCM user token.",
        "trigger_event": "REPO_BULK_CLONE",
        "severity_threshold": "HIGH",
        "actions": ["REVOKE_REFRESH_TOKENS", "REVOKE_API_KEYS", "SUSPEND_USER_ACCOUNT", "NOTIFY_DEVSECOPS_LEAD"],
    },

    # 8. Email, Phishing & Social Engineering
    {
        "name": "PB-36: Business Email Compromise (BEC) Forwarding Rule Purge",
        "description": "Scans Exchange/O365 mailboxes for newly created hidden forwarding rules, removes forwarding targets, and forces password reset.",
        "trigger_event": "BEC_FORWARDING",
        "severity_threshold": "HIGH",
        "actions": ["DELETE_MALICIOUS_INBOX_RULES", "REVOKE_REFRESH_TOKENS", "ENABLE_MFA_STEPUP", "NOTIFY_SECURITY_OPS"],
    },
    {
        "name": "PB-37: Spear-Phishing Malicious Link Domain Sinkhole",
        "description": "Sinkholes phishing domains extracted from incoming email payloads, blocking access across corporate web proxies and DNS servers.",
        "trigger_event": "PHISHING_LINK",
        "severity_threshold": "HIGH",
        "actions": ["SINKHOLE_MALICIOUS_NAMESERVER", "BLOCK_EDGE_PROXY_URL", "DYNAMIC_IPTABLES_DROP", "NOTIFY_SECURITY_OPS"],
    },
    {
        "name": "PB-38: Macro-Enabled Malicious Attachment Quarantine",
        "description": "Quarantines emails containing VBA macro payloads, hashes attachment to EDR global blocklist, and isolates recipient host if opened.",
        "trigger_event": "MACRO_ATTACHMENT",
        "severity_threshold": "HIGH",
        "actions": ["QUARANTINE_EMAIL_MESSAGE", "ISOLATE_HOST", "DUMP_PROCESS_MEMORY_ARTIFACTS", "NOTIFY_SECURITY_OPS"],
    },
    {
        "name": "PB-39: Evilginx Reverse-Proxy AitM Session Invalidation",
        "description": "Detects Adversary-in-the-Middle reverse proxy interception, invalidating stolen session cookies and mandating hardware token re-auth.",
        "trigger_event": "AITM_PHISHING",
        "severity_threshold": "CRITICAL",
        "actions": ["FORCE_GLOBAL_SIGNOUT", "INVALIDATE_SESSION_COOKIES", "ENABLE_MFA_STEPUP", "DISPATCH_SOC_URGENT_PAGE"],
    },
    {
        "name": "PB-40: Brand Impersonation Typosquatting DNS Redirection",
        "description": "Blocks freshly registered lookalike domains at recursive DNS resolvers, automatically filing registrar abuse takedown requests.",
        "trigger_event": "TYPOSQUAT_DOMAIN",
        "severity_threshold": "MEDIUM",
        "actions": ["SINKHOLE_MALICIOUS_NAMESERVER", "DYNAMIC_IPTABLES_DROP", "WRITE_FORENSIC_AUDIT_LOG", "NOTIFY_SECURITY_OPS"],
    },

    # 9. Endpoint Defense Evasion & Anti-Forensics
    {
        "name": "PB-41: Living-off-the-Land (LotL) PowerShell Encoded Script Kill",
        "description": "Intercepts base64-encoded PowerShell executions invoking hidden windows or WebClient downloads, terminating process tree.",
        "trigger_event": "ENCODED_POWERSHELL",
        "severity_threshold": "HIGH",
        "actions": ["KILL_PROCESS_TREE", "ISOLATE_HOST", "ENABLE_EXTENDED_SECURITY_AUDIT", "DUMP_PROCESS_MEMORY_ARTIFACTS"],
    },
    {
        "name": "PB-42: Windows Security Event Log Clearing Anti-Forensics Halt",
        "description": "Triggers immediate host quarantine upon wevtutil / Event ID 1102 log clearing commands, capturing memory and disk snapshots.",
        "trigger_event": "LOG_CLEARING",
        "severity_threshold": "CRITICAL",
        "actions": ["ISOLATE_HOST", "DUMP_PROCESS_MEMORY_ARTIFACTS", "ENABLE_EXTENDED_SECURITY_AUDIT", "BROADCAST_INCIDENT_WAR_ROOM"],
    },
    {
        "name": "PB-43: Process Injection / DLL Hollowing Memory Eviction",
        "description": "Detects remote thread injection into svchost.exe or explorer.exe, suspends hollowed thread, and dumps payload for malware analysis.",
        "trigger_event": "PROCESS_INJECTION",
        "severity_threshold": "CRITICAL",
        "actions": ["SUSPEND_HOLLOWED_THREAD", "KILL_PROCESS_TREE", "ISOLATE_HOST", "CAPTURE_FORENSIC_PCAP_STREAM"],
    },
    {
        "name": "PB-44: Scheduled Task / Cron Persistence Backdoor Removal",
        "description": "Removes hostile recurring scheduled tasks or cron scripts created in non-standard paths (/tmp, /dev/shm, AppData).",
        "trigger_event": "PERSISTENCE_TASK",
        "severity_threshold": "HIGH",
        "actions": ["DELETE_MALICIOUS_SCHEDULED_TASK", "ISOLATE_HOST", "WRITE_FORENSIC_AUDIT_LOG", "NOTIFY_SECURITY_OPS"],
    },
    {
        "name": "PB-45: Kernel Rootkit / Hidden Driver eBPF Quarantine",
        "description": "Identifies hidden kernel modules or hooked syscall tables via eBPF integrity checks, quarantining machine to prevent persistence.",
        "trigger_event": "ROOTKIT_DETECT",
        "severity_threshold": "CRITICAL",
        "actions": ["UNLOAD_SUSPICIOUS_KERNEL_MODULE", "ISOLATE_HOST", "DISPATCH_PAGERDUTY_ALERT", "BROADCAST_INCIDENT_WAR_ROOM"],
    },

    # 10. Supply Chain, CI/CD & DevSecOps
    {
        "name": "PB-46: CI/CD Pipeline Secret Leakage & Workflow Halt",
        "description": "Cancels active GitHub Actions or GitLab CI jobs printing exposed private keys or tokens to stdout, rotating secrets in HashiCorp Vault.",
        "trigger_event": "PIPELINE_SECRET_LEAK",
        "severity_threshold": "CRITICAL",
        "actions": ["CANCEL_RUNNING_CI_PIPELINE", "REVOKE_API_KEYS", "WRITE_FORENSIC_AUDIT_LOG", "NOTIFY_DEVSECOPS_LEAD"],
    },
    {
        "name": "PB-47: Typosquatted NPM/PyPI Dependency Confusion Block",
        "description": "Blocks internal builds from pulling suspicious package names mirroring private internal scopes from public registries.",
        "trigger_event": "DEPENDENCY_CONFUSION",
        "severity_threshold": "HIGH",
        "actions": ["BLOCK_PACKAGE_HASH_IN_ARTIFACTORY", "WRITE_FORENSIC_AUDIT_LOG", "NOTIFY_DEVSECOPS_LEAD"],
    },
    {
        "name": "PB-48: GitHub Actions Runner Tamper & Token Invalidation",
        "description": "Terminates compromised self-hosted runner VMs executing untrusted third-party pull request scripts, rolling runner registration tokens.",
        "trigger_event": "GITHUB_RUNNER_TAMPER",
        "severity_threshold": "HIGH",
        "actions": ["TERMINATE_EPHEMERAL_RUNNER_VM", "REVOKE_API_KEYS", "ISOLATE_HOST", "WRITE_FORENSIC_AUDIT_LOG"],
    },
    {
        "name": "PB-49: Terraform State File S3 Exposure Rapid Lockdown",
        "description": "Locks down public S3 buckets storing plaintext tfstate files with cleartext database passwords, rotating all embedded credentials.",
        "trigger_event": "TFSTATE_EXPOSURE",
        "severity_threshold": "CRITICAL",
        "actions": ["LOCK_S3_TFSTATE_ENCRYPTION_KMS", "ENFORCE_S3_BLOCK_PUBLIC_ACCESS", "REVOKE_API_KEYS", "PAGE_CLOUD_ARCHITECT"],
    },
    {
        "name": "PB-50: Dockerfile Poisoning & Malicious Base Layer Rejection",
        "description": "Quarantines container images containing known CVE vulnerabilities or embedded reverse shells, halting production deployment gates.",
        "trigger_event": "POISONED_CONTAINER_IMAGE",
        "severity_threshold": "HIGH",
        "actions": ["QUARANTINE_REGISTRY_IMAGE_TAG", "TERMINATE_KUBERNETES_POD", "NOTIFY_DEVSECOPS_LEAD"],
    },

    # 11. SCADA, IoT & Emerging AI Threat Defense
    {
        "name": "PB-51: SCADA / Modbus Unauthorized Function Code Invalidation",
        "description": "Drops unauthorized Modbus TCP function code 0x05/0x06 write commands directed at Programmable Logic Controllers (PLCs).",
        "trigger_event": "SCADA_MODBUS_TAMPER",
        "severity_threshold": "CRITICAL",
        "actions": ["DROP_MODBUS_TCP_PACKETS", "ISOLATE_PLC_NETWORK_SEGMENT", "DISPATCH_PAGERDUTY_ALERT", "BROADCAST_INCIDENT_WAR_ROOM"],
    },
    {
        "name": "PB-52: Industrial OT BACnet / Siemens S7 Network Isolation",
        "description": "Enforces strict air-gap firewall filters upon identifying rogue S7Comm packet injections into industrial automation segments.",
        "trigger_event": "OT_S7_INJECTION",
        "severity_threshold": "CRITICAL",
        "actions": ["ENFORCE_AIR_GAP_FIREWALL_RULE", "ISOLATE_HOST", "DISPATCH_SOC_URGENT_PAGE", "WRITE_FORENSIC_AUDIT_LOG"],
    },
    {
        "name": "PB-53: IoT Mirai / Mozi Botnet Telnet Sweep Neutralization",
        "description": "Detects Mirai botnet propagation sweeps targeting default Telnet/SSH ports on IoT devices, applying dynamic port filters.",
        "trigger_event": "IOT_BOTNET_MIRAI",
        "severity_threshold": "HIGH",
        "actions": ["BLOCK_SOURCE_IP_24H", "DISABLE_TELNET_PORTS_GLOBAL", "DYNAMIC_IPTABLES_DROP", "NOTIFY_NETWORK_ADMIN"],
    },
    {
        "name": "PB-54: LLM Prompt Injection & System Jailbreak Guardrail Freeze",
        "description": "Terminates LLM conversational sessions attempting DAN/jailbreak bypasses or system prompt extraction, imposing temporary token bans.",
        "trigger_event": "LLM_PROMPT_INJECTION",
        "severity_threshold": "HIGH",
        "actions": ["TERMINATE_LLM_SESSION", "REVOKE_API_KEYS", "WRITE_FORENSIC_AUDIT_LOG", "NOTIFY_SECURITY_OPS"],
    },
    {
        "name": "PB-55: Adversarial AI Agent Model Weight Exfiltration Severance",
        "description": "Blocks unauthorized outbound transfer of multi-gigabyte safetensors or PyTorch model checkpoints, revoking cloud storage tokens.",
        "trigger_event": "AI_MODEL_EXFIL",
        "severity_threshold": "CRITICAL",
        "actions": ["DROP_OUTBOUND_TUNNEL", "FREEZE_MODEL_STORAGE_VOLUME", "REVOKE_API_KEYS", "PAGE_INCIDENT_COMMANDER"],
    }
]


def seed_55_playbooks(conn=None):
    """Seed or update all 55 SOAR playbooks idempotently."""
    should_close = False
    if conn is None:
        db_url = os.getenv("DATABASE_URL", "postgresql://idsips:change-me-in-development@localhost:5432/idsips")
        conn = psycopg.connect(db_url, row_factory=psycopg.rows.dict_row)
        should_close = True

    try:
        with conn.cursor() as cur:
            logger.info(f"Synchronizing {len(PLAYBOOKS_55)} Autonomous SOAR Playbooks (PB-01 to PB-55)...")
            created = 0
            updated = 0

            for pb in PLAYBOOKS_55:
                pb_prefix = pb["name"].split(":")[0].strip()  # e.g. "PB-01"
                cur.execute("SELECT id, name FROM playbooks WHERE name LIKE %s", (f"{pb_prefix}:%",))
                existing = cur.fetchone()

                if existing:
                    cur.execute(
                        """
                        UPDATE playbooks
                        SET name = %s, description = %s, trigger_event = %s, severity_threshold = %s, actions = %s, is_active = TRUE
                        WHERE id = %s
                        """,
                        (pb["name"], pb["description"], pb["trigger_event"], pb["severity_threshold"], Jsonb(pb["actions"]), existing["id"])
                    )
                    updated += 1
                else:
                    cur.execute(
                        """
                        INSERT INTO playbooks (name, description, trigger_event, severity_threshold, actions, is_active)
                        VALUES (%s, %s, %s, %s, %s, TRUE)
                        """,
                        (pb["name"], pb["description"], pb["trigger_event"], pb["severity_threshold"], Jsonb(pb["actions"]))
                    )
                    created += 1

            conn.commit()
            logger.info(f"✓ Playbooks synchronized: {created} new created, {updated} existing updated. Total: {len(PLAYBOOKS_55)}")

            # Verify total count in table
            cur.execute("SELECT COUNT(*) as c FROM playbooks")
            total_pbs = cur.fetchone()["c"]
            logger.info(f"✓ Total Playbooks in database: {total_pbs}")

            # Check if playbook_executions table has executions
            cur.execute("SELECT COUNT(*) as c FROM playbook_executions")
            exec_count = cur.fetchone()["c"]
            if exec_count < 50:
                logger.info("Generating realistic historical execution telemetry for newly seeded playbooks...")
                cur.execute("SELECT id, name, trigger_event FROM playbooks")
                all_pbs = cur.fetchall()
                now = datetime.now(timezone.utc)
                source_ips = [
                    "185.220.101.5", "45.33.32.156", "198.51.100.99", "103.208.220.12",
                    "192.168.1.105", "10.240.10.4", "172.16.0.45", "192.168.1.150"
                ]

                seeded_execs = 0
                for day_offset in range(45):
                    day_date = now - timedelta(days=day_offset)
                    # Pick 2-4 playbooks to have executed on this day
                    daily_picks = random.sample(all_pbs, k=random.randint(2, 4))
                    for pb_row in daily_picks:
                        exec_time = day_date.replace(hour=random.randint(0, 23), minute=random.randint(0, 59))
                        target_ip = random.choice(source_ips)
                        cur.execute(
                            """
                            INSERT INTO playbook_executions (
                                playbook_id, playbook_name, status, target,
                                actions_taken, logs, triggered_by, executed_at
                            )
                            VALUES (%s, %s, 'SUCCESS', %s, %s, %s, 'AI_AUTONOMOUS_ENGINE', %s)
                            """,
                            (
                                pb_row["id"],
                                pb_row["name"],
                                target_ip,
                                Jsonb(["ISOLATE_HOST", "BLOCK_SOURCE_IP_24H", "WRITE_FORENSIC_AUDIT_LOG"]),
                                Jsonb([
                                    f"Trigger received: {pb_row['trigger_event']}",
                                    f"Enacted containment sequence on target {target_ip}",
                                    "Execution finalized with zero residual risk."
                                ]),
                                exec_time
                            )
                        )
                        seeded_execs += 1

                conn.commit()
                logger.info(f"✓ Generated {seeded_execs} historical playbook execution records across 45-day window.")

    finally:
        if should_close:
            conn.close()


if __name__ == "__main__":
    seed_55_playbooks()
