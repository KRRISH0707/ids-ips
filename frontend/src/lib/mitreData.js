/**
 * Comprehensive MITRE ATT&CK Enterprise Knowledge Base
 * Detailed descriptive profiles, attack mechanics, threat actor intelligence,
 * detection engineering signatures, and automated SOAR playbooks for each technique.
 */

export const MITRE_TECHNIQUES_KB = {
  'T1190': {
    id: 'T1190',
    name: 'Exploit Public-Facing Application',
    tactic: 'Initial Access',
    tacticId: 'TA0001',
    severity: 'CRITICAL',
    cvssBase: '9.8 / 10.0',
    shortDesc: 'Adversaries exploit software vulnerabilities in Internet-facing applications to execute arbitrary code or gain initial unauthorized network access.',
    overview: `Exploitation of public-facing applications represents one of the most prevalent and damaging initial access vectors in enterprise cybersecurity. Threat actors scan external corporate perimeters for web servers, API endpoints, VPN gateways, and remote management interfaces harboring unpatched Common Vulnerabilities and Exposures (CVEs) or zero-day vulnerabilities.
    
Upon identifying a vulnerable service, adversaries transmit carefully weaponized request payloads—such as serialized Java objects, malformed HTTP headers, or SQL manipulation strings—to bypass input sanitization and execute malicious commands in the context of the host web server. Successful execution typically yields an interactive web shell or reverse shell, enabling lateral movement and payload deployment without requiring stolen user credentials.`,
    attackMechanism: [
      {
        phase: '1. Reconnaissance & Target Discovery',
        detail: 'Adversaries utilize mass network scanners (Shodan, Censys, Project Discovery Nuclei) to identify exposed service versions, banners, and unpatched web technologies.'
      },
      {
        phase: '2. Vulnerability Probing & Fuzzing',
        detail: 'Ingress traffic analyzes HTTP endpoints with automated fuzzers, seeking SQL injection flaws, deserialization entrypoints, or path traversal opportunities.'
      },
      {
        phase: '3. Weaponized Ingress Exploitation',
        detail: 'Exploit payload (e.g. JNDI lookup string, SQL injection stack, or buffer overflow binary) is transmitted directly over standard HTTP/HTTPS ports 80/443.'
      },
      {
        phase: '4. Arbitrary Code Execution (RCE)',
        detail: 'Target server runtime executes injected instructions under daemon privileges (e.g. www-data, SYSTEM, or container root), bypassing network perimeter controls.'
      },
      {
        phase: '5. Reverse Shell & C2 Persistence',
        detail: 'Spawned process opens an outbound egress beacon to adversary Command & Control server or writes an obfuscated web shell to disk.'
      }
    ],
    adversaryGroups: [
      { name: 'APT29 (Cozy Bear)', origin: 'State-Sponsored', notes: 'Known for exploiting exposed VPN gateways and Microsoft Exchange ProxyShell vulnerabilities.' },
      { name: 'Lazarus Group', origin: 'State-Sponsored', notes: 'Frequently exploits Log4Shell (CVE-2021-44228) and public Confluence instances for initial network ingress.' },
      { name: 'FIN7', origin: 'Cybercriminal Syndicate', notes: 'Weaponizes public web applications and SQL injection for e-skimming and credit card data exfiltration.' },
      { name: 'LockBit Affiliates', origin: 'Ransomware-as-a-Service', notes: 'Leverages edge SSL VPN flaws (Fortinet, Pulse Secure) to deploy enterprise-wide ransomware.' },
      { name: 'Volt Typhoon', origin: 'State-Sponsored', notes: 'Focuses on critical infrastructure edge appliances using zero-day SOHO router exploits.' }
    ],
    platforms: ['Linux (Ubuntu/RHEL)', 'Windows Server (IIS)', 'Cloud Infrastructure (AWS/GCP/Azure)', 'Docker / Kubernetes Clusters', 'F5 BIG-IP / Citrix ADC'],
    protocols: ['HTTP / HTTPS (Ports 80, 443, 8080, 8443)', 'TLS / SSL', 'REST / GraphQL APIs', 'SOAP / XML-RPC'],
    cveExamples: [
      'CVE-2021-44228 (Apache Log4j2 JNDI Injection / Log4Shell - CVSS 10.0)',
      'CVE-2021-34473 (Microsoft Exchange Remote Code Execution / ProxyShell - CVSS 9.8)',
      'CVE-2022-22965 (Spring Framework RCE / Spring4Shell - CVSS 9.8)',
      'CVE-2023-34362 (MOVEit Transfer SQL Injection to RCE - CVSS 9.8)',
      'CVE-2024-1709 (ConnectWise ScreenConnect Authentication Bypass - CVSS 10.0)'
    ],
    detectionLogic: {
      dpiAnalysis: 'Neural deep packet inspection inspects HTTP headers, POST bodies, and URI parameters for known injection sequences, malicious regex patterns, and shellcode markers.',
      suricataRule: `alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"APEX-IDS: T1190 Web Exploit Ingress Pattern - Remote Command Injection Attempt"; flow:established,to_server; content:"POST"; http_method; content:"cmd="; http_uri; pcre:"/(=|\\%3d)(sh|bash|powershell|cmd\\.exe|certutil|curl|wget)/Ui"; classtype:web-application-attack; sid:2009481; rev:3;)`,
      sigmaRule: `title: Public-Facing Application RCE Process Spawn
status: production
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        ParentImage|endswith:
            - '/nginx'
            - '/apache2'
            - '/httpd'
            - '/w3wp.exe'
        Image|endswith:
            - '/bin/sh'
            - '/bin/bash'
            - 'cmd.exe'
            - 'powershell.exe'
    condition: selection
level: critical`,
      ebpfHook: 'eBPF kprobe on sys_enter_execve checks parent process cgroup and socket binding. If a network worker forks a shell, the socket is dropped and process terminated in 0.34s.'
    },
    mitreMitigations: [
      { id: 'M1041', name: 'Application Isolation and Sandboxing', desc: 'Isolate external applications inside unprivileged containers or isolated DMZ network segments.' },
      { id: 'M1050', name: 'Exploit Protection', desc: 'Enforce DEP, ASLR, and stack canaries on host operating systems to impede memory corruption exploits.' },
      { id: 'M1042', name: 'Disable or Remove Feature or Program', desc: 'Disable unnecessary HTTP methods (PUT, DELETE, TRACE) and remove unused modules, debug endpoints, and admin consoles.' },
      { id: 'M1026', name: 'Privileged Account Management', desc: 'Ensure web service processes execute with least-privilege daemon service accounts (e.g. www-data), preventing root takeover.' },
      { id: 'M1030', name: 'Network Segmentation', desc: 'Segment DMZ systems from internal Active Directory and production databases using stateful firewall inspection rules.' }
    ],
    recommendedPlaybook: {
      id: 'PB-07',
      name: 'PB-07: Remote Code Execution & Web Exploit Lockdown',
      trigger: 'RCE_EXPLOIT',
      severity: 'CRITICAL',
      actions: ['TERMINATE_WEB_WORKER_PROCESS', 'BLOCK_SOURCE_IP_24H', 'INVALIDATE_SESSION_COOKIES', 'CAPTURE_FORENSIC_PCAP_STREAM'],
      description: 'Terminates hijacked worker threads, enforces 24-hour firewall drop on attacking botnet IP, flushes active session tokens, and dumps forensic packet streams.'
    },
    socRemediationSteps: [
      'Verify whether the exploit payload resulted in arbitrary process execution or reverse shell connection.',
      'Check host process tree under the web daemon (w3wp.exe, nginx, apache2) for unauthorized child processes (cmd.exe, powershell, /bin/sh).',
      'Inspect web server access logs for anomalous HTTP status codes (200/500) following encoded traversal or command sequences.',
      'Execute SOAR Playbook PB-07 to sever active ingress sessions and drop attacker source IP across edge firewalls.',
      'Quarantine the targeted server and capture volatile RAM memory artifacts before applying hotfix/patch.'
    ]
  },

  'T1059': {
    id: 'T1059',
    name: 'Command and Scripting Interpreter',
    tactic: 'Execution',
    tacticId: 'TA0002',
    severity: 'HIGH',
    cvssBase: '8.8 / 10.0',
    shortDesc: 'Adversaries abuse command line interfaces, PowerShell, Bash, Python, or VBScript interpreters to execute arbitrary malicious code.',
    overview: `Command and scripting interpreters are native system utilities built into modern operating systems to automate administration tasks. Because tools like PowerShell, Windows Command Shell (cmd.exe), Bash, Unix shell (/bin/sh), and Python are universally trusted by system defenders, adversaries heavily rely on them to execute arbitrary scripts, download second-stage payloads, and manipulate system configuration ("Living off the Land" / LotL techniques).
    
By executing commands in-memory (e.g. via PowerShell -ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -EncodedCommand), attackers avoid dropping traditional binary files onto disk, thereby bypassing legacy antivirus signature scanners.`,
    attackMechanism: [
      { phase: '1. Ingress Trigger', detail: 'Interpreter invoked via malicious email macro, weaponized shortcut (.lnk), or web shell execution.' },
      { phase: '2. Obfuscation & Flag Bypasses', detail: 'Command executed with Base64 encoding, environment variable string concats, or AMSI bypass scripts.' },
      { phase: '3. In-Memory Execution', detail: 'Script executes entirely in memory without writing an executable payload binary to physical disk.' },
      { phase: '4. Discovery & Staging', detail: 'Interpreter executes built-in system enumeration commands (whoami, net user, ifconfig, route print).' }
    ],
    adversaryGroups: [
      { name: 'Wizard Spider', origin: 'Cybercriminal Syndicate', notes: 'Extensive use of PowerShell and cmd.exe for TrickBot and Conti deployment.' },
      { name: 'APT28 (Fancy Bear)', origin: 'State-Sponsored', notes: 'Executes obfuscated Bash scripts and PowerShell downloaders in targeted intelligence operations.' },
      { name: 'Sandworm Team', origin: 'State-Sponsored', notes: 'Known for weaponizing Unix shell commands against industrial control systems and utility grids.' }
    ],
    platforms: ['Windows (PowerShell, Cmd)', 'Linux (Bash, Zsh, Sh)', 'macOS (Zsh, AppleScript)', 'Containerized Microservices'],
    protocols: ['Local Process Inter-Process Communication', 'WinRM', 'SSH (Port 22)', 'WMI / DCOM'],
    cveExamples: [
      'CVE-2022-30190 (Microsoft Windows Support Diagnostic Tool Follina RCE via PowerShell)',
      'CVE-2021-40444 (Microsoft MSHTML Remote Code Execution invoking Command Interpreters)',
      'CVE-2023-36884 (Office and Windows HTML RCE Vulnerability)'
    ],
    detectionLogic: {
      dpiAnalysis: 'Network DPI monitors HTTP/DNS egress stemming from spawned shell processes, flagging outbound connections originating from bash or cmd.exe.',
      suricataRule: `alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"APEX-IDS: T1059 Suspicious PowerShell Outbound WebClient Stream"; flow:established,to_server; content:"Net.WebClient"; nocase; content:"DownloadString"; nocase; classtype:trojan-activity; sid:2009512; rev:1;)`,
      sigmaRule: `title: Suspicious PowerShell Encoded Command Execution
status: production
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\powershell.exe'
        CommandLine|contains:
            - ' -enc '
            - ' -EncodedCommand '
            - ' -w hidden '
            - 'DownloadString('
    condition: selection
level: high`,
      ebpfHook: 'eBPF monitors all sys_enter_execve calls where image matches /bin/sh or /bin/bash, logging command arguments, parent process PID, and EUID.'
    },
    mitreMitigations: [
      { id: 'M1038', name: 'Execution Prevention', desc: 'Use AppLocker or Software Restriction Policies to block script interpreters for standard users.' },
      { id: 'M1047', name: 'Audit', desc: 'Enable PowerShell Script Block Logging (Event ID 4104) and Transcription Logging across all endpoints.' },
      { id: 'M1026', name: 'Privileged Account Management', desc: 'Enforce Just-In-Time (JIT) administrative privilege elevation to limit interpreter scope.' }
    ],
    recommendedPlaybook: {
      id: 'PB-05',
      name: 'PB-05: High Anomaly Behavioral Isolation',
      trigger: 'HIGH_ANOMALY',
      severity: 'CRITICAL',
      actions: ['ISOLATE_HOST', 'START_PROMISCUOUS_PCAP_CAPTURE', 'ESCALATE_TO_TIER2_ANALYST'],
      description: 'Isolates internal machine displaying acute script execution anomalies and starts promiscuous packet forensics.'
    },
    socRemediationSteps: [
      'Review decoded PowerShell script blocks in Event ID 4104 logs to identify the exact payload executed.',
      'Check parent process to determine how the interpreter was initiated (e.g. WINWORD.EXE, Outlook, or web daemon).',
      'Identify any outbound network connections initiated by the interpreter process.',
      'Terminate suspicious process trees and revoke compromised user session tokens.'
    ]
  },

  'T1486': {
    id: 'T1486',
    name: 'Data Encrypted for Impact (Ransomware)',
    tactic: 'Impact',
    tacticId: 'TA0040',
    severity: 'CRITICAL',
    cvssBase: '9.9 / 10.0',
    shortDesc: 'Adversaries encrypt data on target systems to interrupt availability, lock critical systems, and extort ransom payments.',
    overview: `Data Encrypted for Impact is the defining execution technique of modern enterprise ransomware campaigns. Once adversaries achieve elevated privileges and identify high-value operational databases, file shares, and virtual machine disks (VMDKs), they deploy multi-threaded encryption routines utilizing military-grade symmetric encryption (such as ChaCha20 or AES-256) combined with asymmetric public-key cryptography (RSA-4096).
    
To maximize irreversible damage and prevent victim recovery, ransomware payloads routinely delete Volume Shadow Copies (vssadmin delete shadows /all /quiet), disable Windows Recovery services (bcdedit /set {default} recoveryenabled No), and terminate local endpoint security agents before initiating high-speed cryptographic file transformation.`,
    attackMechanism: [
      { phase: '1. Defense Neutralization', detail: 'Terminates security processes, disables hypervisor services, and executes vssadmin shadow storage deletion.' },
      { phase: '2. Encryption Key Generation', detail: 'Generates local symmetric AES session keys, encrypted on-the-fly with the attacker hardcoded RSA public key.' },
      { phase: '3. Rapid File Traversal', detail: 'Multi-threaded disk sweep scans all fixed, removable, and mapped network drives, identifying target document extensions.' },
      { phase: '4. Cryptographic Transformation', detail: 'Files are read, encrypted, and overwritten in-place, appending a custom ransomware extension (e.g. .lockbit, .blackcat).' },
      { phase: '5. Ransom Note Drop', detail: 'Ransom notes (README.txt, RESTORE_FILES.html) dropped in every directory; desktop wallpaper replaced with extortion instructions.' }
    ],
    adversaryGroups: [
      { name: 'LockBit Gang', origin: 'Cybercriminal Syndicate', notes: 'Fastest known enterprise ransomware payload; leverages multi-threading and eBPF avoidance.' },
      { name: 'BlackCat / ALPHV', origin: 'Cybercriminal Syndicate', notes: 'Rust-based modular ransomware targeting both Windows Active Directory and Linux ESXi servers.' },
      { name: 'Lazarus Group', origin: 'State-Sponsored', notes: 'Deploys wiper and ransomware hybrid variants (WannaCry, Hermes) in geopolitical extortion operations.' }
    ],
    platforms: ['Windows (Workstations & Domain Controllers)', 'Linux (Ubuntu/RHEL/CentOS)', 'VMware ESXi Hypervisors', 'NAS & SAN Storage Arrays'],
    protocols: ['SMB (Port 445)', 'NFS (Port 2049)', 'Local Block Storage I/O', 'VSS RPC Interfaces'],
    cveExamples: [
      'CVE-2017-0144 (EternalBlue SMBv1 Exploit used by WannaCry)',
      'CVE-2023-27532 (Veeam Backup & Replication Vulnerability exploited by Ransomware)',
      'CVE-2024-21887 (Ivanti Connect Secure Zero-Day leading to Ransomware Deployment)'
    ],
    detectionLogic: {
      dpiAnalysis: 'Apex Sentinel DPI analyzes SMB frame frequency and packet entropy. Bursts of high-entropy write requests exceeding 50 IOPS trigger sub-second kernel isolation.',
      suricataRule: `alert smb $HOME_NET any -> $HOME_NET 445 (msg:"APEX-IDS: T1486 Ransomware Lateral SMB Spray - Rapid Write Burst"; flow:established,to_server; smb.named_pipe; content:"srvsvc"; classtype:trojan-activity; threshold:type both, track by_src, count 25, seconds 3; sid:2009601; rev:2;)`,
      sigmaRule: `title: Volume Shadow Copy Deletion via VSSAdmin
status: production
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - 'vssadmin'
            - 'delete'
            - 'shadows'
    condition: selection
level: critical`,
      ebpfHook: 'Kernel eBPF block-layer tracepoint monitors disk write entropy. File write entropy jumps above 7.8/8.0 trigger immediate process freeze and host network quarantine.'
    },
    mitreMitigations: [
      { id: 'M1053', name: 'Data Backup', desc: 'Maintain immutable, air-gapped, offline data backups that cannot be modified over network shares.' },
      { id: 'M1040', name: 'Network Segmentation', desc: 'Isolate mission-critical databases and virtualized hypervisors from general employee workstations.' },
      { id: 'M1022', name: 'Restrict File and Directory Permissions', desc: 'Enforce strict discretionary access control lists (DACLs) preventing unauthorized write access to backups.' }
    ],
    recommendedPlaybook: {
      id: 'PB-01',
      name: 'PB-01: Rapid Ransomware Containment',
      trigger: 'RANSOMWARE',
      severity: 'CRITICAL',
      actions: ['ISOLATE_HOST', 'LOCK_SHADOW_COPIES', 'BLOCK_LATERAL_SMB', 'DISPATCH_PAGERDUTY_ALERT'],
      description: 'Immediately cuts endpoint network access, locks read-only shadow snapshots, filters local SMB ports 445/139, and alerts SOC incident commanders.'
    },
    socRemediationSteps: [
      'Initiate emergency network containment immediately to prevent lateral SMB spread across subnet file shares.',
      'Execute SOAR Playbook PB-01 to lock volume shadow storage and filter port 445 traffic.',
      'Preserve memory dumps of active ransomware processes before shutting down machines to recover encryption keys from RAM.',
      'Check Domain Controller event logs for anomalous administrative logins or GPO policy pushes.',
      'Restore affected systems from verified immutable air-gapped backup snapshots.'
    ]
  },

  'T1071': {
    id: 'T1071',
    name: 'Application Layer Protocol (C2 Beaconing)',
    tactic: 'Command & Control',
    tacticId: 'TA0011',
    severity: 'CRITICAL',
    cvssBase: '9.3 / 10.0',
    shortDesc: 'Adversaries communicate using OSI application layer protocols (HTTP/S, DNS, WebSockets) to blend with legitimate network traffic and evade firewalls.',
    overview: `Command and Control (C2) communication is the backbone of remote adversary operations. Once an implant compromises an internal asset, it must establish a reliable communication channel back to the threat actor infrastructure to receive instructions, exfiltrate stolen data, and orchestrate secondary intrusion phases.
    
Adversaries mimic standard enterprise web protocols—such as HTTPS traffic over port 443, DNS queries, or cloud WebSockets—to disguise malicious telemetry amidst millions of routine corporate web sessions. Modern frameworks like Cobalt Strike, Sliver, and Havoc employ malleable C2 profiles that emulate legitimate HTTP headers (User-Agents, Referrers, Cookie formats) and inject random jitter delays to thwart traditional threshold-based network alarms.`,
    attackMechanism: [
      { phase: '1. Egress Discovery', detail: 'Malware probes outbound network paths to determine whether edge firewalls permit direct egress or require corporate proxy traversal.' },
      { phase: '2. Session Handshake', detail: 'Initial cryptographic handshake authenticates the implant with the C2 controller, establishing an encrypted tunnel.' },
      { phase: '3. Jittered Beaconing', detail: 'Implant enters an idle loop, checking in at randomized intervals (e.g. every 60s ± 25% jitter) to request pending tasks.' },
      { phase: '4. Task Ingestion & Execution', detail: 'Commands (e.g. process injection, token theft, shell execution) received inside encrypted HTTP response bodies and executed in-memory.' },
      { phase: '5. Response Exfiltration', detail: 'Task output encrypted and transmitted upstream via HTTP POST requests disguised as image uploads or telemetry pings.' }
    ],
    adversaryGroups: [
      { name: 'APT28 / Fancy Bear', origin: 'State-Sponsored', notes: 'Utilizes custom C2 frameworks and modular backdoors communicating over TLS-encrypted HTTPS.' },
      { name: 'Cobalt Strike Operators', origin: 'Global Threat Landscape', notes: 'Employs malleable C2 profiles masquerading as Amazon, Microsoft, or Cloudflare web traffic.' },
      { name: 'FIN7 Syndicate', origin: 'Cybercrime Syndicate', notes: 'Routes C2 channels through commercial cloud services (Google Drive, Dropbox, AWS S3) to bypass IP reputation blocklists.' }
    ],
    platforms: ['Windows', 'Linux Servers', 'macOS Workstations', 'Cloud Workloads & Serverless'],
    protocols: ['HTTPS (Port 443)', 'HTTP (Port 80)', 'DNS (Port 53)', 'WebSocket (WSS)', 'DoH (DNS-over-HTTPS)'],
    cveExamples: [
      'T1071 / Cobalt Strike Beacon Protocol',
      'CVE-2023-38831 (WinRAR Vulnerability dropping C2 Beacon implants)',
      'CVE-2022-41082 (ProxyNotShell weaponized for C2 backdoors)'
    ],
    detectionLogic: {
      dpiAnalysis: 'Apex Sentinel calculates beacon periodicity and TLS JA3/JA3S fingerprint signatures. Regular check-ins matching Cobalt Strike malleable headers trigger immediate alert.',
      suricataRule: `alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"APEX-IDS: T1071 Cobalt Strike Default Malleable Beacon URI"; flow:established,to_server; http.uri; content:"/jquery-3.3.1.min.js"; nocase; http.cookie; content:"__cfduid="; classtype:trojan-activity; sid:2009714; rev:4;)`,
      sigmaRule: `title: Suspicious Periodic C2 Beaconing Pattern
status: production
logsource:
    category: network_connection
    product: zeek
detection:
    selection:
        dst_port: [80, 443]
        connection_count_gt: 100
    condition: selection
level: high`,
      ebpfHook: 'eBPF kretprobe on sys_connect correlates outbound socket destination IPs against live Threat Intelligence IOC feeds and TOR exit nodes.'
    },
    mitreMitigations: [
      { id: 'M1031', name: 'Network Intrusion Prevention', desc: 'Deploy deep packet inspection firewalls capable of TLS inspection and protocol anomaly detection.' },
      { id: 'M1037', name: 'Filter Network Traffic', desc: 'Enforce outbound egress filtering, permitting connections only to vetted enterprise proxies and domains.' },
      { id: 'M1021', name: 'Restrict Web-Based Content', desc: 'Utilize enterprise DNS filtering to block newly registered domains (NRDs) and dynamic DNS providers.' }
    ],
    recommendedPlaybook: {
      id: 'PB-02',
      name: 'PB-02: Cobalt Strike & C2 Neutralization',
      trigger: 'C2_BEACON',
      severity: 'CRITICAL',
      actions: ['FIREWALL_DROP_EGRESS', 'ISOLATE_COMPROMISED_HOST', 'DUMP_PROCESS_MEMORY_ARTIFACTS', 'SOC_HIGH_PRIORITY_INCIDENT'],
      description: 'Drops outbound firewall egress routes, quarantines the beaconing endpoint, dumps volatile process memory artifacts, and pages tier-3 SOC responders.'
    },
    socRemediationSteps: [
      'Identify the host PID responsible for the outbound beaconing connection using netstat or eBPF socket maps.',
      'Execute Playbook PB-02 to immediately sever the external communication socket and prevent lateral commands.',
      'Block the target external IP, domain, and ASN across edge firewall boundary gateways.',
      'Acquire memory dump of the offending process to extract C2 configuration, fallback servers, and encryption keys.',
      'Scan internal systems for identical JA3 fingerprints or beacon check-in patterns.'
    ]
  },

  'T1110': {
    id: 'T1110',
    name: 'Brute Force & Credential Stuffing',
    tactic: 'Credential Access',
    tacticId: 'TA0006',
    severity: 'HIGH',
    cvssBase: '8.4 / 10.0',
    shortDesc: 'Adversaries systematically attempt multiple passwords or use leaked credential dumps to gain unauthorized access to accounts.',
    overview: `Brute force attacks involve automated attempts to discover valid username and password combinations across exposed authentication endpoints. Variants include traditional dictionary attacks, password spraying (testing a single common password against thousands of enterprise user accounts to avoid account lockout policies), and credential stuffing (replaying usernames and passwords leaked from third-party breach dumps).
    
Publicly accessible authentication portals—including SSH, RDP, VPN gateways, web login forms, and Microsoft 365 OWA portals—are relentlessly subjected to distributed botnet brute force campaigns, providing adversaries with legitimate access credentials without triggering traditional malware alarms.`,
    attackMechanism: [
      { phase: '1. Target Account Enumeration', detail: 'Adversaries harvest corporate email addresses via LinkedIn, breach archives, and O365 user enumeration tools.' },
      { phase: '2. Distributed Proxy Setup', detail: 'Attacks routed through residential proxy networks or infected Mirai botnet nodes to bypass IP rate limits.' },
      { phase: '3. Low-and-Slow Password Spraying', detail: 'Tests 1-2 common passwords (e.g. Winter2024!, Password123) across all users once every 4 hours to evade lockouts.' },
      { phase: '4. Authentication Success', detail: 'Upon validating credentials, attacker registers a secondary MFA token or creates an OAuth application grant.' }
    ],
    adversaryGroups: [
      { name: 'Midnight Blizzard (APT29)', origin: 'State-Sponsored', notes: 'Famous for massive password spraying campaigns against corporate Microsoft tenants.' },
      { name: 'FIN7', origin: 'Cybercriminal Syndicate', notes: 'Utilizes credential stuffing to compromise administrative VPN portals and cloud SaaS applications.' },
      { name: 'Anonymous Botnet Operators', origin: 'Opportunistic', notes: 'Automated Hydra/Medusa scripts sweeping internet IP blocks on SSH port 22 and RDP port 3389.' }
    ],
    platforms: ['Windows (Active Directory & RDP)', 'Linux (SSH, PAM, Sudo)', 'Cloud Portals (Azure AD, AWS IAM, Okta)', 'VPN Gateways (Cisco, Fortinet)'],
    protocols: ['SSH (Port 22)', 'RDP (Port 3389)', 'Kerberos (Port 88)', 'LDAP (Port 389/636)', 'HTTPS OAuth / SAML'],
    cveExamples: [
      'T1110.001 / Password Guessing',
      'T1110.003 / Password Spraying',
      'T1110.004 / Credential Stuffing'
    ],
    detectionLogic: {
      dpiAnalysis: 'Apex Sentinel monitors authentication failure rates per IP and per username. Threshold violations (e.g. >5 failed logins in 60 seconds) trigger instant IP bans.',
      suricataRule: `alert tcp $EXTERNAL_NET any -> $HOME_NET 22 (msg:"APEX-IDS: T1110 SSH Brute Force Ingress Rate Exceeded"; flow:to_server; flags:S; threshold:type both, track by_src, count 8, seconds 60; classtype:attempted-admin; sid:2009801; rev:1;)`,
      sigmaRule: `title: High Volume Authentication Failure from Single Source
status: production
logsource:
    category: authentication
    product: linux
detection:
    selection:
        action: 'failed'
    condition: selection | count() by src_ip > 10
    timeframe: 1m
level: high`,
      ebpfHook: 'Kernel eBPF filter captures PAM authentication return codes; repeated pam_authenticate failures trigger automatic eBPF XDP discard on offending socket.'
    },
    mitreMitigations: [
      { id: 'M1032', name: 'Multi-Factor Authentication', desc: 'Enforce hardware FIDO2 or biometric MFA across all external and internal authentication surfaces.' },
      { id: 'M1036', name: 'Account Use Policies', desc: 'Enforce smart lockout policies that lock out source IP addresses rather than disabling user accounts.' },
      { id: 'M1027', name: 'Password Policies', desc: 'Prevent usage of commonly compromised passwords listed in NIST and HaveIBeenPwned databases.' }
    ],
    recommendedPlaybook: {
      id: 'PB-03',
      name: 'PB-03: Credential Stuffing & SSH Brute Force Mitigation',
      trigger: 'BRUTE_FORCE',
      severity: 'HIGH',
      actions: ['BLOCK_SOURCE_IP_24H', 'FORCE_USER_SESSION_TERMINATION', 'ENABLE_MFA_STEPUP', 'WRITE_FORENSIC_AUDIT_LOG'],
      description: 'Enforces an immediate 24-hour edge firewall block on attacking IP, terminates active user sessions, and requires MFA step-up authentication.'
    },
    socRemediationSteps: [
      'Identify the targeted usernames and verify whether any authentication attempts succeeded.',
      'If an account was successfully compromised, immediately reset the user password and invalidate all active session tokens.',
      'Check whether the attacker attempted to register an unauthorized authenticator device or modify forwarding rules.',
      'Execute Playbook PB-03 to ban the source IP and enforce step-up MFA verification.'
    ]
  },

  'T1498': {
    id: 'T1498',
    name: 'Network Denial of Service (SYN / UDP Flood)',
    tactic: 'Impact',
    tacticId: 'TA0040',
    severity: 'CRITICAL',
    cvssBase: '9.4 / 10.0',
    shortDesc: 'Adversaries flood network interfaces with volumetric traffic to exhaust bandwidth and crash critical edge services.',
    overview: `Network Denial of Service (DoS) attacks seek to degrade or completely extinguish the availability of enterprise networks, applications, and cloud infrastructures. Adversaries leverage compromised IoT botnets (such as Mirai) or distributed reflection/amplification vectors (utilizing open DNS resolvers, NTP servers, or memcached instances) to generate multi-gigabit or multi-terabit volumetric traffic floods.
    
Common techniques include TCP SYN Floods (which exhaust the target operating system TCP connection state table and backlog queues with half-open handshakes), UDP Reflection Floods, and ICMP fragmentation saturation, rendering internal and external services completely unreachable for legitimate users.`,
    attackMechanism: [
      { phase: '1. Botnet Coordination', detail: 'Central C2 server commands thousands of weaponized IoT nodes or reflection servers to target victim enterprise IP.' },
      { phase: '2. Packet Spoofing & Reflection', detail: 'Attacker injects spoofed UDP requests toward amplification reflectors, multiplying payload size up to 500x.' },
      { phase: '3. Bandwidth & Socket Saturation', detail: 'Volumetric packet stream saturates ISP edge uplink bandwidth and fills operating system TCP SYN backlog queues.' },
      { phase: '4. Service Denial & Latency Collapse', detail: 'Legitimate user connection handshakes timeout; edge routers and firewall state tables crash under packet load.' }
    ],
    adversaryGroups: [
      { name: 'Mirai Fleet Operators', origin: 'Global Botnet Landscape', notes: 'Weaponizes hundreds of thousands of compromised routers and IP cameras for massive volumetric floods.' },
      { name: 'Killnet / Hacktivist Collectives', origin: 'Politically Motivated', notes: 'Launches targeted DDoS campaigns against banking, healthcare, and government digital infrastructure.' },
      { name: 'DDoS-for-Hire / Booter Services', origin: 'Underground Markets', notes: 'Rents automated stressor capabilities to criminal actors for ransom extortion.' }
    ],
    platforms: ['Enterprise Edge Routers', 'Firewalls & Load Balancers', 'Web Application Gateways', 'DNS Infrastructure'],
    protocols: ['TCP SYN (Port 80/443)', 'UDP (DNS Port 53, NTP Port 123)', 'ICMP Echo', 'BGP Routing'],
    cveExamples: [
      'T1498.001 / Direct Network Flood',
      'T1498.002 / Reflection & Amplification Flood',
      'CVE-2023-44487 (HTTP/2 Rapid Reset DDoS Vulnerability)'
    ],
    detectionLogic: {
      dpiAnalysis: 'Apex Sentinel tracking detects packets-per-second (PPS) spikes and incomplete TCP three-way handshakes exceeding safe system thresholds.',
      suricataRule: `alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"APEX-IDS: T1498 Volumetric TCP SYN Flood Detected"; flags:S; threshold:type both, track by_dst, count 500, seconds 1; classtype:denial-of-service; sid:2009911; rev:2;)`,
      sigmaRule: `title: Inbound Bandwidth and SYN Packet Surge
status: production
logsource:
    category: firewall
    product: pf
detection:
    selection:
        tcp_flags: 'SYN'
    condition: selection | count() > 1000
    timeframe: 5s
level: critical`,
      ebpfHook: 'eBPF XDP driver level filter drops invalid SYN flood packets at the network interface card (NIC) before operating system kernel memory allocation.'
    },
    mitreMitigations: [
      { id: 'M1037', name: 'Filter Network Traffic', desc: 'Implement upstream BGP Flowspec rate limiting and cloud DDoS scrubbing centers (Cloudflare, Akamai).' },
      { id: 'M1050', name: 'Exploit Protection', desc: 'Enable kernel TCP SYN cookies (sysctl -w net.ipv4.tcp_syncookies=1) to prevent half-open state table exhaustion.' },
      { id: 'M1030', name: 'Network Segmentation', desc: 'Separate mission-critical operational networks from public-facing customer service interfaces.' }
    ],
    recommendedPlaybook: {
      id: 'PB-06',
      name: 'PB-06: Distributed Denial-of-Service (DDoS) Volumetric Shield',
      trigger: 'SYN_FLOOD',
      severity: 'CRITICAL',
      actions: ['ACTIVATE_BGP_FLOWSPEC_SCRUBBING', 'DYNAMIC_IPTABLES_DROP', 'RATE_LIMIT_SYN_COOKIES', 'BROADCAST_INCIDENT_WAR_ROOM'],
      description: 'Activates upstream BGP Flowspec filtering, enforces dynamic iptables drop rules, enables kernel SYN cookies, and broadcasts an incident war room.'
    },
    socRemediationSteps: [
      'Engage upstream ISP transit provider to activate BGP Flowspec route scrubbing.',
      'Execute Playbook PB-06 to enable kernel-level SYN cookie protection and rate-limiting.',
      'Verify whether edge firewall CPU and RAM utilization have returned to normal operating thresholds.',
      'Inspect traffic flow logs to identify attacker IP clusters and geographic origins.'
    ]
  },

  'T1558': {
    id: 'T1558',
    name: 'Steal or Forge Kerberos Tickets (Kerberoasting)',
    tactic: 'Credential Access',
    tacticId: 'TA0006',
    severity: 'CRITICAL',
    cvssBase: '9.4 / 10.0',
    shortDesc: 'Adversaries abuse Active Directory Kerberos Service Principal Names (SPNs) to request service tickets and crack plaintext passwords offline.',
    overview: `Kerberoasting is a potent Active Directory post-exploitation technique where any authenticated domain user—regardless of privilege level—can request Kerberos Ticket-Granting Service (TGS) tickets for service accounts registered with Service Principal Names (SPNs).
    
Because these tickets are encrypted using the NTLM hash of the target service account password, adversaries export the ticket payloads from memory and perform high-speed offline dictionary or brute-force cracking on dedicated GPU clusters (using Hashcat or John the Ripper). Because the ticket request appears as legitimate Active Directory protocol behavior, traditional security tools frequently overlook the intrusion until Domain Admin accounts are compromised.`,
    attackMechanism: [
      { phase: '1. Domain Account Enumeration', detail: 'Queries Active Directory via LDAP filters for accounts with non-null ServicePrincipalName (SPN) attributes.' },
      { phase: '2. TGS-REQ Request', detail: 'Sends standard Kerberos TGS-REQ packet to Domain Controller (KDC) requesting ticket for service account SPN.' },
      { phase: '3. TGS-REP Ticket Extraction', detail: 'KDC returns TGS ticket encrypted with service account password hash. Attacker extracts ticket using Mimikatz or Rubeus.' },
      { phase: '4. Offline Hashcat Cracking', detail: 'Exports ticket in Kerberos 5 TGS-REP etype 23 format ($krb5tgs$23$...) and cracks plaintext password offline.' }
    ],
    adversaryGroups: [
      { name: 'Wizard Spider', origin: 'Cybercriminal Syndicate', notes: 'Routinely executes Kerberoasting to acquire Domain Admin rights prior to ransomware deployment.' },
      { name: 'FIN6', origin: 'Cybercrime Syndicate', notes: 'Known for harvesting POS and payment service account tickets in retail corporate environments.' },
      { name: 'APT29', origin: 'State-Sponsored', notes: 'Employs Kerberoasting and Golden Ticket attacks to establish long-term enterprise persistence.' }
    ],
    platforms: ['Windows Active Directory Domain Services', 'Azure AD Domain Services', 'Hybrid Identity Environments'],
    protocols: ['Kerberos (Port 88)', 'LDAP (Port 389/636)', 'RPC / SMB (Port 445)'],
    cveExamples: [
      'T1558.003 / Kerberoasting',
      'T1558.001 / Golden Ticket',
      'T1558.002 / Silver Ticket'
    ],
    detectionLogic: {
      dpiAnalysis: 'Apex Sentinel inspects Kerberos TGS requests on port 88. Unusually high volume of RC4 (encryption type 0x17) ticket requests from single hosts flags Kerberoasting.',
      suricataRule: `alert tcp any any -> $DC_SERVERS 88 (msg:"APEX-IDS: T1558 Kerberos TGS Request Burst (Kerberoasting)"; flow:established,to_server; content:"|05 0e|"; depth:2; threshold:type both, track by_src, count 10, seconds 30; classtype:attempted-admin; sid:2009855; rev:2;)`,
      sigmaRule: `title: Active Directory Kerberoasting Activity
status: production
logsource:
    category: kerberos
    product: windows
detection:
    selection:
        EventID: 4769
        TicketOptions: '0x40810000'
        TicketEncryptionType: '0x17'
    condition: selection | count() by WorkstationName > 5
    timeframe: 2m
level: critical`,
      ebpfHook: 'Kernel eBPF monitor inspects LSASS memory access events; alerts on unauthorized processes reading credentials or tickets from lsass.exe.'
    },
    mitreMitigations: [
      { id: 'M1027', name: 'Password Policies', desc: 'Enforce minimum 25-character complex passwords for all service accounts with registered SPNs.' },
      { id: 'M1026', name: 'Privileged Account Management', desc: 'Migrate legacy service accounts to Group Managed Service Accounts (gMSA) with automatic 128-bit key rotation.' },
      { id: 'M1047', name: 'Audit', desc: 'Monitor Windows Event ID 4769 for RC4 ticket requests targeting privileged domain accounts.' }
    ],
    recommendedPlaybook: {
      id: 'PB-08',
      name: 'PB-08: Active Directory Domain Controller Breach Containment',
      trigger: 'KERBEROASTING',
      severity: 'CRITICAL',
      actions: ['SUSPEND_COMPROMISED_AD_ACCOUNT', 'SEVER_SMB_RPC_TUNNELS', 'TRIGGER_KRBTGT_PASSWORD_RESET', 'DISPATCH_SOC_URGENT_PAGE'],
      description: 'Locks compromised AD accounts, severs active RPC/SMB sessions, queues emergency KRBTGT password rotation, and alerts identity defenders.'
    },
    socRemediationSteps: [
      'Identify the user account and endpoint IP from which the TGS-REQ burst originated.',
      'Check which specific service accounts were requested (Event ID 4769).',
      'Immediately change the passwords of requested service accounts to random 30+ character strings.',
      'Execute SOAR Playbook PB-08 to suspend compromised accounts and sever active RPC connections.',
      'Evaluate migrating target service accounts to Active Directory Group Managed Service Accounts (gMSA).'
    ]
  },

  'T1048': {
    id: 'T1048',
    name: 'Exfiltration Over Alternative Protocol (DNS Tunneling)',
    tactic: 'Exfiltration',
    tacticId: 'TA0010',
    severity: 'HIGH',
    cvssBase: '8.7 / 10.0',
    shortDesc: 'Adversaries steal sensitive data by encoding it inside covert protocols such as DNS queries to bypass network boundary firewalls.',
    overview: `DNS Tunneling is a covert communication and data exfiltration technique that exploits the universal availability of the Domain Name System. In modern corporate environments, outbound HTTP/HTTPS traffic is heavily inspected by proxy servers and next-generation firewalls. However, UDP port 53 (DNS) is routinely permitted to flow unrestricted to external or recursive resolvers.
    
Adversaries register an attacker-controlled authoritative nameserver (e.g. evil-c2.com). The compromised endpoint chunks sensitive enterprise data (such as proprietary source code or database dumps), encodes it into Base32 or Base64 subdomains (e.g. data123.evil-c2.com), and dispatches standard DNS lookup queries. Recursive internet resolvers forward these subdomains directly to the adversary nameserver, successfully exfiltrating data without establishing a direct TCP socket connection.`,
    attackMechanism: [
      { phase: '1. Data Chunking & Base32 Encoding', detail: 'Malware reads target files, compresses them, and encodes data chunks into RFC-compliant DNS subdomain labels.' },
      { phase: '2. Recursive Query Dispatch', detail: 'Client sends recursive DNS queries (A, AAAA, or TXT record lookups) to internal corporate DNS server.' },
      { phase: '3. Upstream Root Resolution', detail: 'Internal DNS resolver forwards query through internet hierarchy until reaching attacker authoritative nameserver.' },
      { phase: '4. Server Reassembly', detail: 'Attacker nameserver decodes subdomain labels from incoming queries and reconstructs the exfiltrated file.' }
    ],
    adversaryGroups: [
      { name: 'OILRIG / APT34', origin: 'State-Sponsored', notes: 'Pioneered custom DNS tunneling tools (DNSProwler, ALMA Communication) in espionage campaigns.' },
      { name: 'FIN7', origin: 'Cybercriminal Syndicate', notes: 'Uses DNS tunneling as a stealthy fallback channel for C2 beaconing and telemetry extraction.' },
      { name: 'Lazarus Group', origin: 'State-Sponsored', notes: 'Utilizes DNS tunneling for exfiltration during restricted air-gapped financial breaches.' }
    ],
    platforms: ['Linux Servers', 'Windows Workstations', 'Containerized Applications', 'Network Appliances'],
    protocols: ['DNS (UDP & TCP Port 53)', 'DoH (DNS over HTTPS Port 443)', 'DoT (DNS over TLS Port 853)'],
    cveExamples: [
      'T1048.003 / Exfiltration Over DNS',
      'CVE-2020-1350 (SIGRed Windows DNS Server Vulnerability)',
      'CVE-2021-25216 (BIND9 DNS Forwarding Vulnerability)'
    ],
    detectionLogic: {
      dpiAnalysis: 'Apex Sentinel calculates Shannon entropy and label length of DNS query strings. High-entropy subdomains (>4.2) and high query frequencies flag DNS tunneling.',
      suricataRule: `alert dns $HOME_NET any -> any 53 (msg:"APEX-IDS: T1048 Covert DNS Tunneling High Entropy Subdomain"; dns.query; pcre:"/^[a-z0-9]{32,}\\.[a-z0-9-]+\\.[a-z]{2,}$/i"; threshold:type both, track by_src, count 15, seconds 10; classtype:bad-unknown; sid:2009948; rev:3;)`,
      sigmaRule: `title: High Frequency Long DNS Query Stream
status: production
logsource:
    category: dns
    product: zeek
detection:
    selection:
        query_length_gt: 55
    condition: selection | count() by src_ip > 50
    timeframe: 2m
level: high`,
      ebpfHook: 'eBPF kprobe on udp_sendmsg extracts DNS payload lengths and flags outbound queries to unapproved external nameservers.'
    },
    mitreMitigations: [
      { id: 'M1037', name: 'Filter Network Traffic', desc: 'Block direct outbound UDP/TCP port 53 traffic from endpoints, forcing all queries through vetted internal resolvers.' },
      { id: 'M1031', name: 'Network Intrusion Prevention', desc: 'Deploy Protective DNS (PDNS) and DNS firewalls to sinkhole newly registered or known tunneling domains.' },
      { id: 'M1040', name: 'Network Segmentation', desc: 'Segregate internal production networks and prevent unauthorized egress to external public resolvers.' }
    ],
    recommendedPlaybook: {
      id: 'PB-09',
      name: 'PB-09: Covert DNS Tunneling & Data Exfiltration Interception',
      trigger: 'DNS_TUNNELING',
      severity: 'HIGH',
      actions: ['SINKHOLE_MALICIOUS_NAMESERVER', 'INJECT_TCP_RESET_STREAM', 'ISOLATE_EXFILTRATING_HOST', 'DUMP_ENDPOINT_NETWORK_SOCKETS'],
      description: 'Injects DNS sinkhole pointers (0.0.0.0), severs active sockets, quarantines the host, and extracts active endpoint socket mappings.'
    },
    socRemediationSteps: [
      'Examine the destination DNS query domains and calculate subdomain string entropy.',
      'Execute Playbook PB-09 to sinkhole the malicious nameserver and isolate the infected host.',
      'Check internal DNS server logs to determine how many endpoints are querying the adversary domain.',
      'Review endpoint disk activity to determine what proprietary files were accessed prior to exfiltration.'
    ]
  },

  'T1611': {
    id: 'T1611',
    name: 'Escape to Host (Container Breakout)',
    tactic: 'Privilege Escalation',
    tacticId: 'TA0004',
    severity: 'CRITICAL',
    cvssBase: '9.8 / 10.0',
    shortDesc: 'Adversaries break out of isolated container environments (Docker, Kubernetes) to gain root execution on the underlying physical host node.',
    overview: `Containerization technologies provide logical process isolation by leveraging Linux kernel namespaces (PID, Mount, Network, IPC) and control groups (cgroups). However, if containers are misconfigured—such as running with the --privileged flag, mounting the host Docker socket (/var/run/docker.sock), or utilizing vulnerable Linux kernels—adversaries can break out of container boundaries.
    
Once outside the container sandbox, the attacker gains direct root access to the underlying Kubernetes worker node, granting access to all neighboring pods, container storage volumes, host credentials, and cloud instance metadata services (IMDS).`,
    attackMechanism: [
      { phase: '1. Container Compromise', detail: 'Attacker gains initial foothold in container via vulnerable web application or supply-chain package.' },
      { phase: '2. Environment Discovery', detail: 'Inspects /proc/1/cgroup, checks capabilities (capsh --print), and searches for mounted Docker sockets.' },
      { phase: '3. Privileged Breakout Exploit', detail: 'Abuses CAP_SYS_ADMIN, cgroup release_agent, or kernel vulnerability (e.g. Dirty COW) to execute on host.' },
      { phase: '4. Host Root Takeover', detail: 'Attacker establishes root shell on the underlying host node, gaining access to host filesystem and cloud IAM tokens.' }
    ],
    adversaryGroups: [
      { name: 'TeamTNT', origin: 'Cryptomining Cybercriminal Group', notes: 'Pioneered automated Docker socket sweeping and AWS cloud credential harvesting via container escapes.' },
      { name: 'Kinsing Gang', origin: 'Cryptomining Cybercriminal Group', notes: 'Specializes in Kubernetes RBAC misconfigurations, Redis container breakouts, and cloud API abuse.' }
    ],
    platforms: ['Kubernetes Clusters', 'Docker Engine', 'Containerd / CRI-O', 'AWS EKS / Azure AKS / GCP GKE'],
    protocols: ['Kubernetes API (Port 6443)', 'Docker Daemon Socket (Unix / TCP 2375)', 'Kubelet (Port 10250)'],
    cveExamples: [
      'CVE-2019-5736 (runc Container Breakout Vulnerability)',
      'CVE-2022-0185 (Linux Kernel Heap Overflow leading to Container Escape)',
      'CVE-2024-21626 (runc Leaked File Descriptor Container Breakout - CVSS 8.6)'
    ],
    detectionLogic: {
      dpiAnalysis: 'Apex Sentinel monitors internal Kubernetes east-west traffic for unauthorized calls to the Kubelet API or cloud metadata service (169.254.169.254).',
      suricataRule: `alert http any any -> 169.254.169.254 any (msg:"APEX-IDS: T1611 Unauthorized Container IMDS Metadata Harvesting"; flow:to_server; content:"/latest/meta-data/"; classtype:attempted-admin; sid:2009961; rev:2;)`,
      sigmaRule: `title: Docker Socket Mounted or Accessed by Pod
status: production
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        CommandLine|contains: '/var/run/docker.sock'
    condition: selection
level: critical`,
      ebpfHook: 'eBPF monitors all openat calls on the host node; alerts immediately if a container namespace PID accesses host-level /etc/shadow or /root files.'
    },
    mitreMitigations: [
      { id: 'M1042', name: 'Disable or Remove Feature or Program', desc: 'Disallow running containers with --privileged mode or root user execution.' },
      { id: 'M1050', name: 'Exploit Protection', desc: 'Deploy AppArmor and SELinux profiles to strictly limit syscall capabilities granted to containers.' },
      { id: 'M1026', name: 'Privileged Account Management', desc: 'Block access to the cloud Instance Metadata Service (IMDSv2) using network security policies.' }
    ],
    recommendedPlaybook: {
      id: 'PB-10',
      name: 'PB-10: Cloud Container Escape & Supply Chain Tamper Quarantine',
      trigger: 'CONTAINER_ESCAPE',
      severity: 'CRITICAL',
      actions: ['FREEZE_CONTAINER_RUNTIME_CGROUP', 'REVOKE_CLOUD_IAM_ROLE_TOKENS', 'TERMINATE_KUBERNETES_POD', 'NOTIFY_DEVSECOPS_LEAD'],
      description: 'Enforces kernel cgroup freeze, revokes cloud IAM STS tokens, evicts compromised Kubernetes pods, and alerts DevSecOps engineers.'
    },
    socRemediationSteps: [
      'Immediately isolate the compromised host worker node to prevent cluster-wide lateral movement.',
      'Execute Playbook PB-10 to terminate the offending container and freeze runtime cgroups.',
      'Revoke all cloud provider temporary IAM credentials associated with the node instance profile.',
      'Inspect container build manifests and Dockerfiles for insecure volume mounts or privileged capability flags.'
    ]
  },

  'T1595': {
    id: 'T1595',
    name: 'Active Scanning',
    tactic: 'Reconnaissance',
    tacticId: 'TA0043',
    severity: 'MEDIUM',
    cvssBase: '5.3 / 10.0',
    shortDesc: 'Adversaries execute port scans, vulnerability sweeps, and network probes to identify exploitable edge targets.',
    overview: `Active Scanning is the primary exploratory technique deployed by adversaries to probe public IP spaces and internal subnets. Utilizing tools such as Nmap, Masscan, and ZMap, threat actors transmit probe packets (SYN scans, UDP sweeps, ICMP echoes) to discover active hosts, open listening ports, operating system fingerprints, and running daemon versions.
    
While reconnaissance does not directly damage target systems, high-velocity active scanning invariably precedes targeted exploitation and ransomware delivery. Detecting and neutralizing reconnaissance early disrupts the adversary kill chain before weapons are deployed.`,
    attackMechanism: [
      { phase: '1. Port Sweeping', detail: 'Rapid transmission of TCP SYN packets across thousands of destination ports to detect listening services.' },
      { phase: '2. Banner Grabbing', detail: 'Connects to open ports to inspect daemon headers, service banners, and software versions (e.g. Apache/2.4.49).' },
      { phase: '3. Vulnerability Correlation', detail: 'Matches discovered service versions against known CVE vulnerability databases to select exploit tools.' }
    ],
    adversaryGroups: [
      { name: 'Shadowserver / Masscan Sweepers', origin: 'Automated Global Sweepers', notes: 'Continuous internet-wide port scans identifying vulnerable exposed infrastructure.' },
      { name: 'APT41', origin: 'State-Sponsored', notes: 'Conducts systematic reconnaissance sweeps targeting healthcare and telecommunications networks.' }
    ],
    platforms: ['All Network Infrastructure', 'Firewalls', 'DMZ Web Servers', 'VPN Gateways'],
    protocols: ['TCP SYN', 'UDP', 'ICMP', 'SCTP'],
    cveExamples: ['T1595.001 / Port Scanning', 'T1595.002 / Vulnerability Scanning'],
    detectionLogic: {
      dpiAnalysis: 'Apex Sentinel tracks connection attempt diversity per source IP. More than 15 unique port connection attempts in 10 seconds flags active reconnaissance.',
      suricataRule: `alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"APEX-IDS: T1595 Nmap SYN Stealth Reconnaissance Scan"; flags:S; threshold:type both, track by_src, count 20, seconds 5; classtype:attempted-recon; sid:2009595; rev:1;)`,
      sigmaRule: `title: Multi-Port Scan from Single External Source
status: production
logsource:
    category: firewall
    product: iptables
detection:
    selection:
        action: 'DROP'
    condition: selection | count() by src_ip > 30
    timeframe: 10s
level: medium`,
      ebpfHook: 'eBPF TCP state tracker detects rapid SYN-without-ACK sweeps; automatically drops scanner packets in eBPF XDP layer.'
    },
    mitreMitigations: [
      { id: 'M1056', name: 'Pre-compromise', desc: 'Minimize public footprint by closing unused ports and placing administrative interfaces behind zero-trust VPNs.' },
      { id: 'M1037', name: 'Filter Network Traffic', desc: 'Deploy dynamic tarpit and blackhole firewall rules to drop scanning botnets.' }
    ],
    recommendedPlaybook: {
      id: 'PB-04',
      name: 'PB-04: Automated Network Reconnaissance Countermeasure',
      trigger: 'PORT_SCAN',
      severity: 'HIGH',
      actions: ['TARPIT_ATTACKER_TCP', 'DYNAMIC_IPTABLES_DROP', 'NOTIFY_NETWORK_ADMIN'],
      description: 'Redirects attacker packets into a TCP tarpit honey-queue and drops traffic at edge firewall gateways.'
    },
    socRemediationSteps: [
      'Verify whether the scanning source IP is associated with commercial security research (e.g. Censys) or threat botnets.',
      'Execute Playbook PB-04 to immediately blackhole the scanner IP across edge firewalls.',
      'Audit the scanned ports on destination servers to ensure no unnecessary administrative services are publicly exposed.'
    ]
  }
};

/**
 * Helper to retrieve a descriptive technique profile with dynamic fallback
 */
export function getTechniqueDetails(techniqueId) {
  const tid = (techniqueId || '').toUpperCase().trim();
  if (MITRE_TECHNIQUES_KB[tid]) {
    return MITRE_TECHNIQUES_KB[tid];
  }

  // Fallback profile for unlisted technique IDs
  return {
    id: tid,
    name: `Technique ${tid}`,
    tactic: 'Enterprise Defense',
    tacticId: 'TA0001',
    severity: 'HIGH',
    cvssBase: '8.5 / 10.0',
    shortDesc: `Adversary operations mapped under MITRE ATT&CK enterprise technique ${tid}.`,
    overview: `This technique represents adversary operational procedures monitored by the Apex Sentinel Autonomous IDS/IPS neural detection engine. Telemetry streams, DPI heuristic rules, and eBPF kernel hooks continuously correlate incoming packet headers and process behaviors against this technique pattern to intercept unauthorized adversarial activity.`,
    attackMechanism: [
      { phase: '1. Adversary Ingress / Trigger', detail: `Adversary initiates actions aligned with ${tid} through network requests or process manipulation.` },
      { phase: '2. Execution & Exploitation', detail: 'Payload exploits system or application behavior to establish an unauthorized foothold.' },
      { phase: '3. Detection & Containment', detail: 'Apex Sentinel eBPF neural sensors detect anomalous telemetry and trigger automated SOAR containment.' }
    ],
    adversaryGroups: [
      { name: 'Advanced Persistent Threats (APTs)', origin: 'Nation-State & Cybercrime', notes: `Observed leveraging technique ${tid} in enterprise intrusion campaigns.` }
    ],
    platforms: ['Linux (Ubuntu/RHEL)', 'Windows Server', 'Cloud Workloads', 'Kubernetes'],
    protocols: ['TCP/IP', 'HTTP/HTTPS', 'DNS', 'Kernel Syscalls'],
    cveExamples: [`MITRE ATT&CK Standard Mapping: ${tid}`],
    detectionLogic: {
      dpiAnalysis: `Apex Sentinel monitors network packet frames and host syscalls, correlating behavioral indicators against ${tid}.`,
      suricataRule: `alert ip any any -> any any (msg:"APEX-IDS: ${tid} Heuristic Threat Signature"; classtype:bad-unknown; sid:2990001; rev:1;)`,
      sigmaRule: `title: Correlation Rule for ${tid}\nstatus: production\nlevel: high`,
      ebpfHook: `eBPF kernel probe tracing syscall telemetry matching pattern ${tid}.`
    },
    mitreMitigations: [
      { id: 'M1040', name: 'Network Segmentation', desc: 'Isolate sensitive network segments to prevent adversary propagation.' },
      { id: 'M1026', name: 'Privileged Account Management', desc: 'Enforce principle of least privilege across all user and service accounts.' }
    ],
    recommendedPlaybook: {
      id: 'PB-05',
      name: 'PB-05: High Anomaly Behavioral Isolation',
      trigger: 'HIGH_ANOMALY',
      severity: 'CRITICAL',
      actions: ['ISOLATE_HOST', 'START_PROMISCUOUS_PCAP_CAPTURE', 'ESCALATE_TO_TIER2_ANALYST'],
      description: 'Quarantines target host displaying acute behavioral deviations and captures promiscuous PCAP forensics.'
    },
    socRemediationSteps: [
      `Review live alert telemetry associated with technique ${tid}.`,
      'Identify target endpoints and assess whether any unauthorized processes executed.',
      'Execute recommended SOAR containment playbook to quarantine affected hosts and drop source IPs.'
    ]
  };
}
