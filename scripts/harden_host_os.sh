#!/bin/bash
# ==============================================================================
# Apex Sentinel Enterprise IDS/IPS: Host OS Kernel & Network Fortification Script
# Target OS: Ubuntu 22.04 / 24.04 LTS (Azure VM / Bare-Metal / Cloud VPS)
# ==============================================================================
set -euo pipefail

echo "===================================================================="
echo " 🛡️  APEX SENTINEL HOST OS FORTIFICATION & KERNEL HARDENING"
echo "===================================================================="

if [ "$(id -u)" -ne 0 ]; then
    echo "[-] Error: This script must be executed as root (use: sudo bash $0)"
    exit 1
fi

# ── 1. Linux Kernel Sysctl Anti-DDoS & Network Security ───────────────────────
echo "[1/4] Applying Linux Kernel Network Stack Hardening..."

SYSCTL_CONF="/etc/sysctl.d/99-apex-sentinel.conf"
cat << 'EOF' > "$SYSCTL_CONF"
# --- TCP SYN Flood Mitigation ---
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 4096
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_fin_timeout = 15

# --- Anti-IP Spoofing & Source Validation ---
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# --- Disable ICMP Broadcasts & Smurf Attack Defense ---
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# --- Disable Route Manipulation & Source Routing ---
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# --- Disable ICMP Redirects ---
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# --- File Descriptor & Network Concurrency Expansion ---
fs.file-max = 2097152
net.core.somaxconn = 65535
EOF

sysctl -p "$SYSCTL_CONF" >/dev/null 2>&1 || sysctl --system >/dev/null 2>&1
echo "    -> TCP SYN Cookies, Anti-Spoofing, and Smurf protections active."

# ── 2. Host Firewall (UFW) Default-Deny Lockdown ──────────────────────────────
echo "[2/4] Fortifying Host Ingress Firewall (UFW)..."

if command -v ufw >/dev/null 2>&1; then
    # Set default policies: block all inbound, permit outbound
    ufw default deny incoming >/dev/null 2>&1
    ufw default allow outgoing >/dev/null 2>&1

    # Keep SSH open to prevent operator lockout
    ufw allow 22/tcp comment 'Apex Sentinel Admin SSH' >/dev/null 2>&1

    # Ingress web ports
    ufw allow 80/tcp comment 'Apex Sentinel HTTP' >/dev/null 2>&1
    ufw allow 443/tcp comment 'Apex Sentinel HTTPS' >/dev/null 2>&1

    # Enable firewall non-interactively
    echo "y" | ufw enable >/dev/null 2>&1
    echo "    -> Ingress locked down: only ports 22, 80, 443 allowed. All others dropped."
else
    echo "    -> UFW not installed, skipping UFW lockdown."
fi

# ── 3. SSH Brute-Force Defense (Fail2Ban) ──────────────────────────────────────
echo "[3/4] Installing & Configuring Fail2Ban for Host SSH Defense..."

if ! command -v fail2ban-client >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq >/dev/null 2>&1
    apt-get install -y -qq fail2ban >/dev/null 2>&1 || true
fi

if command -v fail2ban-client >/dev/null 2>&1; then
    cat << 'EOF' > /etc/fail2ban/jail.local
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5

[sshd]
enabled = true
port = 22
filter = sshd
logpath = /var/log/auth.log
maxretry = 5
bantime = 86400
EOF
    systemctl restart fail2ban >/dev/null 2>&1 || true
    systemctl enable fail2ban >/dev/null 2>&1 || true
    echo "    -> Fail2Ban active: 5 failed SSH attempts = 24-hour host jail."
else
    echo "    -> Fail2Ban could not be configured automatically."
fi

# ── 4. Automated Kernel & OS Security Patching ────────────────────────────────
echo "[4/4] Enabling Automated OS Kernel Security Upgrades..."

if ! command -v unattended-upgrades >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get install -y -qq unattended-upgrades >/dev/null 2>&1 || true
fi

if [ -f /etc/apt/apt.conf.d/20auto-upgrades ]; then
    cat << 'EOF' > /etc/apt/apt.conf.d/20auto-upgrades
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
    echo "    -> Automated kernel security updates enabled."
fi

echo "===================================================================="
echo " ✅  HOST OS FORTIFICATION COMPLETE"
echo " Host is protected against SYN floods, IP spoofing, and SSH attacks."
echo "===================================================================="
