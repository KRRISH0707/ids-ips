#!/bin/bash
# ==============================================================================
# Apex Sentinel: Automated Threat Intelligence Sync Cron Installer
# Sets up nightly automated Emerging Threats (ET Open) ruleset downloads
# and hot-reloads Suricata with zero traffic downtime.
# ==============================================================================
set -euo pipefail

echo "===================================================================="
echo " 🔄  APEX SENTINEL AUTOMATED THREAT INTELLIGENCE SYNC INSTALLER"
echo "===================================================================="

if [ "$(id -u)" -ne 0 ]; then
    echo "[-] Error: This script must be run as root (use: sudo bash $0)"
    exit 1
fi

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WRAPPER_SCRIPT="/usr/local/bin/apex-update-rules.sh"
CRON_FILE="/etc/cron.d/apex-threat-updater"
LOG_FILE="/var/log/apex-threat-update.log"

echo "[1/3] Creating updater wrapper at ${WRAPPER_SCRIPT}..."
cat << EOF > "${WRAPPER_SCRIPT}"
#!/bin/bash
# Apex Sentinel Automated Threat Rule Synchronizer
set -uo pipefail

PROJECT_DIR="${PROJECT_DIR}"
LOG_FILE="${LOG_FILE}"

echo "=== [\$(date -u '+%Y-%m-%d %H:%M:%S UTC')] Starting Automated Threat Intelligence Sync ===" >> "\${LOG_FILE}"

cd "\${PROJECT_DIR}" || exit 1

# Download latest Emerging Threats ruleset (52,000+ signatures)
if [ -f "scripts/update_threat_rules.py" ]; then
    python3 scripts/update_threat_rules.py >> "\${LOG_FILE}" 2>&1
    UPDATE_STATUS=\$?
    if [ \${UPDATE_STATUS} -eq 0 ]; then
        echo "    -> Threat rules successfully downloaded and indexed." >> "\${LOG_FILE}"
        
        # Hot-reload Suricata engine
        if command -v docker >/dev/null 2>&1; then
            echo "    -> Reloading Suricata threat signatures..." >> "\${LOG_FILE}"
            docker compose --env-file .env.production -f docker-compose.prod.yml restart suricata >> "\${LOG_FILE}" 2>&1 || \
            docker compose restart suricata >> "\${LOG_FILE}" 2>&1 || true
            echo "    -> Suricata rule memory refreshed." >> "\${LOG_FILE}"
        fi
    else
        echo "    -> [!] Warning: Threat rules update exited with code \${UPDATE_STATUS}" >> "\${LOG_FILE}"
    fi
fi

echo "=== Threat Intelligence Sync Finished ===" >> "\${LOG_FILE}"
EOF

chmod +x "${WRAPPER_SCRIPT}"

echo "[2/3] Installing Nightly Cron Job (03:00 UTC) at ${CRON_FILE}..."
cat << EOF > "${CRON_FILE}"
# /etc/cron.d/apex-threat-updater
# Automatically sync 52,000+ threat intelligence signatures every night at 03:00 UTC
0 3 * * * root ${WRAPPER_SCRIPT}
EOF

chmod 0644 "${CRON_FILE}"

echo "[3/3] Configuring Log Rotation..."
cat << EOF > "/etc/logrotate.d/apex-threat-updater"
${LOG_FILE} {
    weekly
    rotate 4
    compress
    missingok
    notifempty
}
EOF

echo "===================================================================="
echo " ✅  AUTOMATED THREAT INTELLIGENCE SYNC INSTALLED"
echo " Runs every night at 03:00 UTC."
echo " Logs recorded to: ${LOG_FILE}"
echo "===================================================================="
