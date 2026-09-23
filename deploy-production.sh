#!/usr/bin/env bash
# ==============================================================================
# ENTERPRISE IDS/IPS PRODUCTION 1-CLICK SERVER DEPLOYMENT SCRIPT
# Supported OS: Ubuntu 20.04/22.04/24.04, Debian 11/12, RHEL/Rocky/Alma 8/9
# ==============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m' # No Color

echo -e "${CYAN}${BOLD}"
cat << "EOF"
  ___ ____  ____       ___ ____  ____  
 |_ _|  _ \/ ___|     |_ _|  _ \/ ___| 
  | || | | \___ \ _____| || |_) \___ \ 
  | || |_| |___) |_____| ||  __/ ___) |
 |___|____/|____/     |___|_|   |____/  
  ENTERPRISE COMMERCIAL PRODUCTION DEPLOYER
EOF
echo -e "${NC}"

# Check for root
if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}[ERROR] This script must be run as root or with sudo.${NC}"
    exit 1
fi

# Detect Server Public IP & Primary Interface
PUBLIC_IP=$(curl -s https://api.ipify.org || curl -s https://ifconfig.me || echo "SERVER_IP")
PRIMARY_IFACE=$(ip route show default 2>/dev/null | awk '{print $5}' | head -n1 || echo "eth0")
PRIMARY_IFACE=${PRIMARY_IFACE:-eth0}
echo -e "${CYAN}Detected Public Server IP:${NC} ${BOLD}${PUBLIC_IP}${NC}"
echo -e "${CYAN}Detected Primary Network Interface:${NC} ${BOLD}${PRIMARY_IFACE}${NC}"

# Gather Configuration
DOMAIN="${1:-}"
ADMIN_EMAIL="${2:-}"

# Zero-Domain Fallback: If user has no company portal/domain yet, map public IP to sslip.io for free Let's Encrypt SSL
DEFAULT_DOMAIN="${PUBLIC_IP}.sslip.io"

if [ -z "$DOMAIN" ]; then
    echo -e "${YELLOW}>> No domain? Press Enter to auto-generate a free SSL domain (${DEFAULT_DOMAIN}):${NC}"
    read -rp "Enter your company domain [${DEFAULT_DOMAIN}]: " INPUT_DOMAIN
    DOMAIN=${INPUT_DOMAIN:-$DEFAULT_DOMAIN}
fi

if [ -z "$ADMIN_EMAIL" ]; then
    read -rp "Enter admin notification email [krrish183224@gmail.com]: " ADMIN_EMAIL
    ADMIN_EMAIL=${ADMIN_EMAIL:-krrish183224@gmail.com}
fi

read -rsp "Enter platform admin password [Default: 183@Krrish]: " ADMIN_PASSWORD
echo ""
ADMIN_PASSWORD=${ADMIN_PASSWORD:-183@Krrish}

read -rp "Enter Cloudflare Tunnel Token (optional, press Enter if using direct IP/Domain): " CLOUDFLARE_TUNNEL_TOKEN
CLOUDFLARE_TUNNEL_TOKEN=${CLOUDFLARE_TUNNEL_TOKEN:-}

echo -e "\n${GREEN}>> Deploying for Commercial Host:${NC} ${BOLD}https://${DOMAIN}${NC}"
echo -e "${GREEN}>> Administrator Email:${NC}           ${BOLD}${ADMIN_EMAIL}${NC}"
if [ -n "$CLOUDFLARE_TUNNEL_TOKEN" ]; then
    echo -e "${GREEN}>> Cloudflare Zero-Trust Tunnel:${NC}  ${BOLD}ACTIVE (Zero open inbound ports)${NC}\n"
else
    echo -e "${YELLOW}>> Cloudflare Tunnel:${NC}             ${BOLD}NONE (Direct ingress via ports 80/443)${NC}\n"
fi

# Step 1: Install Docker & Docker Compose if missing
echo -e "${CYAN}[1/6] Installing Prerequisites & Optimizing Memory...${NC}"

# Auto-configure 4GB Swap if system RAM < 4GB (e.g. AWS EC2 t2.micro Free Tier)
TOTAL_RAM_MB=$(free -m | awk '/^Mem:/{print $2}')
if [ "$TOTAL_RAM_MB" -lt 4000 ] && [ "$(swapon --show | wc -l)" -le 1 ]; then
    echo -e "${YELLOW}>> AWS Free Tier / Low RAM detected (${TOTAL_RAM_MB}MB). Creating 4GB Swap Space...${NC}"
    fallocate -l 4G /swapfile || dd if=/dev/zero of=/swapfile bs=1M count=4096
    chmod 600 /swapfile
    mkswap /swapfile
    swapon /swapfile
    if ! grep -q '/swapfile' /etc/fstab; then
        echo '/swapfile none swap sw 0 0' >> /etc/fstab
    fi
    echo -e "${GREEN}>> 4GB Swap active! Virtual memory successfully expanded.${NC}"
fi

if ! command -v docker &> /dev/null; then
    echo "Installing Docker Engine..."
    curl -fsSL https://get.docker.com | sh
    systemctl enable --now docker
else
    echo "Docker is already installed."
fi

if ! docker compose version &> /dev/null; then
    echo "Installing Docker Compose Plugin..."
    apt-get update -y && apt-get install -y docker-compose-plugin || yum install -y docker-compose-plugin
fi

# Step 2: Configure UFW Firewall
echo -e "${CYAN}[2/6] Hardening Firewall (UFW)...${NC}"
if command -v ufw &> /dev/null; then
    ufw allow 22/tcp comment 'SSH' || true
    ufw allow 80/tcp comment 'HTTP ACME' || true
    ufw allow 443/tcp comment 'HTTPS SOC Portal' || true
    ufw --force enable || true
    echo "Firewall active. Only ports 22, 80, 443 permitted."
fi

# Step 3: Generate Strong Cryptographic Secrets (preserve existing if present)
echo -e "${CYAN}[3/6] Generating Cryptographic Keys & Secrets...${NC}"
EXISTING_POSTGRES_PASSWORD=""
EXISTING_REDIS_PASSWORD=""
EXISTING_JWT_SECRET=""
EXISTING_GRAFANA_PASSWORD=""
EXISTING_ALLOWLIST=""

if [ -f .env.production ]; then
    EXISTING_POSTGRES_PASSWORD=$(grep -E '^POSTGRES_PASSWORD=' .env.production | cut -d= -f2- || true)
    EXISTING_REDIS_PASSWORD=$(grep -E '^REDIS_PASSWORD=' .env.production | cut -d= -f2- || true)
    EXISTING_JWT_SECRET=$(grep -E '^JWT_SECRET=' .env.production | cut -d= -f2- || true)
    EXISTING_GRAFANA_PASSWORD=$(grep -E '^GRAFANA_ADMIN_PASSWORD=' .env.production | cut -d= -f2- || true)
    EXISTING_ALLOWLIST=$(grep -E '^IPS_MANAGEMENT_ALLOWLIST=' .env.production | cut -d= -f2- || true)
fi

JWT_SECRET=${EXISTING_JWT_SECRET:-$(openssl rand -hex 32)}
POSTGRES_PASSWORD=${EXISTING_POSTGRES_PASSWORD:-$(openssl rand -hex 16)}
REDIS_PASSWORD=${EXISTING_REDIS_PASSWORD:-$(openssl rand -hex 16)}
GRAFANA_PASSWORD=${EXISTING_GRAFANA_PASSWORD:-$(openssl rand -hex 16)}
IPS_MANAGEMENT_ALLOWLIST=${IPS_MANAGEMENT_ALLOWLIST:-${EXISTING_ALLOWLIST:-}}

# Generate .env.production file
cat > .env.production << EOF
DOMAIN=${DOMAIN}
ADMIN_EMAIL=${ADMIN_EMAIL}
ADMIN_PASSWORD=${ADMIN_PASSWORD}
JWT_SECRET=${JWT_SECRET}
POSTGRES_USER=idsips
POSTGRES_DB=idsips
POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
REDIS_PASSWORD=${REDIS_PASSWORD}
GRAFANA_ADMIN_PASSWORD=${GRAFANA_PASSWORD}
IPS_SIMULATION_MODE=false
CORS_ORIGINS=https://${DOMAIN}
# Optional comma-separated fixed operator IPs/CIDRs permitted to recover from
# an application-level IPS false positive.
IPS_MANAGEMENT_ALLOWLIST=${IPS_MANAGEMENT_ALLOWLIST:-}
CLOUDFLARE_TUNNEL_TOKEN=${CLOUDFLARE_TUNNEL_TOKEN}
OPENSEARCH_INITIAL_ADMIN_PASSWORD=${OPENSEARCH_INITIAL_ADMIN_PASSWORD:-Apex@Sentinel1!}
SURICATA_INTERFACE=${PRIMARY_IFACE}
EOF

chmod 600 .env.production
cp .env.production .env
chmod 600 .env
echo "Created secured .env.production and .env."

# Step 4: Configure Nginx & Self-Signed Bootstrap SSL
echo -e "${CYAN}[4/6] Bootstrapping Nginx SSL Reverse Proxy...${NC}"
mkdir -p nginx/ssl

# Step 5: Start Production Containers
echo -e "${CYAN}[5/6] Building & Launching Production Services...${NC}"
docker compose --env-file .env.production -f docker-compose.prod.yml down --remove-orphans || true
docker compose --env-file .env.production -f docker-compose.prod.yml up -d --build

# Optional: Certbot SSL request if domain is valid FQDN
if [[ "$DOMAIN" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
    echo -e "${YELLOW}>> Requesting Let's Encrypt TLS Certificate for ${DOMAIN}...${NC}"
    sleep 5
    docker compose --env-file .env.production -f docker-compose.prod.yml run --rm certbot certonly --webroot \
        --webroot-path=/var/www/certbot \
        --cert-name default \
        --email "$ADMIN_EMAIL" \
        --agree-tos \
        --no-eff-email \
        -d "$DOMAIN" || echo -e "${YELLOW}[NOTE] Let's Encrypt request skipped/deferred. Self-signed certificate active.${NC}"

    # Ensure Nginx uses the real domain certificate and reloads
    docker compose --env-file .env.production -f docker-compose.prod.yml exec nginx sh -c "
        if [ -f /etc/letsencrypt/live/$DOMAIN/fullchain.pem ]; then
            rm -rf /etc/letsencrypt/live/default
            ln -sf /etc/letsencrypt/live/$DOMAIN /etc/letsencrypt/live/default
        fi
        nginx -s reload
    " || true
fi

# Step 6: Install systemd auto-restart service
echo -e "${CYAN}[6/6] Installing Systemd Auto-Start Service...${NC}"
CURRENT_DIR=$(pwd)
cat > /etc/systemd/system/ids-ips.service << EOF
[Unit]
Description=Enterprise IDS/IPS Platform Production Stack
After=docker.service network-online.target
Requires=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=${CURRENT_DIR}
ExecStart=/usr/bin/docker compose --env-file .env.production -f docker-compose.prod.yml up -d
ExecStop=/usr/bin/docker compose --env-file .env.production -f docker-compose.prod.yml down

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable ids-ips.service
echo "Systemd service 'ids-ips.service' enabled (auto-starts on boot)."

# Output Summary
echo -e "\n${GREEN}${BOLD}=================================================================${NC}"
echo -e "${GREEN}${BOLD}  ENTERPRISE IDS/IPS PRODUCTION DEPLOYMENT SUCCESSFUL!           ${NC}"
echo -e "${GREEN}${BOLD}=================================================================${NC}"
echo -e "Access your commercial platform:"
echo -e "  🌐 ${BOLD}Company Portal & Showcase:${NC} https://${DOMAIN}/landing"
echo -e "  🛡️ ${BOLD}SOC Security Console:${NC}     https://${DOMAIN}/login"
echo -e "  📡 ${BOLD}REST API Swagger Docs:${NC}    https://${DOMAIN}/api/docs"
echo -e "  📊 ${BOLD}Grafana SOC Telemetry:${NC}    https://${DOMAIN}/grafana"
echo -e ""
echo -e "Authentication Credentials:"
echo -e "  👤 ${BOLD}Admin Email:${NC}               ${ADMIN_EMAIL}"
echo -e "  🔑 ${BOLD}Admin Password:${NC}            ${ADMIN_PASSWORD}"
echo -e "  📈 ${BOLD}Grafana Password:${NC}          ${GRAFANA_PASSWORD}"
echo -e ""
echo -e "System Management Commands:"
echo -e "  • Check Stack Status:   docker compose --env-file .env.production -f docker-compose.prod.yml ps"
echo -e "  • View Real-Time Logs:  docker compose --env-file .env.production -f docker-compose.prod.yml logs -f"
echo -e "  • Restart Service:      systemctl restart ids-ips"
echo -e "${GREEN}${BOLD}=================================================================${NC}\n"
