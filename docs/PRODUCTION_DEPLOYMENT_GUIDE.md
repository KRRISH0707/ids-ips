# Enterprise IDS/IPS — Cloud Production Deployment Guide

This guide walks through deploying the Enterprise IDS/IPS platform as a standalone commercial product for your company on **AWS EC2**, **DigitalOcean**, **Hetzner**, or **Google Cloud Platform (GCP)** with automated SSL (HTTPS), custom domain routing, and firewall protection.

---

## 🏗️ Production Sizing Recommendations

| Scale | Monitored Endpoints | Recommended Spec | Cloud Instance Type |
|---|---|---|---|
| **Standard Commercial** | Up to 250 Endpoints | 4 vCPUs, 8 GB RAM, 80 GB SSD | AWS `t3.xlarge`, DO Droplet (8GB/4vCPU), Hetzner `CPX31` |
| **High Throughput** | 250 - 2,500 Endpoints | 8 vCPUs, 16 GB RAM, 200 GB NVMe | AWS `c6i.2xlarge`, DO Droplet (16GB/8vCPU), Hetzner `CPX41` |

---

## ⚡ Step 1: Provision Cloud Virtual Machine

### Option A: AWS EC2
1. Launch an EC2 Instance with **Ubuntu Server 24.04 LTS (x86_64)**.
2. Select instance type: `t3.xlarge` (or `t3.large`).
3. Configure Security Group **Inbound Rules**:
   - `SSH` (Port 22) -> Your management IP (or `0.0.0.0/0`)
   - `HTTP` (Port 80) -> `0.0.0.0/0` (for ACME Let's Encrypt validation)
   - `HTTPS` (Port 443) -> `0.0.0.0/0` (public SOC access)
   *(All internal ports: PostgreSQL 5432, Redis 6379, Kafka 9092, OpenSearch 9200 remain completely closed and private).*
4. Attach an **Elastic IP** to your EC2 instance so the IP never changes.

### Option B: DigitalOcean / Hetzner / Linode
1. Create a Droplet/Cloud Server running **Ubuntu 24.04 LTS**.
2. Note the Public IPv4 address assigned to the server.

---

---

## 🌐 Step 2: Configure Host / Domain

### Option A: You DO NOT Have a Company Domain Yet (Instant Zero-Domain Launch)
You do **not** need to buy a domain or build a separate company website.
1. The platform includes a **Commercial Product Landing Page & Customer Showcase** built directly in at `/landing`.
2. When running the deployer, simply press `Enter` to use **`sslip.io`** (e.g. `54.210.12.34.sslip.io`).
   - `sslip.io` is a free DNS mapping service that resolves directly to your cloud server's public IP.
   - Let's Encrypt recognizes `*.sslip.io` as a valid FQDN and automatically issues a **free, 100% browser-trusted SSL certificate** with a green lock!
   - Zero cost, zero waiting for DNS propagation.

### Option B: You Have a Custom Company Domain (e.g., `soc.yourcompany.com`)
1. Go to your domain registrar or DNS management console (Cloudflare, AWS Route53, GoDaddy, Namecheap).
2. Add an **A Record**:
   - **Host / Name**: `soc` (or `@` for root domain)
   - **Type**: `A`
   - **Value / Target**: `<Your-Cloud-Server-Public-IP>`
   - **TTL**: Auto / 300s
3. Verify DNS propagation:
   ```bash
   ping soc.yourcompany.com
   ```

---

## 🚀 Step 3: Run the 1-Click Production Installer

1. SSH into your newly provisioned cloud server:
   ```bash
   ssh ubuntu@<YOUR-SERVER-PUBLIC-IP>
   ```

2. Clone your repository:
   ```bash
   git clone https://github.com/KRRISH0707/ids-ips.git /opt/ids-ips
   cd /opt/ids-ips
   ```

3. Make the production deployer executable and run it:
   ```bash
   chmod +x deploy-production.sh
   sudo ./deploy-production.sh
   ```

4. The installer will automatically:
   - Install Docker Engine, Docker Compose, Git, and UFW firewall.
   - Configure UFW firewall rules (only ports 22, 80, 443 permitted).
   - Prompt for your domain (e.g. `soc.yourcompany.com`) and admin email.
   - Generate cryptographically strong random secrets for PostgreSQL, Redis, and JWT authentication.
   - Provision free trusted SSL/TLS certificates via Let's Encrypt.
   - Register a `systemd` auto-start service (`ids-ips.service`) so the platform auto-boots on server reboot.

---

## 🔒 Step 4: Access Your Commercial Product

Once the script finishes:
- **Commercial Product Showcase & Portal**: `https://<YOUR-HOST>/landing` (Customer-facing showcase, pricing, lead generation, agent downloads)
- **SOC Executive Dashboard**: `https://<YOUR-HOST>`
- **SOC Security Console Login**: `https://<YOUR-HOST>/login`
- **Interactive Network Topology**: `https://<YOUR-HOST>/topology`
- **SOAR Incident Playbooks**: `https://<YOUR-HOST>/playbooks`
- **MITRE ATT&CK Matrix**: `https://<YOUR-HOST>/mitre`
- **Threat Intelligence Hub**: `https://<YOUR-HOST>/threat-intel`
- **REST API Swagger Documentation**: `https://<YOUR-HOST>/api/docs`
- **Grafana Deep Telemetry**: `https://<YOUR-HOST>/grafana`

Default Admin Credentials:
- **Email**: `krrish183224@gmail.com`
- **Password**: `183@Krrish`

---

## 🤖 Step 5: Continuous Deployment via GitHub Actions (CI/CD)

Whenever you push code updates to `main` on GitHub, your cloud production server can automatically update with zero downtime.

1. In your GitHub repository, navigate to **Settings -> Secrets and variables -> Actions**.
2. Add the following repository secrets:
   - `PRODUCTION_SERVER_HOST`: Your server's public IP or hostname (e.g., `54.210.12.34`)
   - `PRODUCTION_SERVER_USER`: `ubuntu` (or your SSH user)
   - `PRODUCTION_SSH_KEY`: Your private SSH key (`~/.ssh/id_rsa` or AWS `.pem` file content)
   - `PRODUCTION_SSH_PORT`: `22`
3. Any push to `main` will now trigger `.github/workflows/deploy.yml` and automatically pull, build, and deploy the update!

---

## 💾 Maintenance & Operational Commands

### Check Stack Status
```bash
docker compose --env-file .env.production -f docker-compose.prod.yml ps
```

### Stream Live Logs
```bash
docker compose --env-file .env.production -f docker-compose.prod.yml logs -f --tail 100
```

### Restart All Services
```bash
sudo systemctl restart ids-ips
```

### Automated Database Backup (Daily Cron)
To schedule automatic daily backups of PostgreSQL:
```bash
# Open crontab
sudo crontab -e

# Add daily backup at 2:00 AM
0 2 * * * docker exec idsips-postgres pg_dump -U idsips idsips | gzip > /opt/backups/idsips_backup_$(date +\%F).sql.gz
```
