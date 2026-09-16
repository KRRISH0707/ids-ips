# Enterprise IDS/IPS — Cloudflare Zero Trust & Cloudflare Access Production Guide

This guide details how to deploy the Enterprise IDS/IPS platform for **true corporate production** using **Cloudflare Tunnel (`cloudflared`)** and **Cloudflare Access (Zero Trust)**.

---

## 🏛️ Enterprise Zero Trust Architecture

```
                    ┌────────────────────────────┐
                    │ Authorized Enterprise User │
                    │   (e.g. you@company.com)   │
                    └─────────────┬──────────────┘
                                  │
                    ┌─────────────▼──────────────┐
                    │   Unauthorized Attacker    │
                    │   or Public Port Scanner   │
                    └─────────────┬──────────────┘
                                  │
                                  ▼
                     https://soc.yourcompany.com
                                  │
                                  ▼
                    ┌────────────────────────────┐
                    │  Cloudflare Access (Edge)  │
                    │  "Enter Authorized Email"  │
                    │   One-Time PIN / SAML SSO  │
                    └─────────────┬──────────────┘
                                  │
                      ┌───────────┴───────────┐
                      │                       │
                Email Approved          Email Rejected
                      │                       │
                      ▼                       ▼
            ┌──────────────────┐       ┌──────────────┐
            │  Encrypted TLS   │       │ HTTP 403 /   │
            │  Cloudflare      │       │ BLOCKED AT   │
            │  Tunnel Outbound │       │ THE EDGE     │
            └─────────┬────────┘       └──────────────┘
                      │
                      ▼ (No Inbound Ports Opened!)
         ┌────────────────────────────┐
         │ Production Docker Host     │
         │                            │
         │  ┌──────────────────────┐  │
         │  │ idsips-cloudflared   │  │
         │  └──────────┬───────────┘  │
         │             │              │
         │             ▼              │
         │  ┌──────────────────────┐  │
         │  │ Hardened Nginx (:80) │  │
         │  └──────────┬───────────┘  │
         │             │              │
         │    Internal Bridge Network │
         │    (idsips-net: ISOLATED)  │
         │             │              │
         │   ├── Frontend (:3000)     │
         │   ├── Backend (:8000)      │
         │   ├── Detection Engine     │
         │   ├── PostgreSQL  ❌ (NO PUBLIC PORT)
         │   ├── Redis       ❌ (NO PUBLIC PORT)
         │   ├── Kafka       ❌ (NO PUBLIC PORT)
         │   └── OpenSearch  ❌ (NO PUBLIC PORT)
         └────────────────────────────┘
```

### 🔒 Why This is the Commercial Gold Standard
1. **Zero Open Inbound Ports**: You do **NOT** need to open ports 22, 80, or 443 on your router or cloud security group. The `cloudflared` container establishes an outbound encrypted TLS tunnel to Cloudflare's global edge network.
2. **Database & Broker Isolation**:
   - `5432 PostgreSQL` ❌ (100% private to `idsips-net`)
   - `6379 Redis` ❌ (100% private to `idsips-net`)
   - `9092 Kafka` ❌ (100% private to `idsips-net`)
   - `9200 OpenSearch` ❌ (100% private to `idsips-net`)
   - `8000 FastAPI` ❌ (100% private to `idsips-net`)
3. **Edge-Level Identity Verification (Cloudflare Access)**:
   - Attackers, automated bots, and Shodan scanners cannot even reach your Nginx server.
   - Anyone visiting `https://soc.yourcompany.com` must pass Cloudflare's email OTP or Google/Azure SSO verification before a single HTTP request reaches your server.

---

## ⚡ Step-by-Step Setup (10 Minutes)

### Step 1: Create a Free Cloudflare Account
1. Go to [dash.cloudflare.com](https://dash.cloudflare.com) and create an account.
2. If you have a domain (e.g. `yourcompany.com`), add it to Cloudflare (Free Plan).
   *(Even a $1-$2 `.xyz` or free domain from any registrar works).*

---

### Step 2: Create a Cloudflare Tunnel
1. In the Cloudflare Dashboard sidebar, navigate to **Zero Trust**.
2. Go to **Networks** > **Tunnels** > Click **"Add a tunnel"**.
3. Select **Cloudflared** as the connector type > Click **Next**.
4. Name your tunnel: `enterprise-ids-ips` > Click **Save tunnel**.
5. You will see an installation page with a command containing a long base64 token:
   ```bash
   cloudflared.exe service install eyJhIjoiY2...<LONG-TOKEN>...
   ```
6. **Copy ONLY that token string** (`eyJhIjoi...`). This is your `CLOUDFLARE_TUNNEL_TOKEN`.

---

### Step 3: Configure the Public Hostname Route
In the Cloudflare Tunnel setup screen under **Public Hostnames**:
1. Click **"Add a public hostname"**.
2. Configure:
   * **Subdomain**: `soc` (or whatever you prefer)
   * **Domain**: `yourcompany.com`
   * **Path**: Leave blank
   * **Type**: `HTTP`
   * **URL**: `nginx:80` *(because inside the Docker network, Nginx is named `nginx`!)*
3. Under **Additional application settings** > **HTTP Settings**:
   * Enable **HTTP2**
   * Enable **No TLS Verify** (since traffic between cloudflared and nginx is inside the internal Docker bridge network)
4. Click **Save hostname**.

---

### Step 4: Configure Cloudflare Access (Email Whitelist / OTP)
Now lock down the URL so only designated corporate personnel can enter:

1. In the Cloudflare Zero Trust Dashboard, go to **Access** > **Applications**.
2. Click **"Add an application"** > Choose **Self-hosted**.
3. Enter application details:
   * **Application name**: `Enterprise IDS/IPS SOC`
   * **Session Duration**: `24 hours`
   * **Application domain**: `soc.yourcompany.com`
4. Click **Next** to configure Policies:
   * **Policy name**: `Authorized Security Staff Only`
   * **Action**: `Allow`
5. Under **Configure rules** > **Include**:
   * **Selector**: `Emails`
   * **Value**: Enter your authorized corporate emails:
     * `krrish183224@gmail.com`
     * `ciso@yourcompany.com`
     * `analyst@yourcompany.com`
6. Click **Next** > Click **Save application**.

> 🎯 **Result**: When anyone visits `https://soc.yourcompany.com`, Cloudflare presents a branded security gate requesting an email verification PIN. If an unauthorized person enters their email, Cloudflare drops the request immediately at the edge.

---

### Step 5: Launch the Platform with Docker Compose

1. In your project directory, configure `.env.production`:
   ```bash
   # Add your token to .env.production:
   CLOUDFLARE_TUNNEL_TOKEN=eyJhIjoiY2...<YOUR-TOKEN-HERE>
   DOMAIN=soc.yourcompany.com
   ```

2. Start the production stack:
   ```bash
   docker compose --env-file .env.production -f docker-compose.prod.yml up -d --build
   ```

3. Check that `idsips-cloudflared` is connected:
   ```bash
   docker logs idsips-cloudflared
   ```
   You will see:
   ```text
   Connected to INF (Infrastructure Edge)
   Connection established with Cloudflare edge
   Registered tunnel connection
   ```

---

### Step 6: Log In and Operate

1. Open **`https://soc.yourcompany.com`** in any browser.
2. Cloudflare Access prompts: **"Enter your email to receive an access code"**.
3. Enter your authorized email (`krrish183224@gmail.com`) and paste the 6-digit code sent to your inbox.
4. You are admitted to the **Enterprise IDS/IPS Platform**!
5. Log into the SOC console:
   * **Email**: `krrish183224@gmail.com`
   * **Password**: `183@Krrish`

---

## 🛠️ Verification Commands

* **Check Tunnel Status**:
  ```bash
  docker compose --env-file .env.production -f docker-compose.prod.yml ps cloudflared
  ```
* **Verify Zero External Host Ports**:
  ```bash
  # Check that only ports 80/443 (or zero ports) are listening on host:
  netstat -tuln | grep -E '5432|6379|9092|9200|8000'
  # Output will be EMPTY! All database and backend ports are 100% private.
  ```
* **Restart the Stack**:
  ```bash
  docker compose --env-file .env.production -f docker-compose.prod.yml restart
  ```
