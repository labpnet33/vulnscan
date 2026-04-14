# ⚡ VulnScan Pro

<div align="center">

![VulnScan Pro](https://img.shields.io/badge/VulnScan-Pro%20v3.7-00e5ff?style=for-the-badge&logo=shield&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-2.x-000000?style=for-the-badge&logo=flask&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Active-00ff9d?style=for-the-badge)

**Professional security reconnaissance & vulnerability assessment platform.**  
Built for pentesters, sysadmins, and security researchers.

[Features](#-features) · [Screenshots](#-screenshots) · [Installation](#-installation) · [Usage](#-usage) · [API](#-api-reference) · [Contributing](#-contributing)

</div>

---

## ⚠️ Legal Disclaimer

> **Authorized Use Only.** VulnScan Pro is designed exclusively for security testing on systems you own or have **explicit written permission** to assess. Unauthorized scanning is illegal and unethical under the Computer Fraud and Abuse Act (CFAA) and equivalent laws worldwide. Always obtain proper authorization before scanning any system or network.

---

## 🔍 Overview

VulnScan Pro is a free, open-source vulnerability assessment platform featuring a sleek cyberpunk-themed web UI and a powerful Python backend. It orchestrates industry-standard tools (nmap, nikto, dnsrecon, theHarvester, WPScan, Lynis) and enriches their output with live CVE intelligence from the NVD database.

### Why VulnScan Pro?

- **All-in-one** — 12 tools unified under a single, polished interface
- **CVE-enriched** — every open port is cross-referenced against the NVD in real time
- **Multi-user** — full authentication, role-based access, and per-user audit logging
- **Beautiful UI** — 10 unique themes, animated terminal output, and a live dashboard

---

## ✨ Features

<details>
<summary><strong>🌐 Information Gathering</strong></summary>

| Tool | Description |
|------|-------------|
| **Network Scanner** | Deep port scan with nmap · CVE lookups via NVD · SSL analysis · DNS records · HTTP header auditing |
| **DNSRecon** | Zone transfers · A/MX/NS/TXT/SRV records · Reverse lookups · Cache snooping |
| **Network Discovery** | Sweep subnets · Discover live hosts · OS fingerprinting · Topology mapping |
| **Legion** | Semi-automated recon framework orchestrating nmap, nikto, SMB, SNMP, and more |
| **theHarvester** | OSINT email/subdomain/IP harvesting from Google, Bing, LinkedIn, crt.sh |
| **Subdomain Finder** | DNS brute-force + crt.sh + HackerTarget passive enumeration |

</details>

<details>
<summary><strong>🌍 Web Application Testing</strong></summary>

| Tool | Description |
|------|-------------|
| **Nikto** | 6700+ web vulnerability checks · Outdated software · Misconfiguration detection |
| **WPScan** | WordPress plugin/theme vulnerabilities · User enumeration · Config exposure |
| **Directory Buster** | Hidden path & file enumeration · Admin panels · Sensitive file discovery |

</details>

<details>
<summary><strong>🔐 Password Attacks</strong></summary>

| Tool | Description |
|------|-------------|
| **Brute Force** | HTTP form login testing · SSH credential testing · Custom wordlists |

</details>

<details>
<summary><strong>🛡️ System Auditing</strong></summary>

| Tool | Description |
|------|-------------|
| **Lynis** | OS hardening audit · Package review · Firewall rules · Compliance posture (ISO27001, PCI-DSS, HIPAA, CIS) |

</details>

### 🧰 Extended Tool Catalog (Collapsible)

<details>
<summary><strong>Information Gathering</strong></summary>

- nmap
- dnsrecon
- theHarvester
- whatweb
- searchsploit
- seclists

</details>

<details>
<summary><strong>Web Application Testing</strong></summary>

- nikto
- wpscan
- ffuf
- dalfox
- sqlmap
- wapiti
- nuclei
- kxss

</details>

<details>
<summary><strong>Password Attacks</strong></summary>

- medusa
- hashcat
- john

</details>

<details>
<summary><strong>System Auditing</strong></summary>

- lynis
- openvas
- chkrootkit
- rkhunter
- grype

</details>

<details>
<summary><strong>Network Attack Simulation</strong></summary>

- hping3
- scapy
- yersinia

</details>

<details>
<summary><strong>Exploit / Payload / Post-Exploitation</strong></summary>

- msfvenom
- pwncat
- pspy

</details>

<details>
<summary><strong>Reverse Engineering</strong></summary>

- radare2

</details>

<details>
<summary><strong>Tunneling / Pivoting</strong></summary>

- ligolo-ng
- chisel
- rlwrap

</details>

### 👥 Platform Features
- **Authentication** — Register/login, email verification, password reset, session management
- **Role-based access** — Admin and user roles with granular permissions
- **Scan History** — Full scan archive with per-user scoping
- **Security Dashboard** — Statistics, CVE trends, activity charts
- **Admin Console** — User management, audit log, server CLI (allowlisted commands)
- **PDF Reports** — One-click export of scan results
- **10 UI Themes** — Cyberpunk, Midnight Blue, Matrix, Aurora, Solar Flare, and more
- **Auto-install** — Missing tools are automatically installed via apt on first use

---

## 🖼️ Screenshots

> The UI features a cyberpunk aesthetic with animated particle backgrounds, real-time terminal output, and color-coded CVE severity panels.

| Home Dashboard | Network Scan Results | Subdomain Finder |
|:-:|:-:|:-:|
| Animated stats cards | Port + CVE breakdown | crt.sh + brute-force |

---

## 📦 Installation

### Prerequisites

- Python 3.8+
- pip
- nmap (for port scanning)
- Optional: nikto, dnsrecon, theHarvester, lynis, wpscan, whatweb, nuclei, sqlmap

### Quick Start

**1. Clone the repository**
```bash
git clone <your-current-vulnscan-repo-url>
cd vulnscan
```

**2. Install Python dependencies**
```bash
pip install flask flask-cors reportlab
```

**3. Start the server**
```bash
python3 api_server.py
```

**4. Open in your browser**
```
http://localhost:5000
```

---

## 🧩 Remote Lynis Agent (Pull Model)

This project supports running Lynis on **user Linux systems** via outbound HTTP(S) polling (no inbound firewall opening required).

### Server used in this deployment

- `http://161.118.189.254`

### One-line install (copy/paste on user Linux machine)

```bash
curl -fsSL http://161.118.189.254/agent/install.sh | bash
```

> Optional: pass your own ID via `bash -s -- my-client-id`. If omitted, installer auto-generates a unique ID (hostname + random suffix).

### What the install flow does

1. Checks connectivity to `http://161.118.189.254/health`.
2. Downloads `lynis_pull_agent.py` and installer script from the server.
3. Installs a systemd service (`vulnscan-lynis-agent`) for auto-start on boot.
4. Registers the endpoint so it appears in the Lynis dashboard as a detected system.

### Optional: explicit token flow

```bash
# Register and get token
curl -sS -X POST http://161.118.189.254/api/agent/register \
  -H "Content-Type: application/json" \
  -d '{"client_id":"my-client-id","hostname":"myhost","os_info":"Linux"}'
```

Then run installer with token:

```bash
curl -fsSL http://161.118.189.254/agent/install.sh | bash -s -- my-client-id <TOKEN>
```

### Dashboard workflow (Lynis page)

1. Open **Lynis** page in VulnScan.
2. Confirm the endpoint appears under **Connected Agent Systems** (`new system detected` list).
3. Click a detected system to select it for remote scan (or keep no selection for local scan).
4. Select profile/compliance/category.
5. Click **RUN LYNIS AUDIT**.
6. Watch live status/progress in the Lynis terminal/progress bar.
7. Use **Lynis Job Queue** to monitor pending/running/completed jobs and cancel active jobs.
8. After completion, use **DOWNLOAD RAW REPORT** to download full audit output from the server.

The first registered account is automatically granted **admin** role.

---

### Docker (Optional)

```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY . .
RUN pip install flask flask-cors reportlab && \
    apt-get update && apt-get install -y nmap dnsutils
EXPOSE 5000
CMD ["python3", "api_server.py"]
```

---

## 🚀 Usage

### Web Interface

1. Navigate to `http://localhost:5000`
2. Create an account (first account = admin)
3. Select a tool from the navigation menu
4. Enter your authorized target and run the scan
5. View results, export PDF, and browse scan history

### Backend CLI (Direct)

The backend can be invoked directly for scripting or integration:

```
python3 backend.py <target>                          # Full scan (ports + SSL + DNS + headers)
python3 backend.py --modules ports,ssl <target>      # Specific modules
python3 backend.py --subdomains example.com medium   # Subdomain enumeration
python3 backend.py --dirbust http://target small     # Directory busting
python3 backend.py --discover 192.168.1.0/24         # Network discovery
```

Output is always JSON, making it easy to pipe into other tools.

---

## 🔌 API Reference

All endpoints require an active session (login via `/api/login` first).

### Authentication

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/register` | Create a new account |
| `POST` | `/api/login` | Login and create session |
| `POST` | `/api/logout` | End session |
| `GET` | `/api/me` | Get current user info |
| `POST` | `/api/forgot-password` | Request password reset email |
| `POST` | `/api/change-password` | Change password (authenticated) |

### Scanning

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET/POST` | `/scan?target=<ip>` | Full vulnerability scan |
| `GET` | `/subdomains?domain=<domain>` | Subdomain enumeration |
| `GET` | `/dirbust?url=<url>` | Directory busting |
| `GET` | `/discover?subnet=<cidr>` | Network host discovery |
| `POST` | `/harvester` | theHarvester OSINT recon |
| `POST` | `/dnsrecon` | DNS enumeration |
| `POST` | `/nikto` | Nikto web scan |
| `POST` | `/wpscan` | WordPress scan |
| `POST` | `/lynis` | System security audit |
| `POST` | `/legion` | Legion auto-recon |
| `POST` | `/web-deep` | Deep website audit (multi-tool + risk rating + detailed report JSON) |
| `POST` | `/brute-http` | HTTP brute force |
| `POST` | `/brute-ssh` | SSH brute force |

### Lynis Pull-Agent APIs (remote Linux audits)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/agent/register` | Register/rotate token for a Linux agent |
| `POST` | `/api/create-job` | Queue a Lynis job for a specific `client_id` |
| `GET` | `/api/jobs` | Agent poll endpoint (Bearer token) |
| `POST` | `/api/jobs/<id>/progress` | Agent sends running progress updates |
| `POST` | `/api/upload` | Agent uploads parsed Lynis results |
| `GET` | `/api/job-status/<id>` | Website polls status/results for queued job |

Agent files are included in `agent/`:
- `agent/lynis_pull_agent.py` (polling runner)
- `agent/install_agent.sh [client_id] [token] [api_base]` (systemd installer, auto-start; generates ID if omitted)

### History & Reports

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/history` | Paginated scan history |
| `GET` | `/scan/<id>` | Retrieve a specific scan |
| `POST` | `/report` | Generate PDF report |
| `GET` | `/health` | Server health check |

### Admin (admin role required)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/admin/users` | List all users |
| `POST` | `/api/admin/users/<id>/toggle` | Enable/disable user |
| `POST` | `/api/admin/users/<id>/role` | Change user role |
| `DELETE` | `/api/admin/users/<id>` | Delete user |
| `GET` | `/api/admin/stats` | Platform statistics |
| `GET` | `/api/admin/audit` | Audit log |
| `POST` | `/api/exec` | Server CLI (allowlisted commands) |

---

## ⚙️ Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `VULNSCAN_SECRET` | `change-this-secret-key-in-production-2024` | Flask session secret key |

> **Important:** Always set a strong `VULNSCAN_SECRET` in production.

### Email (Optional)

Edit `mail_config.py` to enable email verification and password reset:

```python
APP_URL   = "https://your-server.com"
SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_USER = "your-email@gmail.com"
SMTP_PASS = "your-app-password"
```

Gmail users: generate an [App Password](https://myaccount.google.com/apppasswords) (requires 2FA enabled).

### NVD API Key (Optional)

Adding a free [NVD API key](https://nvd.nist.gov/developers/request-an-api-key) in `backend.py` increases the CVE rate limit from 1 request/6s to 1 request/1s, significantly speeding up scans with many open ports.

```python
NVD_API_KEY = "your-nvd-api-key-here"
```

---

## 🏗️ Architecture

```
vulnscan/
├── api_server.py       # Flask API server + full HTML/JS UI
├── backend.py          # Scan engine (nmap, CVE, SSL, DNS, dirs, brute)
├── auth.py             # Authentication, sessions, password hashing
├── database.py         # SQLite ORM (users, scans, audit log)
├── mail_config.py      # SMTP email configuration
├── vulnscan.jsx        # Standalone React component (alternative UI)
└── vulnscan.db         # SQLite database (auto-created on first run)
```

### Tech Stack

- **Backend:** Python 3, Flask, SQLite
- **Scan Engine:** nmap, nikto, dnsrecon, theHarvester, WPScan, Lynis
- **CVE Data:** NVD REST API v2
- **Frontend:** Vanilla JS + CSS (embedded in Flask), optional React component
- **Auth:** PBKDF2-SHA256 password hashing, server-side sessions
- **Reports:** ReportLab PDF generation

---

## 🛡️ Security

- Passwords hashed with **PBKDF2-HMAC-SHA256** (260,000 iterations)
- **CSRF protection** via session-bound tokens
- **Input validation** on all scan targets (strict regex allowlist)
- **Admin CLI** uses a command allowlist + dangerous pattern blocklist
- **Audit logging** on every scan, login, and admin action
- **Rate limiting** on NVD API calls to respect upstream limits

---

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Commit your changes (`git commit -m 'Add my feature'`)
4. Push to the branch (`git push origin feature/my-feature`)
5. Open a Pull Request

### Reporting Issues

Please use [GitHub Issues](https://github.com/labpnet33/vulnscan/issues) to report bugs or request features.

---

## 👤 Author

**Vijay Katariya**  
Creator & Lead Developer  
[Organization](https://github.com/labpnet33)

---

## 📄 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgements

- [nmap](https://nmap.org/) — Network scanning
- [Nikto](https://cirt.net/Nikto2) — Web vulnerability scanning  
- [theHarvester](https://github.com/laramies/theHarvester) — OSINT recon
- [dnsrecon](https://github.com/darkoperator/dnsrecon) — DNS enumeration
- [WPScan](https://wpscan.com/) — WordPress security
- [Lynis](https://cisofy.com/lynis/) — System auditing
- [NVD](https://nvd.nist.gov/) — CVE vulnerability database

---

<div align="center">
  <sub>Built with ⚡ by Vijay Katariya · Organization</sub>
</div>
