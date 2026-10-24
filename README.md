# Unified Threat Sandbox & Web Origin Reconnaissance Platform

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-3.0%2B-lightgrey.svg)](https://palletsprojects.com/p/flask/)
[![VirtualBox](https://img.shields.io/badge/Oracle-VirtualBox_7.0%2B-orange.svg)](https://www.virtualbox.org/)
[![Playwright](https://img.shields.io/badge/Playwright-Chromium-red.svg)](https://playwright.dev/)
[![Security](https://img.shields.io/badge/Security-HSTS%20%7C%20CSP%20%7C%20CSRF%20%7C%20SSRF%20Guard-green.svg)](#security-architecture)
[![License](https://img.shields.io/badge/License-Proprietary%20%2F%20Open%20Defense-purple.svg)](#)

A high-performance, enterprise-grade hybrid cyber intelligence and threat analysis sandbox. The platform provides dual-vector threat inspection: **dynamic web origin reconnaissance** via automated headless browser probes, and **hardware-isolated binary detonation** inside disposable virtual machine environments with real-time behavioral machine learning classification.

---

## Architecture Overview

```
+----------------------------------------------------------------------------------------------------+
|                                    CLIENT BROWSER LAYER                                            |
|   - Responsive Glassmorphic SOC HUD (Desktop / Tablet / Mobile 360px-1920px)                       |
|   - HTTPS Padlock Security Badge (TLS 1.3 / HSTS Preload Verified)                                 |
|   - Web Audio API Real-Time Tactical Synthesizer (Safari User-Gesture Unlocked)                    |
|   - Real-Time WebSocket Telemetry Stream (Socket.IO with REST Fallback)                            |
|   - Native Lazy Loading & Asynchronous Image Decoding (`loading="lazy"`)                           |
+-------------------------------------------------+--------------------------------------------------+
                                                  |
                    HTTPS / WSS Transport         | Double-Submit CSRF Header: `X-CSRF-Token`
                    Rate-Limited Gateways         | Per-IP Sliding Window Quotas
                                                  v
+----------------------------------------------------------------------------------------------------+
|                                    APPLICATION GATEWAY (app.py)                                    |
|   - Flask 3.x Application Gateway with SocketIO Real-Time Threading Engine                         |
|   - Enterprise Security Headers: HSTS (2-Year Preload), CSP, X-Frame-Options: DENY, nosniff        |
|   - Cryptographic Anti-CSRF Protection (Double-Submit Cookie Pattern)                              |
|   - Thread-Safe Sliding Window Rate Limiter (RFC 6585 `429 Too Many Requests` + `Retry-After`)      |
|   - Reverse-Proxy Canonical IP Extractor (Safe `X-Forwarded-For` with RFC 1918 Sanitization)        |
+------------------------------------+-------------------------------------------+-------------------+
                                     |                                           |
                                     v                                           v
+----------------------------------------------------+   +-------------------------------------------+
|              MODULE 1: RECON ENGINE                |   |        MODULE 2: DETONATION CONTROLLER    |
|                (url_scanner.py)                    |   |           (sandbox_controller.py)         |
+----------------------------------------------------+   +-------------------------------------------+
| - Multi-Layered SSRF Guard                         |   | - Oracle VirtualBox VBoxManage Automation |
|   * Rejects RFC 1918, RFC 3927, CGNAT, Loopback    |   | - Cold Boot & State Revert (`CleanState`) |
|   * Rejects AWS/GCP/Azure Metadata (169.254.x)     |   | - Hypervisor Guest Control Injection      |
|   * Restricts Destination Ports (80, 443, 8080)   |   | - In-Guest PowerShell Telemetry Harvester |
| - Playwright Chromium Headless Container           |   | - Base64 Encoded In-Memory Agent Execution|
| - Subrequest Route Interception (`page.route`)     |   +---------------------+---------------------+
| - SSL/TLS Socket X.509 Extraction                  |                         |
| - DOM Form & Credential Harvest Analysis           |                         v
| - Viewport Snapshot Renderer                       |   +-------------------------------------------+
+----------------------------------------------------+   |      MODULE 3: BEHAVIORAL ML ENGINE       |
                                                         |             (train_model.py)              |
                                                         +-------------------------------------------+
                                                         | - TF-IDF Vectorizer (N-Gram Text Model)   |
                                                         | - Scikit-Learn Random Forest Classifier   |
                                                         | - Real-Time Behavioral Threat Scoring     |
                                                         +-------------------------------------------+
```

---

## Key Features

### 1. Dynamic Web Origin Reconnaissance (`url_scanner.py`)
- **Multi-Layered SSRF Defense:** Rejects all RFC 1918/6890 private IP ranges, link-local addresses, loopback interfaces, cloud metadata endpoints (`169.254.169.254`, `metadata.google.internal`), and non-standard web ports.
- **Subrequest Route Interception:** Enforces Playwright Chromium `page.route("**/*")` validation to block sub-resource probing or malicious server-side redirects targeting the internal host.
- **SSL/TLS X.509 Certificate Audit:** Extracts certificate subject, issuer, validity period, SAN extensions, cipher suites, and calculates remaining valid days.
- **HTTP Security Header Audit:** Rates the target's posture across HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and Permissions-Policy.
- **DOM & Attack Surface Profiling:** Detects login forms, unencrypted password fields, cross-domain submission actions, mixed active content, and external tracker scripts.
- **Automated High-Resolution Viewport Capture:** Renders an interactive page snapshot with native lazy loading.

### 2. Hardware-Isolated Binary Detonation (`sandbox_controller.py`)
- **Disposable Hypervisor Environment:** Automates Oracle VirtualBox headless guest execution (e.g. Windows 10 isolated VM).
- **Instant Snapshot Rollback:** Reverts the guest VM to a pristine snapshot (`CleanState`) before and after each detonation, guaranteeing zero persistent malware contamination.
- **Guest Control Execution:** Injects and executes suspicious payloads via secure `VBoxManage guestcontrol` interfaces without shared folders or open guest network drives.
- **Real-Time Telemetry Harvesting:** Collects spawned processes, PID trees, registry run keys, dropped temporary binaries, and network beacon attempts.

### 3. Behavioral Machine Learning Classifier (`train_model.py` / `malware_model.pkl`)
- **TF-IDF + Random Forest Pipeline:** Analyzes harvested process execution logs and API call traces using n-gram tokenization and an ensemble Random Forest classifier.
- **Deterministic Threat Scoring:** Returns probability distributions across Benign vs. Malicious indicators with key feature attribution.

### 4. Hardened SOC Interface (`templates/index.html`)
- **Responsive Tactical Glassmorphic HUD:** Optimized for desktop displays, tablets, and mobile screens ($360\text{px}$ to $1920\text{px}$) with dynamic viewport heights (`100dvh`).
- **Real-Time WebSocket Stream:** Powered by Flask-SocketIO for live hypervisor logs and detonation step-by-step progress.
- **Double-Submit CSRF Protection:** Cryptographic `ts_csrf_token` cookie paired with `X-CSRF-Token` header verification on all mutating endpoints.
- **Sliding-Window Rate Limiting:** Enforces per-IP request quotas with RFC 6585 `429 Too Many Requests` responses and `Retry-After` headers.
- **XSS & DOM Sanitization:** Strict character entity encoding and secure DOM text bindings.
- **Audio Tactical Synthesis:** Built-in Web Audio API sound generator for SOC alerts with iOS/Safari audio context touch-unlocking.

---

## Directory Structure

```text
threat-sandbox/
├── app.py                      # Core Flask 3.x Application Gateway & SocketIO Server
├── url_scanner.py              # Playwright Headless Web Origin & SSL Reconnaissance Engine
├── sandbox_controller.py       # Oracle VirtualBox Hypervisor Orchestration Controller
├── train_model.py              # Scikit-Learn TF-IDF Random Forest Training Pipeline
├── malware_model.pkl           # Pre-Trained Machine Learning Model
├── dataset.csv                 # Behavioral Telemetry Training Dataset
├── requirements.txt            # Production Python Dependencies
├── .env.example                # Environment Variables Configuration Template
├── .gitignore                  # Git Ignore Rules for Secrets, Storage & Bytecode
├── CHANGELOG.md                # Platform Version & Engineering History
├── VIRTUALBOX_SETUP_GUIDE.txt  # Step-by-Step Guest VM Snapshot & Setup Manual
├── project report.md           # Comprehensive Architecture & Pre-Launch Audit Report
├── SITE_OPERATIONS_GUIDE.txt   # Step-by-Step Public Live Operations & Management Manual
├── start_live.bat              # One-Click Live Production Launcher (Flask + Cloudflare)
├── stop_live.bat               # One-Click Live Production Shutdown Script
├── static/
│   ├── favicon.ico             # Terminal Shield Application Icon
│   └── js/
│       └── socket.io.min.js    # Vendored Socket.IO Client Library
├── templates/
│   └── index.html              # Responsive SOC HUD Dashboard & Tactical Interface
└── uploads/
    └── .gitkeep                # Staged Payload & Artifact Isolation Directory
```

---

## Installation & Setup

### Prerequisites
- Python 3.10 or newer
- Oracle VirtualBox 7.0+ (with VirtualBox Extension Pack)
- Playwright Chromium browser binaries

### 1. Clone the Repository
```bash
git clone https://github.com/arshadshaik037/Threat-SandBox.git
cd Threat-SandBox
```

### 2. Configure Virtual Environment
```bash
python -m venv .venv

# On Linux/macOS:
source .venv/bin/activate

# On Windows:
.\.venv\Scripts\activate
```

### 3. Install Dependencies & Playwright
```bash
pip install -r requirements.txt
playwright install chromium
```

### 4. Configure Environment Variables
Copy `.env.example` to `.env` and fill in your desired secret tokens:
```bash
cp .env.example .env
```
Generate a strong secret key for Flask session security:
```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

### 5. Configure VirtualBox Guest VM
Refer to [VIRTUALBOX_SETUP_GUIDE.txt](VIRTUALBOX_SETUP_GUIDE.txt) for instructions on creating the isolated guest VM:
1. Create a Windows 10 VM named `Win10_Sandbox`.
2. Configure a local user account (`SandboxUser` / `SandboxPass@2026!`).
3. Set the network adapter to **Host-Only** or **Internal Network** (isolate from LAN).
4. Take a pristine baseline snapshot named `CleanState`.

---

## Running the Application

### Development Mode
```bash
python app.py
```
Access the dashboard at `http://127.0.0.1:5000` (or `https://` if behind a reverse proxy).

### Public Internet Deployment (Cloudflare Tunnel)
To immediately publish the platform to the public internet with a free SSL/TLS certificate and DDoS protection:

**Option 1: One-Click Quick Launch**
- Run `start_live.bat` (launches Flask + Cloudflare Tunnel in parallel).
- Run `stop_live.bat` (instantly halts the tunnel and frees port 5000).

**Option 2: Command Line**
```bash
# Terminal 1: Start backend
python app.py

# Terminal 2: Expose via Cloudflare Tunnel (HTTP/2 transport)
cloudflared tunnel --protocol http2 --url http://127.0.0.1:5000
```
Detailed teardown, reboot, and permanent custom domain setup instructions are available in [SITE_OPERATIONS_GUIDE.txt](SITE_OPERATIONS_GUIDE.txt).

### Production Deployment (Gunicorn + Eventlet / Gevent)
```bash
gunicorn --worker-class eventlet -w 1 --bind 127.0.0.1:5000 app:app
```

Recommended Nginx configuration for reverse-proxying with WebSocket support and SSL termination:
```nginx
server {
    listen 80;
    server_name sandbox.yourdomain.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name sandbox.yourdomain.com;

    ssl_certificate /etc/letsencrypt/live/sandbox.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/sandbox.yourdomain.com/privkey.pem;

    client_max_body_size 50M;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
    }
}
```

---

## Security Architecture

| Security Domain | Defense Mechanism | Verified In |
|---|---|---|
| **SSRF** | Multi-tiered CIDR block (RFC 1918, RFC 3927, CGNAT, Loopback, Cloud Metadata) + Playwright route interception | `url_scanner.py` |
| **CSRF** | Cryptographic Double-Submit Cookie Pattern (`ts_csrf_token` cookie + `X-CSRF-Token` header) | `app.py` |
| **XSS** | Full HTML entity escaping + Strict Content Security Policy (CSP) | `app.py`, `templates/index.html` |
| **Transport** | Strict-Transport-Security (HSTS 2-Year + Preload), Automatic 301 HTTPS Redirection | `app.py` |
| **DoS / Abuse** | Per-IP Sliding-Window Rate Limiting with RFC 6585 `429 Too Many Requests` & `Retry-After` headers | `app.py` |
| **Hypervisor Escape** | Complete hypervisor state rollbacks (`CleanState`), host-only networking, non-shared guest filesystem | `sandbox_controller.py` |

---

## License & Disclaimer
This software is intended for legitimate cybersecurity defense, malware analysis, educational, and authorized penetration testing purposes only. Executing unverified or hostile binaries carries inherent risk; always run detonations inside isolated, unbridged virtualization environments.
