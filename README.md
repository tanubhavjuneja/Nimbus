<![CDATA[<div align="center">

# ⚡ Nimbus

### Cloud Security Vulnerability Scanner

**Scan. Detect. Fix. Secure.**

*Nimbus is a desktop tool that scans Cloudflare project configurations for security misconfigurations, exposes hidden vulnerabilities, and offers one-click automated fixes with AI-powered explanations.*

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![PySide6](https://img.shields.io/badge/PySide6-6.5+-41CD52?style=for-the-badge&logo=qt&logoColor=white)
![Cloudflare](https://img.shields.io/badge/Cloudflare-F48120?style=for-the-badge&logo=cloudflare&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-blue?style=for-the-badge)

</div>

---

## 🎯 Problem Statement

As businesses migrate to cloud infrastructure, **misconfigurations, excessive permissions, and exposed data** have become leading causes of breaches. Many organizations lack the tooling to continuously audit their cloud environments for these risks.

Cloudflare is one of the most widely used cloud platforms — yet there is **no unified desktop tool** that provides a visual, real-time security audit of a Cloudflare project. Developers are left juggling CLI commands, manually inspecting config files, and guessing whether their setup is secure.

---

## 💡 Our Solution

**Nimbus** is a cross-platform desktop application that:

1. **Connects** to your Cloudflare account and discovers all Pages, Workers, D1 databases, KV namespaces, R2 buckets, and Secrets.
2. **Scans** your local project configurations against **7 security scanners** with 50+ vulnerability checks.
3. **Auto-fixes** critical findings with one click — no manual edits required.
4. **Explains** every finding in plain language using an AI assistant, tailored to your technical level.

> *"One dashboard to see it all. One click to fix it all."*

---

## 🚀 Key Features

### 🔍 7-Powered Security Scanning Engine

| Scanner | What It Detects |
|---|---|
| **Config Scanner** | Plaintext secrets in `wrangler.toml`, exposed `account_id`, missing `.dev.vars` in `.gitignore`, hardcoded secrets in source |
| **Secret Scanner** | 18+ secret patterns — API keys, AWS keys, GitHub/Slack/Stripe/OpenAI tokens, database URLs, private keys, SMTP passwords |
| **Dependency Scanner** | Known CVEs in `package.json` and `requirements.txt` (lodash, minimist, axios, express, ws, jsonwebtoken, and more) |
| **Environment Exposure** | `.env` files not in `.gitignore`, variables that should be Cloudflare Secrets |
| **Security Headers Checker** | Missing CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, X-XSS-Protection |
| **CORS Checker** | Wildcard origins, null origins, credentials-with-wildcard misconfigurations |
| **Full Security Audit** | Combines all scanners + optional AI code review into a single report |

### 🔧 One-Click Auto-Fix

Nimbus can automatically remediate findings across **12+ vulnerability categories**:

- Remove plaintext secrets from `wrangler.toml`
- Add `.dev.vars` to `.gitignore`
- Comment out exposed `account_id`
- Replace hardcoded secrets with safe placeholders
- Update vulnerable dependencies to patched versions
- Inject missing security headers into Workers
- Fix CORS misconfigurations
- Sanitize secrets detected in source code

### 🤖 AI-Powered Assistant

Powered by **ASI:One** (OpenAI-compatible API):

- **Explain Finding** — Plain-language explanation of any security issue, tailored to beginner, intermediate, or technical audiences
- **Deep Analysis** — Detailed breakdown of severity, impact, and remediation steps
- **Code Review** — AI scans your source code for additional security risks
- **General Q&A** — Ask anything about your Cloudflare setup in natural language

### 📊 Cloudflare Service Dashboard

- Visual overview of all Pages, Workers, D1, KV, R2, and Secrets
- Deploy Pages and Workers directly from the UI
- Create and delete databases, buckets, and namespaces
- Execute SQL queries against D1 databases
- Upload files to R2 buckets
- Full deployment and scan history

### 📚 Security Glossary

Built-in glossary with **15 security terms** (SSL/TLS, WAF, HSTS, DNSSEC, CORS, CSP, and more), each with three explanation levels — from beginner to technical.

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────┐
│                  NIMBUS DESKTOP                  │
│                                                  │
│  ┌──────────────┐    QWebChannel    ┌──────────┐│
│  │   Python     │◄─────────────────►│  Vanilla  ││
│  │   Backend    │   (bidirectional) │  JS/UI   ││
│  │              │                   │          ││
│  │  ┌────────┐  │                   │  Glassmorphism│
│  │  │Wrangler│  │                   │  Design  ││
│  │  │  CLI   │  │                   └──────────┘│
│  │  └────────┘  │                                │
│  │  ┌────────┐  │                                │
│  │  │Warning │  │                                │
│  │  │Manager │  │                                │
│  │  └────────┘  │                                │
│  │  ┌────────┐  │                                │
│  │  │ASI:One │  │                                │
│  │  │  AI    │  │                                │
│  │  └────────┘  │                                │
│  └──────────────┘                                │
└─────────────────────────────────────────────────┘
         │                    │
         ▼                    ▼
   ┌───────────┐      ┌────────────┐
   │Wrangler   │      │ Cloudflare │
   │  (CLI)    │      │   REST API │
   └───────────┘      └────────────┘
         │                    │
         ▼                    ▼
   ┌─────────────────────────────┐
   │     Cloudflare Account      │
   │  Pages · Workers · D1 · KV  │
   │  R2 · Secrets · DNS         │
   └─────────────────────────────┘
```

**How it works:**
- **Python backend** handles all Cloudflare API interactions, security scanning, and AI inference via `subprocess` (Wrangler CLI) and REST API calls
- **Vanilla JS frontend** renders inside a PySide6 WebEngineView with a glassmorphism UI
- **QWebChannel** provides a bidirectional bridge — JS calls Python methods and polls for async results
- **QThread workers** keep the UI responsive during long-running scans and deploys

---

## 🛠️ Tech Stack

| Layer | Technology |
|---|---|
| **Language** | Python 3.10+ |
| **Desktop Framework** | PySide6 (Qt 6.5+) |
| **Web Engine** | PySide6-WebEngine (Chromium) |
| **Frontend** | Vanilla HTML / CSS / JavaScript |
| **UI Design** | Glassmorphism — frosted-glass cards, animated orbs, gradient accents |
| **Cloud Integration** | Cloudflare Wrangler CLI + Cloudflare REST API |
| **AI Backend** | ASI:One (OpenAI-compatible) |
| **Config Storage** | JSON files (`~/.cloudguard/`) |

---

## ⚙️ Prerequisites

- **Python 3.10+** — [Download](https://www.python.org/downloads/)
- **Cloudflare Wrangler CLI** — Install via `npm install -g wrangler`
- **Node.js & npm** — Required for Wrangler
- **Cloudflare Account** — Free tier works
- **ASI:One API Key** (optional) — For AI features — [Get one here](https://ASI1.ai)

---

## 📦 Installation & Setup

### 1. Clone the Repository

```bash
git clone https://github.com/your-org/nimbus.git
cd nimbus
```

### 2. Install Python Dependencies

```bash
pip install -r requirements.txt
```

This installs:
- `PySide6>=6.5.0`
- `PySide6-WebEngine>=6.5.0`

### 3. Install Wrangler (if not already installed)

```bash
npm install -g wrangler
```

### 4. Run Nimbus

**Linux / macOS:**

```bash
python src/main.py
```

**Windows:**

```cmd
run.bat
```

That's it — the application opens in a native desktop window.

---

## 🖥️ Usage

### First Launch

1. **Login** — Click "Login to Cloudflare" and authenticate via the OAuth flow
2. **Scan** — Nimbus automatically scans your local projects for security issues
3. **Review** — Browse findings in the Warnings tab with severity ratings
4. **Fix** — Click "Fix" on any finding for one-click automated remediation
5. **Ask AI** — Click "Ask AI" on any finding for a plain-language explanation

### Dashboard Views

| Tab | Purpose |
|---|---|
| **Dashboard** | Overview of all Cloudflare services, recent deployments, security summary |
| **Warnings** | Active security findings with Fix / Ask AI / Dismiss / Always Ignore actions |
| **Services** | Detailed tables of Pages, Workers, D1, KV, R2, Secrets — with drill-down panels |
| **History** | Past scan results and warning history (fixed / ignored) |
| **Ask AI** | Chat with the Nimbus AI assistant about your setup |
| **Settings** | Audience level, API key, always-ignored checks |

---

## 📁 Project Structure

```
nimbus/
├── requirements.txt              # Python dependencies
├── run.bat                       # Windows launcher
├── README.md
└── src/
    ├── main.py                   # App entry point (Qt event loop, bridge setup)
    ├── backend/
    │   ├── __init__.py
    │   ├── wrangler.py           # Wrangler CLI wrapper, scanners, auto-fix engine
    │   └── warnings.py           # Warning system, glossary, ASI:One AI client
    └── frontend/
        ├── index.html            # Main HTML shell
        ├── css/
        │   └── style.css         # Glassmorphism UI styles
        └── js/
            └── app.js            # Full frontend logic (dashboard, services, AI chat)
```

---

## 🔐 Security Checks Detail

Nimbus performs **50+ individual checks** across your Cloudflare project:

<details>
<summary><strong>Config & Secrets</strong></summary>

- Plaintext API tokens in `wrangler.toml` `[vars]`
- `account_id` exposed in committed config
- Missing `.dev.vars` in `.gitignore`
- Hardcoded secrets in JavaScript/TypeScript/Python source files
- 18+ regex patterns for API keys, tokens, and credentials

</details>

<details>
<summary><strong>Dependencies</strong></summary>

- Known CVE detection for npm and PyPI packages
- Vulnerable versions of: lodash, minimist, axios, express, ws, jsonwebtoken, node-forge, tar, glob-parent, trim, normalize-url, marked, qs, follow-redirects, dns-packet, bson, and more

</details>

<details>
<summary><strong>Environment & Exposure</strong></summary>

- `.env` files not listed in `.gitignore`
- Environment variables that should be migrated to Cloudflare Secrets
- `.dev.vars` file exposure risks

</details>

<details>
<summary><strong>HTTP Security Headers</strong></summary>

- Content-Security-Policy (CSP)
- Strict-Transport-Security (HSTS)
- X-Frame-Options
- X-Content-Type-Options
- Referrer-Policy
- Permissions-Policy
- X-XSS-Protection

</details>

<details>
<summary><strong>CORS Configuration</strong></summary>

- Wildcard (`*`) origin usage
- `null` origin exploitation
- Credentials with wildcard origins
- Missing CORS headers entirely

</details>

---

## 🎨 UI Design

Nimbus features a **glassmorphism** design language:

- Frosted-glass sidebar and cards with `backdrop-filter: blur()`
- Animated floating orbs in the background
- Gradient accents (blue-to-green theme)
- Toast notifications for scan progress
- Modal dialogs for create/upload/deploy actions
- Loading overlays with step-by-step progress indicators
- Responsive grid layout

---

## 📊 How It Differs

| Feature | Nimbus | CLI Tools | Web Dashboards |
|---|---|---|---|
| **Visual Desktop App** | ✅ | ❌ | ❌ |
| **One-Click Auto-Fix** | ✅ | ❌ | ❌ |
| **AI-Powered Explanations** | ✅ | ❌ | ❌ |
| **Audience-Adapted Output** | ✅ | ❌ | ❌ |
| **Local Project Scanning** | ✅ | Partial | ❌ |
| **Full Cloudflare Service Mgmt** | ✅ | ✅ | Partial |
| **Security Glossary** | ✅ | ❌ | ❌ |
| **No Cloud Provider Lock-in** | ✅ (Cloudflare focused) | — | — |

---

## 🧪 Example: End-to-End Workflow

```
1. Launch Nimbus → python src/main.py
2. Login to Cloudflare via OAuth
3. Nimbus scans local wrangler.toml + source files
4. Dashboard shows: "5 warnings found"
5. Click "Warnings" → see severity-ranked findings
6. Click "Fix" on "Plaintext Secret in wrangler.toml"
   → Nimbus removes the secret, prompts you to set it via `wrangler secret put`
7. Click "Ask AI" on "Missing Content-Security-Policy Header"
   → AI explains: "Your Worker doesn't set a CSP header, which means..."
   → AI suggests the exact header to add
8. Click "Fix" → header is injected into your Worker source code
9. Run full audit → all green ✅
```

---

## 🤝 Contributing

Contributions welcome! Please open an issue or PR.

1. Fork the repo
2. Create a feature branch (`git checkout -b feature/amazing`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing`)
5. Open a Pull Request

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

<div align="center">

**Built with ❤️ for Cloudflare security**

*Scan your cloud. Fix it fast. Sleep well.*

</div>
]]>