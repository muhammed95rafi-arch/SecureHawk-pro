# ⚡ SecureHawk — Advanced Pentesting Suite

<p align="center">
  <img src="https://img.shields.io/badge/version-3.0.0-00d4ff?style=for-the-badge&logo=github" />
  <img src="https://img.shields.io/badge/platform-Kali%20%7C%20Termux%20%7C%20macOS%20%7C%20Windows-00ff9d?style=for-the-badge" />
  <img src="https://img.shields.io/badge/python-3.8+-yellow?style=for-the-badge&logo=python" />
  <img src="https://img.shields.io/badge/browser-HTML5-ff3e6c?style=for-the-badge&logo=html5" />
  <img src="https://img.shields.io/badge/scan-REAL%20LIVE-00ff9d?style=for-the-badge&logo=radar" />
  <img src="https://img.shields.io/badge/AI-Claude%20Powered-blueviolet?style=for-the-badge&logo=anthropic" />
  <img src="https://img.shields.io/badge/license-MIT-white?style=for-the-badge" />
</p>

<p align="center">
  <b>A comprehensive real-scan security testing suite for Web, Web Applications, Android APKs, and AI systems.</b><br/>
  Covers OWASP Top 10, Mobile Pentesting, Reverse Engineering, and AI/LLM attack vectors.<br/>
  Available as a <b>Browser UI</b> and a <b>Terminal CLI</b>.<br/>
  <b>v3.0: Live HTTP scanning + Claude AI deep analysis.</b>
</p>

---

> ⚠️ **DISCLAIMER:** SecureHawk is intended for **authorized security testing only.**
> Do not use against systems you do not own or have explicit written permission to test.
> Unauthorized use is illegal and unethical.

---

## 📸 Features

- ✅ **Real Live Scanning** — Actual HTTP requests, not simulated data
- ✅ **10 Live Check Modules** — Headers, SSL, CORS, Cookies, XSS, SQLi, DNS, Paths & more
- ✅ **Claude AI Deep Analysis** — AI analyzes real collected data for hidden vulnerabilities
- ✅ **33 Vulnerability Categories** — Web, Mobile, Reverse Engineering, AI/LLM
- ✅ **OWASP Top 10** full coverage
- ✅ **Color-coded findings** — Critical / High / Medium / Low / Info
- ✅ **CVSS Score + CWE** for every finding
- ✅ **Real Evidence** — Actual data from target quoted in every finding
- ✅ **Proof-of-Concept payloads** and remediation guidance
- ✅ **Export reports** — JSON, CSV, HTML, TXT
- ✅ **Browser UI** + **Terminal CLI** — same engine, two interfaces
- ✅ **Cross-platform** — Kali Linux, Termux, macOS, Windows

---

## ⚡ Real Scan Modules (v3.0)

| Module | Type | What It Checks |
|--------|------|---------------|
| `headers` | 🔴 LIVE | CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy |
| `ssl` | 🔴 LIVE | Certificate expiry, TLS version, weak ciphers, self-signed certs |
| `cors` | 🔴 LIVE | Wildcard policy, arbitrary origin reflection test |
| `cookies` | 🔴 LIVE | HttpOnly, Secure, SameSite flags on all cookies |
| `xss` | 🔴 LIVE | Reflected XSS via URL params, DOM XSS sinks in inline JS |
| `sqli` | 🔴 LIVE | SQL error triggers via parameter injection |
| `infodisclosure` | 🔴 LIVE | DB errors, stack traces, API keys, passwords in response body |
| `exposed` | 🔴 LIVE | 25+ sensitive paths: `.git`, `.env`, `/admin/`, `phpinfo.php` etc. |
| `dns` | 🔴 LIVE | DNS resolution, private IP check, zone transfer (AXFR) attempt |
| `ratelimit` | 🔴 LIVE | 10 rapid requests — throttling / 429 detection |
| Other categories | 🤖 AI | Claude AI analyzes collected data for BAC, SSRF, hardcoded secrets, etc. |

---

## 🗂️ Vulnerability Categories

### 🌐 Web / Web Application
| ID | Category |
|----|----------|
| `headers` | Security Headers |
| `ssl` | SSL/TLS Analysis |
| `cors` | CORS Policy |
| `cookies` | Cookie Security |
| `xss` | XSS Vectors |
| `sqli` | SQL Injection |
| `infodisclosure` | Information Disclosure |
| `exposed` | Exposed Files/Paths |
| `dns` | DNS Analysis |
| `bac` | Broken Access Control |
| `ssrf` | SSRF Vectors |
| `misconfig` | Security Misconfigurations |
| `ratelimit` | Rate Limiting |

### 📱 Mobile (Android / iOS)
| ID | Category |
|----|----------|
| `mobile` | Mobile Pentesting (General) |
| `storage` | Insecure Data Storage |
| `certpin` | Certificate Pinning Bypass |

### 🔬 Reverse Engineering & Binary Analysis
| ID | Category |
|----|----------|
| `re` | Reverse Engineering & Analysis |
| `hardcoded` | Hardcoded Secrets / API Keys |
| `weakcrypto` | Weak Cryptography |

### 🤖 AI / LLM Security
| ID | Category |
|----|----------|
| `adversarial` | Adversarial Prompting |
| `promptinj` | Indirect Prompt Injection |

---

## 🚀 Quick Start

### 🌐 Browser Version

Just open the file in any browser:

```bash
# Download and open
open SecureHawk.html        # macOS
start SecureHawk.html       # Windows
xdg-open SecureHawk.html    # Linux
```

No installation required. Works fully offline. Browser version uses live HTTP checks + Claude AI analysis.

---

### 💻 Terminal / CLI Version

**Install dependencies:**

```bash
pip install requests colorama urllib3
```

**Basic usage:**

```bash
# Scan a website (live checks)
python3 securehawk.py -u https://target.com

# Scan with specific categories
python3 securehawk.py -u https://target.com --categories headers,ssl,cors,cookies

# Run ALL categories
python3 securehawk.py -u https://target.com --all

# Run ALL + Claude AI deep analysis
python3 securehawk.py -u https://target.com --all --api-key sk-ant-YOUR_KEY

# Or set API key via environment variable
export ANTHROPIC_API_KEY=sk-ant-YOUR_KEY
python3 securehawk.py -u https://target.com --all

# Save report
python3 securehawk.py -u https://target.com --all -o report.json
python3 securehawk.py -u https://target.com --all -o report.html
python3 securehawk.py -u https://target.com --all -o report.csv

# List all available categories
python3 securehawk.py --list-categories

# Verbose output
python3 securehawk.py -u https://target.com --all -v
```

---

## 📦 Installation

### Kali Linux
```bash
git clone https://github.com/muhammed95rafi-arch/SecureHawk-pro.git
cd SecureHawk-pro
pip install requests colorama urllib3
python3 securehawk.py --list-categories
```

### Termux (Android)
```bash
pkg update && pkg install python git
git clone https://github.com/muhammed95rafi-arch/SecureHawk-pro.git
cd SecureHawk-pro
pip install requests colorama urllib3
python3 securehawk.py --list-categories
```

### macOS
```bash
git clone https://github.com/muhammed95rafi-arch/SecureHawk-pro.git
cd SecureHawk-pro
pip3 install requests colorama urllib3
python3 securehawk.py --list-categories
```

### Windows
```bash
git clone https://github.com/muhammed95rafi-arch/SecureHawk-pro.git
cd SecureHawk-pro
pip install requests colorama urllib3
python securehawk.py --list-categories
```

---

## 📊 Report Output

Every finding includes:

| Field | Description |
|-------|-------------|
| **Severity** | Critical / High / Medium / Low / Info |
| **CVSS Score** | 0.0 – 10.0 numeric score |
| **CWE** | Common Weakness Enumeration ID |
| **Location** | Exact URL, header, or path where found |
| **Description** | Detailed vulnerability explanation |
| **Evidence** | Actual data from target proving the finding |
| **Payload / PoC** | Proof-of-concept attack string |
| **Remediation** | How to fix the vulnerability |

**Export formats:**
- `report.json` — Machine-readable, use with CI/CD pipelines
- `report.csv` — Import into Excel / Google Sheets
- `report.html` — Standalone visual report for sharing
- `report.txt` — Plain text for quick review

---

## 🖥️ CLI Options

```
usage: securehawk.py [-h] -u URL [-t TYPE] [--categories CATS] [--all]
                     [-o OUTPUT] [-v] [--api-key KEY] [--list-categories]

options:
  -u, --url           Target URL or IP address
  -t, --type          Scan type: web | webapp | android | api | all
  --categories        Comma-separated category IDs (e.g. headers,ssl,cors)
  --all               Run all categories
  -o, --output        Output file: report.json / report.csv / report.html / report.txt
  -v, --verbose       Verbose output
  --api-key           Anthropic API key for Claude AI deep analysis
  --list-categories   List all available category IDs
  -h, --help          Show this help message
```

---

## 📁 Project Structure

```
SecureHawk-pro/
├── SecureHawk.html     # Browser-based UI (real scan + AI powered)
├── securehawk.py       # Terminal CLI tool (real live scan)
├── README.md           # This file
└── LICENSE             # MIT License
```

---

## 🔧 Requirements

| Requirement | Version |
|-------------|---------|
| Python | 3.8 or higher |
| requests | Latest (`pip install requests`) |
| colorama | Latest (`pip install colorama`) |
| urllib3 | Latest (`pip install urllib3`) |
| Browser | Any modern browser (Chrome, Firefox, Safari, Edge) |
| Anthropic API Key | Optional — for Claude AI deep analysis |

> `colorama` is optional on Linux/macOS — ANSI colors work natively.
> Required on Windows for colored terminal output.

---

## 🤝 Contributing

Pull requests are welcome!

1. Fork the repository
2. Create your feature branch: `git checkout -b feature/new-check`
3. Commit your changes: `git commit -m 'Add new vulnerability check'`
4. Push to the branch: `git push origin feature/new-check`
5. Open a Pull Request

---

## 📜 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

## ⚖️ Legal

SecureHawk is a security research tool.

- ✅ Use on systems **you own**
- ✅ Use with **written permission** from the target owner
- ✅ Use in **CTF / lab environments**
- ❌ Do **NOT** use on systems without authorization
- ❌ Do **NOT** use for illegal activities

The authors are not responsible for any misuse or damage caused by this tool.

---

<p align="center">
  Made with ❤️ for the security community<br/>
  <b>SecureHawk v3.0</b> — Real Pentesting Suite<br/>
  <a href="https://github.com/muhammed95rafi-arch/SecureHawk-pro">github.com/muhammed95rafi-arch/SecureHawk-pro</a>
</p>
