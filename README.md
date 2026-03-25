# ⚡ SecureHawk — Advanced Pentesting Suite

<p align="center">
  <img src="https://img.shields.io/badge/version-2.0.0-00d4ff?style=for-the-badge&logo=github" />
  <img src="https://img.shields.io/badge/platform-Kali%20%7C%20Termux%20%7C%20macOS%20%7C%20Windows-00ff9d?style=for-the-badge" />
  <img src="https://img.shields.io/badge/python-3.8+-yellow?style=for-the-badge&logo=python" />
  <img src="https://img.shields.io/badge/browser-HTML5-ff3e6c?style=for-the-badge&logo=html5" />
  <img src="https://img.shields.io/badge/license-MIT-white?style=for-the-badge" />
</p>

<p align="center">
  <b>A comprehensive security testing suite for Web, Web Applications, Android APKs, and AI systems.</b><br/>
  Covers OWASP Top 10, Mobile Pentesting, Reverse Engineering, and AI/LLM attack vectors.<br/>
  Available as a <b>Browser UI</b> and a <b>Terminal CLI</b>.
</p>

---

> ⚠️ **DISCLAIMER:** SecureHawk is intended for **authorized security testing only.**
> Do not use against systems you do not own or have explicit written permission to test.
> Unauthorized use is illegal and unethical.

---

## 📸 Features

- ✅ **33 Vulnerability Categories** — Web, Mobile, Reverse Engineering, AI/LLM
- ✅ **OWASP Top 10** full coverage
- ✅ **Color-coded findings** — Critical / High / Medium / Low / Info
- ✅ **Separate categories** for every vulnerability class
- ✅ **CVSS Score + CWE** for every finding
- ✅ **Proof-of-Concept payloads** and remediation guidance
- ✅ **Export reports** — JSON, CSV, HTML, TXT
- ✅ **Browser UI** + **Terminal CLI** — same engine, two interfaces
- ✅ **Cross-platform** — Kali Linux, Termux, macOS, Windows

---

## 🗂️ Vulnerability Categories

### 🌐 Web / Web Application
| ID | Category |
|----|----------|
| `bac` | Broken Access Control |
| `sqli` | SQL Injection |
| `owasp` | OWASP Top 10 Analysis |
| `xss` | Cross-Site Scripting (XSS) |
| `crypto` | Cryptographic Failures |
| `misconfig` | Security Misconfigurations |
| `ssrf` | Server-Side Request Forgery (SSRF) |
| `idor` | Insecure Direct Object Reference (IDOR) |
| `race` | Race Conditions |
| `click` | Clickjacking |
| `ratelimit` | Rate Limiting Issues |
| `infodisclosure` | Information Disclosure |
| `path` | Path Traversal |
| `bizlogic` | Business Logic Errors |

### 📱 Mobile (Android / iOS)
| ID | Category |
|----|----------|
| `mobile` | Mobile Pentesting (General) |
| `storage` | Insecure Data Storage |
| `session` | Improper Session Handling |
| `deeplink` | Unvalidated Deep Links |
| `validation` | Weak Input Validation |
| `rootbypass` | Root / Jailbreak Detection Bypass |
| `intent` | Intent Spoofing |
| `backup` | Insecure Backup |
| `antidebug` | Anti-Debugging Tricks |
| `certpin` | Certificate Pinning Bypass |
| `dyncode` | Dynamic Code Injection |
| `jailbreak` | Jailbreaking Risks |

### 🔬 Reverse Engineering & Binary Analysis
| ID | Category |
|----|----------|
| `re` | Reverse Engineering & Analysis |
| `hardcoded` | Hardcoded Secrets / API Keys |
| `obfusc` | Lack of Obfuscation |
| `weakcrypto` | Weak Cryptography |
| `debug` | Leftover Debug Info |

### 🤖 AI / LLM Security
| ID | Category |
|----|----------|
| `adversarial` | Adversarial Prompting |
| `promptinj` | Indirect Prompt Injection |
| `soceng` | Social Engineering for AI |

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

No installation required. Works fully offline.

---

### 💻 Terminal / CLI Version

**Install dependencies:**

```bash
pip install colorama
```

**Basic usage:**

```bash
# Scan a website
python3 securehawk.py -u https://target.com -t web

# Scan a web application (all web + AI categories)
python3 securehawk.py -u https://target.com -t webapp

# Scan an Android APK
python3 securehawk.py -u /path/to/app.apk -t android

# Run ALL categories
python3 securehawk.py -u https://target.com --all

# Specific categories only
python3 securehawk.py -u https://target.com --categories sqli,xss,ssrf,bac,idor

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
git clone https://github.com/YOUR_USERNAME/securehawk.git
cd securehawk
pip install colorama
python3 securehawk.py --list-categories
```

### Termux (Android)
```bash
pkg update && pkg install python git
git clone https://github.com/YOUR_USERNAME/securehawk.git
cd securehawk
pip install colorama
python3 securehawk.py --list-categories
```

### macOS
```bash
git clone https://github.com/YOUR_USERNAME/securehawk.git
cd securehawk
pip3 install colorama
python3 securehawk.py --list-categories
```

### Windows
```bash
git clone https://github.com/YOUR_USERNAME/securehawk.git
cd securehawk
pip install colorama
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
| **Description** | Detailed vulnerability explanation |
| **Payload / PoC** | Proof-of-concept attack string |
| **Evidence** | What was observed during testing |
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
                     [-o OUTPUT] [-v] [--list-categories]

options:
  -u, --url           Target URL, IP address, or APK file path
  -t, --type          Scan type: web | webapp | android | api | all
  --categories        Comma-separated category IDs (e.g. sqli,xss,bac)
  --all               Run all 33 categories
  -o, --output        Output file: report.json / report.csv / report.html
  -v, --verbose       Verbose output
  --list-categories   List all available category IDs
  -h, --help          Show this help message
```

---

## 📁 Project Structure

```
securehawk/
├── SecureHawk.html     # Browser-based UI (no install needed)
├── securehawk.py       # Terminal CLI tool
├── README.md           # This file
└── LICENSE             # MIT License
```

---

## 🔧 Requirements

| Requirement | Version |
|-------------|---------|
| Python | 3.8 or higher |
| colorama | Latest (`pip install colorama`) |
| Browser | Any modern browser (Chrome, Firefox, Safari, Edge) |

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
  <b>SecureHawk v2.0</b> — Advanced Pentesting Suite
</p>
