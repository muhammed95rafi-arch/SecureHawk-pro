#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║   SecureHawk v3.0 — Real Pentesting CLI Suite                   ║
║   Live HTTP · SSL · DNS · Header · Path · AI Analysis           ║
║   Supports: Kali Linux | Termux | macOS | Windows               ║
║   ⚠  FOR AUTHORIZED TESTING ONLY                                ║
╚══════════════════════════════════════════════════════════════════╝

Install deps:
    pip install requests colorama urllib3

Usage:
    python3 securehawk.py -u https://target.com
    python3 securehawk.py -u https://target.com -t web --categories headers,ssl,cors
    python3 securehawk.py -u https://target.com --all -o report.json
    python3 securehawk.py -u https://target.com --all -o report.html -v
    python3 securehawk.py --list-categories
"""

import argparse
import json
import sys
import time
import os
import platform
import datetime
import socket
import ssl
import urllib.parse
import re
import csv
from typing import List, Dict, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

# ── Colorama ──────────────────────────────────────────────────────────────────
try:
    from colorama import Fore, Back, Style, init as colorama_init
    colorama_init(autoreset=True)
    HAS_COLOR = True
except ImportError:
    class Fore:
        RED='\033[91m'; GREEN='\033[92m'; YELLOW='\033[93m'; CYAN='\033[96m'
        WHITE='\033[97m'; MAGENTA='\033[95m'; BLUE='\033[94m'
        LIGHTBLACK_EX='\033[90m'; RESET='\033[0m'
    class Style:
        BRIGHT='\033[1m'; DIM='\033[2m'; RESET_ALL='\033[0m'
    class Back:
        RED='\033[41m'; RESET='\033[0m'
    HAS_COLOR = True

# ── Requests ──────────────────────────────────────────────────────────────────
try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

# ── Constants ─────────────────────────────────────────────────────────────────
VERSION = "3.0.0"

BANNER = f"""
{Fore.CYAN}{Style.BRIGHT}
 ███████╗███████╗ ██████╗██╗   ██╗██████╗ ███████╗██╗  ██╗ █████╗ ██╗    ██╗██╗  ██╗
 ██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██╔════╝██║  ██║██╔══██╗██║    ██║██║ ██╔╝
 ███████╗█████╗  ██║     ██║   ██║██████╔╝█████╗  ███████║███████║██║ █╗ ██║█████╔╝
 ╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██╔══╝  ██╔══██║██╔══██║██║███╗██║██╔═██╗
 ███████║███████╗╚██████╗╚██████╔╝██║  ██║███████╗██║  ██║██║  ██║╚███╔███╔╝██║  ██╗
 ╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═╝
{Style.RESET_ALL}
{Fore.WHITE}  Real Pentesting Suite v{VERSION} | {Fore.YELLOW}⚡ LIVE SCAN MODE{Style.RESET_ALL}
{Fore.LIGHTBLACK_EX}  Platform: {platform.system()} | Python {sys.version.split()[0]}{Style.RESET_ALL}
"""

SEV_COLOR = {
    "critical": Fore.RED + Style.BRIGHT,
    "high":     Fore.YELLOW + Style.BRIGHT,
    "medium":   Fore.YELLOW,
    "low":      Fore.GREEN,
    "info":     Fore.CYAN,
}
SEV_WEIGHT = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

CATEGORIES = {
    "headers":       {"name": "Security Headers",          "type": "web",    "icon": "🛡️"},
    "ssl":           {"name": "SSL/TLS Analysis",           "type": "web",    "icon": "🔐"},
    "cors":          {"name": "CORS Policy",                "type": "web",    "icon": "🔄"},
    "cookies":       {"name": "Cookie Security",            "type": "web",    "icon": "🍪"},
    "xss":           {"name": "XSS Vectors",                "type": "web",    "icon": "⚡"},
    "sqli":          {"name": "SQL Injection",              "type": "web",    "icon": "💉"},
    "infodisclosure":{"name": "Information Disclosure",     "type": "web",    "icon": "📢"},
    "exposed":       {"name": "Exposed Files/Paths",        "type": "web",    "icon": "📁"},
    "dns":           {"name": "DNS Analysis",               "type": "web",    "icon": "🌐"},
    "bac":           {"name": "Broken Access Control",      "type": "web",    "icon": "🔓"},
    "ssrf":          {"name": "SSRF Vectors",               "type": "web",    "icon": "🔁"},
    "misconfig":     {"name": "Misconfigurations",          "type": "web",    "icon": "⚙️"},
    "ratelimit":     {"name": "Rate Limiting",              "type": "web",    "icon": "🚦"},
    "mobile":        {"name": "Mobile Pentesting",          "type": "mobile", "icon": "📱"},
    "storage":       {"name": "Insecure Data Storage",      "type": "mobile", "icon": "💾"},
    "certpin":       {"name": "Certificate Pinning",        "type": "mobile", "icon": "📜"},
    "re":            {"name": "Reverse Engineering",        "type": "re",     "icon": "🔬"},
    "hardcoded":     {"name": "Hardcoded Secrets",          "type": "re",     "icon": "🗝️"},
    "weakcrypto":    {"name": "Weak Cryptography",          "type": "re",     "icon": "🔑"},
    "adversarial":   {"name": "Adversarial Prompting",      "type": "ai",     "icon": "🤖"},
    "promptinj":     {"name": "Prompt Injection",           "type": "ai",     "icon": "💬"},
}

SENSITIVE_PATHS = [
    "/robots.txt", "/.well-known/security.txt", "/sitemap.xml",
    "/.git/config", "/.git/HEAD", "/.env", "/.env.local", "/.env.backup",
    "/wp-admin/", "/wp-login.php", "/admin/", "/admin/login",
    "/phpinfo.php", "/info.php", "/test.php",
    "/config.php", "/config.yml", "/config.json",
    "/backup/", "/backup.zip", "/backup.tar.gz",
    "/api/", "/api/v1/", "/swagger/", "/swagger-ui.html",
    "/actuator/", "/actuator/env", "/actuator/health",
    "/.htaccess", "/web.config", "/server-status",
    "/crossdomain.xml", "/clientaccesspolicy.xml",
]

SECURITY_HEADERS = [
    ("Strict-Transport-Security", "HSTS", "high",
     "Missing HSTS allows protocol downgrade attacks.",
     "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"),
    ("Content-Security-Policy", "CSP", "high",
     "Missing CSP allows XSS attacks via inline scripts and untrusted sources.",
     "Define a strict Content-Security-Policy header. Start with: default-src 'self'"),
    ("X-Frame-Options", "Clickjacking Protection", "medium",
     "Page can be embedded in iframes — clickjacking attack possible.",
     "Add: X-Frame-Options: DENY (or use CSP frame-ancestors)"),
    ("X-Content-Type-Options", "MIME Sniffing", "medium",
     "Browser may MIME-sniff content type, enabling XSS via file uploads.",
     "Add: X-Content-Type-Options: nosniff"),
    ("Referrer-Policy", "Referrer Leakage", "low",
     "No Referrer-Policy — sensitive URL data may leak to third parties.",
     "Add: Referrer-Policy: strict-origin-when-cross-origin"),
    ("Permissions-Policy", "Feature Policy", "low",
     "No Permissions-Policy — browser features (camera, mic) unrestricted.",
     "Add: Permissions-Policy: camera=(), microphone=(), geolocation=()"),
    ("X-XSS-Protection", "Legacy XSS Filter", "info",
     "X-XSS-Protection header absent (informational for modern browsers).",
     "Add: X-XSS-Protection: 1; mode=block (for legacy browser support)"),
]

# ── Utilities ─────────────────────────────────────────────────────────────────
def sev_tag(sev: str) -> str:
    color = SEV_COLOR.get(sev, Fore.WHITE)
    return f"{color}[{sev.upper():^8}]{Style.RESET_ALL}"

def print_sep(char="─", width=72, color=Fore.LIGHTBLACK_EX):
    print(f"{color}{char * width}{Style.RESET_ALL}")

def print_banner():
    print(BANNER)

def print_progress(current, total, label, width=42):
    pct = current / total if total > 0 else 0
    filled = int(width * pct)
    bar = "█" * filled + "░" * (width - filled)
    sys.stdout.write(f"\r  {Fore.CYAN}[{bar}]{Style.RESET_ALL} {pct*100:5.1f}%  {Fore.WHITE}{label:<38}{Style.RESET_ALL}")
    sys.stdout.flush()

def log(msg, level="info", indent=2):
    colors = {"info": Fore.CYAN, "warn": Fore.YELLOW, "error": Fore.RED,
              "ok": Fore.GREEN, "dim": Fore.LIGHTBLACK_EX, "debug": Fore.LIGHTBLACK_EX}
    prefix = {"info": "◈", "warn": "!", "error": "✗", "ok": "✓", "dim": "·", "debug": "·"}
    c = colors.get(level, Fore.WHITE)
    p = prefix.get(level, "·")
    print(f"{' ' * indent}{c}{p}{Style.RESET_ALL} {msg}")

# ── Real Scanner Modules ───────────────────────────────────────────────────────

def make_session() -> "requests.Session":
    s = requests.Session()
    s.headers.update({
        "User-Agent": "SecureHawk/3.0 Security Scanner (authorized-testing)",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
    })
    return s


def fetch_target(url: str, session, timeout=10, verify=False) -> Optional[requests.Response]:
    try:
        r = session.get(url, timeout=timeout, verify=verify, allow_redirects=True)
        return r
    except Exception as e:
        return None


def check_headers(response, target_url: str) -> List[Dict]:
    findings = []
    headers = {k.lower(): v for k, v in response.headers.items()}

    for header, label, severity, desc, fix in SECURITY_HEADERS:
        if header.lower() not in headers:
            findings.append({
                "title": f"Missing {label} Header ({header})",
                "severity": severity, "cvss": {"high": 7.2, "medium": 5.3, "low": 3.1, "info": 0.0}.get(severity, 0),
                "cwe": "CWE-693",
                "description": desc,
                "payload": f"curl -I {target_url}",
                "evidence": f"Header '{header}' absent in HTTP response",
                "remediation": fix,
                "location": f"{target_url} → HTTP Response Headers",
            })

    # Check dangerous headers present
    server = headers.get("server", "")
    if server and any(c.isdigit() for c in server):
        findings.append({
            "title": "Server Version Disclosure",
            "severity": "medium", "cvss": 5.3, "cwe": "CWE-200",
            "description": "Server header reveals exact software version. Aids targeted attacks.",
            "payload": f"curl -I {target_url} | grep Server",
            "evidence": f"Server: {server}",
            "remediation": "Set ServerTokens Prod (Apache) or server_tokens off (Nginx). Remove version strings.",
            "location": f"{target_url} → Server header",
        })

    xpb = headers.get("x-powered-by", "")
    if xpb:
        findings.append({
            "title": "Technology Disclosure via X-Powered-By",
            "severity": "low", "cvss": 3.1, "cwe": "CWE-200",
            "description": "X-Powered-By header reveals backend technology stack.",
            "payload": f"curl -I {target_url} | grep X-Powered-By",
            "evidence": f"X-Powered-By: {xpb}",
            "remediation": "Remove X-Powered-By header. In PHP: expose_php = Off. In Express: app.disable('x-powered-by').",
            "location": f"{target_url} → X-Powered-By header",
        })

    return findings


def check_ssl(url: str) -> List[Dict]:
    findings = []
    parsed = urllib.parse.urlparse(url)
    hostname = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    if parsed.scheme != "https":
        findings.append({
            "title": "Site Not Using HTTPS",
            "severity": "critical", "cvss": 9.1, "cwe": "CWE-319",
            "description": "All traffic is transmitted in plaintext. Credentials and data exposed to MITM.",
            "payload": f"tcpdump -i any host {hostname}",
            "evidence": f"URL scheme is HTTP not HTTPS: {url}",
            "remediation": "Enable HTTPS. Obtain TLS certificate (Let's Encrypt is free). Redirect all HTTP → HTTPS.",
            "location": url,
        })
        return findings

    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.create_connection((hostname, port), timeout=8), server_hostname=hostname) as conn:
            cert = conn.getpeercert()
            cipher = conn.cipher()
            version = conn.version()

            # Check expiry
            expire_str = cert.get("notAfter", "")
            if expire_str:
                from datetime import datetime as dt
                expire_dt = dt.strptime(expire_str, "%b %d %H:%M:%S %Y %Z")
                days_left = (expire_dt - dt.utcnow()).days
                if days_left < 30:
                    sev = "critical" if days_left < 7 else "high"
                    findings.append({
                        "title": f"SSL Certificate Expiring Soon ({days_left} days)",
                        "severity": sev, "cvss": 8.1, "cwe": "CWE-295",
                        "description": f"Certificate expires in {days_left} days. Expiry causes browser warnings and connection failures.",
                        "payload": f"openssl s_client -connect {hostname}:{port} | openssl x509 -noout -dates",
                        "evidence": f"notAfter: {expire_str} ({days_left} days remaining)",
                        "remediation": "Renew certificate immediately. Set up auto-renewal (certbot --renew).",
                        "location": f"{hostname}:{port} → SSL Certificate",
                    })

            # Weak TLS version
            if version in ("TLSv1", "TLSv1.1", "SSLv2", "SSLv3"):
                findings.append({
                    "title": f"Weak TLS Version in Use: {version}",
                    "severity": "high", "cvss": 7.5, "cwe": "CWE-326",
                    "description": f"{version} is deprecated and vulnerable to POODLE, BEAST, and similar attacks.",
                    "payload": f"openssl s_client -connect {hostname}:{port} -{version.lower().replace('.','')}",
                    "evidence": f"Negotiated TLS version: {version}",
                    "remediation": "Disable TLS 1.0 and 1.1. Enforce TLS 1.2 minimum, prefer TLS 1.3.",
                    "location": f"{hostname}:{port} → TLS Configuration",
                })

            # Weak cipher
            if cipher and any(w in str(cipher).upper() for w in ["RC4", "DES", "NULL", "EXPORT", "MD5"]):
                findings.append({
                    "title": f"Weak Cipher Suite Negotiated",
                    "severity": "high", "cvss": 7.4, "cwe": "CWE-327",
                    "description": f"Server negotiated a weak or insecure cipher suite.",
                    "payload": f"openssl s_client -connect {hostname}:{port} -cipher RC4",
                    "evidence": f"Cipher: {cipher}",
                    "remediation": "Configure server to support only ECDHE+AESGCM ciphers. Disable RC4, DES, EXPORT.",
                    "location": f"{hostname}:{port} → TLS Cipher",
                })

    except ssl.SSLCertVerificationError as e:
        findings.append({
            "title": "Invalid or Self-Signed SSL Certificate",
            "severity": "high", "cvss": 7.4, "cwe": "CWE-295",
            "description": "Certificate validation failed. Users are vulnerable to MITM attacks.",
            "payload": f"openssl s_client -connect {hostname}:{port}",
            "evidence": str(e),
            "remediation": "Install a valid certificate from a trusted CA. Use Let's Encrypt for free certificates.",
            "location": f"{hostname}:{port} → SSL Certificate",
        })
    except Exception:
        pass

    return findings


def check_cors(response, target_url: str, session) -> List[Dict]:
    findings = []
    acao = response.headers.get("Access-Control-Allow-Origin", "")
    acac = response.headers.get("Access-Control-Allow-Credentials", "")

    if acao == "*" and acac.lower() == "true":
        findings.append({
            "title": "CORS Wildcard with Credentials Allowed",
            "severity": "critical", "cvss": 9.1, "cwe": "CWE-942",
            "description": "CORS wildcard combined with credentials enables any website to make authenticated requests on behalf of users.",
            "payload": "fetch('{url}',{{credentials:'include'}}) from attacker.com".format(url=target_url),
            "evidence": f"Access-Control-Allow-Origin: {acao}\nAccess-Control-Allow-Credentials: {acac}",
            "remediation": "Never use '*' with credentials. Explicitly whitelist specific trusted origins.",
            "location": f"{target_url} → CORS Headers",
        })
    elif acao == "*":
        findings.append({
            "title": "Overly Permissive CORS Policy (Wildcard)",
            "severity": "medium", "cvss": 5.4, "cwe": "CWE-942",
            "description": "API accepts requests from any origin. May expose non-public data.",
            "payload": f"curl -H 'Origin: https://evil.com' {target_url}",
            "evidence": f"Access-Control-Allow-Origin: *",
            "remediation": "Restrict CORS to specific trusted origins instead of using wildcard.",
            "location": f"{target_url} → CORS Headers",
        })

    # Test arbitrary origin reflection
    try:
        evil_origin = "https://evil-securehawk-test.com"
        r2 = session.get(target_url, headers={"Origin": evil_origin}, timeout=8, verify=False)
        reflected = r2.headers.get("Access-Control-Allow-Origin", "")
        if reflected == evil_origin:
            findings.append({
                "title": "CORS Arbitrary Origin Reflection",
                "severity": "high", "cvss": 8.1, "cwe": "CWE-942",
                "description": "Server reflects arbitrary Origin header. Any domain can make cross-origin requests.",
                "payload": f"curl -H 'Origin: {evil_origin}' {target_url}",
                "evidence": f"Sent Origin: {evil_origin} → Got ACAO: {reflected}",
                "remediation": "Maintain an explicit allowlist of trusted origins. Do not reflect user-supplied Origin.",
                "location": f"{target_url} → CORS Reflection",
            })
    except Exception:
        pass

    return findings


def check_cookies(response, target_url: str) -> List[Dict]:
    findings = []
    is_https = target_url.startswith("https://")

    for cookie in response.cookies:
        issues = []
        name = cookie.name

        if not cookie.has_nonstandard_attr("HttpOnly") and "httponly" not in str(cookie._rest).lower():
            issues.append(("Missing HttpOnly flag", "medium", "CWE-1004",
                "Cookie without HttpOnly accessible via JavaScript. XSS can steal session.",
                "Add HttpOnly flag to all session cookies: Set-Cookie: session=...; HttpOnly"))

        if is_https and not cookie.secure:
            issues.append(("Missing Secure flag", "medium", "CWE-614",
                "Cookie sent over HTTP. Can be intercepted on unencrypted connections.",
                "Add Secure flag: Set-Cookie: session=...; Secure"))

        samesite = str(cookie._rest).lower()
        if "samesite" not in samesite:
            issues.append(("Missing SameSite attribute", "medium", "CWE-352",
                "Cookie without SameSite can be sent in CSRF attacks.",
                "Add SameSite=Strict or SameSite=Lax to all cookies."))

        for title, severity, cwe, desc, fix in issues:
            findings.append({
                "title": f"{title} on Cookie '{name}'",
                "severity": severity, "cvss": 5.9, "cwe": cwe,
                "description": desc,
                "payload": f"document.cookie (JavaScript access to {name})",
                "evidence": f"Set-Cookie: {name}={cookie.value[:20]}... [flags checked: {cookie._rest}]",
                "remediation": fix,
                "location": f"{target_url} → Set-Cookie: {name}",
            })

    return findings


def check_exposed_paths(base_url: str, session) -> List[Dict]:
    findings = []
    parsed = urllib.parse.urlparse(base_url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    log(f"Probing {len(SENSITIVE_PATHS)} sensitive paths...", "dim")

    for path in SENSITIVE_PATHS:
        url = base + path
        try:
            r = session.get(url, timeout=6, verify=False, allow_redirects=False)
            if r.status_code in (200, 206):
                body_snippet = r.text[:300].strip()

                # Classify what was found
                sev, desc = "medium", f"Path {path} is accessible (HTTP {r.status_code})"

                if ".git" in path:
                    sev = "critical"
                    desc = "Git repository exposed. Full source code and commit history accessible."
                elif ".env" in path:
                    sev = "critical"
                    desc = "Environment file exposed. May contain API keys, DB passwords, secrets."
                elif "phpinfo" in path or "info.php" in path:
                    sev = "high"
                    desc = "phpinfo() page exposed. Reveals PHP config, server paths, loaded modules."
                elif "actuator" in path:
                    sev = "high"
                    desc = "Spring Boot Actuator endpoint exposed. May leak environment variables and config."
                elif "swagger" in path:
                    sev = "medium"
                    desc = "API documentation (Swagger/OpenAPI) publicly accessible."
                elif "backup" in path:
                    sev = "critical"
                    desc = "Backup file accessible. May contain database dumps or source code."
                elif "robots.txt" in path:
                    sev = "info"
                    desc = f"robots.txt found — reveals hidden paths:\n{body_snippet}"

                findings.append({
                    "title": f"Exposed Path: {path}",
                    "severity": sev,
                    "cvss": {"critical": 9.8, "high": 7.5, "medium": 5.3, "low": 3.1, "info": 0.0}[sev],
                    "cwe": "CWE-548",
                    "description": desc,
                    "payload": f"curl -v {url}",
                    "evidence": f"HTTP {r.status_code} | Content-Length: {len(r.content)} bytes\nSnippet: {body_snippet[:200]}",
                    "remediation": f"Restrict access to {path}. Add authentication or deny rule in web server config.",
                    "location": url,
                })
        except Exception:
            pass

    return findings


def check_dns(target_url: str) -> List[Dict]:
    findings = []
    parsed = urllib.parse.urlparse(target_url)
    hostname = parsed.hostname

    # Resolve A records
    try:
        ips = socket.getaddrinfo(hostname, None)
        ip_list = list(set(r[4][0] for r in ips))

        # Check for private IPs (shouldn't resolve to these publicly)
        private_ranges = [
            ("10.", "RFC-1918 class A"),
            ("192.168.", "RFC-1918 class C"),
            ("172.16.", "RFC-1918 class B"),
        ]
        for ip in ip_list:
            for prefix, label in private_ranges:
                if ip.startswith(prefix):
                    findings.append({
                        "title": f"Domain Resolves to Private IP ({label})",
                        "severity": "high", "cvss": 7.5, "cwe": "CWE-918",
                        "description": f"Hostname resolves to private IP range. May indicate SSRF vector or DNS misconfiguration.",
                        "payload": f"dig {hostname}",
                        "evidence": f"{hostname} → {ip}",
                        "remediation": "Ensure public domain does not resolve to private IP ranges. Review DNS configuration.",
                        "location": f"DNS: {hostname}",
                    })

    except Exception as e:
        findings.append({
            "title": "DNS Resolution Failed",
            "severity": "info", "cvss": 0.0, "cwe": "CWE-0",
            "description": "Could not resolve hostname. Host may be down or DNS misconfigured.",
            "payload": f"dig {hostname}",
            "evidence": str(e),
            "remediation": "Verify DNS configuration and host availability.",
            "location": f"DNS: {hostname}",
        })

    # Zone transfer attempt
    try:
        import dns.resolver
        import dns.zone
        ns_records = dns.resolver.resolve(hostname, 'NS')
        for ns in ns_records:
            try:
                zone = dns.zone.from_xfr(dns.query.xfr(str(ns), hostname, timeout=4))
                if zone:
                    findings.append({
                        "title": "DNS Zone Transfer Allowed (AXFR)",
                        "severity": "critical", "cvss": 9.3, "cwe": "CWE-200",
                        "description": "DNS server allows full zone transfer. All subdomains and internal records exposed.",
                        "payload": f"dig AXFR {hostname} @{ns}",
                        "evidence": f"Zone transfer succeeded from nameserver: {ns}",
                        "remediation": "Restrict AXFR to authorized IPs only. Configure allow-transfer in BIND.",
                        "location": f"DNS Nameserver: {ns}",
                    })
            except Exception:
                pass
    except ImportError:
        pass
    except Exception:
        pass

    return findings


def check_information_disclosure(response, target_url: str) -> List[Dict]:
    findings = []
    body = response.text[:10000] if response.text else ""
    headers = {k.lower(): v for k, v in response.headers.items()}

    # Patterns to detect in body
    patterns = [
        (r"(?i)(mysql_fetch|pg_connect|ORA-\d+|Microsoft OLE DB|SQL syntax.*MySQL|Warning.*mysqli)",
         "Database Error Leaked in Response", "critical", 9.8, "CWE-209",
         "Database error messages exposed. Confirms DB type and may reveal table/column names."),
        (r"(?i)(stack trace|traceback \(most recent|at [\w\.]+\.java:\d+|in /\w+/[\w/]+\.php)",
         "Stack Trace Exposed in Response", "high", 7.5, "CWE-209",
         "Server-side stack trace reveals internal file paths, class names, and code structure."),
        (r"(?i)(AWS_ACCESS_KEY|AKIA[0-9A-Z]{16}|api[_-]?key\s*[:=]\s*['\"][a-zA-Z0-9]{20,})",
         "Potential API Key/Secret in Response", "critical", 9.9, "CWE-798",
         "API key or credential pattern detected in HTTP response body."),
        (r"(?i)(password\s*[:=]\s*['\"][^'\"]{6,}|passwd\s*[:=]\s*['\"][^'\"]{6,})",
         "Plaintext Password in Response Body", "critical", 9.8, "CWE-312",
         "Password or credential string detected in HTTP response."),
        (r"(?i)(private[_-]?key|BEGIN RSA PRIVATE|BEGIN PRIVATE KEY)",
         "Private Key Material in Response", "critical", 10.0, "CWE-320",
         "Private key material detected in HTTP response."),
        (r"(?i)(phpinfo\(\)|PHP Version \d+\.\d+\.\d+)",
         "PHP Version Disclosure in Body", "medium", 5.3, "CWE-200",
         "PHP version information exposed in response body."),
        (r"/home/\w+/|/var/www/|/usr/local/|C:\\Users\\|C:\\inetpub\\",
         "Internal File Path Disclosure", "medium", 5.3, "CWE-200",
         "Internal server file system paths revealed in response."),
    ]

    for pattern, title, severity, cvss, cwe, desc in patterns:
        match = re.search(pattern, body)
        if match:
            snippet = match.group(0)[:120]
            findings.append({
                "title": title,
                "severity": severity, "cvss": cvss, "cwe": cwe,
                "description": desc,
                "payload": f"curl {target_url} | grep -E '{pattern[:50]}'",
                "evidence": f"Found in response body: '{snippet}'",
                "remediation": "Remove sensitive data from responses. Implement generic error handling. Never expose internals.",
                "location": target_url,
            })

    return findings


def check_xss_vectors(response, target_url: str, session) -> List[Dict]:
    findings = []
    body = response.text if response.text else ""

    # Check for reflected parameters
    parsed = urllib.parse.urlparse(target_url)
    if parsed.query:
        params = urllib.parse.parse_qs(parsed.query)
        xss_payload = "<script>alert('XSS')</script>"
        for param in list(params.keys())[:3]:  # Test first 3 params
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{param}={urllib.parse.quote(xss_payload)}"
            try:
                r = session.get(test_url, timeout=6, verify=False)
                if xss_payload in r.text or xss_payload.lower() in r.text.lower():
                    findings.append({
                        "title": f"Reflected XSS — Parameter '{param}'",
                        "severity": "high", "cvss": 7.4, "cwe": "CWE-79",
                        "description": f"XSS payload reflected unescaped in HTTP response via parameter '{param}'.",
                        "payload": f"{test_url}",
                        "evidence": f"Payload <script>alert('XSS')</script> reflected in response body",
                        "remediation": "HTML-encode all user-supplied output. Implement Content-Security-Policy.",
                        "location": f"{target_url} → ?{param}=",
                    })
            except Exception:
                pass

    # Check for inline scripts (potential DOM XSS surface)
    inline_scripts = re.findall(r'<script[^>]*>(.*?)</script>', body, re.DOTALL | re.IGNORECASE)
    unsafe_sinks = ["document.write", "innerHTML", "outerHTML", "eval(", "setTimeout(", "setInterval("]
    for script in inline_scripts:
        for sink in unsafe_sinks:
            if sink in script and ("location" in script or "search" in script or "hash" in script or "param" in script.lower()):
                findings.append({
                    "title": f"Potential DOM XSS Sink: {sink}",
                    "severity": "medium", "cvss": 6.1, "cwe": "CWE-79",
                    "description": f"Inline JavaScript uses dangerous sink '{sink}' with URL data — potential DOM XSS.",
                    "payload": f"{target_url}#<img src=x onerror=alert(1)>",
                    "evidence": f"Found '{sink}' in inline script reading URL/DOM data",
                    "remediation": "Avoid dangerous sinks. Use textContent instead of innerHTML. Sanitize with DOMPurify.",
                    "location": f"{target_url} → Inline <script>",
                })
                break

    return findings


def check_sqli_vectors(target_url: str, session) -> List[Dict]:
    findings = []
    parsed = urllib.parse.urlparse(target_url)
    if not parsed.query:
        return findings

    params = urllib.parse.parse_qs(parsed.query)
    sqli_payloads = ["'", "\"", "' OR '1'='1", "1 AND SLEEP(1)--"]

    for param in list(params.keys())[:3]:
        original_val = params[param][0]
        for payload in sqli_payloads[:2]:  # Basic checks only
            test_params = {**{k: v[0] for k, v in params.items()}, param: original_val + payload}
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?" + urllib.parse.urlencode(test_params)
            try:
                r = session.get(test_url, timeout=8, verify=False)
                body = r.text.lower()
                sql_errors = ["sql syntax", "mysql_fetch", "ora-", "pg_", "microsoft ole db",
                              "sqlite_", "you have an error in your sql", "warning: mysql"]
                for err in sql_errors:
                    if err in body:
                        findings.append({
                            "title": f"SQL Error — Possible SQLi in Parameter '{param}'",
                            "severity": "high", "cvss": 8.8, "cwe": "CWE-89",
                            "description": f"SQL error message triggered by injecting into parameter '{param}'. Indicates unsanitized SQL query.",
                            "payload": test_url,
                            "evidence": f"SQL error pattern '{err}' found in response after injecting: {payload}",
                            "remediation": "Use parameterized queries/prepared statements. Never concatenate user input in SQL. Use an ORM.",
                            "location": f"{target_url} → ?{param}=",
                        })
                        break
            except Exception:
                pass

    return findings


def check_ratelimit(target_url: str, session) -> List[Dict]:
    findings = []
    # Send 10 rapid requests and check if rate limiting kicks in
    statuses = []
    try:
        for _ in range(10):
            r = session.get(target_url, timeout=5, verify=False)
            statuses.append(r.status_code)
        # If all 10 return 200 without 429/503
        if statuses.count(200) == 10:
            findings.append({
                "title": "No Rate Limiting Detected",
                "severity": "medium", "cvss": 5.3, "cwe": "CWE-307",
                "description": "10 rapid consecutive requests returned HTTP 200 with no throttling or rate limit response.",
                "payload": "for i in $(seq 10); do curl -s -o /dev/null -w '%{http_code}\\n' " + target_url + "; done",
                "evidence": f"10/10 requests returned HTTP 200 (statuses: {statuses})",
                "remediation": "Implement rate limiting (e.g., 60 requests/minute per IP). Return 429 on excess. Use Nginx/Cloudflare rate limiting.",
                "location": target_url,
            })
    except Exception:
        pass
    return findings


# ── AI Analysis ───────────────────────────────────────────────────────────────

def ai_analyze(target: str, collected_data: dict, categories: List[str], api_key: str) -> List[Dict]:
    """Send collected data to Claude AI for deep analysis."""
    try:
        import http.client
        import urllib.request

        prompt = f"""You are an expert penetration tester. Analyze this REAL data collected from a live target and identify security vulnerabilities NOT already covered by automated checks.

TARGET: {target}
CATEGORIES: {', '.join(categories)}

=== COLLECTED DATA ===
HTTP Status: {collected_data.get('status_code')}
Response Headers:
{json.dumps(collected_data.get('headers', {}), indent=2)}

Body Snippet (first 3000 chars):
{collected_data.get('body_snippet', '')[:3000]}

Accessible Paths Found: {collected_data.get('accessible_paths', [])}
SSL Info: {collected_data.get('ssl_info', {})}
DNS IPs: {collected_data.get('dns_ips', [])}

=== TASK ===
Identify additional security issues from this data. Focus on:
- Business logic flaws visible in HTML/JS
- Hardcoded tokens, keys, or credentials in page source
- Insecure form configurations (no CSRF tokens, autocomplete on passwords)
- Third-party scripts from untrusted CDNs
- Comment disclosures (developer comments with sensitive info)
- Outdated library versions in script tags
- Email/phone/PII exposure in response
- Open redirect indicators
- Interesting endpoints in JS source
- Any other real issues from the actual data

Return ONLY a JSON array. Each finding:
{{
  "title": "...",
  "severity": "critical|high|medium|low|info",
  "cvss": 0.0,
  "cwe": "CWE-XXX",
  "location": "exact location",
  "description": "what was found and why it matters",
  "payload": "proof of concept",
  "evidence": "exact text or data from the response",
  "remediation": "how to fix"
}}

Return [] if no additional issues found. Return ONLY the JSON array."""

        payload = json.dumps({
            "model": "claude-sonnet-4-20250514",
            "max_tokens": 3000,
            "messages": [{"role": "user", "content": prompt}]
        }).encode("utf-8")

        req = urllib.request.Request(
            "https://api.anthropic.com/v1/messages",
            data=payload,
            headers={
                "Content-Type": "application/json",
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
            },
            method="POST"
        )

        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            text = "".join(b.get("text", "") for b in data.get("content", []))
            clean = re.sub(r"```json\n?|```\n?", "", text).strip()
            return json.loads(clean)

    except Exception as e:
        log(f"AI analysis skipped: {e}", "warn")
        return []


# ── Main Scanner ───────────────────────────────────────────────────────────────

class SecureHawk:
    def __init__(self, target: str, scan_type: str, categories: List[str],
                 verbose: bool = False, api_key: Optional[str] = None):
        self.target = target
        self.scan_type = scan_type
        self.categories = categories
        self.verbose = verbose
        self.api_key = api_key
        self.findings: List[Dict] = []
        self.start_time = None
        self.end_time = None
        self.session = make_session() if HAS_REQUESTS else None
        self.response = None
        self.collected_data = {}

    def run(self):
        self.start_time = time.time()
        print_banner()

        print(f"  {Fore.WHITE}Target  :{Style.RESET_ALL} {Fore.CYAN}{self.target}{Style.RESET_ALL}")
        print(f"  {Fore.WHITE}Type    :{Style.RESET_ALL} {self.scan_type.upper()}")
        print(f"  {Fore.WHITE}Checks  :{Style.RESET_ALL} {len(self.categories)} categories")
        print(f"  {Fore.WHITE}Mode    :{Style.RESET_ALL} {Fore.GREEN}⚡ REAL LIVE SCAN{Style.RESET_ALL}")
        if self.api_key:
            print(f"  {Fore.WHITE}AI      :{Style.RESET_ALL} {Fore.MAGENTA}Claude AI deep analysis enabled{Style.RESET_ALL}")
        print(f"  {Fore.WHITE}Started :{Style.RESET_ALL} {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print()

        # Phase 1: Initial fetch
        print_sep("─", 72)
        log(f"Phase 1/3: Fetching target...", "info")
        self.response = fetch_target(self.target, self.session)
        if self.response is None:
            log("Could not connect to target. Check URL and network.", "error")
            sys.exit(1)

        log(f"HTTP {self.response.status_code} | {len(self.response.content)} bytes | "
            f"{self.response.elapsed.total_seconds():.2f}s", "ok")

        # Collect data for AI
        self.collected_data = {
            "status_code": self.response.status_code,
            "headers": dict(self.response.headers),
            "body_snippet": self.response.text[:5000] if self.response.text else "",
            "ssl_info": {},
            "dns_ips": [],
            "accessible_paths": [],
        }

        # DNS resolution
        try:
            parsed = urllib.parse.urlparse(self.target)
            ips = list(set(r[4][0] for r in socket.getaddrinfo(parsed.hostname, None)))
            self.collected_data["dns_ips"] = ips
            log(f"Resolved {parsed.hostname} → {', '.join(ips)}", "ok")
        except Exception:
            pass

        # Phase 2: Run checks
        print()
        print_sep("─", 72)
        log("Phase 2/3: Running security checks...", "info")
        print()

        total = len(self.categories)
        all_findings = []

        check_map = {
            "headers":        lambda: check_headers(self.response, self.target),
            "ssl":            lambda: check_ssl(self.target),
            "cors":           lambda: check_cors(self.response, self.target, self.session),
            "cookies":        lambda: check_cookies(self.response, self.target),
            "xss":            lambda: check_xss_vectors(self.response, self.target, self.session),
            "sqli":           lambda: check_sqli_vectors(self.target, self.session),
            "infodisclosure": lambda: check_information_disclosure(self.response, self.target),
            "exposed":        lambda: check_exposed_paths(self.target, self.session),
            "dns":            lambda: check_dns(self.target),
            "ratelimit":      lambda: check_ratelimit(self.target, self.session),
        }

        for i, cat_id in enumerate(self.categories):
            cat_info = CATEGORIES.get(cat_id, {"name": cat_id, "icon": "🔍", "type": "web"})
            print_progress(i, total, f"Testing {cat_info['name']}")

            cat_findings = []
            checker = check_map.get(cat_id)
            if checker:
                try:
                    cat_findings = checker()
                except Exception as e:
                    if self.verbose:
                        log(f"  {cat_id} error: {e}", "warn")

            for f in cat_findings:
                f["category"] = cat_info["name"]
                f["category_id"] = cat_id
                f["icon"] = cat_info["icon"]
                f["target"] = self.target
                all_findings.append(f)

            # Track exposed paths
            if cat_id == "exposed":
                self.collected_data["accessible_paths"] = [
                    f["location"] for f in cat_findings if "critical" in f.get("severity","")
                    or "high" in f.get("severity","")
                ]

        print_progress(total, total, "Live checks complete!")
        print("\n")

        # Phase 3: AI deep analysis
        if self.api_key:
            print_sep("─", 72)
            log("Phase 3/3: Claude AI deep analysis...", "info")
            ai_cats = [c for c in self.categories if c not in check_map]
            ai_cats += ["bac", "ssrf", "misconfig", "hardcoded", "mobile", "storage",
                        "certpin", "re", "weakcrypto", "adversarial", "promptinj", "idor"]
            ai_cats = list(set(ai_cats) & set(self.categories))

            ai_results = ai_analyze(self.target, self.collected_data, ai_cats, self.api_key)
            for f in ai_results:
                f.setdefault("category", "AI Analysis")
                f.setdefault("category_id", "ai")
                f.setdefault("icon", "🤖")
                f.setdefault("target", self.target)
                all_findings.append(f)

            log(f"AI identified {len(ai_results)} additional findings", "ok")
        else:
            log("Phase 3/3: Skipped (use --api-key for Claude AI deep analysis)", "dim")

        self.findings = all_findings
        self.end_time = time.time()
        self._print_results()
        self._print_summary()

    def _print_results(self):
        if not self.findings:
            print(f"\n  {Fore.GREEN}✔ No vulnerabilities detected.{Style.RESET_ALL}\n")
            return

        grouped = {}
        for f in self.findings:
            cid = f.get("category_id", "other")
            if cid not in grouped:
                grouped[cid] = []
            grouped[cid].append(f)

        def max_sev(items):
            return max(SEV_WEIGHT.get(i.get("severity","info"), 0) for i in items)

        for cat_id, items in sorted(grouped.items(), key=lambda x: max_sev(x[1]), reverse=True):
            cat_info = CATEGORIES.get(cat_id, {"name": cat_id, "icon": "🔍", "type": "web"})
            print()
            print_sep("═", 72, Fore.CYAN)
            print(f"{Fore.CYAN}{Style.BRIGHT}  {cat_info.get('icon','🔍')}  {cat_info.get('name',cat_id).upper()}{Style.RESET_ALL}  "
                  f"{Fore.LIGHTBLACK_EX}[{cat_info.get('type','web').upper()}]{Style.RESET_ALL}")
            print_sep("═", 72, Fore.CYAN)

            for finding in sorted(items, key=lambda x: SEV_WEIGHT.get(x.get("severity","info"),0), reverse=True):
                sev = finding.get("severity", "info")
                color = SEV_COLOR.get(sev, Fore.WHITE)
                print()
                print(f"  {sev_tag(sev)}  {color}{finding.get('title','')}{Style.RESET_ALL}")
                print(f"  {Fore.LIGHTBLACK_EX}{'─' * 62}{Style.RESET_ALL}")
                print(f"  {Fore.WHITE}CVSS:{Style.RESET_ALL}  {color}{finding.get('cvss', '?')}/10.0{Style.RESET_ALL}  "
                      f"{Fore.LIGHTBLACK_EX}{finding.get('cwe','')}{Style.RESET_ALL}")
                print(f"  {Fore.WHITE}Loc :{Style.RESET_ALL}  {Fore.CYAN}{finding.get('location','')}{Style.RESET_ALL}")
                print(f"  {Fore.WHITE}Desc:{Style.RESET_ALL}  {finding.get('description','')}")
                if finding.get("evidence"):
                    evid = finding["evidence"].replace("\n", " | ")[:160]
                    print(f"  {Fore.MAGENTA}Evid:{Style.RESET_ALL}  {Fore.MAGENTA}{evid}{Style.RESET_ALL}")
                print(f"  {Fore.YELLOW}PoC :{Style.RESET_ALL}  {Fore.YELLOW}{finding.get('payload','')[:120]}{Style.RESET_ALL}")
                print(f"  {Fore.GREEN}Fix :{Style.RESET_ALL}  {Fore.GREEN}{finding.get('remediation','')}{Style.RESET_ALL}")
        print()

    def _print_summary(self):
        elapsed = self.end_time - self.start_time if self.end_time else 0
        counts = {s: sum(1 for f in self.findings if f.get("severity")==s)
                  for s in ["critical","high","medium","low","info"]}
        risk = min(100, counts["critical"]*25 + counts["high"]*10 + counts["medium"]*4 + counts["low"]*1)
        risk_color = Fore.RED if risk>=75 else Fore.YELLOW if risk>=50 else Fore.GREEN

        print()
        print_sep("═", 72, Fore.WHITE)
        print(f"{Fore.WHITE}{Style.BRIGHT}  SCAN SUMMARY{Style.RESET_ALL}")
        print_sep("─", 72, Fore.LIGHTBLACK_EX)
        print(f"  Target        : {Fore.CYAN}{self.target}{Style.RESET_ALL}")
        print(f"  Duration      : {elapsed:.1f}s")
        print(f"  Mode          : {Fore.GREEN}⚡ REAL LIVE SCAN{Style.RESET_ALL}")
        print(f"  Total Findings: {len(self.findings)}")
        print()
        print(f"  {SEV_COLOR['critical']}CRITICAL  : {counts['critical']}{Style.RESET_ALL}")
        print(f"  {SEV_COLOR['high']}HIGH      : {counts['high']}{Style.RESET_ALL}")
        print(f"  {SEV_COLOR['medium']}MEDIUM    : {counts['medium']}{Style.RESET_ALL}")
        print(f"  {SEV_COLOR['low']}LOW       : {counts['low']}{Style.RESET_ALL}")
        print(f"  {SEV_COLOR['info']}INFO      : {counts['info']}{Style.RESET_ALL}")
        print()
        print(f"  Risk Score    : {risk_color}{Style.BRIGHT}{risk}/100{Style.RESET_ALL}")
        print_sep("═", 72, Fore.WHITE)
        print()

    def export(self, filepath: str):
        data = {
            "tool": "SecureHawk", "version": VERSION, "mode": "real-live-scan",
            "target": self.target, "scan_type": self.scan_type,
            "timestamp": datetime.datetime.now().isoformat(),
            "total_findings": len(self.findings),
            "findings": self.findings
        }
        ext = filepath.rsplit(".", 1)[-1].lower() if "." in filepath else "json"

        if ext == "json":
            with open(filepath, "w") as f:
                json.dump(data, f, indent=2)

        elif ext == "csv":
            with open(filepath, "w", newline="", encoding="utf-8") as f:
                fields = ["category","title","severity","cvss","cwe","location","evidence","remediation","target"]
                writer = csv.DictWriter(f, fieldnames=fields)
                writer.writeheader()
                for fi in self.findings:
                    writer.writerow({k: str(fi.get(k,""))[:500] for k in fields})

        elif ext in ("html", "htm"):
            self._export_html(filepath, data)

        else:
            with open(filepath, "w") as f:
                for fi in self.findings:
                    f.write(f"\n[{fi.get('severity','?').upper()}] {fi.get('title','')}\n")
                    f.write(f"  Location   : {fi.get('location','')}\n")
                    f.write(f"  CVSS       : {fi.get('cvss','?')} | {fi.get('cwe','')}\n")
                    f.write(f"  Description: {fi.get('description','')}\n")
                    if fi.get("evidence"):
                        f.write(f"  Evidence   : {fi.get('evidence','')}\n")
                    f.write(f"  Remediation: {fi.get('remediation','')}\n")

        log(f"Report saved: {filepath}", "ok")

    def _export_html(self, filepath: str, data: dict):
        sev_colors = {"critical":"#ff2b4a","high":"#ff7c2b","medium":"#ffb800","low":"#00ff9d","info":"#00d4ff"}
        rows = ""
        for f in data["findings"]:
            c = sev_colors.get(f.get("severity","info"), "#fff")
            evid = str(f.get("evidence","")).replace("<","&lt;").replace(">","&gt;")[:200]
            rows += f"""<tr>
                <td style="color:{c};font-weight:bold">{f.get('severity','').upper()}</td>
                <td>{f.get('category','')}</td>
                <td>{f.get('title','')}</td>
                <td style="color:{c}">{f.get('cvss','')}</td>
                <td style="font-family:monospace;font-size:11px;color:#7fd8ff">{f.get('location','')[:80]}</td>
                <td style="font-family:monospace;font-size:11px;color:#aaa">{evid}</td>
                <td style="color:#00ff9d;font-size:12px">{f.get('remediation','')[:200]}</td>
            </tr>"""

        risk = min(100, sum(f.get("severity","")=="critical" for f in data["findings"])*25 +
                   sum(f.get("severity","")=="high" for f in data["findings"])*10)
        rc = "#ff2b4a" if risk>=75 else "#ffb800" if risk>=50 else "#00ff9d"

        html = f"""<!DOCTYPE html><html><head>
<meta charset="UTF-8"><title>SecureHawk Real Scan Report</title>
<style>
  body{{background:#080e14;color:#c8dde8;font-family:'Courier New',monospace;margin:0;padding:20px}}
  h1{{color:#00d4ff;font-size:22px;letter-spacing:4px;margin-bottom:4px}}
  .meta{{color:#4a6b7c;font-size:12px;margin-bottom:6px}}
  .badge{{display:inline-block;background:rgba(0,255,157,0.15);border:1px solid rgba(0,255,157,0.4);color:#00ff9d;font-size:10px;padding:2px 8px;border-radius:2px;letter-spacing:2px;margin-left:12px}}
  .score{{font-size:42px;font-weight:bold;color:{rc};margin:10px 0}}
  table{{width:100%;border-collapse:collapse;font-size:12px;margin-top:16px}}
  th{{background:#0d1520;color:#00d4ff;padding:10px;text-align:left;border-bottom:1px solid #1a2d3d;letter-spacing:1px;font-size:10px}}
  td{{padding:8px 10px;border-bottom:1px solid #0f1923;vertical-align:top}}
  tr:hover{{background:rgba(0,212,255,0.02)}}
</style></head><body>
<h1>⚡ SECUREHAWK REAL SCAN REPORT <span class="badge">LIVE DATA</span></h1>
<div class="meta">Target: {data['target']} | {data['timestamp']} | {data['total_findings']} findings</div>
<div class="score">{risk}<span style="font-size:16px;color:#4a6b7c">/100 RISK</span></div>
<table>
<tr><th>SEV</th><th>CATEGORY</th><th>TITLE</th><th>CVSS</th><th>LOCATION</th><th>EVIDENCE</th><th>REMEDIATION</th></tr>
{rows}
</table></body></html>"""
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html)


# ── CLI Entry Point ───────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="SecureHawk v3.0 — Real Pentesting Suite (Live Scan)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 securehawk.py -u https://example.com
  python3 securehawk.py -u https://example.com -t web --categories headers,ssl,cors,cookies
  python3 securehawk.py -u https://example.com --all -v
  python3 securehawk.py -u https://example.com --all -o report.html
  python3 securehawk.py -u https://example.com --all --api-key sk-ant-... -o report.json

Supported on: Kali Linux | Termux | macOS | Windows
        """
    )
    parser.add_argument("-u", "--url", default=None, help="Target URL (e.g. https://target.com)")
    parser.add_argument("-t", "--type", default="web",
                        choices=["web","webapp","android","api","all"],
                        help="Scan type (default: web)")
    parser.add_argument("--categories", default=None,
                        help="Comma-separated category IDs")
    parser.add_argument("--all", action="store_true", help="Run all categories")
    parser.add_argument("-o", "--output", default=None,
                        help="Output file: report.json / report.csv / report.html / report.txt")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--api-key", default=None,
                        help="Anthropic API key for Claude AI deep analysis (or set ANTHROPIC_API_KEY env var)")
    parser.add_argument("--list-categories", action="store_true", help="List all available categories")

    args = parser.parse_args()

    # Resolve API key
    api_key = args.api_key or os.environ.get("ANTHROPIC_API_KEY")

    if args.list_categories:
        print_banner()
        print(f"  {Fore.CYAN}{Style.BRIGHT}Available Categories:{Style.RESET_ALL}\n")
        for cid, info in CATEGORIES.items():
            type_color = {"web":Fore.CYAN,"mobile":Fore.GREEN,"re":Fore.YELLOW,"ai":Fore.MAGENTA}.get(info["type"],Fore.WHITE)
            live = f"{Fore.GREEN}[LIVE CHECK]{Style.RESET_ALL}" if cid in ["headers","ssl","cors","cookies","xss","sqli","infodisclosure","exposed","dns","ratelimit"] else f"{Fore.MAGENTA}[AI ANALYSIS]{Style.RESET_ALL}"
            print(f"  {Fore.WHITE}{cid:<16}{Style.RESET_ALL} {info['icon']} {info['name']:<40} {type_color}[{info['type']}]{Style.RESET_ALL} {live}")
        print()
        print(f"  {Fore.GREEN}[LIVE CHECK]{Style.RESET_ALL}  = Real HTTP requests made to target")
        print(f"  {Fore.MAGENTA}[AI ANALYSIS]{Style.RESET_ALL} = Claude AI analyzes collected data (requires --api-key)\n")
        return

    if not args.url:
        parser.error("the following arguments are required: -u/--url")

    if not HAS_REQUESTS:
        print(f"\n{Fore.RED}✗ requests library not installed. Run: pip install requests colorama{Style.RESET_ALL}\n")
        sys.exit(1)

    # Normalize URL
    url = args.url
    if not url.startswith("http"):
        url = "https://" + url

    # Build category list
    if args.all or args.categories is None:
        selected = list(CATEGORIES.keys())
    else:
        selected = [c.strip() for c in args.categories.split(",")]
        invalid = [c for c in selected if c not in CATEGORIES]
        if invalid:
            print(f"{Fore.RED}✗ Unknown categories: {', '.join(invalid)}{Style.RESET_ALL}")
            sys.exit(1)

    # Filter by type
    if args.type != "all":
        type_map = {"web":["web"],"webapp":["web","ai"],"android":["mobile","re"],"api":["web","ai"]}
        allowed = type_map.get(args.type, ["web"])
        selected = [c for c in selected if CATEGORIES[c]["type"] in allowed]

    scanner = SecureHawk(target=url, scan_type=args.type, categories=selected,
                         verbose=args.verbose, api_key=api_key)
    try:
        scanner.run()
        if args.output:
            scanner.export(args.output)
    except KeyboardInterrupt:
        print(f"\n\n  {Fore.YELLOW}⏹ Scan interrupted{Style.RESET_ALL}\n")
        if scanner.findings and args.output:
            scanner.end_time = time.time()
            scanner.export(args.output)

if __name__ == "__main__":
    main()