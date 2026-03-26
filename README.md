# diverg-lite

Lightweight web security scanner — HTTP headers, SSL/TLS, CSP, cookies, content analysis. Built for autonomous agents.

**diverg-lite** extracts the security scanning engine from [Diverg](https://github.com/fennq/diverg) into a standalone, pip-installable package. It's designed to be used by OpenClaw agents, CI pipelines, or any Python project that needs fast, structured security posture checks.

> **Security sector only.** This package covers web security scanning. Blockchain investigation tools remain in the main Diverg repo.

## Install

```bash
pip install diverg-lite
```

Or from source:

```bash
git clone https://github.com/fennq/diverg-auto.git
cd diverg-lite
pip install -e .
```

## Quick Start

### Python

```python
from diverg_lite import scan, quick_scan

# Standard scan: headers + SSL + content
report = scan("https://example.com")
print(report.summary)
# {'total': 8, 'by_severity': {'Critical': 0, 'High': 1, ...}, ...}

for finding in report.findings:
    print(f"[{finding.severity}] {finding.title}")

# JSON output
print(report.to_json())

# Quick scan: headers only (~2s)
quick = quick_scan("https://example.com")
```

### CLI

```bash
# Human-readable output
diverg-scan https://example.com

# JSON output (for piping / agent consumption)
diverg-scan https://example.com --json

# Headers-only (fast)
diverg-scan https://example.com --type quick

# Save report
diverg-scan https://example.com --json > report.json
```

## What It Checks

| Category | Checks |
|----------|--------|
| **Transport Security** | HSTS (value quality), HTTPS enforcement, TLS version, cipher strength, certificate expiry/validity |
| **Content Security** | CSP presence + weak directives (unsafe-inline, unsafe-eval, wildcards, missing frame-ancestors), mixed content, inline scripts, third-party scripts without SRI, CSRF token presence |
| **Cookie Security** | Secure, HttpOnly, SameSite flags on response cookies |
| **Information Disclosure** | Server, X-Powered-By, ASP.NET version headers |
| **CORS** | Overly permissive Access-Control-Allow-Origin |

### Scan Types

- **`quick`** / **`headers`** — HTTP headers only. ~2 seconds.
- **`standard`** (default) — Headers + SSL/TLS + HTML content analysis. ~5-10 seconds.
- **`full`** — Same as standard. Reserved for future depth (path probing, etc.).

## OpenClaw Integration

diverg-lite ships with an [OpenClaw](https://github.com/openclaw/openclaw) skill file for autonomous agents.

### Install the skill

```bash
openclaw skill install ./skills/diverg-security-scan.md
```

Or from the repo:

```bash
openclaw clawhub install https://github.com/fennq/diverg-auto/skills/diverg-security-scan.md
```

### How the agent uses it

Once installed, your OpenClaw agent responds to natural language:

- *"scan https://example.com for security issues"*
- *"check the security headers on our staging site"*
- *"is this website secure? https://suspicious-site.xyz"*
- *"full security audit and save the report"*

The skill runs `diverg-scan` via the shell tool, parses the JSON output, and presents findings grouped by severity with remediation steps.

### Trigger phrases

`security scan`, `scan website`, `check security`, `diverg scan`, `security headers`, `ssl check`, `check headers`, `website security`, `scan url`, `security audit`

## Output Format

Every scan returns a `ScanReport` with:

```python
{
    "target_url": "https://example.com",
    "scan_type": "standard",
    "scanned_at": "2026-03-26T...",
    "duration_ms": 4200,
    "summary": {
        "total": 8,
        "by_severity": {"Critical": 0, "High": 1, "Medium": 3, "Low": 2, "Info": 2},
        "has_critical": false,
        "has_high": true
    },
    "findings": [
        {
            "title": "Missing security header: Strict-Transport-Security",
            "severity": "High",
            "category": "Transport Security",
            "evidence": "Header 'Strict-Transport-Security' is not present.",
            "impact": "Without HSTS, the application may be vulnerable to downgrade attacks.",
            "remediation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'",
            "finding_type": "hardening",
            "context": "If the site already redirects HTTP→HTTPS, real risk is lower."
        }
    ],
    "errors": []
}
```

## Stealth

Scans use realistic browser fingerprints (rotating User-Agent, headers, timing jitter) and adaptive rate limiting to avoid triggering WAFs. Configure a proxy:

```bash
export DIVERG_PROXY=socks5://127.0.0.1:9050  # Tor
diverg-scan https://example.com
```

## Project Structure

```
diverg-lite/
├── diverg_lite/           # pip-installable package
│   ├── __init__.py        # Public API: scan(), quick_scan()
│   ├── scanner.py         # Core engine
│   ├── stealth.py         # Stealth networking
│   ├── models.py          # Finding, ScanReport dataclasses
│   └── cli.py             # CLI entry point
├── skills/
│   └── diverg-security-scan.md   # OpenClaw skill file
├── examples/
│   ├── basic_scan.py
│   └── openclaw_integration.py
├── pyproject.toml
└── README.md
```

## License

MIT
