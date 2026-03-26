# diverg-auto

Lightweight web security scanner — HTTP headers, SSL/TLS, CSP, cookies, content analysis, tech fingerprinting, and security scoring. Built for autonomous agents.

**diverg-auto** extracts the security scanning engine from [Diverg](https://github.com/fennq/diverg) into a standalone, pip-installable package. Designed for OpenClaw agents, CI pipelines, or any Python project that needs fast, structured security posture checks.

*Install from PyPI as `diverg-lite`; Python import path is `diverg_lite`.*

> **Security sector only.** This package covers web security scanning. Blockchain investigation tools remain in the main Diverg repo.

## Install

```bash
pip install diverg-lite   # PyPI name; product/repo: diverg-auto
```

Or from source:

```bash
git clone https://github.com/fennq/diverg-auto.git
cd diverg-auto
pip install -e .
```

## Quick Start

### Python

```python
from diverg_lite import scan, quick_scan, batch_scan

report = scan("https://example.com")
print(report.score, report.grade)   # 72, "B"
print(report.technologies)          # ["cloudflare", "next.js"]
print(report.redirect_chain)        # [{url, status, location}, ...]

for f in report.findings:
    print(f"[{f.severity}] {f.title}")

# Filter to Medium+ only
actionable = report.filter_by_severity("Medium")

# Headers-only (fast, ~1-2s)
quick = quick_scan("https://example.com")

# Batch scan multiple URLs
reports = batch_scan(["https://a.com", "https://b.com"])
for r in reports:
    print(f"{r.target_url}: {r.score}/100 ({r.grade})")

# Export
print(report.to_json())       # structured JSON
print(report.to_markdown())   # human-readable report
```

### CLI

```bash
# Human-readable output with score
diverg-scan https://example.com

# JSON output
diverg-scan https://example.com --json

# Multiple URLs
diverg-scan https://a.com https://b.com --json

# From a file (one URL per line)
diverg-scan --file urls.txt --json

# Headers-only (fast)
diverg-scan https://example.com --type quick

# Markdown report
diverg-scan https://example.com --markdown

# Save to file
diverg-scan https://example.com --json --output report.json
diverg-scan https://example.com --markdown -o report.md

# Only show Medium+ findings
diverg-scan https://example.com --min-severity Medium

# CI mode: exit 1 if any High+ findings
diverg-scan https://staging.example.com --fail-on High
```

## What It Checks

| Category | Checks |
|----------|--------|
| **Transport Security** | HSTS (value quality), HTTPS enforcement, TLS version, cipher strength, certificate expiry/validity, deprecated protocol probing |
| **Content Security** | CSP presence + weak directives (unsafe-inline, unsafe-eval, wildcards, missing frame-ancestors), mixed content, inline scripts, third-party scripts without SRI, CSRF token presence |
| **Cookie Security** | Secure, HttpOnly, SameSite flags on response cookies |
| **Information Disclosure** | Server, X-Powered-By, ASP.NET version headers |
| **CORS** | Overly permissive Access-Control-Allow-Origin |
| **Tech Fingerprint** | CDN (Cloudflare, Akamai, Fastly, Vercel), frameworks (Next.js, Express, ASP.NET, PHP), security headers present |
| **Redirects** | Full redirect chain with status codes |

### Scan Types

| Type | What it does | Speed |
|------|-------------|-------|
| `quick` / `headers` | HTTP headers only | ~1-2s |
| `standard` (default) | Headers + SSL/TLS + content analysis | ~3-5s |
| `full` | Same as standard (reserved for future path probing) | ~3-5s |

### Security Score

Every scan produces a **0-100 score** and **letter grade** (A-F):

| Grade | Score | Meaning |
|-------|-------|---------|
| A | 90-100 | Excellent — minimal or no issues |
| B | 75-89 | Good — minor hardening gaps |
| C | 55-74 | Fair — several medium issues |
| D | 35-54 | Poor — significant security gaps |
| F | 0-34 | Failing — critical issues present |

Scoring: each finding deducts points based on severity (Critical: 25, High: 15, Medium: 8, Low: 3, Info: 0).

## OpenClaw Integration

**diverg-auto** ships with an [OpenClaw](https://github.com/openclaw/openclaw) skill file for autonomous agents.

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
- *"what's the security score for https://myapp.com?"*
- *"scan these three URLs and compare their scores"*
- *"save a security report for https://example.com"*

The skill auto-installs the PyPI package (`diverg-lite`) if missing, runs the scan, and presents findings with score, grade, and remediation steps.

### Trigger phrases

`security scan`, `scan website`, `check security`, `diverg scan`, `security headers`, `ssl check`, `check headers`, `website security`, `scan url`, `security audit`, `check ssl`, `scan domain`

## Output Formats

### JSON

```json
{
    "target_url": "https://example.com",
    "score": 72,
    "grade": "B",
    "scan_type": "standard",
    "duration_ms": 3200,
    "technologies": ["cloudflare"],
    "redirect_chain": [
        {"url": "http://example.com", "status": 301, "location": "https://example.com/"},
        {"url": "https://example.com/", "status": 200, "location": ""}
    ],
    "summary": {"total": 8, "by_severity": {...}, "score": 72, "grade": "B"},
    "findings": [...]
}
```

### Markdown

`diverg-scan https://example.com --markdown` produces a formatted report with severity-grouped findings, redirect chain, tech stack, and remediation steps.

## Stealth

Scans use realistic browser fingerprints (rotating User-Agent, headers, timing jitter) and adaptive rate limiting to avoid triggering WAFs. Configure a proxy:

```bash
export DIVERG_PROXY=socks5://127.0.0.1:9050
diverg-scan https://example.com
```

## Project Structure

```
diverg-auto/
├── diverg_lite/
│   ├── __init__.py        # Public API: scan(), quick_scan(), batch_scan()
│   ├── scanner.py         # Core engine (shared fetch, headers, SSL, content, score, tech detect)
│   ├── stealth.py         # Stealth networking
│   ├── models.py          # Finding, ScanReport (JSON, Markdown, filtering)
│   └── cli.py             # CLI (multi-URL, --json, --markdown, --output, --min-severity, --fail-on)
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
