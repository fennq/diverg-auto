# diverg-auto

Autonomous web security scanner — passive analysis, active vulnerability probing, and attack-path reasoning. Built for agents and CI.

**diverg-auto** goes beyond header checking. It passively analyses headers, SSL/TLS, CSP, cookies, and content, then *actively probes* for real vulnerabilities — reflected XSS, SQL injection, path traversal, open redirects, SSRF, and auth bypass — and chains findings into **exploit narratives** so an agent (or human) knows exactly what an attacker would do.

*Install from PyPI as `diverg-lite`; Python import path is `diverg_lite`.*

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
from diverg_lite import scan, quick_scan, active_scan, batch_scan

# Standard passive scan (headers + SSL + content)
report = scan("https://example.com")
print(report.score, report.grade)   # 72, "B"

# Full active probing — XSS, SQLi, traversal, SSRF, auth bypass
report = active_scan("https://example.com")
print(report.attack_paths)          # exploit chains

for f in report.findings:
    print(f"[{f.severity}] {f.title}")

# Run specific probes only
report = active_scan("https://example.com", probe_names=["xss", "sqli"])

# Headers-only (fast, ~1-2s)
quick = quick_scan("https://example.com")

# Batch scan multiple URLs
reports = batch_scan(["https://a.com", "https://b.com"])
for r in reports:
    print(f"{r.target_url}: {r.score}/100 ({r.grade})")

# Export
print(report.to_json())
print(report.to_markdown())
```

### CLI

```bash
# Standard scan (passive)
diverg-scan https://example.com

# Full active probing
diverg-scan https://example.com --type full

# Active with specific probes only
diverg-scan https://example.com --type active --probe xss,sqli

# JSON output
diverg-scan https://example.com --type full --json

# Multiple URLs
diverg-scan https://a.com https://b.com --type full --json

# From a file (one URL per line)
diverg-scan --file urls.txt --json

# Headers-only (fast)
diverg-scan https://example.com --type quick

# Markdown report with attack paths
diverg-scan https://example.com --type full --markdown -o report.md

# Only show Medium+ findings
diverg-scan https://example.com --min-severity Medium

# CI mode: exit 1 if any High+ findings
diverg-scan https://staging.example.com --fail-on High
```

## Scan Types

| Type | What it does | Speed |
|------|-------------|-------|
| `quick` / `headers` | HTTP headers only | ~1-2s |
| `standard` (default) | Headers + SSL/TLS + content analysis | ~3-5s |
| `full` / `active` | Standard + active vulnerability probes + attack-path reasoning | ~10-30s |

## Passive Checks

| Category | Checks |
|----------|--------|
| **Transport Security** | HSTS (value quality), HTTPS enforcement, TLS version, cipher strength, certificate expiry/validity, deprecated protocol probing |
| **Content Security** | CSP presence + weak directives (unsafe-inline, unsafe-eval, wildcards, missing frame-ancestors), mixed content, inline scripts, third-party scripts without SRI, CSRF token presence |
| **Cookie Security** | Secure, HttpOnly, SameSite flags on response cookies |
| **Information Disclosure** | Server, X-Powered-By, ASP.NET version headers |
| **CORS** | Overly permissive Access-Control-Allow-Origin |
| **Tech Fingerprint** | CDN (Cloudflare, Akamai, Fastly, Vercel), frameworks (Next.js, Express, ASP.NET, PHP) |
| **Redirects** | Full redirect chain with status codes |

## Active Probes

Active probes send non-destructive test payloads to discover real vulnerabilities. Only run against targets you have authorization to test.

| Probe | What it finds | CWE |
|-------|--------------|-----|
| **xss** | Reflected XSS — canary injection, context-aware (HTML body, attribute, script, comment) | CWE-79 |
| **sqli** | SQL injection — error-based (MySQL, PostgreSQL, MSSQL, SQLite, Oracle) + boolean-blind | CWE-89 |
| **traversal** | Path traversal / LFI — directory traversal sequences, encoding bypasses, OS file markers | CWE-22 |
| **redirect** | Open redirect — redirect parameter detection, protocol-relative/backslash/encoding bypasses | CWE-601 |
| **ssrf** | SSRF — cloud metadata (AWS/GCP/Azure), internal IPs, loopback, hex/octal/decimal representations | CWE-918 |
| **auth** | Auth bypass — forced browsing (admin panels, .git, actuator, debug), HTTP verb tampering, IDOR hints | CWE-284 |

### How probes work

1. **Discovery** — extract injection points from URL parameters, HTML forms, and fuzz-seed parameters.
2. **Injection** — send safe, non-destructive payloads into each parameter.
3. **Analysis** — check responses for vulnerability indicators (error messages, reflected content, traversal markers, redirect targets).
4. **Confirmation** — re-test with variations to reduce false positives.
5. **Attack paths** — chain findings into exploit narratives with severity, likelihood, and prioritized remediation.

### Safety controls

- Hard per-probe request cap (default 20-40 per probe type).
- Stealth session with timing jitter, rate limiting, WAF backoff.
- No destructive payloads — all tests are read-only.
- Authorization warning in CLI and docs.

## Attack-Path Reasoning

Active scans chain individual findings into **exploit narratives**:

| Chain | Example |
|-------|---------|
| **Session Hijack via XSS** | Reflected XSS + missing HttpOnly cookie → steal session tokens |
| **XSS Amplified by Weak CSP** | XSS + unsafe-inline CSP → no browser defence |
| **Database Compromise** | SQL injection → full database read/write |
| **Phishing via Open Redirect** | Open redirect on trusted domain → credential harvesting |
| **Internal Pivot via SSRF** | SSRF → cloud metadata / internal APIs |
| **Source Exposure** | Path traversal → config files, secrets, source code |
| **Admin Takeover** | Exposed admin panel + no auth → full application control |
| **Git Exposure** | Accessible .git directory → full source + history |

Each path includes severity, likelihood score, and a prioritized fix order.

## Security Score

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
- *"deep scan this URL for vulnerabilities"*
- *"run active probes against staging"*
- *"scan these three URLs and compare their scores"*
- *"save a security report with attack paths"*

The skill auto-installs the PyPI package (`diverg-lite`) if missing, runs the scan, and presents findings with score, grade, attack paths, and remediation steps.

### Trigger phrases

`security scan`, `scan website`, `check security`, `diverg scan`, `security headers`, `ssl check`, `check headers`, `website security`, `scan url`, `security audit`, `check ssl`, `scan domain`

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
│   ├── __init__.py        # Public API: scan(), quick_scan(), active_scan(), batch_scan()
│   ├── scanner.py         # Core engine (passive + active orchestration)
│   ├── stealth.py         # Stealth networking
│   ├── models.py          # Finding, ScanReport (JSON, Markdown, filtering, attack paths)
│   ├── cli.py             # CLI (--type full, --probe, --json, --markdown, --fail-on)
│   ├── attack_path.py     # Attack-path reasoning engine
│   └── probes/
│       ├── __init__.py    # Probe registry + run_probes()
│       ├── base.py        # BaseProbe, InjectionPoint, safety controls
│       ├── discovery.py   # Injection-point discovery (params, forms, fuzz)
│       ├── xss.py         # Reflected XSS probe
│       ├── sqli.py        # SQL injection probe
│       ├── traversal.py   # Path traversal / LFI probe
│       ├── redirect.py    # Open redirect probe
│       ├── ssrf.py        # SSRF probe
│       └── auth.py        # Auth bypass / forced browsing probe
├── skills/
│   └── diverg-security-scan.md
├── examples/
│   ├── basic_scan.py
│   └── openclaw_integration.py
├── pyproject.toml
└── README.md
```

## License

MIT
