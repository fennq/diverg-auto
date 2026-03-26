---
name: diverg-security-scan
version: 2.0.0
description: Run a Diverg Lite web security scan — headers, SSL/TLS, CSP, cookies, content analysis. Returns score, grade, findings with remediation, redirect chain, and tech fingerprint. Supports multi-URL batch scans.
trigger: "security scan|scan website|check security|diverg scan|security headers|ssl check|check headers|website security|scan url|security audit|check ssl|scan domain"
tools: [shell, filesystem]
author: diverg
config:
  scan_type: "standard"
---

# Diverg Security Scan

Run a security assessment on one or more target URLs using Diverg Lite. Returns a score (0-100), letter grade (A-F), structured findings, redirect chain, and detected technologies.

## Prerequisites

Check if Diverg Lite is installed, install if not:

```bash
python3 -c "import diverg_lite" 2>/dev/null || pip install diverg-lite
```

## When to Use

- User asks to "scan", "check security", or "audit" a website or URL
- User provides a URL and asks about its security posture
- User wants to know if a site has proper HTTPS, headers, CSP
- User wants a security score or grade for a site
- Before deploying or reviewing a web application
- When investigating a suspicious or unfamiliar website
- User wants to scan multiple URLs at once

## Steps

1. Identify target URL(s) from the user's message. If only a domain is given, prepend `https://`.

2. Determine scan type and options:
   - `quick` — headers only (~1-2 seconds)
   - `standard` — headers + SSL/TLS + content analysis (default, ~3-5 seconds)
   - If user only cares about Critical/High issues, add `--min-severity High`

3. Run the scan:

```bash
# Single URL
diverg-scan "TARGET_URL" --type standard --json

# Multiple URLs
diverg-scan "URL1" "URL2" "URL3" --json

# From a file (one URL per line)
diverg-scan --file urls.txt --json

# Only show Medium+ findings
diverg-scan "TARGET_URL" --json --min-severity Medium

# Save to file
diverg-scan "TARGET_URL" --json --output report.json

# Markdown report (human-friendly)
diverg-scan "TARGET_URL" --markdown --output report.md
```

4. Read the JSON output. Key fields:
   - `score` — 0-100 security score (100 = no issues)
   - `grade` — A through F
   - `summary.by_severity` — counts per severity level
   - `technologies` — detected stack (CDN, framework, etc.)
   - `redirect_chain` — full redirect path if any
   - `findings[]` — each has `title`, `severity`, `category`, `evidence`, `impact`, `remediation`

5. Present findings to the user:
   - Lead with the **score and grade** (e.g. "72/100, Grade B")
   - Mention detected technologies if present
   - Note redirects if the URL changed
   - List Critical and High findings first with remediation
   - Include `context` when present — it explains real-world risk
   - For batch scans, compare scores across URLs

6. For CI/CD usage, add `--fail-on` to exit with code 1:

```bash
diverg-scan "https://staging.example.com" --fail-on High
```

## Severity Levels

- **Critical** — Expired SSL cert, cert verification failure
- **High** — Missing HSTS, plain HTTP, deprecated TLS, weak ciphers
- **Medium** — Missing CSP, X-Frame-Options, CORS wildcard, weak CSP, mixed content, CSRF
- **Low** — Missing minor headers, info disclosure, SRI gaps, password autocomplete
- **Info** — Inline scripts count, HSTS subdomain coverage

## Examples

- "scan https://example.com" → standard scan, show score + findings
- "quick security check on example.com" → quick scan, headers only
- "is this website secure? https://suspicious-site.xyz" → standard scan, highlight Critical/High
- "scan these three sites and compare" → batch scan, compare scores
- "audit security and save a markdown report" → scan with `--markdown --output`
- "check if staging passes before deploy" → scan with `--fail-on High`

## Notes

- **Passive only** — does not attempt exploitation or modify anything
- **Stealth** — realistic browser fingerprints, timing jitter, adaptive rate limiting
- **No API keys** — works out of the box, no accounts needed
- Only scan URLs you have authorization to test
