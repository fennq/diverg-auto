---
name: diverg-security-scan
version: 1.0.0
description: Run a Diverg Lite web security scan on any URL — headers, SSL/TLS, CSP, cookies, content analysis. Returns structured findings with severity, evidence, and remediation.
trigger: "security scan|scan website|check security|diverg scan|security headers|ssl check|check headers|website security|scan url|security audit"
tools: [shell, filesystem]
author: diverg
config:
  scan_type: "standard"
---

# Diverg Security Scan

Run a security assessment on a target URL using Diverg Lite. Returns structured findings covering HTTP security headers, SSL/TLS configuration, CSP weaknesses, cookie security, and content analysis.

## Prerequisites

Diverg Lite must be installed in the Python environment:

```bash
pip install diverg-lite
```

Verify installation:

```bash
diverg-scan --help
```

## When to Use

- User asks to "scan", "check security", "audit" a website or URL
- User provides a URL and asks about its security posture
- User wants to know if a site has proper HTTPS, headers, CSP
- Before deploying or reviewing a web application
- When investigating a suspicious or unfamiliar website

## Steps

1. Identify the target URL from the user's message. If only a domain is given, prepend `https://`.

2. Determine the scan type:
   - `quick` — headers only (fastest, ~2 seconds)
   - `standard` — headers + SSL/TLS + content analysis (default, ~5-10 seconds)
   - `full` — same as standard (reserved for future depth)

3. Run the scan:

```bash
diverg-scan "TARGET_URL" --type standard --json
```

4. Read the JSON output. Key fields:
   - `summary.by_severity` — counts per severity level
   - `findings[]` — each has `title`, `severity`, `category`, `evidence`, `impact`, `remediation`
   - `errors[]` — any scan errors

5. Present findings to the user:
   - Lead with a summary: total findings, severity breakdown
   - List Critical and High findings first with remediation steps
   - Group by category (Transport Security, Content Security, Cookie Security, Information Disclosure)
   - Include the `context` field when present — it explains real-world risk

6. If the user asks for a report, save the JSON output:

```bash
diverg-scan "TARGET_URL" --type standard --json > diverg-report.json
```

## Programmatic Alternative

For more control, use the Python API directly:

```bash
python3 -c "
from diverg_lite import scan
report = scan('TARGET_URL')
print(report.to_json())
"
```

## Severity Levels

- **Critical** — Expired SSL cert, cert verification failure
- **High** — Missing HSTS, plain HTTP, deprecated TLS, weak ciphers
- **Medium** — Missing CSP, X-Frame-Options, CORS wildcard, weak CSP directives, mixed content, CSRF gaps
- **Low** — Missing minor headers, info disclosure, SRI gaps, password autocomplete
- **Info** — Inline scripts count, HSTS subdomain coverage

## Examples

- "scan https://example.com for security issues" → run standard scan, present findings
- "quick security check on example.com" → run quick (headers-only) scan
- "is this website secure? https://suspicious-site.xyz" → run standard scan, highlight Critical/High
- "audit the security headers on our staging site" → run quick scan, focus on header findings
- "full security scan and save report" → run standard scan, save JSON, present summary

## Notes

- This skill performs **passive and semi-passive** checks only — it does not attempt exploitation
- Scans use stealth networking (realistic browser fingerprints, timing jitter) to avoid triggering WAFs
- Only scan URLs you have authorization to test
- The scan does not require any API keys or accounts
