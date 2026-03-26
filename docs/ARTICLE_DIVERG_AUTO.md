# We built a security scanner that runs inside your AI agent.

Your OpenClaw bot can now scan any website and tell you exactly what's wrong with it — score, grade, findings, remediation. No API keys. No accounts. One pip install.

Here's what it does and why we built it.

---

## The problem

Autonomous agents browse the web, interact with APIs, and make decisions on behalf of users. But they have no way to evaluate whether a site they're about to interact with is actually secure.

Your agent can navigate to a phishing site, submit credentials to an HTTP endpoint, or trust a page with no CSP and inline scripts everywhere — and it won't know the difference.

We wanted to fix that.

## What diverg-auto does

diverg-auto is the security scanning engine from Diverg, extracted into a standalone Python package. It performs passive security checks against any URL and returns structured, actionable results.

**One command:**

```
diverg-scan https://target.com
```

**What you get back:**

- A **security score** from 0 to 100 and a **letter grade** (A through F)
- Findings grouped by severity: Critical, High, Medium, Low, Info
- Every finding includes **evidence**, **impact**, and **remediation** — not just a title
- **Technology fingerprint** — detects Cloudflare, Vercel, Next.js, Express, and more from response headers
- **Redirect chain** — full path with status codes so you see exactly where a URL lands
- **Context** on each finding — explains real-world risk so agents (and humans) don't overreact to low-signal issues

## What it checks

**Transport Security** — HSTS (and value quality: max-age, includeSubDomains), HTTPS enforcement, TLS version probing, cipher strength, certificate expiry and validity.

**Content Security** — CSP presence and weakness analysis (unsafe-inline, unsafe-eval, wildcards, missing frame-ancestors), mixed content detection, CSRF token presence in forms, inline script count, third-party scripts without Subresource Integrity.

**Cookie Security** — Secure, HttpOnly, and SameSite flags on every response cookie.

**Information Disclosure** — Server, X-Powered-By, and ASP.NET version headers that reveal stack details.

**CORS** — Flags overly permissive Access-Control-Allow-Origin: * configurations.

All passive. No exploitation. No modification. Just reads what the server sends back and tells you what's missing or misconfigured.

## The score

Every scan produces a 0-100 score. Each finding deducts points based on severity:

- Critical: -25 (expired cert, verification failure)
- High: -15 (missing HSTS, plain HTTP, deprecated TLS)
- Medium: -8 (missing CSP, weak CSP, CORS wildcard)
- Low: -3 (info disclosure, missing minor headers)
- Info: 0

Grades map to score ranges: A (90-100), B (75-89), C (55-74), D (35-54), F (0-34).

One number. One letter. Your agent can act on it without parsing a vulnerability report.

## Built for agents

The whole point is that an autonomous agent can use this without human intervention.

**OpenClaw integration** is a single skill file. Install it:

```
openclaw skill install ./skills/diverg-security-scan.md
```

Then your agent responds to natural language:

- "scan this site for security issues"
- "what's the security score for example.com"
- "compare the security of these three URLs"
- "save a report before we deploy"

The skill auto-installs diverg-auto if it's missing, runs the scan via CLI, parses the JSON, and presents findings grouped by severity with remediation steps.

No configuration. No API keys. No accounts.

## For humans and CI too

Not just for agents. The CLI is designed for humans and pipelines:

```
# Human-readable with score
diverg-scan https://your-site.com

# JSON for piping
diverg-scan https://your-site.com --json

# Markdown report
diverg-scan https://your-site.com --markdown -o report.md

# Batch scan
diverg-scan https://a.com https://b.com https://c.com

# From a file
diverg-scan --file urls.txt --json

# CI gate: exit 1 if any High+ findings
diverg-scan https://staging.app --fail-on High

# Only show actionable findings
diverg-scan https://your-site.com --min-severity Medium
```

Python API if you want programmatic control:

```python
from diverg_auto import scan, batch_scan

report = scan("https://example.com")
print(report.score, report.grade)  # 72, "B"
print(report.technologies)         # ["cloudflare", "next.js"]

# Batch
for r in batch_scan(["https://a.com", "https://b.com"]):
    print(f"{r.target_url}: {r.grade}")
```

## Stealth

Scans use realistic browser fingerprints — rotating User-Agent strings, randomized headers, timing jitter, and adaptive rate limiting. If a target pushes back with 429s or 403s, the scanner backs off automatically.

Proxy and Tor support via `DIVERG_PROXY` environment variable.

## What this is not

This is the **security sector** of Diverg — web security scanning only. The blockchain investigation stack (wallet analysis, Bags API, Helius, Arkham, on-chain forensics) stays in the main Diverg repo. We'll ship that as a separate package when it's ready.

## Ship it

```
pip install diverg-auto
```

Source: https://github.com/fennq/diverg-auto

MIT licensed. Contributions welcome.
