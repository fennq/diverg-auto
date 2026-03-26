# Tweet drafts — diverg-auto (Diverg Lite for OpenClaw agents)

Product launch tweet. Link to repo: https://github.com/fennq/diverg-auto

---

## Single post (copy-paste)

**Option A — full**

Shipping **diverg-lite** — open-source web security scanner built for autonomous agents.

`pip install diverg-lite` or drop the skill into your **@OpenClaw** bot.

What it does:
- **Score + grade** — 0-100 security score and A-F grade on every scan
- **Headers, SSL/TLS, CSP, cookies, content** — structured findings with evidence + remediation
- **Tech fingerprint** — detects your stack (Cloudflare, Vercel, Next.js, Express…)
- **Redirect chain** — full path with status codes
- **Batch scan** — multiple URLs in one command
- **CI mode** — `--fail-on High` exits 1 when it matters

One command:
`diverg-scan https://your-site.com`

OpenClaw skill included — your agent just says "scan this site" and it runs.

Security sector only. No API keys. No accounts.

https://github.com/fennq/diverg-auto

---

## Single post (shorter — ~280 friendly)

**diverg-lite** — open-source security scanner for autonomous agents.

`pip install diverg-lite`

Score (0-100), grade (A-F), headers/SSL/CSP/cookies, tech fingerprint, redirect chain, batch scan, markdown reports, CI mode.

Drop the skill into @OpenClaw and say "scan this site."

https://github.com/fennq/diverg-auto

---

## Thread (5 posts)

**1/**
Shipping **diverg-lite** — the security scanning engine from Diverg, extracted into a standalone pip package for @OpenClaw agents and CI pipelines.

Open source. No API keys. No accounts.

https://github.com/fennq/diverg-auto

**2/**
Every scan returns a **security score** (0-100) and **letter grade** (A-F).

Not just a list of findings — a single number your agent can act on.

"72/100, Grade B — 3 medium issues, no critical."

That's what your bot tells the user. Done.

**3/**
What it checks:
→ HTTP security headers (HSTS, CSP, X-Frame-Options, CORS…)
→ SSL/TLS (cert expiry, deprecated protocols, weak ciphers)
→ CSP weakness (unsafe-inline, unsafe-eval, wildcards)
→ Cookies (Secure, HttpOnly, SameSite)
→ Content (mixed content, CSRF tokens, SRI, inline scripts)
→ Tech fingerprint (Cloudflare, Vercel, Next.js, Express…)
→ Full redirect chain with status codes

**4/**
Built for agents, not dashboards:

```
diverg-scan https://target.com --json
diverg-scan url1 url2 url3 --json
diverg-scan --file urls.txt --markdown -o report.md
diverg-scan https://staging.app --fail-on High
```

Python API:
```python
from diverg_lite import scan
r = scan("https://target.com")
print(r.score, r.grade)
```

**5/**
OpenClaw integration is a single skill file — install it and your agent responds to:

"scan this site for security issues"
"what's the security score for example.com"
"compare these three URLs"
"save a security report"

Auto-installs if missing. Stealth networking built in.

Security sector only — blockchain investigation stays in the main Diverg repo.

Ship it: https://github.com/fennq/diverg-auto

---

## Optional CTA

Code: https://github.com/fennq/diverg-auto · `pip install diverg-lite` · OpenClaw skill: `skills/diverg-security-scan.md`
