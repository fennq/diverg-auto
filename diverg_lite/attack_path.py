"""
Attack-path reasoning engine — correlate findings into exploit chains.

Instead of a flat list of issues, this module builds causal narratives:
  "Missing CSP + reflected XSS + no HttpOnly on session cookie → session hijack"

Each AttackPath has:
  - ordered steps (findings that combine)
  - escalated severity (chain is worse than individual parts)
  - narrative (human-readable kill-chain description)
  - likelihood score (0.0–1.0)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .models import Finding, SEVERITY_ORDER


@dataclass
class AttackPath:
    name: str
    narrative: str
    steps: list[Finding] = field(default_factory=list)
    severity: str = "High"
    likelihood: float = 0.5
    impact_summary: str = ""
    remediation_priority: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "narrative": self.narrative,
            "severity": self.severity,
            "likelihood": self.likelihood,
            "impact_summary": self.impact_summary,
            "steps": [
                {"title": s.title, "severity": s.severity, "category": s.category}
                for s in self.steps
            ],
            "remediation_priority": self.remediation_priority,
        }

    def to_markdown(self) -> str:
        lines = [
            f"### Attack Path: {self.name}",
            f"",
            f"**Severity:** {self.severity}  |  **Likelihood:** {self.likelihood:.0%}",
            f"",
            f"**Narrative:** {self.narrative}",
            f"",
            f"**Steps:**",
        ]
        for i, s in enumerate(self.steps, 1):
            lines.append(f"  {i}. [{s.severity}] {s.title}")
        if self.impact_summary:
            lines.append(f"")
            lines.append(f"**Impact:** {self.impact_summary}")
        if self.remediation_priority:
            lines.append(f"")
            lines.append(f"**Fix order:**")
            for i, fix in enumerate(self.remediation_priority, 1):
                lines.append(f"  {i}. {fix}")
        lines.append("")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Chain rules — each rule defines what combination of findings forms a path
# ---------------------------------------------------------------------------

@dataclass
class _ChainRule:
    name: str
    narrative_template: str
    required: list[str]       # substrings that must appear in finding titles/categories
    optional: list[str] = field(default_factory=list)
    min_matches: int = 2
    severity: str = "Critical"
    likelihood_base: float = 0.6
    impact: str = ""
    fix_order: list[str] = field(default_factory=list)


_RULES: list[_ChainRule] = [
    _ChainRule(
        name="Session Hijack via XSS",
        narrative_template=(
            "Reflected XSS allows script injection. Combined with {cookie_issue}, "
            "an attacker can steal session tokens and impersonate any user."
        ),
        required=["XSS", "cookie"],
        optional=["CSP"],
        min_matches=2,
        severity="Critical",
        likelihood_base=0.75,
        impact="Full account takeover — attacker steals session cookies via injected script.",
        fix_order=[
            "Fix XSS: encode all reflected output",
            "Set HttpOnly + Secure + SameSite on session cookies",
            "Deploy strict Content-Security-Policy",
        ],
    ),
    _ChainRule(
        name="XSS Amplified by Weak CSP",
        narrative_template=(
            "XSS is exploitable because CSP allows {csp_weakness}, removing "
            "the browser's last line of defence against injected scripts."
        ),
        required=["XSS", "CSP"],
        min_matches=2,
        severity="Critical",
        likelihood_base=0.7,
        impact="XSS payloads execute freely — CSP does not block them.",
        fix_order=[
            "Fix the XSS injection point",
            "Remove unsafe-inline / unsafe-eval from CSP",
            "Use nonce or hash-based CSP",
        ],
    ),
    _ChainRule(
        name="Database Compromise via SQLi",
        narrative_template=(
            "SQL injection in {param} gives direct database access. "
            "{extra_context}"
        ),
        required=["SQL injection"],
        optional=["admin", "Exposed"],
        min_matches=1,
        severity="Critical",
        likelihood_base=0.85,
        impact="Full database read/write — credential theft, data exfiltration, potential RCE.",
        fix_order=[
            "Use parameterized queries immediately",
            "Restrict DB account privileges",
            "Audit all query construction for concatenation",
        ],
    ),
    _ChainRule(
        name="Credential Theft via Phishing Redirect",
        narrative_template=(
            "Open redirect lets an attacker craft a trusted-domain URL that "
            "sends victims to a phishing site. {extra_context}"
        ),
        required=["Open redirect"],
        optional=["HSTS", "cookie"],
        min_matches=1,
        severity="High",
        likelihood_base=0.55,
        impact="Victims trust the original domain — phishing success rate increases dramatically.",
        fix_order=[
            "Validate redirect targets against an allowlist",
            "Use relative-path redirects only",
        ],
    ),
    _ChainRule(
        name="Internal Network Pivot via SSRF",
        narrative_template=(
            "SSRF lets the attacker reach internal services through the server. "
            "{extra_context}"
        ),
        required=["SSRF"],
        optional=["metadata", "cloud"],
        min_matches=1,
        severity="Critical",
        likelihood_base=0.7,
        impact="Access to cloud metadata, internal APIs, and private services from outside.",
        fix_order=[
            "Block requests to private IP ranges and metadata endpoints",
            "Validate URL inputs with an allowlist",
            "Use IMDSv2 (token-required) for AWS metadata",
        ],
    ),
    _ChainRule(
        name="Source Code / Secret Exposure via Path Traversal",
        narrative_template=(
            "Path traversal reads arbitrary server files. Attackers can extract "
            "config files, source code, and credentials. {extra_context}"
        ),
        required=["Path traversal", "LFI"],
        min_matches=1,
        severity="Critical",
        likelihood_base=0.8,
        impact="Exposure of secrets, database credentials, API keys, and application source.",
        fix_order=[
            "Sanitize file path inputs — reject traversal sequences",
            "Use an allowlist of permitted files",
            "Chroot / jail the application process",
        ],
    ),
    _ChainRule(
        name="Admin Panel Takeover",
        narrative_template=(
            "An unprotected admin endpoint is accessible. Combined with "
            "{supporting_issues}, full application control is likely."
        ),
        required=["Exposed", "admin"],
        optional=["verb", "IDOR", "cookie"],
        min_matches=1,
        severity="Critical",
        likelihood_base=0.65,
        impact="Administrative access without credentials — full application compromise.",
        fix_order=[
            "Add authentication + authorization to admin endpoints",
            "Return 401/403 for unauthenticated requests",
            "Remove or disable admin panels in production",
        ],
    ),
    _ChainRule(
        name="Exposed Git Repository",
        narrative_template=(
            "The .git directory is publicly accessible, allowing attackers to "
            "reconstruct the full source code and commit history."
        ),
        required=[".git"],
        min_matches=1,
        severity="High",
        likelihood_base=0.9,
        impact="Full source code exposure, including hardcoded secrets in git history.",
        fix_order=[
            "Block access to .git/ at the web-server level",
            "Rotate any secrets found in git history",
        ],
    ),
]


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

def analyze_attack_paths(findings: list[Finding]) -> list[AttackPath]:
    """Build attack-path chains from a flat list of findings."""
    if not findings:
        return []

    paths: list[AttackPath] = []
    titles_lower = " | ".join(f.title.lower() for f in findings)
    cats_lower = " | ".join(f.category.lower() for f in findings)
    combined = titles_lower + " | " + cats_lower

    for rule in _RULES:
        matched_findings: list[Finding] = []
        matched_keywords: list[str] = []

        for keyword in rule.required:
            for f in findings:
                haystack = f"{f.title} {f.category} {f.evidence}".lower()
                if keyword.lower() in haystack and f not in matched_findings:
                    matched_findings.append(f)
                    matched_keywords.append(keyword)
                    break

        # Also grab optional supporting findings
        for keyword in rule.optional:
            for f in findings:
                haystack = f"{f.title} {f.category}".lower()
                if keyword.lower() in haystack and f not in matched_findings:
                    matched_findings.append(f)

        if len(matched_keywords) < rule.min_matches:
            continue

        # Build narrative from template
        template_vars = {
            "cookie_issue": _summarize(matched_findings, "cookie"),
            "csp_weakness": _summarize(matched_findings, "csp"),
            "param": _summarize(matched_findings, "via '"),
            "extra_context": _extra_context(matched_findings),
            "supporting_issues": _summarize_all(matched_findings),
        }
        narrative = rule.narrative_template.format_map(_SafeDict(template_vars))

        # Adjust likelihood based on match quality
        likelihood = rule.likelihood_base
        if len(matched_findings) > rule.min_matches:
            likelihood = min(0.95, likelihood + 0.1 * (len(matched_findings) - rule.min_matches))

        paths.append(AttackPath(
            name=rule.name,
            narrative=narrative,
            steps=matched_findings,
            severity=rule.severity,
            likelihood=likelihood,
            impact_summary=rule.impact,
            remediation_priority=rule.fix_order,
        ))

    # Sort by severity then likelihood
    paths.sort(key=lambda p: (SEVERITY_ORDER.get(p.severity, 4), -p.likelihood))
    return paths


class _SafeDict(dict):
    """Return the key name if a template variable is missing."""
    def __missing__(self, key):
        return f"[{key}]"


def _summarize(findings: list[Finding], keyword: str) -> str:
    for f in findings:
        if keyword.lower() in f.title.lower():
            return f.title
    return "related issue"


def _summarize_all(findings: list[Finding]) -> str:
    if not findings:
        return "no supporting issues"
    return ", ".join(f.title for f in findings[:3])


def _extra_context(findings: list[Finding]) -> str:
    extras = []
    for f in findings:
        if f.context and "CWE" not in f.context:
            extras.append(f.context)
    return " ".join(extras[:2]) if extras else ""
