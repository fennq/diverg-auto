"""Data models for scan findings, attack paths, and reports."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional


@dataclass
class Finding:
    title: str
    severity: str  # Critical | High | Medium | Low | Info
    category: str  # e.g. "Transport Security", "Content Security", "Injection"
    evidence: str
    impact: str
    remediation: str
    url: str = ""
    finding_type: str = ""  # hardening | vulnerability | info_disclosure
    context: str = ""  # operational context / CWE
    confidence: str = ""  # high | medium | low

    def to_dict(self) -> dict:
        return {k: v for k, v in asdict(self).items() if v}


SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}


@dataclass
class ScanReport:
    target_url: str
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    scanned_at: str = ""
    scan_type: str = "standard"
    duration_ms: int = 0
    score: int = 100
    grade: str = "A"
    redirect_chain: list[dict] = field(default_factory=list)
    technologies: list[str] = field(default_factory=list)
    final_url: str = ""
    status_code: int = 0
    attack_paths: list[dict] = field(default_factory=list)

    def __post_init__(self):
        if not self.scanned_at:
            self.scanned_at = datetime.now(timezone.utc).isoformat()

    @property
    def summary(self) -> dict:
        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        for f in self.findings:
            sev = f.severity if f.severity in counts else "Info"
            counts[sev] += 1
        return {
            "total": len(self.findings),
            "by_severity": counts,
            "has_critical": counts["Critical"] > 0,
            "has_high": counts["High"] > 0,
            "score": self.score,
            "grade": self.grade,
        }

    def filter_by_severity(self, min_severity: str = "Info") -> list[Finding]:
        """Return findings at or above the given severity level."""
        threshold = SEVERITY_ORDER.get(min_severity, 4)
        return [f for f in self.findings if SEVERITY_ORDER.get(f.severity, 4) <= threshold]

    def to_dict(self) -> dict:
        d = {
            "target_url": self.target_url,
            "scan_type": self.scan_type,
            "scanned_at": self.scanned_at,
            "duration_ms": self.duration_ms,
            "score": self.score,
            "grade": self.grade,
            "summary": self.summary,
            "findings": [f.to_dict() for f in self.findings],
            "errors": self.errors,
        }
        if self.redirect_chain:
            d["redirect_chain"] = self.redirect_chain
        if self.final_url:
            d["final_url"] = self.final_url
        if self.technologies:
            d["technologies"] = self.technologies
        if self.status_code:
            d["status_code"] = self.status_code
        if self.attack_paths:
            d["attack_paths"] = self.attack_paths
        return d

    def to_json(self, indent: int = 2) -> str:
        import json
        return json.dumps(self.to_dict(), indent=indent, default=str)

    def to_markdown(self) -> str:
        s = self.summary
        lines = [
            f"# Security Scan Report",
            f"",
            f"**Target:** {self.target_url}",
            f"**Score:** {self.score}/100 (Grade: {self.grade})",
            f"**Scan type:** {self.scan_type}  |  **Duration:** {self.duration_ms}ms",
            f"**Scanned at:** {self.scanned_at}",
        ]
        if self.final_url:
            lines.append(f"**Final URL:** {self.final_url}")
        if self.technologies:
            lines.append(f"**Technologies:** {', '.join(self.technologies)}")
        if self.redirect_chain:
            lines.append(f"")
            lines.append(f"## Redirect Chain")
            for i, hop in enumerate(self.redirect_chain):
                arrow = "→" if i < len(self.redirect_chain) - 1 else "(final)"
                lines.append(f"- `{hop.get('status', '?')}` {hop.get('url', '')} {arrow}")

        lines.append(f"")
        lines.append(f"## Summary")
        lines.append(f"")
        lines.append(f"| Severity | Count |")
        lines.append(f"|----------|-------|")
        for sev in ("Critical", "High", "Medium", "Low", "Info"):
            count = s["by_severity"][sev]
            if count:
                lines.append(f"| **{sev}** | {count} |")
        lines.append(f"| **Total** | **{s['total']}** |")

        for sev in ("Critical", "High", "Medium", "Low", "Info"):
            group = [f for f in self.findings if f.severity == sev]
            if not group:
                continue
            lines.append(f"")
            lines.append(f"## {sev}")
            lines.append(f"")
            for f in group:
                lines.append(f"### {f.title}")
                lines.append(f"")
                lines.append(f"- **Category:** {f.category}")
                lines.append(f"- **Evidence:** {f.evidence}")
                lines.append(f"- **Impact:** {f.impact}")
                lines.append(f"- **Remediation:** {f.remediation}")
                if f.context:
                    lines.append(f"- **Context:** {f.context}")
                lines.append(f"")

        if self.attack_paths:
            lines.append(f"## Attack Paths")
            lines.append(f"")
            for ap in self.attack_paths:
                lines.append(f"### {ap.get('name', 'Unknown')}")
                lines.append(f"")
                lines.append(f"**Severity:** {ap.get('severity', '?')}  |  "
                             f"**Likelihood:** {ap.get('likelihood', 0):.0%}")
                lines.append(f"")
                if ap.get("narrative"):
                    lines.append(f"{ap['narrative']}")
                    lines.append(f"")
                if ap.get("steps"):
                    for i, step in enumerate(ap["steps"], 1):
                        lines.append(f"  {i}. [{step.get('severity', '?')}] {step.get('title', '')}")
                    lines.append(f"")
                if ap.get("impact_summary"):
                    lines.append(f"**Impact:** {ap['impact_summary']}")
                    lines.append(f"")
                if ap.get("remediation_priority"):
                    lines.append(f"**Fix order:**")
                    for i, fix in enumerate(ap["remediation_priority"], 1):
                        lines.append(f"  {i}. {fix}")
                    lines.append(f"")

        if self.errors:
            lines.append(f"## Errors")
            lines.append(f"")
            for e in self.errors:
                lines.append(f"- {e}")

        return "\n".join(lines) + "\n"
