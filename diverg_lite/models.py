"""Data models for scan findings and reports."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional


@dataclass
class Finding:
    title: str
    severity: str  # Critical | High | Medium | Low | Info
    category: str  # e.g. "Transport Security", "Content Security", "Cookie Security"
    evidence: str
    impact: str
    remediation: str
    url: str = ""
    finding_type: str = ""  # hardening | vulnerability | info_disclosure
    context: str = ""  # operational context for analysts
    confidence: str = ""  # high | medium | low

    def to_dict(self) -> dict:
        return {k: v for k, v in asdict(self).items() if v}


@dataclass
class ScanReport:
    target_url: str
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    scanned_at: str = ""
    scan_type: str = "standard"
    duration_ms: int = 0

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
        }

    def to_dict(self) -> dict:
        return {
            "target_url": self.target_url,
            "scan_type": self.scan_type,
            "scanned_at": self.scanned_at,
            "duration_ms": self.duration_ms,
            "summary": self.summary,
            "findings": [f.to_dict() for f in self.findings],
            "errors": self.errors,
        }

    def to_json(self, indent: int = 2) -> str:
        import json
        return json.dumps(self.to_dict(), indent=indent, default=str)
