"""
Using diverg-auto from an OpenClaw agent skill.

OpenClaw skills call diverg-auto via CLI:
    diverg-scan "https://target.com" --json

Or programmatically for richer control:
"""

import json
from diverg_lite import scan, batch_scan


def scan_for_agent(url: str, scan_type: str = "standard") -> dict:
    """
    Run a diverg-auto scan and return a dict optimized for agent consumption.
    Includes a plain-text summary the agent can relay directly to the user.
    """
    report = scan(url, scan_type=scan_type)
    result = report.to_dict()
    result["agent_summary"] = _build_agent_summary(report)
    return result


def batch_scan_for_agent(urls: list[str]) -> dict:
    """Scan multiple URLs and return a comparison summary."""
    reports = batch_scan(urls)
    return {
        "count": len(reports),
        "results": [r.to_dict() for r in reports],
        "agent_summary": _build_batch_summary(reports),
    }


def _build_agent_summary(report) -> str:
    lines = [
        f"Security scan of {report.target_url}",
        f"Score: {report.score}/100 (Grade: {report.grade})",
        f"Findings: {report.summary['total']} total",
    ]

    if report.technologies:
        lines.append(f"Stack: {', '.join(report.technologies[:5])}")
    if report.final_url:
        lines.append(f"Redirected to: {report.final_url}")

    critical_high = [f for f in report.findings if f.severity in ("Critical", "High")]
    if critical_high:
        lines.append(f"\n{len(critical_high)} issue(s) need immediate attention:")
        for f in critical_high[:5]:
            lines.append(f"  - [{f.severity}] {f.title}")
            lines.append(f"    Fix: {f.remediation}")
    elif report.score >= 75:
        lines.append("\nNo critical or high severity issues found.")

    return "\n".join(lines)


def _build_batch_summary(reports) -> str:
    lines = [f"Scanned {len(reports)} URLs:\n"]
    for r in sorted(reports, key=lambda x: x.score):
        lines.append(f"  {r.score:3d}/100 ({r.grade}) — {r.target_url}")
    best = max(reports, key=lambda x: x.score)
    worst = min(reports, key=lambda x: x.score)
    lines.append(f"\nBest:  {best.target_url} ({best.score}/100)")
    lines.append(f"Worst: {worst.target_url} ({worst.score}/100)")
    return "\n".join(lines)


if __name__ == "__main__":
    result = scan_for_agent("https://example.com")
    print(result["agent_summary"])
