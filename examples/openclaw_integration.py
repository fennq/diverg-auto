"""
Example: Using diverg-lite from an OpenClaw agent skill.

OpenClaw skills typically call diverg-lite via the CLI:
    diverg-scan "https://target.com" --type standard --json

But if the agent uses the Python tool, this shows the programmatic path.
"""

import json
from diverg_lite import scan


def scan_for_agent(url: str, scan_type: str = "standard") -> dict:
    """
    Run a Diverg scan and return a dict suitable for agent consumption.

    The agent can use this to:
    - Summarize security posture in natural language
    - Flag critical/high issues for the user
    - Save the full report as JSON
    """
    report = scan(url, scan_type=scan_type)
    result = report.to_dict()

    # Add agent-friendly fields
    result["agent_summary"] = _build_agent_summary(report)
    return result


def _build_agent_summary(report) -> str:
    s = report.summary
    lines = [f"Scanned {report.target_url} ({report.scan_type}, {report.duration_ms}ms)"]
    lines.append(f"Total: {s['total']} findings")

    for sev in ("Critical", "High", "Medium", "Low", "Info"):
        count = s["by_severity"][sev]
        if count:
            lines.append(f"  {sev}: {count}")

    critical_high = [f for f in report.findings if f.severity in ("Critical", "High")]
    if critical_high:
        lines.append("\nImmediate attention:")
        for f in critical_high[:5]:
            lines.append(f"  - [{f.severity}] {f.title}")
            lines.append(f"    Fix: {f.remediation}")

    return "\n".join(lines)


if __name__ == "__main__":
    result = scan_for_agent("https://example.com")
    print(result["agent_summary"])
    print("\n--- Full JSON ---")
    print(json.dumps(result, indent=2, default=str))
