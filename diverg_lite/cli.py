"""CLI entry point: diverg-scan <url> [urls...] [--type] [--json] [--markdown] [--output] [--min-severity] [--probe]"""

from __future__ import annotations

import argparse
import sys

from .scanner import scan, batch_scan
from .models import SEVERITY_ORDER


_BANNER_ACTIVE = """
  ⚠  ACTIVE PROBING MODE
  This sends test payloads (XSS canaries, SQLi strings, traversal
  sequences, etc.) to the target. All payloads are non-destructive
  and read-only, but they ARE visible in server logs.

  Only scan targets you have authorization to test.
"""


def main():
    parser = argparse.ArgumentParser(
        prog="diverg-scan",
        description="diverg-auto — autonomous web security scanner",
    )
    parser.add_argument("urls", nargs="*", help="Target URL(s) to scan")
    parser.add_argument(
        "--file", "-f",
        dest="url_file",
        help="File containing URLs to scan (one per line)",
    )
    parser.add_argument(
        "--type", "-t",
        dest="scan_type",
        default="standard",
        choices=["quick", "standard", "full", "active", "headers"],
        help="Scan depth: quick (headers), standard (+ SSL + content), full/active (+ vulnerability probes)",
    )
    parser.add_argument("--json", action="store_true", help="Output JSON")
    parser.add_argument("--markdown", "--md", action="store_true", help="Output Markdown report")
    parser.add_argument(
        "--output", "-o",
        dest="output_file",
        help="Write output to file instead of stdout",
    )
    parser.add_argument(
        "--min-severity", "-s",
        dest="min_severity",
        default="Info",
        choices=["Critical", "High", "Medium", "Low", "Info"],
        help="Only show findings at or above this severity (default: Info = show all)",
    )
    parser.add_argument(
        "--fail-on",
        dest="fail_severity",
        default=None,
        choices=["Critical", "High", "Medium", "Low"],
        help="Exit with code 1 if any finding at or above this severity (for CI)",
    )
    parser.add_argument(
        "--probe",
        dest="probes",
        default=None,
        help="Comma-separated probe names to run (default: all). "
             "Options: xss,sqli,traversal,redirect,ssrf,auth",
    )
    parser.add_argument(
        "--max-probe-requests",
        dest="max_probe_requests",
        type=int,
        default=None,
        help="Max HTTP requests per probe (default: probe-specific)",
    )
    args = parser.parse_args()

    urls = list(args.urls or [])
    if args.url_file:
        try:
            with open(args.url_file) as fh:
                for line in fh:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        urls.append(line)
        except FileNotFoundError:
            print(f"Error: file not found: {args.url_file}", file=sys.stderr)
            sys.exit(1)

    if not urls:
        parser.print_help()
        sys.exit(1)

    # Warn when using active probing
    if args.scan_type in ("full", "active") and not args.json:
        print(_BANNER_ACTIVE, file=sys.stderr)

    probe_names = None
    if args.probes:
        probe_names = [p.strip() for p in args.probes.split(",") if p.strip()]

    scan_kwargs = {}
    if probe_names:
        scan_kwargs["probe_names"] = probe_names
    if args.max_probe_requests is not None:
        scan_kwargs["max_requests_per_probe"] = args.max_probe_requests

    reports = [
        scan(u, scan_type=args.scan_type, **scan_kwargs) for u in urls
    ]

    output_parts = []

    for report in reports:
        if args.min_severity != "Info":
            report.findings = report.filter_by_severity(args.min_severity)

        if args.json:
            import json
            if len(reports) == 1:
                output_parts.append(report.to_json())
            else:
                output_parts.append(json.dumps(report.to_dict(), default=str))
        elif args.markdown:
            output_parts.append(report.to_markdown())
        else:
            output_parts.append(_format_human(report))

    if args.json and len(reports) > 1:
        import json
        combined = json.dumps([r.to_dict() for r in reports], indent=2, default=str)
        output = combined
    else:
        output = "\n".join(output_parts)

    if args.output_file:
        with open(args.output_file, "w", encoding="utf-8") as fh:
            fh.write(output + "\n")
        print(f"Report written to {args.output_file}")
    else:
        print(output)

    if args.fail_severity:
        threshold = SEVERITY_ORDER.get(args.fail_severity, 4)
        for r in reports:
            for f in r.findings:
                if SEVERITY_ORDER.get(f.severity, 4) <= threshold:
                    sys.exit(1)


def _format_human(report) -> str:
    s = report.summary
    lines = []
    lines.append(f"\n{'='*60}")
    lines.append(f"  DIVERG AUTO — {report.target_url}")
    lines.append(f"  Score: {report.score}/100 (Grade: {report.grade})")
    lines.append(f"{'='*60}")
    lines.append(f"  Scan type: {report.scan_type}  |  Duration: {report.duration_ms}ms")
    lines.append(f"  Total findings: {s['total']}")

    if report.technologies:
        lines.append(f"  Stack: {', '.join(report.technologies[:5])}")
    if report.final_url:
        lines.append(f"  Redirected to: {report.final_url}")
    lines.append("")

    for sev in ("Critical", "High", "Medium", "Low", "Info"):
        count = s["by_severity"][sev]
        if count:
            indicator = {"Critical": "!!!", "High": "!! ", "Medium": "!  ", "Low": ".  ", "Info": "   "}
            lines.append(f"  {indicator[sev]} {sev}: {count}")
    lines.append("")

    actionable = [f for f in report.findings if f.severity in ("Critical", "High", "Medium")]
    if actionable:
        lines.append("  Actionable findings:")
        lines.append(f"  {'-'*56}")
        for i, f in enumerate(actionable[:20], 1):
            lines.append(f"  {i:2}. [{f.severity:>8}] {f.title}")
            if f.evidence:
                ev = f.evidence.split("\n")[0][:80]
                lines.append(f"               {ev}")

    if report.attack_paths:
        lines.append("")
        lines.append(f"  {'='*56}")
        lines.append(f"  ATTACK PATHS ({len(report.attack_paths)} identified)")
        lines.append(f"  {'='*56}")
        for ap in report.attack_paths:
            likelihood = ap.get("likelihood", 0)
            lines.append(f"")
            lines.append(f"  [{ap.get('severity', '?'):>8}] {ap.get('name', '?')}  "
                         f"(likelihood: {likelihood:.0%})")
            if ap.get("narrative"):
                for nline in _wrap(ap["narrative"], 52):
                    lines.append(f"           {nline}")
            if ap.get("remediation_priority"):
                lines.append(f"           Fix order:")
                for i, fix in enumerate(ap["remediation_priority"][:3], 1):
                    lines.append(f"             {i}. {fix}")

    lines.append(f"\n{'='*60}\n")

    if report.errors:
        for e in report.errors:
            lines.append(f"  [error] {e}")
    return "\n".join(lines)


def _wrap(text: str, width: int) -> list[str]:
    """Simple word-wrap for terminal output."""
    words = text.split()
    lines: list[str] = []
    current: list[str] = []
    length = 0
    for w in words:
        if length + len(w) + 1 > width and current:
            lines.append(" ".join(current))
            current = [w]
            length = len(w)
        else:
            current.append(w)
            length += len(w) + 1
    if current:
        lines.append(" ".join(current))
    return lines


if __name__ == "__main__":
    main()
