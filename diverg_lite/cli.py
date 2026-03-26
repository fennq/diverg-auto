"""CLI entry point: diverg-scan <url> [--type quick|standard|full] [--json]"""

from __future__ import annotations

import argparse
import sys

from .scanner import scan


def main():
    parser = argparse.ArgumentParser(
        prog="diverg-scan",
        description="Diverg Lite — lightweight web security scanner",
    )
    parser.add_argument("url", help="Target URL to scan")
    parser.add_argument(
        "--type",
        dest="scan_type",
        default="standard",
        choices=["quick", "standard", "full", "headers"],
        help="Scan depth (default: standard)",
    )
    parser.add_argument("--json", action="store_true", help="Output raw JSON")
    args = parser.parse_args()

    report = scan(args.url, scan_type=args.scan_type)

    if args.json:
        print(report.to_json())
        return

    s = report.summary
    print(f"\n{'='*60}")
    print(f"  DIVERG LITE — {report.target_url}")
    print(f"{'='*60}")
    print(f"  Scan type: {report.scan_type}  |  Duration: {report.duration_ms}ms")
    print(f"  Total findings: {s['total']}")
    print()
    for sev in ("Critical", "High", "Medium", "Low", "Info"):
        count = s["by_severity"][sev]
        if count:
            indicator = {"Critical": "!!!", "High": "!! ", "Medium": "!  ", "Low": ".  ", "Info": "   "}
            print(f"  {indicator[sev]} {sev}: {count}")
    print()

    severity_rank = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    actionable = [f for f in report.findings if f.severity in ("Critical", "High", "Medium")]
    if actionable:
        print("  Actionable findings:")
        print(f"  {'-'*56}")
        for i, f in enumerate(actionable[:20], 1):
            print(f"  {i:2}. [{f.severity:>8}] {f.title}")
            if f.evidence:
                print(f"               {f.evidence[:80]}")
    print(f"\n{'='*60}\n")

    if report.errors:
        for e in report.errors:
            print(f"  [error] {e}", file=sys.stderr)


if __name__ == "__main__":
    main()
