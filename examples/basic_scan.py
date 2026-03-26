"""Basic usage — scan a URL and print results."""

from diverg_lite import scan, quick_scan

# Standard scan: headers + SSL + content analysis
report = scan("https://example.com")

print(f"Target: {report.target_url}")
print(f"Findings: {report.summary['total']}")
print(f"Severity: {report.summary['by_severity']}")
print()

for finding in report.findings:
    print(f"[{finding.severity}] {finding.title}")
    if finding.context:
        print(f"  Context: {finding.context}")

# Quick scan: headers only
quick = quick_scan("https://example.com")
print(f"\nQuick scan: {quick.summary['total']} findings in {quick.duration_ms}ms")

# JSON output
print(report.to_json())
