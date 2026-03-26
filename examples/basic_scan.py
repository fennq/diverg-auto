"""Basic diverg-auto usage — scan a URL and print results."""

from diverg_lite import scan, quick_scan, batch_scan

# Standard scan: headers + SSL + content analysis
report = scan("https://example.com")

print(f"Target: {report.target_url}")
print(f"Score:  {report.score}/100 (Grade: {report.grade})")
print(f"Findings: {report.summary['total']}")
print(f"Severity: {report.summary['by_severity']}")

if report.technologies:
    print(f"Stack: {', '.join(report.technologies)}")
if report.redirect_chain:
    print(f"Redirects: {' → '.join(h['url'] for h in report.redirect_chain)}")
print()

for finding in report.findings:
    print(f"[{finding.severity}] {finding.title}")
    if finding.context:
        print(f"  Context: {finding.context}")

# Quick scan: headers only
quick = quick_scan("https://example.com")
print(f"\nQuick scan: {quick.summary['total']} findings, score {quick.score} in {quick.duration_ms}ms")

# Filter to Medium+ only
medium_up = report.filter_by_severity("Medium")
print(f"\nMedium+ findings: {len(medium_up)}")

# Batch scan
reports = batch_scan(["https://example.com", "https://google.com"])
for r in reports:
    print(f"{r.target_url}: {r.score}/100 ({r.grade})")

# Markdown report
print(report.to_markdown())

# JSON output
print(report.to_json())
