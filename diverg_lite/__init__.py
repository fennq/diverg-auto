"""
diverg-lite — Lightweight web security scanner for autonomous agents.

Usage:
    from diverg_lite import scan, quick_scan, batch_scan

    report = scan("https://example.com")
    print(report.score, report.grade)  # 72, "B"
    print(report.to_json())

    # Headers-only (fast):
    report = quick_scan("https://example.com")
    print(report.summary)

    # Multiple URLs:
    reports = batch_scan(["https://a.com", "https://b.com"])

    # Markdown report:
    print(report.to_markdown())
"""

from .scanner import scan, quick_scan, batch_scan
from .models import Finding, ScanReport

__version__ = "0.2.0"
__all__ = ["scan", "quick_scan", "batch_scan", "Finding", "ScanReport"]
