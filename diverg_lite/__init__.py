"""
diverg-lite — Lightweight web security scanner for autonomous agents.

Usage:
    from diverg_lite import scan, quick_scan

    report = scan("https://example.com")
    print(report.to_json())

    # Headers-only (fast):
    report = quick_scan("https://example.com")
    print(report.summary)
"""

from .scanner import scan, quick_scan
from .models import Finding, ScanReport

__version__ = "0.1.0"
__all__ = ["scan", "quick_scan", "Finding", "ScanReport"]
