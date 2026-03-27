"""
diverg-auto — autonomous web security scanner for agents and CI.

Passive analysis (headers, SSL, CSP, cookies, content, tech fingerprint):
    from diverg_lite import scan, quick_scan, batch_scan

Active vulnerability probing (XSS, SQLi, traversal, SSRF, auth bypass):
    from diverg_lite import active_scan

    report = active_scan("https://example.com")
    print(report.score, report.grade)
    print(report.attack_paths)   # exploit chains

Quick reference — scan types:
    quick    — headers only
    standard — headers + SSL + content (default)
    full     — standard + active probes + attack-path reasoning
    active   — alias for full
"""

from .scanner import scan, quick_scan, active_scan, batch_scan
from .models import Finding, ScanReport

__version__ = "0.3.0"
__all__ = [
    "scan", "quick_scan", "active_scan", "batch_scan",
    "Finding", "ScanReport",
]
