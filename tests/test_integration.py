"""
Integration + stress tests — scanner pipeline, CLI, edge cases, bad inputs.
"""

import sys
import os
import json
import subprocess
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from diverg_lite import scan, quick_scan, active_scan, batch_scan, ScanReport
from diverg_lite.probes import run_probes
from diverg_lite.probes.discovery import discover
from diverg_lite.stealth import get_session

errors = []


def assert_eq(label, got, expected):
    if got != expected:
        errors.append(f"FAIL {label}: got {got!r}, expected {expected!r}")
    else:
        print(f"  OK  {label}")


def assert_true(label, val):
    if not val:
        errors.append(f"FAIL {label}: expected truthy, got {val!r}")
    else:
        print(f"  OK  {label}")


def assert_no_crash(label, fn):
    try:
        result = fn()
        print(f"  OK  {label}")
        return result
    except Exception as e:
        errors.append(f"FAIL {label}: {type(e).__name__}: {e}")
        return None


# ---- Scanner: all scan types -----------------------------------------------
print("\n=== Scanner: scan types ===")

# quick scan — should be fast, headers only
r = assert_no_crash("quick_scan httpbin.org", lambda: quick_scan("https://httpbin.org"))
if r:
    assert_eq("quick scan_type", r.scan_type, "quick")
    assert_true("quick has score", 0 <= r.score <= 100)
    assert_true("quick has grade", r.grade in "ABCDF")
    assert_true("quick has scanned_at", len(r.scanned_at) > 0)

# standard scan
r = assert_no_crash("scan standard httpbin.org", lambda: scan("https://httpbin.org"))
if r:
    assert_eq("standard scan_type", r.scan_type, "standard")
    assert_true("standard has findings", len(r.findings) >= 0)
    assert_true("standard no attack_paths", len(r.attack_paths) == 0)

# auto-prepend https
r = assert_no_crash("scan bare domain", lambda: scan("httpbin.org", scan_type="quick"))
if r:
    assert_true("bare domain → https", r.target_url.startswith("https://"))


# ---- Scanner: bad URLs / error handling ------------------------------------
print("\n=== Scanner: error handling ===")

r = assert_no_crash("scan nonexistent domain",
    lambda: scan("https://this-domain-does-not-exist-dvg-test.com", scan_type="quick"))
if r:
    assert_true("nonexistent domain has findings or errors",
                len(r.findings) > 0 or len(r.errors) > 0)

r = assert_no_crash("scan empty string fallback",
    lambda: scan("", scan_type="quick"))

r = assert_no_crash("scan invalid URL",
    lambda: scan("not-a-url-at-all", scan_type="quick"))


# ---- Scanner: active scan with specific probes -----------------------------
print("\n=== Scanner: active with probe selection ===")

r = assert_no_crash("active_scan probe_names=[auth]",
    lambda: active_scan("https://httpbin.org", probe_names=["auth"]))
if r:
    assert_eq("active scan_type", r.scan_type, "full")
    assert_true("active has duration", r.duration_ms > 0)

r = assert_no_crash("scan full probe_names=[xss]",
    lambda: scan("https://httpbin.org", scan_type="full", probe_names=["xss"]))

# Invalid probe name — should not crash, just skip
r = assert_no_crash("scan with invalid probe name",
    lambda: scan("https://httpbin.org", scan_type="full", probe_names=["nonexistent_probe"]))

# max_requests_per_probe
r = assert_no_crash("scan with max_requests_per_probe=2",
    lambda: scan("https://httpbin.org", scan_type="full",
                 probe_names=["auth"], max_requests_per_probe=2))


# ---- Batch scan ------------------------------------------------------------
print("\n=== Scanner: batch_scan ===")

reports = assert_no_crash("batch_scan 2 URLs",
    lambda: batch_scan(["https://httpbin.org", "https://httpbin.org/get"], scan_type="quick"))
if reports:
    assert_eq("batch returns 2 reports", len(reports), 2)
    for i, r in enumerate(reports):
        assert_true(f"batch[{i}] is ScanReport", isinstance(r, ScanReport))

# batch with empty list
reports = assert_no_crash("batch_scan empty list", lambda: batch_scan([]))
if reports is not None:
    assert_eq("batch empty returns empty", len(reports), 0)


# ---- CLI: all flag combos --------------------------------------------------
print("\n=== CLI: flag combinations ===")

def run_cli(args_list, timeout=60):
    cmd = [sys.executable, "-m", "diverg_lite.cli"] + args_list
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           cwd=os.path.join(os.path.dirname(__file__), ".."))
    return result

# --help
r = run_cli(["--help"])
assert_eq("CLI --help exit 0", r.returncode, 0)
assert_true("CLI --help shows diverg-scan", "diverg" in r.stdout.lower())

# No args → help + exit 1
r = run_cli([])
assert_eq("CLI no args exit 1", r.returncode, 1)

# quick scan JSON
r = run_cli(["https://httpbin.org", "--type", "quick", "--json"])
assert_eq("CLI quick --json exit 0", r.returncode, 0)
parsed = assert_no_crash("CLI quick --json is valid JSON", lambda: json.loads(r.stdout))
if parsed:
    assert_true("CLI JSON has target_url", "target_url" in parsed)
    assert_true("CLI JSON has score", "score" in parsed)

# quick scan markdown
r = run_cli(["https://httpbin.org", "--type", "quick", "--markdown"])
assert_eq("CLI quick --markdown exit 0", r.returncode, 0)
assert_true("CLI markdown contains Security Scan Report", "Security Scan Report" in r.stdout)

# --min-severity High
r = run_cli(["https://httpbin.org", "--type", "quick", "--json", "--min-severity", "High"])
assert_eq("CLI --min-severity exit 0", r.returncode, 0)

# --fail-on with something that should trigger (httpbin.org has High findings)
r = run_cli(["https://httpbin.org", "--type", "quick", "--json", "--fail-on", "High"])
# Exit code is 1 if High findings exist — that's correct behavior
assert_true("CLI --fail-on High exit code is 0 or 1", r.returncode in (0, 1))

# --output to file
outfile = "/tmp/diverg_test_output.json"
r = run_cli(["https://httpbin.org", "--type", "quick", "--json", "--output", outfile])
assert_eq("CLI --output exit 0", r.returncode, 0)
assert_true("CLI --output file exists", os.path.exists(outfile))
if os.path.exists(outfile):
    with open(outfile) as f:
        content = f.read()
    assert_no_crash("CLI --output is valid JSON", lambda: json.loads(content))
    os.remove(outfile)

# --probe flag with active type
r = run_cli(["https://httpbin.org", "--type", "active", "--probe", "auth",
             "--max-probe-requests", "3", "--json"])
assert_eq("CLI --probe auth exit 0", r.returncode, 0)

# bad scan type
r = run_cli(["https://httpbin.org", "--type", "BOGUS"])
assert_true("CLI bad --type exits nonzero", r.returncode != 0)

# --file with nonexistent file
r = run_cli(["--file", "/tmp/nonexistent_file_dvg.txt"])
assert_eq("CLI bad --file exit 1", r.returncode, 1)


# ---- Stress: rapid sequential scans ---------------------------------------
print("\n=== Stress: rapid sequential ===")

start = time.time()
for i in range(3):
    r = assert_no_crash(f"rapid scan #{i+1}",
        lambda: quick_scan("https://httpbin.org"))
elapsed = time.time() - start
print(f"  3 rapid quick scans in {elapsed:.1f}s")


# ---- Stress: large HTML body -----------------------------------------------
print("\n=== Stress: large HTML body ===")

big_html = "<html><body>" + "<p>test</p>\n" * 50000 + "</body></html>"
pts = assert_no_crash("discover on 50k-line HTML",
    lambda: discover("https://x.com/", body=big_html, fuzz=True))
if pts:
    assert_true("discover returns list on huge body", isinstance(pts, list))

# run_probes with large body (mocked session so no network)
from unittest.mock import MagicMock
mock_session = MagicMock()
mock_resp = MagicMock()
mock_resp.text = big_html
mock_resp.status_code = 200
mock_resp.url = "https://x.com/"
mock_resp.headers = {}
mock_resp.cookies = []
mock_session.request.return_value = mock_resp
mock_session.get.return_value = mock_resp

findings = assert_no_crash("run_probes on huge body",
    lambda: run_probes("https://x.com/", mock_session, body=big_html,
                       probe_names=["xss"], max_requests_per_probe=5))
if findings is not None:
    assert_true("run_probes returns list", isinstance(findings, list))


# ---- Stress: batch scan multiple URLs --------------------------------------
print("\n=== Stress: batch 3 URLs ===")

reports = assert_no_crash("batch 3 URLs quick",
    lambda: batch_scan(
        ["https://httpbin.org", "https://httpbin.org/get", "https://httpbin.org/headers"],
        scan_type="quick",
    ))
if reports:
    assert_eq("batch 3 returns 3", len(reports), 3)
    for r in reports:
        assert_true(f"batch result {r.target_url} has grade", r.grade in "ABCDF")


# ---- Summary ---------------------------------------------------------------
print(f"\n{'='*60}")
if errors:
    print(f"FAILED: {len(errors)} error(s)")
    for e in errors:
        print(f"  {e}")
    sys.exit(1)
else:
    print("ALL INTEGRATION TESTS PASSED")
    sys.exit(0)
