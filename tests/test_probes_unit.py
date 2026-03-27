"""
Unit tests for every probe module — imports, instantiation, edge cases,
and offline probing (mocked HTTP).
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from unittest.mock import MagicMock, patch
from diverg_lite.probes.base import (
    InjectionPoint, BaseProbe, make_canary, inject_query_param,
    response_contains, detect_sql_error, detect_path_traversal_content,
    strip_tags, SQL_ERROR_PATTERNS,
)
from diverg_lite.probes.discovery import (
    discover, extract_links, FUZZ_PARAMS, REDIRECT_PARAMS, URL_PARAMS, FILE_PARAMS,
)
from diverg_lite.probes.xss import XSSProbe
from diverg_lite.probes.sqli import SQLiProbe
from diverg_lite.probes.traversal import TraversalProbe
from diverg_lite.probes.redirect import RedirectProbe
from diverg_lite.probes.ssrf import SSRFProbe
from diverg_lite.probes.auth import AuthBypassProbe
from diverg_lite.probes import ALL_PROBES, PROBE_MAP, run_probes
from diverg_lite.models import Finding, ScanReport, SEVERITY_ORDER
from diverg_lite.attack_path import analyze_attack_paths, AttackPath
from diverg_lite.stealth import StealthSession

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


def assert_false(label, val):
    if val:
        errors.append(f"FAIL {label}: expected falsy, got {val!r}")
    else:
        print(f"  OK  {label}")


def assert_no_exception(label, fn):
    try:
        fn()
        print(f"  OK  {label}")
    except Exception as e:
        errors.append(f"FAIL {label}: raised {type(e).__name__}: {e}")


# ---- base.py ---------------------------------------------------------------
print("\n=== base.py ===")

assert_true("make_canary starts with prefix", make_canary("test").startswith("test"))
assert_eq("make_canary length", len(make_canary("ab")), 2 + 8)  # prefix + 4 hex bytes
assert_true("make_canary unique", make_canary() != make_canary())

assert_eq("inject_query_param new",
    inject_query_param("https://x.com/page", "id", "42"),
    "https://x.com/page?id=42")
assert_eq("inject_query_param replace",
    inject_query_param("https://x.com/page?id=1", "id", "99"),
    "https://x.com/page?id=99")
assert_eq("inject_query_param preserve others",
    inject_query_param("https://x.com/?a=1&b=2", "a", "X"),
    "https://x.com/?a=X&b=2")

assert_true("response_contains case-sensitive hit", response_contains("Hello World", "World"))
assert_false("response_contains case-sensitive miss", response_contains("Hello World", "world"))
assert_true("response_contains case-insensitive", response_contains("Hello World", "world", False))

# SQL error detection
assert_true("detect_sql_error MySQL",
    detect_sql_error("You have an error in your SQL syntax near '") is not None)
assert_true("detect_sql_error PostgreSQL",
    detect_sql_error("ERROR:  syntax error at or near \"foo\"") is not None)
assert_true("detect_sql_error MSSQL",
    detect_sql_error("Unclosed quotation mark after the character string 'x'") is not None)
assert_true("detect_sql_error Oracle",
    detect_sql_error("ORA-00933: SQL command not properly ended") is not None)
assert_true("detect_sql_error SQLite",
    detect_sql_error('near "SELECT": syntax error SQLITE_ERROR') is not None)
assert_true("detect_sql_error none on clean",
    detect_sql_error("Hello, this is a normal page with no errors.") is None)

# Path traversal markers
assert_true("detect_path_traversal unix",
    detect_path_traversal_content("root:x:0:0:root:/root:/bin/bash") is not None)
assert_true("detect_path_traversal windows",
    detect_path_traversal_content("[extensions]\nfoo=bar") is not None)
assert_true("detect_path_traversal none on clean",
    detect_path_traversal_content("Normal page content") is None)

assert_eq("strip_tags", strip_tags("<b>Hello</b> <i>World</i>"), "Hello World")

# InjectionPoint
pt = InjectionPoint(url="https://x.com", name="q", value="test", form_action="https://x.com/search")
assert_eq("InjectionPoint target_url with form_action", pt.target_url, "https://x.com/search")
pt2 = InjectionPoint(url="https://x.com", name="q")
assert_eq("InjectionPoint target_url fallback", pt2.target_url, "https://x.com")


# ---- discovery.py -----------------------------------------------------------
print("\n=== discovery.py ===")

pts = discover("https://x.com/page?id=1&name=foo", fuzz=False)
names = [p.name for p in pts]
assert_true("discover URL params: id", "id" in names)
assert_true("discover URL params: name", "name" in names)

pts_fuzz = discover("https://x.com/", fuzz=True)
assert_true("discover fuzz seeds generated", len(pts_fuzz) > 0)

html_body = '''
<html><body>
<form action="/login" method="POST">
  <input type="text" name="username" value="">
  <input type="password" name="password" value="">
  <input type="hidden" name="csrf_token" value="abc123">
  <input type="submit" value="Login">
</form>
<form action="/search" method="GET">
  <input type="text" name="q">
</form>
</body></html>
'''
pts_forms = discover("https://x.com/", body=html_body, fuzz=False)
form_names = [p.name for p in pts_forms]
assert_true("discover forms: username", "username" in form_names)
assert_true("discover forms: password", "password" in form_names)
assert_true("discover forms: csrf_token", "csrf_token" in form_names)
assert_true("discover forms: q", "q" in form_names)

# Check form action resolved correctly
login_pt = next(p for p in pts_forms if p.name == "username")
assert_eq("discover form action resolved", login_pt.form_action, "https://x.com/login")
assert_eq("discover form method", login_pt.method, "POST")
assert_eq("discover form location body", login_pt.location, "body")

search_pt = next(p for p in pts_forms if p.name == "q")
assert_eq("discover search form method", search_pt.method, "GET")

# Edge: empty body, no params
pts_empty = discover("https://x.com/", body="", fuzz=False)
assert_eq("discover empty body no fuzz", len(pts_empty), 0)

# Edge: malformed HTML
pts_bad = discover("https://x.com/", body="<form><input name='x'><broken", fuzz=False)
assert_true("discover survives malformed HTML", isinstance(pts_bad, list))

# Extract links
links_html = '''
<a href="/about">About</a>
<a href="https://x.com/contact">Contact</a>
<a href="https://other.com/ext">External</a>
<a href="javascript:void(0)">JS</a>
<a href="mailto:a@b.com">Mail</a>
<a href="/page?id=5">Page</a>
'''
links = extract_links("https://x.com/", links_html)
assert_true("extract_links same-origin only", all("x.com" in l for l in links))
assert_true("extract_links no javascript", not any("javascript" in l for l in links))
assert_true("extract_links no mailto", not any("mailto" in l for l in links))
assert_true("extract_links found /about", any("/about" in l for l in links))


# ---- Probe instantiation + empty-input edge cases --------------------------
print("\n=== probe instantiation ===")

mock_session = MagicMock(spec=StealthSession)

for ProbeClass in ALL_PROBES:
    probe = ProbeClass(mock_session)
    assert_true(f"{ProbeClass.name} has name", len(probe.name) > 0)
    assert_true(f"{ProbeClass.name} has cwe", len(probe.cwe) > 0)
    assert_true(f"{ProbeClass.name} has max_requests", probe.max_requests > 0)
    assert_true(f"{ProbeClass.name} can_request initially", probe._can_request())

    # Probe with empty injection points should return empty list, no crash
    result = probe.probe("https://x.com/", [], body="", headers={})
    assert_true(f"{ProbeClass.name} empty points returns list", isinstance(result, list))

# Custom max_requests
xss = XSSProbe(mock_session, max_requests=5)
assert_eq("custom max_requests", xss.max_requests, 5)


# ---- PROBE_MAP registry ----------------------------------------------------
print("\n=== probe registry ===")
assert_eq("PROBE_MAP count", len(PROBE_MAP), len(ALL_PROBES))
for cls in ALL_PROBES:
    assert_true(f"PROBE_MAP has {cls.name}", cls.name in PROBE_MAP)
    assert_eq(f"PROBE_MAP[{cls.name}] is correct class", PROBE_MAP[cls.name], cls)


# ---- Attack path engine ----------------------------------------------------
print("\n=== attack_path.py ===")

# Empty findings
paths = analyze_attack_paths([])
assert_eq("attack_paths empty findings", paths, [])

# Single XSS finding
xss_finding = Finding(
    title="Reflected XSS (html_body context) via 'q'",
    severity="Medium", category="Injection",
    evidence="test", impact="test", remediation="test",
    finding_type="vulnerability",
)
paths = analyze_attack_paths([xss_finding])
assert_true("attack_paths single XSS (may chain or not)", isinstance(paths, list))

# XSS + cookie = session hijack chain
cookie_finding = Finding(
    title="Cookie security issue: session_id",
    severity="Medium", category="Cookie Security",
    evidence="test", impact="test", remediation="test",
    finding_type="hardening",
)
paths = analyze_attack_paths([xss_finding, cookie_finding])
hijack = [p for p in paths if "Session Hijack" in p.name]
assert_true("attack_paths XSS+cookie → session hijack", len(hijack) > 0)
if hijack:
    assert_eq("session hijack severity", hijack[0].severity, "Critical")
    assert_true("session hijack has steps", len(hijack[0].steps) >= 2)
    assert_true("session hijack has fix order", len(hijack[0].remediation_priority) > 0)

# SQLi finding → database compromise
sqli_finding = Finding(
    title="SQL injection (error-based, MySQL) via 'id'",
    severity="Critical", category="Injection",
    evidence="test", impact="test", remediation="test",
    finding_type="vulnerability",
)
paths = analyze_attack_paths([sqli_finding])
db_chain = [p for p in paths if "Database" in p.name]
assert_true("attack_paths SQLi → database compromise", len(db_chain) > 0)

# AttackPath serialization
if paths:
    d = paths[0].to_dict()
    assert_true("AttackPath.to_dict has name", "name" in d)
    assert_true("AttackPath.to_dict has narrative", "narrative" in d)
    assert_true("AttackPath.to_dict has steps", "steps" in d)

    md = paths[0].to_markdown()
    assert_true("AttackPath.to_markdown is string", isinstance(md, str))
    assert_true("AttackPath.to_markdown has content", len(md) > 50)

# SSRF → internal pivot
ssrf_finding = Finding(
    title="SSRF via 'url' — AWS EC2 metadata",
    severity="Critical", category="Injection",
    evidence="test", impact="test", remediation="test",
    finding_type="vulnerability",
)
paths = analyze_attack_paths([ssrf_finding])
ssrf_chain = [p for p in paths if "SSRF" in p.name]
assert_true("attack_paths SSRF → internal pivot", len(ssrf_chain) > 0)

# Git exposure
git_finding = Finding(
    title="Exposed .git config: /.git/config",
    severity="High", category="Access Control",
    evidence="test", impact="test", remediation="test",
    finding_type="vulnerability",
)
paths = analyze_attack_paths([git_finding])
git_chain = [p for p in paths if "Git" in p.name]
assert_true("attack_paths .git → exposure chain", len(git_chain) > 0)


# ---- Models: ScanReport with attack_paths ----------------------------------
print("\n=== models.py ===")

report = ScanReport(
    target_url="https://test.com",
    findings=[xss_finding, sqli_finding],
    scan_type="full",
    score=25,
    grade="F",
    attack_paths=[{"name": "Test Chain", "severity": "Critical",
                   "likelihood": 0.8, "narrative": "test narrative",
                   "steps": [{"title": "step1", "severity": "High"}],
                   "impact_summary": "bad", "remediation_priority": ["fix1"]}],
)
d = report.to_dict()
assert_true("ScanReport.to_dict has attack_paths", "attack_paths" in d)
assert_eq("ScanReport.to_dict attack_paths count", len(d["attack_paths"]), 1)

j = report.to_json()
assert_true("ScanReport.to_json is string", isinstance(j, str))
assert_true("ScanReport.to_json contains attack_paths", "attack_paths" in j)

md = report.to_markdown()
assert_true("ScanReport.to_markdown contains Attack Paths", "Attack Paths" in md)
assert_true("ScanReport.to_markdown contains chain name", "Test Chain" in md)
assert_true("ScanReport.to_markdown contains narrative", "test narrative" in md)
assert_true("ScanReport.to_markdown contains fix order", "fix1" in md)

# Empty attack_paths should not appear in output
report2 = ScanReport(target_url="https://test.com", findings=[], attack_paths=[])
d2 = report2.to_dict()
assert_false("ScanReport empty attack_paths not in dict", "attack_paths" in d2)
md2 = report2.to_markdown()
assert_false("ScanReport empty attack_paths not in markdown", "Attack Paths" in md2)

# filter_by_severity
report3 = ScanReport(
    target_url="https://test.com",
    findings=[
        Finding(title="crit", severity="Critical", category="t", evidence="t", impact="t", remediation="t"),
        Finding(title="high", severity="High", category="t", evidence="t", impact="t", remediation="t"),
        Finding(title="med", severity="Medium", category="t", evidence="t", impact="t", remediation="t"),
        Finding(title="low", severity="Low", category="t", evidence="t", impact="t", remediation="t"),
        Finding(title="info", severity="Info", category="t", evidence="t", impact="t", remediation="t"),
    ],
)
assert_eq("filter_by_severity High", len(report3.filter_by_severity("High")), 2)
assert_eq("filter_by_severity Medium", len(report3.filter_by_severity("Medium")), 3)
assert_eq("filter_by_severity Info", len(report3.filter_by_severity("Info")), 5)

# summary property
s = report3.summary
assert_eq("summary total", s["total"], 5)
assert_eq("summary Critical", s["by_severity"]["Critical"], 1)
assert_true("summary has_critical", s["has_critical"])
assert_true("summary has_high", s["has_high"])


# ---- XSS probe context classification (offline) ----------------------------
print("\n=== xss.py context classification ===")

from diverg_lite.probes.xss import XSSProbe

canary = "xTestCanary123"

# HTML body context
body_html = f"<div>Results for: {canary}</div>"
ctxs = XSSProbe._classify_contexts(body_html, canary)
assert_true("XSS classify html_body", "html_body" in ctxs)

# Attribute context
attr_html = f'<input value="{canary}" type="text">'
ctxs = XSSProbe._classify_contexts(attr_html, canary)
assert_true("XSS classify attribute", "attribute" in ctxs)

# Script context
script_html = f"<script>var x = '{canary}';</script>"
ctxs = XSSProbe._classify_contexts(script_html, canary)
assert_true("XSS classify script", "script" in ctxs)

# Comment context
comment_html = f"<!-- {canary} -->"
ctxs = XSSProbe._classify_contexts(comment_html, canary)
assert_true("XSS classify comment", "comment" in ctxs)

# No reflection → default html_body
ctxs = XSSProbe._classify_contexts("no canary here", canary)
assert_eq("XSS classify no reflection → default", ctxs, ["html_body"])


# ---- SQLi error pattern coverage -------------------------------------------
print("\n=== sqli.py error patterns ===")

test_errors = [
    ("You have an error in your SQL syntax", "MySQL"),
    ("Warning: mysql_fetch_array()", "MySQL"),
    ("Unclosed quotation mark after the character string", "MSSQL"),
    ("ORA-00933: SQL command not properly ended", "Oracle"),
    ("PG::SyntaxError: ERROR", "PostgreSQL"),
    ("ERROR:  syntax error at or near", "PostgreSQL"),
    ('near "SELECT": syntax error', "SQLite"),
    ("SQLITE_ERROR", "SQLite"),
    ("System.Data.SqlClient.SqlException", "MSSQL"),
    ("PDOException", "PHP/PDO"),
    ("com.mysql.jdbc.exceptions", "MySQL"),
    ("org.postgresql.util.PSQLException", "PostgreSQL"),
]

for error_text, expected_db in test_errors:
    result = detect_sql_error(error_text)
    assert_true(f"SQLi detect {expected_db}: '{error_text[:40]}...'", result is not None)
    if result:
        _, detected_db = result
        assert_true(f"SQLi db match {expected_db}", expected_db.lower() in detected_db.lower()
                    or detected_db.lower() in expected_db.lower()
                    or "generic" in detected_db.lower()
                    or "java" in detected_db.lower()
                    or "php" in detected_db.lower())


# ---- Summary ---------------------------------------------------------------
print(f"\n{'='*60}")
if errors:
    print(f"FAILED: {len(errors)} error(s)")
    for e in errors:
        print(f"  {e}")
    sys.exit(1)
else:
    print("ALL TESTS PASSED")
    sys.exit(0)
