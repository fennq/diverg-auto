"""
SQL injection probe — error-based and boolean-based detection.

Strategy:
  1. Inject a single-quote into each parameter.
  2. Check the response for database error messages (error-based SQLi).
  3. Send boolean TRUE / FALSE conditions and compare response lengths
     (boolean-blind detection).

Non-destructive: payloads only read; no INSERT / UPDATE / DELETE / DROP.
"""

from __future__ import annotations

import re

from ..models import Finding
from .base import (
    BaseProbe,
    InjectionPoint,
    detect_sql_error,
    inject_query_param,
    make_canary,
)


class SQLiProbe(BaseProbe):
    name = "sqli"
    cwe = "CWE-89"
    max_requests = 40

    def probe(
        self,
        url: str,
        injection_points: list[InjectionPoint],
        body: str = "",
        headers: dict | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []

        for pt in injection_points:
            if not self._can_request():
                break
            if pt.input_type in ("file", "checkbox", "radio", "submit", "button", "image"):
                continue

            finding = self._test_error_based(pt)
            if finding:
                findings.append(finding)
                continue

            finding = self._test_boolean_blind(pt)
            if finding:
                findings.append(finding)

        return findings

    # -- error-based ---------------------------------------------------------

    def _test_error_based(self, pt: InjectionPoint) -> Finding | None:
        for payload in _ERROR_PAYLOADS:
            if not self._can_request():
                return None

            resp = self._inject(pt, payload)
            if resp is None:
                continue

            body = resp.text[:300_000]
            match = detect_sql_error(body)
            if match:
                error_text, db_type = match
                return self._finding(
                    title=f"SQL injection (error-based, {db_type}) via '{pt.name}'",
                    severity="Critical",
                    category="Injection",
                    evidence=(
                        f"Payload `{payload}` in parameter '{pt.name}' triggered "
                        f"a {db_type} error: \"{error_text}\""
                    ),
                    impact=(
                        "An attacker can read, modify, or delete database contents, "
                        "bypass authentication, and potentially execute OS commands "
                        "depending on DB privileges."
                    ),
                    remediation=(
                        "Use parameterized queries / prepared statements for all "
                        "database access. Never concatenate user input into SQL. "
                        "Apply least-privilege DB accounts."
                    ),
                    url=str(resp.url),
                    confidence="high",
                    proof=f"Injected: {payload}\nDB error: {error_text}",
                    cwe="CWE-89",
                )
        return None

    # -- boolean-blind -------------------------------------------------------

    def _test_boolean_blind(self, pt: InjectionPoint) -> Finding | None:
        if not self._can_request():
            return None

        # Baseline with original value
        baseline_resp = self._inject(pt, pt.value or "1")
        if baseline_resp is None:
            return None
        baseline_len = len(baseline_resp.text)
        baseline_code = baseline_resp.status_code

        results: list[tuple[str, str, int, int]] = []
        for true_payload, false_payload in _BOOLEAN_PAIRS:
            if not self._can_request():
                break
            true_resp = self._inject(pt, true_payload)
            if true_resp is None:
                continue
            if not self._can_request():
                break
            false_resp = self._inject(pt, false_payload)
            if false_resp is None:
                continue

            true_len = len(true_resp.text)
            false_len = len(false_resp.text)

            results.append((true_payload, false_payload, true_len, false_len))

        if not results:
            return None

        # If TRUE response ≈ baseline but FALSE is significantly different,
        # boolean-blind SQLi is likely.
        for true_p, false_p, true_l, false_l in results:
            baseline_diff = abs(true_l - baseline_len)
            bool_diff = abs(true_l - false_l)

            if bool_diff > 100 and baseline_diff < bool_diff * 0.3:
                return self._finding(
                    title=f"SQL injection (boolean-blind) via '{pt.name}'",
                    severity="Critical",
                    category="Injection",
                    evidence=(
                        f"Boolean condition changes response:\n"
                        f"  TRUE  `{true_p}` → {true_l} bytes\n"
                        f"  FALSE `{false_p}` → {false_l} bytes\n"
                        f"  Baseline → {baseline_len} bytes\n"
                        f"  Difference: {bool_diff} bytes"
                    ),
                    impact=(
                        "An attacker can extract database contents one bit at a time "
                        "by observing response differences, leading to full data exfiltration."
                    ),
                    remediation=(
                        "Use parameterized queries / prepared statements. "
                        "Never concatenate user input into SQL."
                    ),
                    url=pt.target_url,
                    confidence="medium",
                    proof=(
                        f"TRUE  payload: {true_p} → {true_l} bytes\n"
                        f"FALSE payload: {false_p} → {false_l} bytes"
                    ),
                    cwe="CWE-89",
                )

        return None

    # -- helpers -------------------------------------------------------------

    def _inject(self, pt: InjectionPoint, payload: str):
        if pt.method == "POST":
            return self._send("POST", pt.target_url, data={pt.name: payload})
        test_url = inject_query_param(pt.target_url, pt.name, payload)
        return self._send("GET", test_url)


_ERROR_PAYLOADS: list[str] = [
    "'",
    "\"",
    "' OR '1'='1",
    "1' ORDER BY 1--",
    "1 UNION SELECT NULL--",
    "') OR ('1'='1",
    "1;SELECT 1",
]

_BOOLEAN_PAIRS: list[tuple[str, str]] = [
    ("1 AND 1=1",      "1 AND 1=2"),
    ("1' AND '1'='1",  "1' AND '1'='2"),
    ("1\" AND \"1\"=\"1\"", "1\" AND \"1\"=\"2\""),
    ("1 OR 1=1",       "1 OR 1=2"),
]
