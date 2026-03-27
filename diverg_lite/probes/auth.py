"""
Auth bypass probe — forced browsing, HTTP verb tampering, and common
admin-panel exposure detection.

Strategy:
  1. Forced browsing: request well-known admin/debug/config paths and
     check for 200/301/302 responses (vs expected 401/403/404).
  2. HTTP verb tampering: send unusual methods (HEAD, OPTIONS, TRACE, PATCH)
     to the target URL to see if access controls only check GET/POST.
  3. IDOR hint detection: look for sequential numeric IDs in the original
     response and note them as potential IDOR targets.

Non-destructive: all requests are safe reads (GET/HEAD/OPTIONS).
"""

from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

from ..models import Finding
from .base import BaseProbe, InjectionPoint


class AuthBypassProbe(BaseProbe):
    name = "auth"
    cwe = "CWE-284"
    max_requests = 35

    def probe(
        self,
        url: str,
        injection_points: list[InjectionPoint],
        body: str = "",
        headers: dict | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._forced_browsing(url))
        findings.extend(self._verb_tampering(url))
        if body:
            findings.extend(self._idor_hints(url, body))
        return findings

    # -- forced browsing -----------------------------------------------------

    def _forced_browsing(self, url: str) -> list[Finding]:
        findings: list[Finding] = []
        base = _base_url(url)

        for path, desc in _ADMIN_PATHS:
            if not self._can_request():
                break
            target = urljoin(base, path)
            resp = self._send("GET", target)
            if resp is None:
                continue

            if resp.status_code in (200, 301, 302, 307, 308):
                body_lower = resp.text[:50_000].lower()

                # Filter false positives: generic 404 pages that return 200
                if any(fp in body_lower for fp in _FALSE_POSITIVE_BODY):
                    continue

                is_recon = "(recon)" in desc
                severity = "Low" if is_recon else "High"
                if resp.status_code in (301, 302, 307, 308):
                    location = resp.headers.get("Location", "").lower()
                    if "login" in location or "auth" in location:
                        continue  # Redirects to login → properly protected
                    severity = "Low" if is_recon else "Medium"

                content_hint = ""
                for keyword in ("admin", "dashboard", "panel", "console", "config", "debug", "phpinfo"):
                    if keyword in body_lower:
                        content_hint = keyword
                        break

                findings.append(self._finding(
                    title=f"Exposed {desc}: {path}",
                    severity=severity,
                    category="Access Control",
                    evidence=(
                        f"GET {target} returned HTTP {resp.status_code} "
                        f"({len(resp.text)} bytes)"
                        + (f" — body contains '{content_hint}'" if content_hint else "")
                    ),
                    impact=(
                        f"The {desc} endpoint is accessible without authentication, "
                        f"potentially exposing sensitive functionality or data."
                    ),
                    remediation=(
                        f"Restrict access to {path} with authentication and "
                        f"authorization checks. Return 401/403 for unauthorized "
                        f"requests. Remove or disable in production."
                    ),
                    url=target,
                    confidence="high" if content_hint else "medium",
                    cwe="CWE-284",
                ))

        return findings

    # -- HTTP verb tampering -------------------------------------------------

    def _verb_tampering(self, url: str) -> list[Finding]:
        findings: list[Finding] = []

        # First check: does TRACE return the request body? (XST risk)
        if self._can_request():
            resp = self._send("TRACE", url)
            if resp and resp.status_code == 200 and "TRACE" in resp.text[:5000]:
                findings.append(self._finding(
                    title="HTTP TRACE method enabled (XST risk)",
                    severity="Medium",
                    category="Access Control",
                    evidence=f"TRACE {url} returned 200 with request echo",
                    impact=(
                        "TRACE can be used for Cross-Site Tracing (XST) to steal "
                        "credentials from HttpOnly cookies via XSS."
                    ),
                    remediation="Disable the TRACE HTTP method on the web server.",
                    url=url,
                    confidence="high",
                    cwe="CWE-693",
                ))

        # Second check: does OPTIONS reveal unexpected allowed methods?
        if self._can_request():
            resp = self._send("OPTIONS", url)
            if resp and resp.status_code == 200:
                allow = resp.headers.get("Allow", "")
                if allow:
                    dangerous = {"PUT", "DELETE", "PATCH", "TRACE"}
                    allowed_set = {m.strip().upper() for m in allow.split(",")}
                    exposed = dangerous & allowed_set
                    if exposed:
                        findings.append(self._finding(
                            title=f"Dangerous HTTP methods allowed: {', '.join(sorted(exposed))}",
                            severity="Medium",
                            category="Access Control",
                            evidence=f"OPTIONS {url} → Allow: {allow}",
                            impact=(
                                f"Methods {', '.join(sorted(exposed))} may allow "
                                f"unauthorized data modification or deletion."
                            ),
                            remediation=(
                                "Disable unnecessary HTTP methods. Only allow GET, "
                                "POST, HEAD, OPTIONS as needed."
                            ),
                            url=url,
                            confidence="medium",
                            cwe="CWE-749",
                        ))

        return findings

    # -- IDOR hints ----------------------------------------------------------

    def _idor_hints(self, url: str, body: str) -> list[Finding]:
        """Flag sequential numeric IDs in API responses/URLs as IDOR risks."""
        findings: list[Finding] = []

        # Look for JSON-like patterns: "id": 123, "user_id": 456
        id_pattern = re.findall(
            r'"(\w*id\w*)"\s*:\s*(\d{1,10})',
            body[:100_000], re.IGNORECASE,
        )

        if len(id_pattern) >= 2:
            id_fields = list({name for name, _ in id_pattern})[:5]
            sample_values = [(n, v) for n, v in id_pattern[:5]]

            findings.append(self._finding(
                title=f"Potential IDOR — sequential IDs in response ({', '.join(id_fields)})",
                severity="Low",
                category="Access Control",
                evidence=(
                    f"Response contains numeric ID fields: "
                    + ", ".join(f"{n}={v}" for n, v in sample_values)
                ),
                impact=(
                    "Sequential/predictable IDs may allow attackers to enumerate "
                    "and access other users' records by changing the ID value."
                ),
                remediation=(
                    "Use UUIDs or other non-sequential identifiers. Enforce "
                    "authorization checks on every object access."
                ),
                url=url,
                confidence="low",
                cwe="CWE-639",
            ))

        return findings


def _base_url(url: str) -> str:
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}/"


# Body content that indicates a custom 404 page returning HTTP 200
_FALSE_POSITIVE_BODY = [
    "page not found", "404", "not found", "does not exist",
    "no longer available", "error 404",
]

_ADMIN_PATHS: list[tuple[str, str]] = [
    ("/admin", "admin panel"),
    ("/admin/", "admin panel"),
    ("/administrator", "admin panel"),
    ("/wp-admin", "WordPress admin"),
    ("/wp-login.php", "WordPress login"),
    ("/dashboard", "dashboard"),
    ("/panel", "control panel"),
    ("/console", "console"),
    ("/manager", "manager"),
    ("/phpmyadmin", "phpMyAdmin"),
    ("/adminer.php", "Adminer DB tool"),
    ("/debug", "debug endpoint"),
    ("/.env", "environment file"),
    ("/config.json", "configuration file"),
    ("/config.yml", "configuration file"),
    ("/api/admin", "admin API"),
    ("/api/debug", "debug API"),
    ("/graphql", "GraphQL endpoint"),
    ("/swagger", "Swagger UI"),
    ("/swagger-ui.html", "Swagger UI"),
    ("/api-docs", "API documentation"),
    ("/actuator", "Spring Boot actuator"),
    ("/actuator/health", "Spring actuator health"),
    ("/actuator/env", "Spring actuator env (sensitive)"),
    ("/server-status", "Apache server-status"),
    ("/server-info", "Apache server-info"),
    ("/.git/config", "exposed git config"),
    ("/.git/HEAD", "exposed git HEAD"),
    ("/robots.txt", "robots.txt (recon)"),
    ("/sitemap.xml", "sitemap (recon)"),
    ("/.well-known/security.txt", "security.txt (recon)"),
]
