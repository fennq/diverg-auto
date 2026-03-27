"""
Open redirect probe — detect when the application redirects to an
attacker-controlled URL based on user input.

Strategy:
  1. Identify parameters whose names suggest redirect behaviour
     (url, redirect, next, return, goto …).
  2. Inject a canary external domain and check if the server issues a 3xx
     redirect or meta-refresh pointing there.
  3. Test common filter-bypass patterns (protocol-relative, backslash,
     URL-encoded).

Non-destructive: no state changes; we only follow redirects to inspect
the Location header.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

from ..models import Finding
from .base import BaseProbe, InjectionPoint, inject_query_param
from .discovery import REDIRECT_PARAMS


# Canary targets — domains we *own nothing on*, used purely to detect
# whether the app would redirect. We never actually follow to these;
# we inspect the Location header before the browser would fetch it.
_CANARY_DOMAIN = "evil.diverg-canary.test"
_CANARY_URL = f"https://{_CANARY_DOMAIN}/pwned"


class RedirectProbe(BaseProbe):
    name = "redirect"
    cwe = "CWE-601"
    max_requests = 25

    def probe(
        self,
        url: str,
        injection_points: list[InjectionPoint],
        body: str = "",
        headers: dict | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []

        # Only test params whose names suggest redirect behaviour
        redirect_pts = [
            pt for pt in injection_points
            if pt.name.lower() in REDIRECT_PARAMS
        ]

        for pt in redirect_pts:
            if not self._can_request():
                break
            finding = self._test_redirect(pt)
            if finding:
                findings.append(finding)

        return findings

    def _test_redirect(self, pt: InjectionPoint) -> Finding | None:
        for payload, desc in _PAYLOADS:
            if not self._can_request():
                return None

            # Send WITHOUT following redirects so we can inspect Location
            if pt.method == "POST":
                resp = self._send(
                    "POST", pt.target_url,
                    data={pt.name: payload},
                    allow_redirects=False,
                )
            else:
                test_url = inject_query_param(pt.target_url, pt.name, payload)
                resp = self._send("GET", test_url, allow_redirects=False)

            if resp is None:
                continue

            redirect_target = self._extract_redirect(resp)
            if redirect_target and self._points_external(redirect_target, pt.target_url):
                return self._finding(
                    title=f"Open redirect via '{pt.name}'",
                    severity="Medium",
                    category="Injection",
                    evidence=(
                        f"Parameter '{pt.name}' with payload `{payload}` caused "
                        f"redirect to external URL: {redirect_target}"
                    ),
                    impact=(
                        "An attacker can craft a link on the trusted domain that "
                        "redirects victims to a phishing page, malware download, "
                        "or OAuth token theft endpoint."
                    ),
                    remediation=(
                        "Validate redirect targets against an allowlist of trusted "
                        "domains. Use relative paths only. Never pass full URLs "
                        "from user input to redirect functions."
                    ),
                    url=str(resp.url),
                    confidence="high",
                    proof=f"Payload: {payload} ({desc})\nRedirects to: {redirect_target}",
                    cwe="CWE-601",
                )

        return None

    # -- helpers -------------------------------------------------------------

    @staticmethod
    def _extract_redirect(resp) -> str | None:
        """Get the redirect target from Location header or meta-refresh."""
        if resp.status_code in (301, 302, 303, 307, 308):
            return resp.headers.get("Location", "")

        # Check meta refresh in body
        body = resp.text[:50_000]
        m = re.search(
            r'<meta[^>]*http-equiv=["\']refresh["\'][^>]*content=["\'][^"\']*url=([^"\'>\s]+)',
            body, re.IGNORECASE,
        )
        if m:
            return m.group(1)
        return None

    @staticmethod
    def _points_external(target: str, original_url: str) -> bool:
        """True if *target* points to a different domain than *original_url*."""
        orig_host = urlparse(original_url).netloc.lower()
        # Handle protocol-relative
        if target.startswith("//"):
            target = "https:" + target
        parsed = urlparse(target)
        target_host = parsed.netloc.lower()
        if not target_host:
            return False
        return target_host != orig_host


_PAYLOADS: list[tuple[str, str]] = [
    (_CANARY_URL,                                    "full URL"),
    (f"//{_CANARY_DOMAIN}/pwned",                    "protocol-relative"),
    (f"/\\{_CANARY_DOMAIN}/pwned",                   "backslash bypass"),
    (f"https://{_CANARY_DOMAIN}%40trusted.com",      "@ sign bypass"),
    (f"https://trusted.com@{_CANARY_DOMAIN}/pwned",  "userinfo bypass"),
    (f"/{_CANARY_DOMAIN}/pwned",                     "single-slash"),
    (f"https%3A%2F%2F{_CANARY_DOMAIN}%2Fpwned",      "URL-encoded"),
]
