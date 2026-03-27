"""
Reflected XSS probe — detects when user input is echoed back into HTML without
proper encoding.

Strategy:
  1. Inject a unique canary string into each parameter.
  2. If the canary appears in the response body → reflection confirmed.
  3. Test HTML context: inject `<canaryTag>` and check if angle brackets survive.
  4. Test attribute breakout: inject `"onmouseover=` pattern.
  5. Test script context: inject `';canary//` pattern.

Non-destructive: no payloads execute (no alert(), no DOM changes).
"""

from __future__ import annotations

import html
import re

from ..models import Finding
from .base import (
    BaseProbe,
    InjectionPoint,
    inject_query_param,
    make_canary,
    response_contains,
)


class XSSProbe(BaseProbe):
    name = "xss"
    cwe = "CWE-79"
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
            # Skip non-text-like inputs
            if pt.input_type in ("file", "checkbox", "radio", "submit", "button", "image"):
                continue

            canary = make_canary("xR")
            reflected = self._check_reflection(pt, canary)
            if not reflected:
                continue

            resp_body, resp_url = reflected

            # Determine reflection context
            contexts = self._classify_contexts(resp_body, canary)

            # Try increasingly dangerous payloads within each context
            for ctx in contexts:
                result = self._test_context(pt, ctx, resp_url)
                if result:
                    findings.append(result)
                    break  # one finding per param is enough

        return findings

    # -- reflection check ----------------------------------------------------

    def _check_reflection(
        self, pt: InjectionPoint, canary: str
    ) -> tuple[str, str] | None:
        """Inject canary; return (response_body, response_url) if reflected."""
        if pt.method == "POST":
            resp = self._send("POST", pt.target_url, data={pt.name: canary})
        else:
            test_url = inject_query_param(pt.target_url, pt.name, canary)
            resp = self._send("GET", test_url)

        if resp is None:
            return None
        body = resp.text[:500_000]
        if response_contains(body, canary):
            return body, str(resp.url)
        return None

    # -- context classification ----------------------------------------------

    @staticmethod
    def _classify_contexts(body: str, canary: str) -> list[str]:
        """Determine where in the HTML the canary landed."""
        contexts: list[str] = []
        idx = 0
        while True:
            pos = body.find(canary, idx)
            if pos == -1:
                break
            # Look at surrounding characters
            before = body[max(0, pos - 80):pos]
            after = body[pos + len(canary):pos + len(canary) + 80]

            if re.search(r"<script[^>]*>[^<]*$", before, re.IGNORECASE):
                contexts.append("script")
            elif re.search(r'=\s*["\']?\s*$', before):
                contexts.append("attribute")
            elif re.search(r"<!--", before) and "-->" not in before[before.rfind("<!--"):]:
                contexts.append("comment")
            else:
                contexts.append("html_body")
            idx = pos + len(canary)

        # Deduplicate while keeping order
        seen: set[str] = set()
        unique: list[str] = []
        for c in contexts:
            if c not in seen:
                seen.add(c)
                unique.append(c)
        return unique or ["html_body"]

    # -- context-specific tests ----------------------------------------------

    def _test_context(
        self, pt: InjectionPoint, context: str, original_url: str
    ) -> Finding | None:
        payloads = _PAYLOADS.get(context, _PAYLOADS["html_body"])

        for payload_tpl, check_fn, desc in payloads:
            if not self._can_request():
                return None

            canary = make_canary("xV")
            payload = payload_tpl.replace("{CANARY}", canary)

            if pt.method == "POST":
                resp = self._send("POST", pt.target_url, data={pt.name: payload})
            else:
                test_url = inject_query_param(pt.target_url, pt.name, payload)
                resp = self._send("GET", test_url)

            if resp is None:
                continue
            body = resp.text[:500_000]

            if check_fn(body, canary):
                severity = "High" if context in ("script", "attribute") else "Medium"
                proof_lines = _extract_proof(body, canary, max_lines=3)

                return self._finding(
                    title=f"Reflected XSS ({context} context) via '{pt.name}'",
                    severity=severity,
                    category="Injection",
                    evidence=(
                        f"Parameter '{pt.name}' reflects input into {context} context "
                        f"without adequate encoding."
                    ),
                    impact=(
                        "An attacker can inject HTML/JavaScript that executes in the "
                        "victim's browser session, leading to session hijack, credential "
                        "theft, or phishing within the trusted domain."
                    ),
                    remediation=(
                        "HTML-encode all reflected output using context-appropriate encoding "
                        "(HTML entities for body, attribute encoding for attributes, "
                        "JavaScript encoding for script blocks). Implement a strict CSP."
                    ),
                    url=str(resp.url),
                    confidence="high" if context != "comment" else "medium",
                    proof="\n".join(proof_lines),
                    cwe="CWE-79",
                )

        return None


# ---------------------------------------------------------------------------
# Payloads — (template, check_function, description)
#
# {CANARY} is replaced with a unique marker at runtime.
# None of these execute code — they test whether the *syntax* survives.
# ---------------------------------------------------------------------------

def _check_tag(body: str, canary: str) -> bool:
    return f"<{canary}>" in body or f"<{canary} " in body

def _check_attr_break(body: str, canary: str) -> bool:
    return f'"{canary}' in body or f"'{canary}" in body

def _check_event_attr(body: str, canary: str) -> bool:
    return re.search(rf'on\w+=.*?{re.escape(canary)}', body) is not None

def _check_script_break(body: str, canary: str) -> bool:
    return f"'{canary}//" in body or f";{canary}" in body


_PAYLOADS: dict[str, list[tuple[str, object, str]]] = {
    "html_body": [
        ("<{CANARY}>",                    _check_tag,        "tag injection"),
        ("<{CANARY} data-test=1>",        _check_tag,        "tag with attribute"),
        ("<img src=x onerror={CANARY}>",  _check_tag,        "img tag injection"),
    ],
    "attribute": [
        ('"{CANARY}',                      _check_attr_break, "double-quote breakout"),
        ("'{CANARY}",                      _check_attr_break, "single-quote breakout"),
        ('" onmouseover="{CANARY}',        _check_event_attr, "event handler injection"),
    ],
    "script": [
        ("';{CANARY}//",                   _check_script_break, "script string breakout"),
        ("\";{CANARY}//",                  _check_script_break, "script dquote breakout"),
        ("</script><{CANARY}>",           _check_tag,          "script tag escape"),
    ],
    "comment": [
        ("--><{CANARY}>",                  _check_tag,        "comment breakout"),
    ],
}


def _extract_proof(body: str, canary: str, max_lines: int = 3) -> list[str]:
    """Pull lines around the canary from the response for evidence."""
    lines: list[str] = []
    for i, line in enumerate(body.splitlines()):
        if canary in line:
            snippet = line.strip()[:200]
            lines.append(f"  Line {i + 1}: {snippet}")
            if len(lines) >= max_lines:
                break
    return lines
