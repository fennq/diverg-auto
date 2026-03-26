"""
Core security scanner — HTTP headers, SSL/TLS, CSP, cookies, content analysis,
redirect chain tracking, and technology fingerprinting.

Single shared HTTP request for header + content checks (no duplicate fetches).
"""

from __future__ import annotations

import re
import socket
import ssl
import time
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

from cryptography import x509
from cryptography.hazmat.backends import default_backend

from .models import Finding, ScanReport
from .stealth import get_session


# ---------------------------------------------------------------------------
# Security header definitions
# ---------------------------------------------------------------------------

SECURITY_HEADERS: dict[str, dict] = {
    "Strict-Transport-Security": {
        "severity": "High",
        "remediation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' to enforce HTTPS.",
        "finding_type": "hardening",
        "context": "If the site already redirects HTTP→HTTPS (common behind Cloudflare/CDN), real risk is lower. HSTS prevents downgrade attacks.",
    },
    "Content-Security-Policy": {
        "severity": "Medium",
        "remediation": "Implement a Content-Security-Policy header to mitigate XSS and data injection.",
        "finding_type": "hardening",
        "context": "CSP matters most on sites with user input, forms, or third-party scripts.",
    },
    "X-Content-Type-Options": {
        "severity": "Low",
        "remediation": "Add 'X-Content-Type-Options: nosniff' to prevent MIME-type sniffing.",
        "finding_type": "hardening",
        "context": "Standard hardening header. Low risk when content types are already set correctly.",
    },
    "X-Frame-Options": {
        "severity": "Medium",
        "remediation": "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN' to prevent clickjacking.",
        "finding_type": "hardening",
        "context": "If CSP frame-ancestors is set, X-Frame-Options is redundant in modern browsers.",
    },
    "Referrer-Policy": {
        "severity": "Low",
        "remediation": "Add 'Referrer-Policy: strict-origin-when-cross-origin' to limit referrer leakage.",
        "finding_type": "hardening",
        "context": "Prevents URL parameters from leaking to third parties via Referer header.",
    },
    "Permissions-Policy": {
        "severity": "Low",
        "remediation": "Add a Permissions-Policy header to restrict browser features (camera, mic, geolocation).",
        "finding_type": "hardening",
        "context": "Limits what browser APIs embedded content or scripts can access.",
    },
    "Cross-Origin-Opener-Policy": {
        "severity": "Low",
        "remediation": "Add 'Cross-Origin-Opener-Policy: same-origin' to isolate browsing context.",
        "finding_type": "hardening",
        "context": "Prevents cross-origin windows from accessing your document. Relevant for auth flows.",
    },
}

INFO_DISCLOSURE_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"]

CSP_WEAK_DIRECTIVES = {
    "unsafe-inline": ("Medium", "CSP allows 'unsafe-inline' — XSS payloads execute without nonce/hash."),
    "unsafe-eval": ("Medium", "CSP allows 'unsafe-eval' — eval(), Function(), setTimeout(string) are permitted."),
    "data:": ("Low", "CSP allows 'data:' URIs — can be used for XSS in some contexts."),
    "*": ("Medium", "CSP uses wildcard '*' — effectively no restriction on that directive."),
}

TECH_SIGNATURES: dict[str, list[tuple[str, str]]] = {
    "CDN / Proxy": [
        ("server", "cloudflare"), ("server", "akamai"), ("server", "fastly"),
        ("x-served-by", "cache"), ("x-cache", ""), ("cf-ray", ""),
        ("x-vercel-id", ""), ("x-amz-cf-id", ""),
    ],
    "Framework": [
        ("x-powered-by", "next.js"), ("x-powered-by", "express"),
        ("x-powered-by", "asp.net"), ("x-powered-by", "php"),
        ("x-generator", ""), ("x-drupal-cache", ""),
        ("x-wordpress", ""), ("x-powered-cms", ""),
    ],
    "Security": [
        ("x-xss-protection", ""), ("x-content-type-options", ""),
        ("strict-transport-security", ""),
    ],
}


# ---------------------------------------------------------------------------
# Shared fetch — single request for headers + content
# ---------------------------------------------------------------------------

class _FetchResult:
    __slots__ = ("response", "headers", "body", "final_url", "status_code",
                 "redirect_chain", "error")

    def __init__(self):
        self.response = None
        self.headers = {}
        self.body = ""
        self.final_url = ""
        self.status_code = 0
        self.redirect_chain: list[dict] = []
        self.error: Optional[str] = None


def _fetch(url: str, session=None) -> _FetchResult:
    result = _FetchResult()
    sess = session or get_session()
    try:
        resp = sess.get(url, allow_redirects=True, timeout=15)
        result.response = resp
        result.headers = resp.headers
        result.body = resp.text[:500_000]
        result.final_url = str(resp.url)
        result.status_code = resp.status_code

        chain = []
        if resp.history:
            for r in resp.history:
                chain.append({
                    "url": str(r.url),
                    "status": r.status_code,
                    "location": r.headers.get("Location", ""),
                })
            chain.append({"url": str(resp.url), "status": resp.status_code, "location": ""})
        result.redirect_chain = chain
    except Exception as e:
        result.error = str(e)
    return result


# ---------------------------------------------------------------------------
# Technology fingerprinting
# ---------------------------------------------------------------------------

def detect_technologies(headers: dict) -> list[str]:
    techs = []
    headers_lower = {k.lower(): str(v).lower() for k, v in headers.items()}

    for category, sigs in TECH_SIGNATURES.items():
        for header_name, value_hint in sigs:
            hval = headers_lower.get(header_name)
            if hval is not None:
                if not value_hint or value_hint in hval:
                    label = f"{hval}" if value_hint else f"{header_name}"
                    if label not in techs:
                        techs.append(label)

    server = headers_lower.get("server", "")
    if server and server not in techs:
        techs.insert(0, server)

    powered = headers_lower.get("x-powered-by", "")
    if powered and powered not in techs:
        techs.insert(0, powered)

    return techs[:10]


# ---------------------------------------------------------------------------
# Header analysis
# ---------------------------------------------------------------------------

def check_headers(fetch: _FetchResult, url: str) -> list[Finding]:
    findings: list[Finding] = []

    if fetch.error:
        return [Finding(
            title="Connection failed",
            severity="High",
            category="Transport Security",
            evidence=fetch.error,
            impact="Cannot assess security headers — site may be unreachable or blocking.",
            remediation="Verify the URL is correct and accessible.",
            url=url,
            finding_type="error",
        )]

    headers = fetch.headers

    for header_name, meta in SECURITY_HEADERS.items():
        value = headers.get(header_name)
        if not value:
            findings.append(Finding(
                title=f"Missing security header: {header_name}",
                severity=meta["severity"],
                category="Transport Security",
                evidence=f"Header '{header_name}' is not present in the response.",
                impact=f"Without {header_name}, the application may be vulnerable to related attacks.",
                remediation=meta["remediation"],
                url=url,
                finding_type=meta.get("finding_type", "hardening"),
                context=meta.get("context", ""),
            ))
        else:
            if header_name == "Strict-Transport-Security":
                _check_hsts_value(value, url, findings)
            elif header_name == "Content-Security-Policy":
                _check_csp_value(value, url, findings)

    for h in INFO_DISCLOSURE_HEADERS:
        val = headers.get(h)
        if val:
            findings.append(Finding(
                title=f"Information disclosure: {h}",
                severity="Low",
                category="Information Disclosure",
                evidence=f"{h}: {val}",
                impact="Reveals server technology, aiding targeted attacks.",
                remediation=f"Remove or mask the '{h}' header in production.",
                url=url,
                finding_type="info_disclosure",
            ))

    cors = headers.get("Access-Control-Allow-Origin")
    if cors and cors.strip() == "*":
        findings.append(Finding(
            title="Overly permissive CORS: Access-Control-Allow-Origin: *",
            severity="Medium",
            category="Transport Security",
            evidence="Access-Control-Allow-Origin: *",
            impact="Any origin can read responses — credential leakage risk if combined with Allow-Credentials.",
            remediation="Restrict CORS to specific trusted origins.",
            url=url,
            finding_type="vulnerability",
        ))

    if fetch.response is not None:
        _check_cookies(fetch.response, url, findings)

    return findings


def _check_hsts_value(value: str, url: str, findings: list[Finding]):
    val_lower = value.lower()
    max_age_match = re.search(r"max-age=(\d+)", val_lower)
    if max_age_match:
        max_age = int(max_age_match.group(1))
        if max_age < 15768000:
            findings.append(Finding(
                title="HSTS max-age is too short",
                severity="Low",
                category="Transport Security",
                evidence=f"Strict-Transport-Security: {value} (max-age={max_age}s < 6 months)",
                impact="Short HSTS duration leaves a window for downgrade attacks.",
                remediation="Set max-age to at least 31536000 (1 year).",
                url=url,
                finding_type="hardening",
            ))
    if "includesubdomains" not in val_lower:
        findings.append(Finding(
            title="HSTS missing includeSubDomains",
            severity="Info",
            category="Transport Security",
            evidence=f"Strict-Transport-Security: {value}",
            impact="Subdomains are not covered by HSTS policy.",
            remediation="Add includeSubDomains to the HSTS header.",
            url=url,
            finding_type="hardening",
        ))


def _check_csp_value(value: str, url: str, findings: list[Finding]):
    for weak, (sev, desc) in CSP_WEAK_DIRECTIVES.items():
        if weak in value:
            findings.append(Finding(
                title=f"Weak CSP directive: {weak}",
                severity=sev,
                category="Content Security",
                evidence=f"CSP contains '{weak}': {value[:200]}",
                impact=desc,
                remediation=f"Remove '{weak}' from the Content-Security-Policy and use nonces or hashes instead.",
                url=url,
                finding_type="vulnerability",
                context="CSP weakness reduces protection against XSS even when the header is present.",
            ))

    if "frame-ancestors" not in value.lower():
        findings.append(Finding(
            title="CSP missing frame-ancestors directive",
            severity="Low",
            category="Content Security",
            evidence=f"CSP does not include frame-ancestors: {value[:200]}",
            impact="Without frame-ancestors, clickjacking protection relies solely on X-Frame-Options.",
            remediation="Add 'frame-ancestors 'self'' (or 'none') to CSP.",
            url=url,
            finding_type="hardening",
        ))


def _check_cookies(resp, url: str, findings: list[Finding]):
    for cookie in resp.cookies:
        issues = []
        if not cookie.secure:
            issues.append("missing Secure flag")
        if not cookie.has_nonstandard_attr("HttpOnly") and cookie.name.lower() not in (
            "_ga", "_gid", "_gat", "__utma", "__utmb", "__utmc", "__utmz",
        ):
            issues.append("missing HttpOnly flag")
        raw_header = resp.headers.get("Set-Cookie", "")
        if "samesite" not in raw_header.lower():
            issues.append("missing SameSite attribute")
        if issues:
            findings.append(Finding(
                title=f"Cookie security issue: {cookie.name}",
                severity="Medium" if "Secure" in " ".join(issues) else "Low",
                category="Cookie Security",
                evidence=f"Cookie '{cookie.name}': {', '.join(issues)}",
                impact="Insecure cookies can be intercepted (no Secure), accessed by scripts (no HttpOnly), or sent in CSRF requests (no SameSite).",
                remediation=f"Set {', '.join(issues).replace('missing ', '')} on cookie '{cookie.name}'.",
                url=url,
                finding_type="hardening",
            ))


# ---------------------------------------------------------------------------
# SSL/TLS analysis
# ---------------------------------------------------------------------------

def check_ssl(url: str) -> list[Finding]:
    findings: list[Finding] = []
    parsed = urlparse(url)
    hostname = parsed.hostname or parsed.netloc.split(":")[0]
    port = parsed.port or 443

    if parsed.scheme == "http":
        findings.append(Finding(
            title="Site served over plain HTTP",
            severity="High",
            category="Transport Security",
            evidence="URL scheme is http:// — no TLS encryption.",
            impact="All traffic including credentials and session tokens is sent in cleartext.",
            remediation="Serve the site over HTTPS with a valid TLS certificate.",
            url=url,
            finding_type="vulnerability",
        ))
        return findings

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert_bin = ssock.getpeercert(binary_form=True)
                protocol = ssock.version()
                cipher = ssock.cipher()

        if protocol and protocol in ("TLSv1", "TLSv1.1"):
            findings.append(Finding(
                title=f"Deprecated TLS version: {protocol}",
                severity="High",
                category="Transport Security",
                evidence=f"Server negotiated {protocol}.",
                impact="TLS 1.0/1.1 have known vulnerabilities (BEAST, POODLE). PCI DSS requires TLS 1.2+.",
                remediation="Disable TLS 1.0 and 1.1; require TLS 1.2 or 1.3.",
                url=url,
                finding_type="vulnerability",
            ))

        if cipher:
            cipher_name = cipher[0] if isinstance(cipher, tuple) else str(cipher)
            weak_ciphers = ("RC4", "DES", "3DES", "NULL", "EXPORT", "anon")
            for wc in weak_ciphers:
                if wc.upper() in cipher_name.upper():
                    findings.append(Finding(
                        title=f"Weak cipher suite: {cipher_name}",
                        severity="High",
                        category="Transport Security",
                        evidence=f"Negotiated cipher: {cipher_name}",
                        impact=f"Cipher contains {wc} which is cryptographically weak.",
                        remediation="Configure the server to use only modern cipher suites (AES-GCM, ChaCha20).",
                        url=url,
                        finding_type="vulnerability",
                    ))
                    break

        if cert_bin:
            cert = x509.load_der_x509_certificate(cert_bin, default_backend())
            not_after = cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc") else cert.not_valid_after
            now = datetime.now(timezone.utc)
            if not_after.tzinfo is None:
                from datetime import timezone as tz
                not_after = not_after.replace(tzinfo=tz.utc)
            days_left = (not_after - now).days
            if days_left < 0:
                findings.append(Finding(
                    title="SSL certificate has expired",
                    severity="Critical",
                    category="Transport Security",
                    evidence=f"Certificate expired {abs(days_left)} days ago (not_after={not_after.isoformat()}).",
                    impact="Browsers will show security warnings; users cannot trust the connection.",
                    remediation="Renew the SSL certificate immediately.",
                    url=url,
                    finding_type="vulnerability",
                ))
            elif days_left < 30:
                findings.append(Finding(
                    title="SSL certificate expiring soon",
                    severity="Medium",
                    category="Transport Security",
                    evidence=f"Certificate expires in {days_left} days (not_after={not_after.isoformat()}).",
                    impact="Certificate will expire soon, potentially causing service disruption.",
                    remediation="Renew the SSL certificate before expiration.",
                    url=url,
                    finding_type="hardening",
                ))

    except ssl.SSLCertVerificationError as e:
        findings.append(Finding(
            title="SSL certificate verification failed",
            severity="Critical",
            category="Transport Security",
            evidence=str(e),
            impact="The certificate is untrusted — connection can be intercepted (MITM).",
            remediation="Install a valid certificate from a trusted CA.",
            url=url,
            finding_type="vulnerability",
        ))
    except Exception as e:
        findings.append(Finding(
            title="SSL/TLS connection error",
            severity="Medium",
            category="Transport Security",
            evidence=str(e),
            impact="Cannot verify TLS configuration.",
            remediation="Ensure the server supports TLS connections on the expected port.",
            url=url,
            finding_type="error",
        ))

    for proto_name in ("TLSv1.0", "TLSv1.1"):
        try:
            ctx_old = ssl.SSLContext(ssl.PROTOCOL_TLS)
            if proto_name == "TLSv1.0":
                ctx_old.maximum_version = ssl.TLSVersion.TLSv1
                ctx_old.minimum_version = ssl.TLSVersion.TLSv1
            else:
                ctx_old.maximum_version = ssl.TLSVersion.TLSv1_1
                ctx_old.minimum_version = ssl.TLSVersion.TLSv1_1
            ctx_old.check_hostname = False
            ctx_old.verify_mode = ssl.CERT_NONE
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with ctx_old.wrap_socket(sock, server_hostname=hostname) as ssock:
                    findings.append(Finding(
                        title=f"Server accepts deprecated {proto_name}",
                        severity="Medium",
                        category="Transport Security",
                        evidence=f"Successful handshake with {proto_name}.",
                        impact=f"{proto_name} is deprecated and has known vulnerabilities.",
                        remediation=f"Disable {proto_name} on the server.",
                        url=url,
                        finding_type="vulnerability",
                    ))
        except Exception:
            pass

    return findings


# ---------------------------------------------------------------------------
# Content analysis (HTML) — uses shared fetch body
# ---------------------------------------------------------------------------

def check_content(fetch: _FetchResult, url: str) -> list[Finding]:
    findings: list[Finding] = []

    if fetch.error or not fetch.body:
        return findings

    content_type = fetch.headers.get("Content-Type", "")
    if "text/html" not in content_type.lower():
        return findings

    body = fetch.body

    if url.startswith("https"):
        http_refs = re.findall(r'(?:src|href|action)=["\']http://[^"\']+["\']', body, re.IGNORECASE)
        if http_refs:
            findings.append(Finding(
                title="Mixed content: HTTP resources on HTTPS page",
                severity="Medium",
                category="Content Security",
                evidence=f"Found {len(http_refs)} HTTP reference(s): {'; '.join(http_refs[:3])}",
                impact="Mixed content can be intercepted and modified by network attackers.",
                remediation="Load all resources over HTTPS.",
                url=url,
                finding_type="vulnerability",
            ))

    forms = re.findall(r"<form[^>]*>.*?</form>", body, re.DOTALL | re.IGNORECASE)
    csrf_names = {"csrf", "csrftoken", "_token", "authenticity_token", "csrfmiddlewaretoken", "__requestverificationtoken"}
    for form in forms[:10]:
        form_lower = form.lower()
        if "method" in form_lower and ("post" in form_lower or "put" in form_lower):
            has_csrf = any(name in form_lower for name in csrf_names)
            if not has_csrf:
                action = re.search(r'action=["\']([^"\']*)["\']', form, re.IGNORECASE)
                findings.append(Finding(
                    title="Form without CSRF token",
                    severity="Medium",
                    category="Content Security",
                    evidence=f"POST/PUT form without visible CSRF token{f' (action={action.group(1)})' if action else ''}",
                    impact="Forms without CSRF protection may be vulnerable to cross-site request forgery.",
                    remediation="Add a CSRF token to all state-changing forms.",
                    url=url,
                    finding_type="vulnerability",
                ))

    pwd_fields = re.findall(r'<input[^>]*type=["\']password["\'][^>]*>', body, re.IGNORECASE)
    for pf in pwd_fields[:5]:
        if 'autocomplete' not in pf.lower() or 'autocomplete="on"' in pf.lower():
            findings.append(Finding(
                title="Password field may allow browser autocomplete",
                severity="Low",
                category="Content Security",
                evidence=f"Password input without autocomplete='off': {pf[:120]}",
                impact="Browser may cache passwords, exposing them on shared devices.",
                remediation="Add autocomplete='off' or autocomplete='new-password' to password fields.",
                url=url,
                finding_type="hardening",
            ))

    inline_scripts = re.findall(r"<script(?![^>]*\bsrc=)[^>]*>", body, re.IGNORECASE)
    if len(inline_scripts) > 5:
        findings.append(Finding(
            title=f"High number of inline scripts ({len(inline_scripts)})",
            severity="Info",
            category="Content Security",
            evidence=f"Found {len(inline_scripts)} inline <script> tags without src attribute.",
            impact="Inline scripts increase XSS attack surface, especially without CSP nonce/hash.",
            remediation="Move scripts to external files and enforce CSP with nonces.",
            url=url,
            finding_type="info_disclosure",
        ))

    ext_scripts = re.findall(r'<script[^>]*src=["\']([^"\']+)["\'][^>]*>', body, re.IGNORECASE)
    parsed_url = urlparse(url)
    for src in ext_scripts:
        src_parsed = urlparse(src)
        if src_parsed.netloc and src_parsed.netloc != parsed_url.netloc:
            tag_match = re.search(rf'<script[^>]*src=["\']' + re.escape(src) + r'["\'][^>]*>', body, re.IGNORECASE)
            tag = tag_match.group(0) if tag_match else ""
            if "integrity=" not in tag.lower():
                findings.append(Finding(
                    title=f"Third-party script without SRI: {src_parsed.netloc}",
                    severity="Low",
                    category="Content Security",
                    evidence=f"External script from {src_parsed.netloc} loaded without integrity attribute: {src[:120]}",
                    impact="If the CDN is compromised, malicious code runs in your users' browsers.",
                    remediation="Add Subresource Integrity (integrity=) to external script tags.",
                    url=url,
                    finding_type="hardening",
                ))

    return findings


# ---------------------------------------------------------------------------
# Security score
# ---------------------------------------------------------------------------

SEVERITY_WEIGHTS = {"Critical": 25, "High": 15, "Medium": 8, "Low": 3, "Info": 0}

def compute_score(findings: list[Finding]) -> tuple[int, str]:
    """Return (score 0-100, grade A-F). 100 = no issues."""
    penalty = 0
    for f in findings:
        if f.finding_type == "error":
            continue
        penalty += SEVERITY_WEIGHTS.get(f.severity, 0)
    score = max(0, min(100, 100 - penalty))
    if score >= 90:
        grade = "A"
    elif score >= 75:
        grade = "B"
    elif score >= 55:
        grade = "C"
    elif score >= 35:
        grade = "D"
    else:
        grade = "F"
    return score, grade


# ---------------------------------------------------------------------------
# Top-level scan functions
# ---------------------------------------------------------------------------

def scan(url: str, scan_type: str = "standard") -> ScanReport:
    """
    Run a security scan on the target URL.

    scan_type:
        - "quick"    — headers only (fastest)
        - "standard" — headers + SSL + content (default)
        - "headers"  — alias for quick
        - "full"     — same as standard (future: adds path probing)

    Returns a ScanReport with findings, score, grade, redirect chain, and detected technologies.
    """
    if not url.startswith("http"):
        url = f"https://{url}"

    start = time.time()
    session = get_session()
    all_findings: list[Finding] = []
    errors: list[str] = []

    fetch = _fetch(url, session)

    try:
        all_findings.extend(check_headers(fetch, url))
    except Exception as e:
        errors.append(f"Header check error: {e}")

    if scan_type not in ("quick", "headers"):
        try:
            all_findings.extend(check_ssl(url))
        except Exception as e:
            errors.append(f"SSL check error: {e}")
        try:
            all_findings.extend(check_content(fetch, url))
        except Exception as e:
            errors.append(f"Content check error: {e}")

    severity_rank = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    all_findings.sort(key=lambda f: severity_rank.get(f.severity, 99))

    score, grade = compute_score(all_findings)
    techs = detect_technologies(fetch.headers) if not fetch.error else []

    elapsed = int((time.time() - start) * 1000)
    return ScanReport(
        target_url=url,
        findings=all_findings,
        errors=errors,
        scan_type=scan_type,
        duration_ms=elapsed,
        score=score,
        grade=grade,
        redirect_chain=fetch.redirect_chain,
        technologies=techs,
        final_url=fetch.final_url if fetch.final_url != url else "",
        status_code=fetch.status_code,
    )


def quick_scan(url: str) -> ScanReport:
    """Headers-only scan — fast, no SSL probe or content analysis."""
    return scan(url, scan_type="quick")


def batch_scan(urls: list[str], scan_type: str = "standard") -> list[ScanReport]:
    """Scan multiple URLs sequentially. Returns a list of ScanReport objects."""
    return [scan(u, scan_type=scan_type) for u in urls]
