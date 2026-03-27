"""
Base probe infrastructure — injection point model, safety-bounded probe class,
and shared utilities for all active vulnerability probes.
"""

from __future__ import annotations

import logging
import re
import secrets
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from ..models import Finding
from ..stealth import StealthSession

log = logging.getLogger("diverg_lite.probes")

# ---------------------------------------------------------------------------
# Injection point — any place user input enters the application
# ---------------------------------------------------------------------------

@dataclass
class InjectionPoint:
    url: str
    name: str
    value: str = ""
    location: str = "query"       # query | body | path | fragment | header
    method: str = "GET"
    form_action: str = ""
    input_type: str = ""          # text, hidden, password, email, search …
    form_enctype: str = ""        # multipart, urlencoded, etc.

    @property
    def target_url(self) -> str:
        return self.form_action or self.url


# ---------------------------------------------------------------------------
# Canary — unique marker for reflection / injection detection
# ---------------------------------------------------------------------------

def make_canary(prefix: str = "dvg") -> str:
    return f"{prefix}{secrets.token_hex(4)}"


# ---------------------------------------------------------------------------
# URL manipulation helpers
# ---------------------------------------------------------------------------

def inject_query_param(url: str, param: str, value: str) -> str:
    """Return *url* with *param* set to *value* (replaces if exists)."""
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [value]
    new_query = urlencode(qs, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def strip_tags(text: str) -> str:
    return re.sub(r"<[^>]+>", "", text)


# ---------------------------------------------------------------------------
# Response analysis helpers
# ---------------------------------------------------------------------------

def response_contains(body: str, marker: str, case_sensitive: bool = True) -> bool:
    if case_sensitive:
        return marker in body
    return marker.lower() in body.lower()


SQL_ERROR_PATTERNS: list[tuple[str, str]] = [
    (r"you have an error in your sql syntax", "MySQL"),
    (r"warning.*?\bmysql", "MySQL"),
    (r"unclosed quotation mark after the character string", "MSSQL"),
    (r"quoted string not properly terminated", "Oracle"),
    (r"ORA-\d{5}", "Oracle"),
    (r"PG::SyntaxError", "PostgreSQL"),
    (r"pg_query\(\).*?ERROR", "PostgreSQL"),
    (r"ERROR:\s+syntax error at or near", "PostgreSQL"),
    (r"SQLite3::SQLException", "SQLite"),
    (r"near \".*?\": syntax error", "SQLite"),
    (r"SQLITE_ERROR", "SQLite"),
    (r"unrecognized token:.*?\"", "SQLite"),
    (r"System\.Data\.SqlClient\.SqlException", "MSSQL"),
    (r"Incorrect syntax near", "MSSQL"),
    (r"com\.mysql\.jdbc", "MySQL"),
    (r"org\.postgresql\.util\.PSQLException", "PostgreSQL"),
    (r"java\.sql\.SQLSyntaxErrorException", "Java/JDBC"),
    (r"PDOException", "PHP/PDO"),
    (r"mysql_fetch", "PHP/MySQL"),
    (r"pg_exec\(\).*?ERROR", "PostgreSQL"),
    (r"SQLSyntaxErrorException", "Java"),
    (r"Driver.*?SQL[\-\_\ ]*Server", "MSSQL"),
    (r"SQL syntax.*?error", "Generic SQL"),
]

_SQL_RE = [(re.compile(p, re.IGNORECASE), db) for p, db in SQL_ERROR_PATTERNS]


def detect_sql_error(body: str) -> Optional[tuple[str, str]]:
    """Return (matched_text, db_type) if a SQL error is found in *body*."""
    for regex, db in _SQL_RE:
        m = regex.search(body)
        if m:
            return m.group(0), db
    return None


PATH_TRAVERSAL_MARKERS: list[tuple[str, str]] = [
    ("root:x:0:0:", "Unix /etc/passwd"),
    ("root:*:0:0:", "Unix /etc/passwd (BSD)"),
    ("[boot loader]", "Windows boot.ini"),
    ("[operating systems]", "Windows boot.ini"),
    ("# localhost", "hosts file"),
    ("127.0.0.1", "hosts file / loopback"),
    ("[extensions]", "Windows win.ini"),
]


def detect_path_traversal_content(body: str) -> Optional[tuple[str, str]]:
    for marker, desc in PATH_TRAVERSAL_MARKERS:
        if marker in body:
            return marker, desc
    return None


# ---------------------------------------------------------------------------
# Base probe class — all probes inherit from this
# ---------------------------------------------------------------------------

class BaseProbe(ABC):
    """
    Bounded-request probe with built-in safety controls.

    Subclasses implement `probe()` and call `_send()` for HTTP requests.
    The base enforces a hard request cap so no probe can hammer a target.
    """

    name: str = "base"
    cwe: str = ""
    max_requests: int = 30

    def __init__(self, session: StealthSession, *, max_requests: int | None = None):
        self.session = session
        self._request_count = 0
        if max_requests is not None:
            self.max_requests = max_requests

    # -- subclass contract ---------------------------------------------------

    @abstractmethod
    def probe(
        self,
        url: str,
        injection_points: list[InjectionPoint],
        body: str = "",
        headers: dict | None = None,
    ) -> list[Finding]:
        ...

    # -- request helper with hard cap ----------------------------------------

    def _can_request(self) -> bool:
        return self._request_count < self.max_requests

    def _send(
        self,
        method: str,
        url: str,
        *,
        data: dict | None = None,
        allow_redirects: bool = True,
        timeout: int = 10,
    ) -> Optional["requests.Response"]:
        if not self._can_request():
            log.debug(f"[{self.name}] request cap ({self.max_requests}) reached, skipping")
            return None
        self._request_count += 1
        try:
            import requests as _req  # noqa: runtime import
            resp = self.session.request(
                method, url,
                data=data,
                allow_redirects=allow_redirects,
                timeout=timeout,
            )
            return resp
        except Exception as exc:
            log.debug(f"[{self.name}] request failed: {exc}")
            return None

    # -- finding factory -----------------------------------------------------

    def _finding(
        self,
        title: str,
        severity: str,
        category: str,
        evidence: str,
        impact: str,
        remediation: str,
        url: str,
        *,
        confidence: str = "high",
        context: str = "",
        cwe: str = "",
        proof: str = "",
    ) -> Finding:
        full_evidence = evidence
        if proof:
            full_evidence = f"{evidence}\n\nProof:\n{proof}"
        return Finding(
            title=title,
            severity=severity,
            category=category,
            evidence=full_evidence,
            impact=impact,
            remediation=remediation,
            url=url,
            finding_type="vulnerability",
            context=context or f"CWE: {cwe or self.cwe}",
            confidence=confidence,
        )
