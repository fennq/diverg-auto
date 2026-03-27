"""
Injection-point discovery — extract testable parameters from a URL and its HTML body.

Sources:
  1. Existing URL query parameters
  2. HTML forms (action + all named inputs)
  3. Common parameter names appended as "fuzz seeds" when no params exist
  4. Links on the page for additional probe targets
"""

from __future__ import annotations

import re
from urllib.parse import parse_qs, urljoin, urlparse

from .base import InjectionPoint


# Parameter names that frequently accept user-controlled data and are worth
# probing even when the original URL has no query string.
FUZZ_PARAMS: list[str] = [
    "id", "page", "q", "search", "query", "s", "keyword",
    "url", "redirect", "next", "return", "goto", "dest",
    "file", "path", "doc", "template", "include", "lang",
    "cat", "category", "item", "product", "user", "name",
    "ref", "callback", "continue", "target", "redir", "out",
    "view", "action", "type", "sort", "order", "filter",
]

REDIRECT_PARAMS: set[str] = {
    "url", "redirect", "next", "return", "goto", "dest",
    "destination", "rurl", "return_url", "redirect_url",
    "continue", "forward", "target", "redir", "out", "link",
    "ref", "callback", "to", "returnto", "return_to",
}

URL_PARAMS: set[str] = {
    "url", "uri", "src", "source", "href", "link", "file",
    "path", "page", "img", "image", "load", "fetch", "request",
    "api", "endpoint", "webhook", "proxy", "feed", "domain",
}

FILE_PARAMS: set[str] = {
    "file", "path", "doc", "template", "include", "page",
    "document", "folder", "root", "dir", "fname", "download",
    "filename", "lang", "locale", "view", "layout",
}


def discover(url: str, body: str = "", *, fuzz: bool = True) -> list[InjectionPoint]:
    """
    Return injection points derived from *url* query params, HTML forms in
    *body*, and (optionally) fuzz-seed parameters.
    """
    points: list[InjectionPoint] = []
    seen: set[tuple[str, str, str]] = set()  # (url, name, location)

    def _add(pt: InjectionPoint):
        key = (pt.target_url, pt.name, pt.location)
        if key not in seen:
            seen.add(key)
            points.append(pt)

    # 1. URL query parameters
    parsed = urlparse(url)
    for name, values in parse_qs(parsed.query, keep_blank_values=True).items():
        _add(InjectionPoint(
            url=url, name=name, value=values[0] if values else "",
            location="query", method="GET",
        ))

    # 2. HTML forms
    if body:
        points.extend(_forms_from_html(url, body, _add))

    # 3. Fuzz seeds — only if we found few params
    if fuzz and len(points) < 3:
        for param in FUZZ_PARAMS[:12]:
            _add(InjectionPoint(
                url=url, name=param, value="1",
                location="query", method="GET",
            ))

    return points


def extract_links(url: str, body: str) -> list[str]:
    """Pull same-origin hrefs from *body* for multi-page probing."""
    parsed = urlparse(url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    links: list[str] = []
    seen: set[str] = set()

    for match in re.finditer(r'href=["\']([^"\'#]+)["\']', body, re.IGNORECASE):
        href = match.group(1)
        if href.startswith("javascript:") or href.startswith("mailto:"):
            continue
        full = urljoin(url, href)
        full_parsed = urlparse(full)
        if full_parsed.netloc == parsed.netloc and full not in seen:
            seen.add(full)
            links.append(full)

    return links[:50]


# ---------------------------------------------------------------------------
# Internal: HTML form parsing
# ---------------------------------------------------------------------------

_FORM_RE = re.compile(r"<form\b([^>]*)>(.*?)</form>", re.DOTALL | re.IGNORECASE)
_INPUT_RE = re.compile(
    r"<(?:input|textarea|select)\b([^>]*)(?:/>|>)", re.IGNORECASE
)
_ATTR_RE = re.compile(r'(\w+)=["\']([^"\']*)["\']')


def _forms_from_html(base_url: str, body: str, add_fn) -> list[InjectionPoint]:
    pts: list[InjectionPoint] = []
    for form_match in _FORM_RE.finditer(body):
        form_attrs_str = form_match.group(1)
        form_body = form_match.group(2)
        form_attrs = dict(_ATTR_RE.findall(form_attrs_str))

        action = form_attrs.get("action", "")
        method = form_attrs.get("method", "GET").upper()
        enctype = form_attrs.get("enctype", "")
        target_url = urljoin(base_url, action) if action else base_url

        for inp_match in _INPUT_RE.finditer(form_body):
            inp_attrs = dict(_ATTR_RE.findall(inp_match.group(1)))
            name = inp_attrs.get("name")
            if not name:
                continue
            pt = InjectionPoint(
                url=base_url,
                name=name,
                value=inp_attrs.get("value", ""),
                location="body" if method == "POST" else "query",
                method=method,
                form_action=target_url,
                input_type=inp_attrs.get("type", "text"),
                form_enctype=enctype,
            )
            add_fn(pt)
            pts.append(pt)

    return pts
