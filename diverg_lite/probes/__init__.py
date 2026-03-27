"""
Active vulnerability probes — modular, safety-bounded, non-destructive.

Usage:
    from diverg_lite.probes import run_probes
    findings = run_probes(url, session, body=page_body, headers=resp_headers)
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..models import Finding
from .discovery import discover, extract_links

if TYPE_CHECKING:
    from ..stealth import StealthSession

from .xss import XSSProbe
from .sqli import SQLiProbe
from .traversal import TraversalProbe
from .redirect import RedirectProbe
from .ssrf import SSRFProbe
from .auth import AuthBypassProbe

ALL_PROBES = [
    XSSProbe,
    SQLiProbe,
    TraversalProbe,
    RedirectProbe,
    SSRFProbe,
    AuthBypassProbe,
]

PROBE_MAP = {cls.name: cls for cls in ALL_PROBES}


def run_probes(
    url: str,
    session: "StealthSession",
    *,
    body: str = "",
    headers: dict | None = None,
    probe_names: list[str] | None = None,
    max_requests_per_probe: int | None = None,
    fuzz: bool = True,
) -> list[Finding]:
    """
    Run active vulnerability probes against *url*.

    Args:
        url: Target URL (already fetched by the passive scanner).
        session: StealthSession for making requests.
        body: HTML body from the passive fetch (reused, no extra request).
        headers: Response headers from the passive fetch.
        probe_names: Subset of probe names to run (default: all).
        max_requests_per_probe: Override per-probe request cap.
        fuzz: Whether to generate fuzz-seed parameters when no params exist.

    Returns:
        List of Finding objects from all probes.
    """
    injection_points = discover(url, body, fuzz=fuzz)

    classes = ALL_PROBES
    if probe_names:
        classes = [PROBE_MAP[n] for n in probe_names if n in PROBE_MAP]

    all_findings: list[Finding] = []

    for cls in classes:
        kwargs = {}
        if max_requests_per_probe is not None:
            kwargs["max_requests"] = max_requests_per_probe
        probe = cls(session, **kwargs)
        try:
            findings = probe.probe(
                url, injection_points, body=body, headers=headers,
            )
            all_findings.extend(findings)
        except Exception as exc:
            import logging
            logging.getLogger("diverg_lite.probes").warning(
                f"Probe {cls.name} failed: {exc}"
            )

    return all_findings
