"""
Stealth networking — realistic browser fingerprints, timing jitter, adaptive rate limiting.

Every request looks like a different real browser session.
"""

from __future__ import annotations

import logging
import os
import random
import time
from typing import Optional
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter

log = logging.getLogger("diverg_lite.stealth")

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:133.0) Gecko/20100101 Firefox/133.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1",
]

ACCEPT_HEADERS = [
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
]

ACCEPT_LANG = [
    "en-US,en;q=0.9",
    "en-GB,en;q=0.9",
    "en-US,en;q=0.5",
    "en-US,en;q=0.9,es;q=0.8",
]


def random_headers(target_url: str = "") -> dict[str, str]:
    headers = {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": random.choice(ACCEPT_HEADERS),
        "Accept-Language": random.choice(ACCEPT_LANG),
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
    }
    if random.random() > 0.3:
        headers["Sec-Fetch-Site"] = random.choice(["none", "same-origin", "cross-site"])
        headers["Sec-Fetch-Mode"] = "navigate"
        headers["Sec-Fetch-Dest"] = "document"
        headers["Sec-Fetch-User"] = "?1"
    if target_url and random.random() > 0.4:
        parsed = urlparse(target_url)
        if parsed.scheme and parsed.netloc:
            headers["Referer"] = f"{parsed.scheme}://{parsed.netloc}/"
    if random.random() > 0.5:
        headers["DNT"] = "1"
    return headers


def jitter(min_s: float = 0.05, max_s: float = 0.3):
    time.sleep(min_s + (max_s - min_s) * random.betavariate(2, 5))


class RateLimiter:
    def __init__(self):
        self._backoff = 0.0
        self._consecutive_blocks = 0

    def check_response(self, resp: requests.Response):
        if resp.status_code in (429, 503):
            self._consecutive_blocks += 1
            self._backoff = min(30.0, 2 ** self._consecutive_blocks)
            log.warning(f"Rate limited ({resp.status_code}), backing off {self._backoff:.1f}s")
            time.sleep(self._backoff)
        elif resp.status_code == 403:
            self._consecutive_blocks += 1
            self._backoff = min(3.0, 1.3 ** self._consecutive_blocks)
            time.sleep(self._backoff)
        else:
            if self._consecutive_blocks > 0:
                self._consecutive_blocks = max(0, self._consecutive_blocks - 1)
                self._backoff = max(0, self._backoff * 0.5)

    @property
    def is_blocked(self) -> bool:
        return self._consecutive_blocks >= 5


class StealthSession(requests.Session):
    def __init__(self, proxy: Optional[str] = None, min_delay: float = 0.05, max_delay: float = 0.3):
        super().__init__()
        self.min_delay = min_delay
        self.max_delay = max_delay
        self.rate_limiter = RateLimiter()
        self._request_count = 0
        if proxy:
            self.proxies = {"http": proxy, "https": proxy}
        self.verify = True
        adapter = HTTPAdapter(pool_connections=5, pool_maxsize=10, max_retries=2)
        self.mount("http://", adapter)
        self.mount("https://", adapter)

    def request(self, method, url, **kwargs):
        custom_headers = kwargs.pop("headers", {}) or {}
        base = random_headers(target_url=url)
        base.update(custom_headers)
        kwargs["headers"] = base
        if "timeout" not in kwargs:
            kwargs["timeout"] = 10
        jitter(self.min_delay, self.max_delay)
        if self.rate_limiter._backoff > 0:
            time.sleep(self.rate_limiter._backoff)
        self._request_count += 1
        resp = super().request(method, url, **kwargs)
        self.rate_limiter.check_response(resp)
        return resp


def get_session(proxy: Optional[str] = None) -> StealthSession:
    proxy = proxy or os.environ.get("DIVERG_PROXY")
    return StealthSession(proxy=proxy)
