"""Adaptive rate control with UA rotation and jittered backoff — thread-safe."""
from __future__ import annotations

import random
import threading
import time
from typing import Dict, List

BROWSER_USER_AGENTS: List[str] = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 OPR/109.0.0.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPad; CPU OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
]

_ACCEPT_VARIANTS: List[str] = [
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
]

_ACCEPT_LANG_VARIANTS: List[str] = [
    "en-US,en;q=0.9",
    "en-US,en;q=0.9,zh-CN;q=0.8",
    "en-GB,en;q=0.9,en-US;q=0.8",
    "en-US,en;q=0.5",
]

_ACCEPT_ENCODING = "gzip, deflate, br"

_BACKOFF_MIN = 0.1
_BACKOFF_MAX = 30.0


class RateController:
    """Thread-safe adaptive rate controller with UA rotation and jittered delays."""

    def __init__(self, base_delay: float = 0.5, jitter: float = 0.3):
        self._base_delay = base_delay
        self._jitter = jitter
        self._backoff_factor = 1.0
        self._current_ua = random.choice(BROWSER_USER_AGENTS)
        self._lock = threading.Lock()

    # -- public API --------------------------------------------------------

    def get_delay(self) -> float:
        with self._lock:
            raw = self._base_delay * self._backoff_factor
            noise = random.uniform(-self._jitter, self._jitter)
            return max(0.0, raw + noise)

    def wait(self) -> float:
        """Sleep for the computed delay and return the actual seconds slept."""
        delay = self.get_delay()
        if delay > 0:
            time.sleep(delay)
        return delay

    def get_headers(self) -> Dict[str, str]:
        with self._lock:
            ua = self._current_ua
        return {
            "User-Agent": ua,
            "Accept": random.choice(_ACCEPT_VARIANTS),
            "Accept-Language": random.choice(_ACCEPT_LANG_VARIANTS),
            "Accept-Encoding": _ACCEPT_ENCODING,
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        }

    def on_response(self, status_code: int) -> None:
        with self._lock:
            if status_code == 429:
                self._backoff_factor = min(self._backoff_factor * 2.0, _BACKOFF_MAX / max(self._base_delay, 0.01))
            elif status_code == 503:
                self._backoff_factor = min(self._backoff_factor * 1.5, _BACKOFF_MAX / max(self._base_delay, 0.01))
            elif 200 <= status_code < 400:
                self._backoff_factor = max(self._backoff_factor * 0.8, _BACKOFF_MIN / max(self._base_delay, 0.01))
            # 4xx / 5xx other than 429/503 leave the factor unchanged

    def rotate_ua(self) -> str:
        with self._lock:
            candidates = [ua for ua in BROWSER_USER_AGENTS if ua != self._current_ua]
            self._current_ua = random.choice(candidates) if candidates else self._current_ua
            return self._current_ua

    @property
    def current_ua(self) -> str:
        with self._lock:
            return self._current_ua

    @property
    def backoff_factor(self) -> float:
        with self._lock:
            return self._backoff_factor
