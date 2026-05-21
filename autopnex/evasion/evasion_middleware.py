"""Orchestrator that ties WAF detection, payload mutation, and rate control together."""
from __future__ import annotations

import logging
import threading
from typing import Dict, List, Optional
from urllib.parse import urlparse

from config.settings import settings
from .waf_detector import WAFDetector, WAFInfo
from .payload_mutator import PayloadMutator
from .rate_controller import RateController

log = logging.getLogger(__name__)


class EvasionMiddleware:
    """Singleton entry-point consumed by tool implementations.

    Disabled by default — activate via ``AUTOPENX_EVASION_ENABLED=true``.
    """

    _instance: Optional["EvasionMiddleware"] = None
    _init_lock = threading.Lock()

    def __init__(self) -> None:
        cfg = settings.effective()
        self.waf_detector = WAFDetector(timeout=cfg.http_timeout)
        self.mutator = PayloadMutator()
        self.rate_controller = RateController(
            base_delay=cfg.evasion_base_delay,
        )
        self._waf_cache: Dict[str, WAFInfo] = {}
        self._cache_lock = threading.Lock()

    # -- singleton access --------------------------------------------------

    @classmethod
    def get_instance(cls) -> Optional["EvasionMiddleware"]:
        """Return the middleware singleton if evasion is enabled, else ``None``."""
        cfg = settings.effective()
        if not cfg.evasion_enabled:
            return None

        if cls._instance is None:
            with cls._init_lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    @classmethod
    def reset(cls) -> None:
        """Tear down the singleton (useful in tests)."""
        with cls._init_lock:
            cls._instance = None

    # -- request preparation -----------------------------------------------

    def prepare_request(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
    ) -> Dict[str, str]:
        """Return merged headers with randomised browser fingerprint and apply rate delay."""
        self.rate_controller.wait()
        merged = dict(self.rate_controller.get_headers())
        if headers:
            merged.update(headers)
        return merged

    def on_response(self, status_code: int) -> None:
        """Feed response status back into the rate controller."""
        self.rate_controller.on_response(status_code)

    # -- payload mutation --------------------------------------------------

    def get_mutated_payloads(
        self,
        payloads: List[str],
        vuln_type: str,
        target_host: str,
    ) -> List[Dict[str, str]]:
        """Return original + mutated variants based on WAF fingerprint for *target_host*."""
        waf = self._detect_waf(target_host)
        if not waf.detected:
            return [{"strategy": "original", "payload": p} for p in payloads]

        cfg = settings.effective()
        level = cfg.waf_bypass_level

        if level == "none":
            return [{"strategy": "original", "payload": p} for p in payloads]

        return self.mutator.mutate_batch(payloads, vuln_type, waf.vendor)

    def detect_waf(self, target_url: str) -> WAFInfo:
        """Public wrapper — cached per host."""
        host = urlparse(target_url).netloc
        return self._detect_waf(host if host else target_url)

    # -- internals ---------------------------------------------------------

    def _detect_waf(self, target_host: str) -> WAFInfo:
        with self._cache_lock:
            if target_host in self._waf_cache:
                return self._waf_cache[target_host]

        if "://" not in target_host:
            probe_url = f"https://{target_host}/"
        else:
            probe_url = target_host

        waf = self.waf_detector.detect(probe_url)
        log.info(
            "WAF detection for %s: vendor=%s confidence=%.2f bypass=%s",
            target_host, waf.vendor, waf.confidence, waf.bypass_level,
        )

        with self._cache_lock:
            self._waf_cache[target_host] = waf
        return waf
