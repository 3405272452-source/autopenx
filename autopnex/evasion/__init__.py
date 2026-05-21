"""WAF evasion engine — detection, payload mutation, and adaptive rate control."""
from __future__ import annotations

from .waf_detector import WAFDetector, WAFInfo
from .payload_mutator import PayloadMutator, MUTATION_STRATEGIES, WAF_STRATEGY_MAP
from .rate_controller import RateController
from .evasion_middleware import EvasionMiddleware

__all__ = [
    "WAFDetector",
    "WAFInfo",
    "PayloadMutator",
    "MUTATION_STRATEGIES",
    "WAF_STRATEGY_MAP",
    "RateController",
    "EvasionMiddleware",
]
