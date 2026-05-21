from __future__ import annotations

from typing import Optional

from .capabilities.base import CTFCapability
from .capabilities.generic import GenericCTFCapability
from .capabilities.pwn import PwnCTFCapability
from .capabilities.reverse import ReverseCTFCapability
from .capabilities.stubs import (
    CryptoCTFCapability,
    ForensicsCTFCapability,
    MiscCTFCapability,
)
from .capabilities.web import WebCTFCapability
from .helpers.dispatcher import DeterministicHelperDispatcher


class CTFCapabilityRegistry:
    def __init__(self, dispatcher: DeterministicHelperDispatcher) -> None:
        self._dispatcher = dispatcher
        self._capabilities = [
            WebCTFCapability(dispatcher),
            PwnCTFCapability(),
            ReverseCTFCapability(),
            CryptoCTFCapability(),
            ForensicsCTFCapability(),
            MiscCTFCapability(),
            GenericCTFCapability(),
        ]

    def resolve(self, challenge_type: Optional[str], target: str) -> CTFCapability:
        normalized = (challenge_type or "").strip().lower() or None
        if normalized is None and str(target).startswith(("http://", "https://")):
            normalized = "web"
        for capability in self._capabilities:
            if capability.applies_to(normalized):
                return capability
        return GenericCTFCapability()
