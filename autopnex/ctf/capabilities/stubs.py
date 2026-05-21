from __future__ import annotations

from .base import CTFCapability


class CryptoCTFCapability(CTFCapability):
    name = "crypto"


class ForensicsCTFCapability(CTFCapability):
    name = "forensics"


class MiscCTFCapability(CTFCapability):
    name = "misc"
