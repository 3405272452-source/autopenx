"""PoC knowledge base — JSON-backed registry of exploit proof-of-concepts."""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

log = logging.getLogger(__name__)

_DEFAULT_POC_DIR = Path(__file__).parent / "poc"


@dataclass
class PoCEntry:
    poc_id: str
    vuln_type: str
    title: str
    tech_stack: List[str]
    cve_ids: List[str]
    cvss_score: float
    payload: str
    expected_response: str
    waf_bypass: bool
    severity: str
    description: str


class PoCRegistry:
    """Load and query PoC payloads from JSON files on disk."""

    def __init__(self, poc_dir: Optional[Path] = None):
        self._entries: List[PoCEntry] = []
        self._load(poc_dir or _DEFAULT_POC_DIR)

    def _load(self, poc_dir: Path) -> None:
        if not poc_dir.is_dir():
            log.warning("PoC directory not found: %s", poc_dir)
            return
        for json_file in sorted(poc_dir.glob("*.json")):
            try:
                raw = json.loads(json_file.read_text(encoding="utf-8"))
                for item in raw:
                    self._entries.append(PoCEntry(**item))
            except Exception:
                log.warning("Failed to load PoC file %s", json_file, exc_info=True)
        log.info("Loaded %d PoC entries from %s", len(self._entries), poc_dir)

    @property
    def entries(self) -> List[PoCEntry]:
        return list(self._entries)

    def query(
        self,
        vuln_type: str = "",
        tech_stack: Optional[List[str]] = None,
        waf_bypass: bool = False,
        min_cvss: float = 0.0,
        limit: int = 10,
    ) -> List[PoCEntry]:
        """Filter PoCs by type/tech/WAF, ranked by tech-stack overlap + CVSS."""
        tech_stack = [t.lower() for t in (tech_stack or [])]
        results: List[PoCEntry] = []
        for entry in self._entries:
            if vuln_type and entry.vuln_type != vuln_type:
                continue
            if waf_bypass and not entry.waf_bypass:
                continue
            if entry.cvss_score < min_cvss:
                continue
            results.append(entry)

        def _score(e: PoCEntry) -> float:
            overlap = sum(1 for t in tech_stack if t in [s.lower() for s in e.tech_stack])
            return overlap * 10 + e.cvss_score

        results.sort(key=_score, reverse=True)
        return results[:limit]

    def enrich_prompt(
        self,
        vuln_type: str,
        technologies: Optional[List[str]] = None,
        max_tokens: int = 500,
    ) -> str:
        """Format top matching PoCs as concise LLM context."""
        matches = self.query(vuln_type=vuln_type, tech_stack=technologies, limit=5)
        if not matches:
            return ""
        lines: list[str] = [f"### Known PoCs for {vuln_type.upper()}"]
        budget = max_tokens
        for entry in matches:
            block = (
                f"- **{entry.title}** (CVSS {entry.cvss_score}, "
                f"{'WAF-bypass ' if entry.waf_bypass else ''}{entry.severity})\n"
                f"  Tech: {', '.join(entry.tech_stack)}\n"
                f"  Payload: `{entry.payload}`\n"
                f"  Expect: `{entry.expected_response}`\n"
            )
            if entry.cve_ids:
                block += f"  CVEs: {', '.join(entry.cve_ids)}\n"
            budget -= len(block)
            if budget < 0:
                break
            lines.append(block)
        return "\n".join(lines)
