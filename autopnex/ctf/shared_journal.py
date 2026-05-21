"""Shared Journal - structured, persistent, auditable record of CTF solving sessions.

Every agent action, hypothesis, evidence, blocker, and next-action recommendation
is written to disk so that:
* Humans can read the timeline
* Other agents can resume context
* Critics can audit decisions
* Frontends can render progress without parsing natural language
"""
from __future__ import annotations

import json
import logging
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

log = logging.getLogger("autopnex.ctf.shared_journal")


# ---------------------------------------------------------------------------
# Record dataclasses (one per JSONL file)
# ---------------------------------------------------------------------------

@dataclass
class AttemptRecord:
    iteration: int
    tool: str
    args_hash: str
    route: str
    success: bool
    result_preview: str
    new_info: bool
    timestamp: float = field(default_factory=time.time)

    def to_line(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False, default=str)


@dataclass
class HypothesisRecord:
    id: str
    text: str
    confidence: float
    status: str  # active | confirmed | rejected | abandoned
    route: str
    abandon_reason: str = ""
    timestamp: float = field(default_factory=time.time)

    def to_line(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False, default=str)


@dataclass
class EvidenceCard:
    id: str
    source: str  # http_response, file_analyze, helper, knowledge, etc.
    agent: str   # web, reverse, crypto, etc.
    route: str
    summary: str
    evidence: str
    confidence: float
    next_action: str
    timestamp: float = field(default_factory=time.time)

    def to_line(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False, default=str)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class BlockerRecord:
    id: str
    description: str
    route: str
    evidence: str
    severity: str  # soft | route | hard
    resolved: bool = False
    timestamp: float = field(default_factory=time.time)

    def to_line(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False, default=str)


# ---------------------------------------------------------------------------
# SharedJournal
# ---------------------------------------------------------------------------

class SharedJournal:
    """Central append-only journal for a CTF session.

    Creates the following layout under *session_dir*:

        shared/
            timeline.md
            attempts.jsonl
            hypotheses.jsonl
            evidence_cards.jsonl
            blockers.jsonl
            next_actions.md
    """

    def __init__(self, session_dir: str, session_id: Optional[str] = None) -> None:
        self.session_id = session_id or uuid.uuid4().hex[:12]
        self.base = Path(session_dir)
        self.shared = self.base / "shared"
        self.shared.mkdir(parents=True, exist_ok=True)

        # File paths
        self._timeline_path = self.shared / "timeline.md"
        self._attempts_path = self.shared / "attempts.jsonl"
        self._hypotheses_path = self.shared / "hypotheses.jsonl"
        self._evidence_path = self.shared / "evidence_cards.jsonl"
        self._blockers_path = self.shared / "blockers.jsonl"
        self._next_actions_path = self.shared / "next_actions.md"

        # In-memory caches for fast read-back
        self._evidence_cache: List[EvidenceCard] = []
        self._hypotheses_cache: List[HypothesisRecord] = []
        self._blockers_cache: List[BlockerRecord] = []
        self._attempts_cache: List[AttemptRecord] = []

        # Seed timeline header
        if not self._timeline_path.exists():
            self._timeline_path.write_text(
                f"# CTF Session Timeline – {self.session_id}\n\n", encoding="utf-8"
            )

    # -- write API --------------------------------------------------------

    def log_timeline(self, text: str) -> None:
        """Append a human-readable line to timeline.md (Chinese preferred)."""
        line = f"- [{time.strftime('%H:%M:%S')}] {text}\n"
        try:
            with self._timeline_path.open("a", encoding="utf-8") as f:
                f.write(line)
        except OSError as e:
            log.warning("Timeline write failed: %s", e)

    def log_attempt(self, record: AttemptRecord) -> None:
        """Append an attempt to attempts.jsonl."""
        self._append_jsonl(self._attempts_path, record.to_line())
        self._attempts_cache.append(record)

    def log_hypothesis(self, record: HypothesisRecord) -> None:
        """Append a hypothesis to hypotheses.jsonl."""
        self._append_jsonl(self._hypotheses_path, record.to_line())
        self._hypotheses_cache.append(record)

    def log_evidence(self, card: EvidenceCard) -> None:
        """Append an evidence card to evidence_cards.jsonl."""
        self._append_jsonl(self._evidence_path, card.to_line())
        self._evidence_cache.append(card)
        # Also mirror to timeline
        self.log_timeline(f"发现证据: {card.summary} (confidence={card.confidence:.2f})")

    def log_blocker(self, record: BlockerRecord) -> None:
        """Append a blocker to blockers.jsonl."""
        self._append_jsonl(self._blockers_path, record.to_line())
        self._blockers_cache.append(record)
        self.log_timeline(
            f"遇到阻塞: {record.description} (severity={record.severity}, route={record.route})"
        )

    def write_next_actions(self, text: str, *, role: str = "coordinator") -> None:
        """Overwrite next_actions.md with the latest recommendation."""
        try:
            self._next_actions_path.write_text(
                f"# Next Actions – {role}\n\n{text}\n", encoding="utf-8"
            )
        except OSError as e:
            log.warning("Next actions write failed: %s", e)

    # -- read API ---------------------------------------------------------

    @property
    def evidence_cards(self) -> List[EvidenceCard]:
        return list(self._evidence_cache)

    @property
    def hypotheses(self) -> List[HypothesisRecord]:
        return list(self._hypotheses_cache)

    @property
    def blockers(self) -> List[BlockerRecord]:
        return list(self._blockers_cache)

    @property
    def attempts(self) -> List[AttemptRecord]:
        return list(self._attempts_cache)

    def latest_evidence(self, n: int = 5) -> List[EvidenceCard]:
        return self._evidence_cache[-n:]

    def latest_hypotheses(self, n: int = 5) -> List[HypothesisRecord]:
        return self._hypotheses_cache[-n:]

    def latest_blockers(self, n: int = 3) -> List[BlockerRecord]:
        return self._blockers_cache[-n:]

    def latest_attempts(self, n: int = 10) -> List[AttemptRecord]:
        return self._attempts_cache[-n:]

    def get_summary(self) -> Dict[str, Any]:
        """Quick summary for Critic / Verifier consumption."""
        return {
            "session_id": self.session_id,
            "attempts_count": len(self._attempts_cache),
            "evidence_count": len(self._evidence_cache),
            "hypotheses_count": len(self._hypotheses_cache),
            "blockers_count": len(self._blockers_cache),
            "latest_evidence": [e.to_dict() for e in self.latest_evidence(3)],
            "latest_blockers": [b.to_line() for b in self.latest_blockers(2)],
        }

    def build_critic_context(self) -> str:
        """Build a concise Chinese context string for the Critic agent."""
        lines: List[str] = [
            "## 审查上下文",
            f"Session ID: {self.session_id}",
            f"总尝试次数: {len(self._attempts_cache)}",
            f"总证据数: {len(self._evidence_cache)}",
            f"总假设数: {len(self._hypotheses_cache)}",
            f"总阻塞数: {len(self._blockers_cache)}",
            "",
            "### 最近证据",
        ]
        for ev in self.latest_evidence(5):
            lines.append(f"- [{ev.route}] {ev.summary} (置信度 {ev.confidence:.2f})")
        lines.append("")
        lines.append("### 最近假设")
        for h in self.latest_hypotheses(5):
            lines.append(f"- [{h.status}] {h.text}")
        lines.append("")
        lines.append("### 最近阻塞")
        for b in self.latest_blockers(3):
            lines.append(f"- [{b.severity}] {b.description}")
        return "\n".join(lines)

    # -- helpers ----------------------------------------------------------

    @staticmethod
    def _append_jsonl(path: Path, line: str) -> None:
        try:
            with path.open("a", encoding="utf-8") as f:
                f.write(line + "\n")
        except OSError as e:
            log.warning("JSONL append failed for %s: %s", path, e)
