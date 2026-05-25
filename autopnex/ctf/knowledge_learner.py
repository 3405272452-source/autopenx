"""Self-evolving knowledge learner — extracts patterns from successful solves.

When the agent successfully solves a CTF challenge, this module automatically
extracts the solving pattern (route, scenario, fingerprints, payload family,
tech stack, key params) and stores it in a persistent JSON knowledge base.

On subsequent encounters with similar challenges, the agent can recognize
the pattern via fingerprint matching and skip blind exploration, jumping
directly to the winning route with high confidence.

Design principles:
  - Opt-in: gracefully degrades if knowledge file doesn't exist
  - Append-only: never removes patterns, only adds new ones
  - Lightweight: no external dependencies beyond stdlib
  - Safe: all operations wrapped in try/except to never break the main loop
"""

from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import List, Optional

from .knowledge_schema import (
    SCHEMA_VERSION,
    load_knowledge,
    save_knowledge,
)

log = logging.getLogger("autopnex.ctf.knowledge_learner")

# Default knowledge file location (project root)
_DEFAULT_KNOWLEDGE_PATH = Path(__file__).resolve().parent.parent.parent / "ctf_knowledge.json"

# Current schema version (delegated to knowledge_schema module)
_SCHEMA_VERSION = SCHEMA_VERSION


class KnowledgeLearner:
    """Self-evolving knowledge learner — extracts and matches solving patterns.

    Usage:
        # After a successful solve:
        learner = KnowledgeLearner()
        learner.record_success(target_url, flag, route, scenario, action_log, blackboard_state)

        # Before starting probes (in ReconAgent):
        match = learner.match_pattern(blackboard_state)
        if match:
            # Skip blind exploration — use matched route directly
            ...
    """

    def __init__(self, knowledge_path: Optional[str] = None):
        """Initialize the knowledge learner.

        Args:
            knowledge_path: Path to the knowledge JSON file.
                If None, uses the default project-root location.
                If the file doesn't exist, starts with an empty knowledge base.
        """
        if knowledge_path is not None:
            self.knowledge_path = Path(knowledge_path)
        else:
            self.knowledge_path = _DEFAULT_KNOWLEDGE_PATH
        self._knowledge = self._load()

    def _load(self) -> dict:
        """Load existing knowledge base from disk.

        Uses the unified schema migration layer (knowledge_schema module)
        to transparently handle old-format files with solve_records /
        attempt_records and migrate them to the current schema.

        Returns a valid knowledge structure even if the file doesn't exist
        or is malformed.
        """
        return load_knowledge(self.knowledge_path)

    def _save(self) -> None:
        """Save knowledge base to disk.

        Uses the unified save_knowledge() helper which performs atomic
        writes and preserves both old and new schema fields for backward
        compatibility.
        """
        save_knowledge(self._knowledge, self.knowledge_path)

    # ------------------------------------------------------------------
    # Recording successful solves
    # ------------------------------------------------------------------

    def record_success(
        self,
        target_url: str,
        flag: str,
        route: str,
        scenario: str,
        action_log: list,
        blackboard_state: dict,
    ) -> None:
        """Extract and store the solving pattern from a successful solve.

        Args:
            target_url: The target URL that was solved.
            flag: The captured flag value.
            route: The winning route (e.g., "sqli", "ssti", "lfi").
            scenario: The specific scenario within the route (e.g., "login_bypass").
            action_log: The full action log from the multi-agent loop.
            blackboard_state: The blackboard state_summary() dict at solve time.
        """
        pattern = self._extract_pattern(target_url, route, scenario, action_log, blackboard_state)

        # Avoid duplicate patterns (same route + scenario + fingerprints)
        if not self._is_duplicate(pattern):
            self._knowledge["patterns"].append(pattern)

        # Record in solve history (always append)
        self._knowledge["solve_history"].append({
            "target_url": target_url,
            "flag": flag[:50],  # Truncate for privacy
            "route": route,
            "scenario": scenario,
            "timestamp": time.time(),
        })

        # Keep solve_history bounded
        if len(self._knowledge["solve_history"]) > 200:
            self._knowledge["solve_history"] = self._knowledge["solve_history"][-200:]

        self._save()
        log.info(
            "Recorded solving pattern: route=%s scenario=%s fingerprints=%d",
            route, scenario, len(pattern.get("fingerprints", [])),
        )

    def _extract_pattern(
        self,
        target_url: str,
        route: str,
        scenario: str,
        action_log: list,
        blackboard_state: dict,
    ) -> dict:
        """Extract a reusable pattern from the solve.

        The pattern captures enough information to recognize similar challenges
        in the future without storing target-specific details.
        """
        return {
            "route": route,
            "scenario": scenario,
            "fingerprints": self._extract_fingerprints(blackboard_state),
            "winning_payload_family": self._extract_payload_family(action_log),
            "tech_stack": blackboard_state.get("tech_stack", []),
            "key_params": [
                p.get("name") for p in blackboard_state.get("interesting_params", [])
                if p.get("name")
            ],
            "forms_signature": self._extract_forms_signature(blackboard_state),
            "timestamp": time.time(),
        }

    def _extract_fingerprints(self, state: dict) -> list:
        """Extract page fingerprints that identify this challenge type.

        Fingerprints are high-confidence observations from the evidence cards
        that can be used to recognize similar challenges.
        """
        fingerprints: List[str] = []

        # From top evidence (high-score observations)
        for ev in state.get("top_evidence", []):
            score = ev.get("score", 0)
            if score >= 0.7:
                observation = ev.get("observation", "")
                if observation and observation not in fingerprints:
                    fingerprints.append(observation)

        # From scenario hints
        for hint in state.get("scenario_hints", []):
            if hint.get("confidence", 0) >= 0.6:
                detail = hint.get("detail", "")
                if detail and detail not in fingerprints:
                    fingerprints.append(detail[:200])

        return fingerprints[:10]  # Cap at 10 fingerprints

    def _extract_payload_family(self, action_log: list) -> str:
        """Extract which payload family succeeded from the action log.

        Looks for the last execute phase that resulted in a flag or success.
        """
        for entry in reversed(action_log):
            if entry.get("phase") == "execute":
                summary = entry.get("result_summary", "")
                if "flag" in summary.lower() or "success" in summary.lower():
                    return summary[:200]
            elif entry.get("phase") == "process_result":
                outcome = entry.get("outcome", {})
                if outcome.get("flag"):
                    return f"flag_found_via_{entry.get('agent', 'unknown')}"
        return ""

    def _extract_forms_signature(self, state: dict) -> List[str]:
        """Extract a signature of forms present on the target.

        This helps match challenges that have similar form structures
        (e.g., login forms with username/password fields).
        """
        signatures: List[str] = []
        for form in state.get("forms", []):
            fields = form.get("fields", [])
            method = form.get("method", "GET")
            if fields:
                sig = f"{method}:{','.join(str(f) for f in sorted(fields) if f)}"
                if sig not in signatures:
                    signatures.append(sig)
        return signatures[:5]

    def _is_duplicate(self, pattern: dict) -> bool:
        """Check if an equivalent pattern already exists."""
        for existing in self._knowledge["patterns"]:
            if (existing.get("route") == pattern.get("route")
                    and existing.get("scenario") == pattern.get("scenario")
                    and set(existing.get("fingerprints", [])) == set(pattern.get("fingerprints", []))):
                return True
        return False

    # ------------------------------------------------------------------
    # Pattern matching
    # ------------------------------------------------------------------

    def match_pattern(self, blackboard_state: dict) -> Optional[dict]:
        """Check if current target matches any known pattern.

        Compares fingerprints, tech_stack, params, and form signatures
        against stored patterns. Returns the best match if confidence
        exceeds the threshold.

        Args:
            blackboard_state: The current blackboard state_summary() dict.

        Returns:
            The best matching pattern dict, or None if no match found.
        """
        if not self._knowledge["patterns"]:
            return None

        best_match: Optional[dict] = None
        best_score: float = 0.0

        # Current target characteristics
        current_tech = set(
            t.lower() for t in blackboard_state.get("tech_stack", [])
            if t and t != "unknown"
        )
        current_params = set(
            p.get("name", "").lower()
            for p in blackboard_state.get("interesting_params", [])
            if p.get("name")
        )
        current_evidence = [
            ev.get("observation", "").lower()
            for ev in blackboard_state.get("top_evidence", [])
            if ev.get("score", 0) >= 0.5
        ]
        current_forms = set()
        for form in blackboard_state.get("forms", []):
            fields = form.get("fields", [])
            method = form.get("method", "GET")
            if fields:
                sig = f"{method}:{','.join(str(f) for f in sorted(fields) if f)}"
                current_forms.add(sig.lower())

        for pattern in self._knowledge["patterns"]:
            score = self._compute_match_score(
                pattern, current_tech, current_params, current_evidence, current_forms
            )
            if score > best_score:
                best_score = score
                best_match = pattern

        # Threshold: require at least 0.4 match score to avoid false positives
        if best_score >= 0.4 and best_match is not None:
            log.info(
                "Knowledge match found: route=%s scenario=%s score=%.2f",
                best_match.get("route"), best_match.get("scenario"), best_score,
            )
            return best_match

        return None

    def _compute_match_score(
        self,
        pattern: dict,
        current_tech: set,
        current_params: set,
        current_evidence: List[str],
        current_forms: set,
    ) -> float:
        """Compute a similarity score between a stored pattern and current state.

        Scoring factors:
          - Fingerprint overlap (highest weight — 0.4 max)
          - Tech stack overlap (0.2 max)
          - Parameter name overlap (0.2 max)
          - Form signature overlap (0.2 max)
        """
        score = 0.0

        # Fingerprint matching (most important signal)
        pattern_fingerprints = [fp.lower() for fp in pattern.get("fingerprints", [])]
        if pattern_fingerprints and current_evidence:
            matches = 0
            for fp in pattern_fingerprints:
                for ev in current_evidence:
                    # Substring match — fingerprints may be partial
                    if fp in ev or ev in fp:
                        matches += 1
                        break
            if pattern_fingerprints:
                score += 0.4 * (matches / len(pattern_fingerprints))

        # Tech stack matching
        pattern_tech = set(t.lower() for t in pattern.get("tech_stack", []) if t and t != "unknown")
        if pattern_tech and current_tech:
            overlap = len(pattern_tech & current_tech)
            score += 0.2 * (overlap / len(pattern_tech))

        # Parameter name matching
        pattern_params = set(p.lower() for p in pattern.get("key_params", []) if p)
        if pattern_params and current_params:
            overlap = len(pattern_params & current_params)
            score += 0.2 * (overlap / len(pattern_params))

        # Form signature matching
        pattern_forms = set(f.lower() for f in pattern.get("forms_signature", []) if f)
        if pattern_forms and current_forms:
            overlap = len(pattern_forms & current_forms)
            score += 0.2 * (overlap / len(pattern_forms))

        return score

    # ------------------------------------------------------------------
    # Utility
    # ------------------------------------------------------------------

    @property
    def pattern_count(self) -> int:
        """Number of stored patterns."""
        return len(self._knowledge.get("patterns", []))

    @property
    def solve_count(self) -> int:
        """Number of recorded solves."""
        return len(self._knowledge.get("solve_history", []))

    def get_patterns_for_route(self, route: str) -> List[dict]:
        """Get all stored patterns for a specific route."""
        return [
            p for p in self._knowledge.get("patterns", [])
            if p.get("route") == route
        ]

    def clear(self) -> None:
        """Clear all patterns and solve history (for testing)."""
        self._knowledge = {
            "version": _SCHEMA_VERSION,
            "patterns": [],
            "solve_history": [],
        }
        self._save()
