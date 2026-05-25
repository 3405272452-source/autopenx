"""StallDetector — evidence-based stall detection for Phase 1 → Phase 2 transition.

Evaluates progress based on evidence delta from the blackboard rather than
fixed round counts. Phase 1 continues when actively discovering new
information and transitions only when genuinely stuck.

Requirements: 4.1, 4.2, 4.3, 4.4
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from autopnex.ctf.web_state_blackboard import WebStateBlackboard


@dataclass
class BlackboardSnapshot:
    """Point-in-time snapshot of blackboard metrics for delta comparison.

    Captures the key indicators that signal progress: new endpoints,
    evidence cards, error signatures, tech stack entries, route scores,
    and candidate flags.
    """

    endpoint_count: int
    evidence_count: int
    error_signature_count: int
    tech_stack_count: int
    max_route_score: float
    candidate_flag_count: int


@dataclass
class StallDetector:
    """Detects when Phase 1 has stalled based on evidence delta.

    Tracks blackboard state across rounds and reports a stall when no
    meaningful progress (new endpoints, error signatures, tech fingerprints,
    or route score increases) has occurred for a configurable number of
    consecutive rounds.

    Attributes:
        window: Number of consecutive rounds without progress before
            declaring a stall. Default is 5.
    """

    window: int = 5
    _round_deltas: List[bool] = field(default_factory=list)
    _last_snapshot: Optional[BlackboardSnapshot] = field(default=None, repr=False)

    @property
    def is_stalled(self) -> bool:
        """True if no evidence delta for the last `window` consecutive rounds."""
        if len(self._round_deltas) < self.window:
            return False
        return not any(self._round_deltas[-self.window:])

    @property
    def reason(self) -> str:
        """Human-readable reason for the current stall state."""
        if not self.is_stalled:
            return ""
        return (
            f"No evidence delta for {self.rounds_without_progress} consecutive "
            f"rounds (window={self.window})"
        )

    @property
    def rounds_without_progress(self) -> int:
        """Number of consecutive rounds at the tail with no progress."""
        count = 0
        for had_progress in reversed(self._round_deltas):
            if had_progress:
                break
            count += 1
        return count

    @property
    def last_progress_round(self) -> int:
        """1-based round number of the most recent round with progress.

        Returns 0 if no progress has ever been recorded.
        """
        for i in range(len(self._round_deltas) - 1, -1, -1):
            if self._round_deltas[i]:
                return i + 1  # 1-based
        return 0

    def record_round(self, blackboard: WebStateBlackboard) -> None:
        """Snapshot blackboard state and compute evidence delta.

        Takes a snapshot of the current blackboard metrics and compares
        it against the previous snapshot to determine if meaningful
        progress was made this round.

        Args:
            blackboard: The current WebStateBlackboard instance.
        """
        curr_snapshot = self._take_snapshot(blackboard)

        if self._last_snapshot is None:
            # First round always counts as progress (initial discovery)
            self._round_deltas.append(True)
        else:
            has_delta = self._compute_evidence_delta(self._last_snapshot, curr_snapshot)
            self._round_deltas.append(has_delta)

        self._last_snapshot = curr_snapshot

    def _take_snapshot(self, blackboard: WebStateBlackboard) -> BlackboardSnapshot:
        """Create a BlackboardSnapshot from the current blackboard state.

        Args:
            blackboard: The current WebStateBlackboard instance.

        Returns:
            A BlackboardSnapshot capturing current metrics.
        """
        # Compute max route score across all routes
        max_score = 0.0
        for card in blackboard.evidence:
            if card.score > max_score:
                max_score = card.score

        # Count unique error signatures (distinct failure reasons from attempts)
        error_signatures = set()
        for attempt in blackboard.attempts:
            if not attempt.success and attempt.failure_reason:
                error_signatures.add(attempt.failure_reason)

        return BlackboardSnapshot(
            endpoint_count=len(blackboard.endpoints),
            evidence_count=len(blackboard.evidence),
            error_signature_count=len(error_signatures),
            tech_stack_count=len(blackboard.tech_stack),
            max_route_score=max_score,
            candidate_flag_count=len(blackboard.candidate_flags),
        )

    def _compute_evidence_delta(
        self, prev_snapshot: BlackboardSnapshot, curr_snapshot: BlackboardSnapshot
    ) -> bool:
        """Determine if meaningful progress occurred between two snapshots.

        Progress is defined as any of:
        - New endpoints discovered
        - New error signatures observed
        - New technology fingerprints identified
        - Route score increases (max evidence score went up)

        Args:
            prev_snapshot: The previous round's snapshot.
            curr_snapshot: The current round's snapshot.

        Returns:
            True if evidence delta was detected, False otherwise.
        """
        # New endpoints discovered
        if curr_snapshot.endpoint_count > prev_snapshot.endpoint_count:
            return True

        # New error signatures observed
        if curr_snapshot.error_signature_count > prev_snapshot.error_signature_count:
            return True

        # New technology fingerprints identified
        if curr_snapshot.tech_stack_count > prev_snapshot.tech_stack_count:
            return True

        # Route score increases
        if curr_snapshot.max_route_score > prev_snapshot.max_route_score:
            return True

        return False
