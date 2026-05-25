"""Attribution module for CTF benchmark result classification.

Provides dataclasses and enums for tracking how a challenge was solved
(deterministic route, LLM fallback, hint-assisted, etc.) and capturing
debug snapshots for failed attempts.

Requirements: 10.1, 10.3, 10.4, 10.5, 14.1, 14.2, 14.5
"""

from enum import Enum
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Union


class LegacyAttribution(Enum):
    """Legacy classification of how a CTF challenge was solved.

    Preserved for backward compatibility with existing benchmark code.
    New code should use the Attribution dataclass instead.
    """

    DETERMINISTIC_ROUTE = "deterministic_route"
    LLM_FALLBACK = "llm_fallback"
    HINT_ASSISTED = "hint_assisted"
    BROAD_ROUTE = "broad_route"
    UNKNOWN = "unknown"


@dataclass
class Attribution:
    """Detailed attribution metadata for CTF solve results.

    Tracks which phase, worker, provider, model, strategy, and tool call
    produced the solution. Used in SolveResult for full traceability.

    Requirements: 10.1, 10.3, 10.4, 10.5

    Backward Compatibility:
        The class provides DETERMINISTIC_ROUTE, LLM_FALLBACK, HINT_ASSISTED,
        BROAD_ROUTE, and UNKNOWN as class-level constants that return
        pre-configured Attribution instances. The .value property maps
        the new dataclass back to legacy string values for reporting.
    """

    solving_phase: str  # "phase1" | "phase2" | "phase3"
    worker_id: Optional[str] = None
    provider: Optional[str] = None
    model: Optional[str] = None
    strategy_hint: Optional[str] = None
    turn_number: Optional[int] = None
    winning_tool_call: Optional[str] = None
    total_api_calls: int = 0
    total_tokens_used: int = 0
    _legacy_value: Optional[str] = field(default=None, repr=False, compare=False)

    @property
    def value(self) -> str:
        """Backward-compatible .value property mirroring the old enum behavior.

        Maps the new dataclass fields back to legacy string values used in
        benchmark reporting. If a _legacy_value was explicitly set (for
        backward-compatible constants), it takes precedence.
        """
        if self._legacy_value is not None:
            return self._legacy_value
        if self.strategy_hint == "hint_assisted":
            return "hint_assisted"
        if self.strategy_hint == "broad_route":
            return "broad_route"
        if self.solving_phase == "phase2":
            return "llm_fallback"
        if self.solving_phase == "phase3":
            return "llm_fallback"
        if self.worker_id is not None:
            return "llm_fallback"
        return "deterministic_route"

    def to_dict(self) -> Dict[str, Any]:
        """Serialize attribution to a dictionary for JSON reporting.

        Returns:
            Dictionary containing all attribution fields with None values
            preserved for explicit representation.
        """
        return {
            "solving_phase": self.solving_phase,
            "worker_id": self.worker_id,
            "provider": self.provider,
            "model": self.model,
            "strategy_hint": self.strategy_hint,
            "turn_number": self.turn_number,
            "winning_tool_call": self.winning_tool_call,
            "total_api_calls": self.total_api_calls,
            "total_tokens_used": self.total_tokens_used,
        }


# Backward-compatible class-level constants matching old Attribution enum members.
# These are set after class definition since Python 3.12 doesn't support
# @classmethod @property combination on dataclasses.
Attribution.DETERMINISTIC_ROUTE = Attribution(solving_phase="phase1", _legacy_value="deterministic_route")  # type: ignore[attr-defined]
Attribution.LLM_FALLBACK = Attribution(solving_phase="phase2", _legacy_value="llm_fallback")  # type: ignore[attr-defined]
Attribution.HINT_ASSISTED = Attribution(solving_phase="phase1", strategy_hint="hint_assisted", _legacy_value="hint_assisted")  # type: ignore[attr-defined]
Attribution.BROAD_ROUTE = Attribution(solving_phase="phase1", strategy_hint="broad_route", _legacy_value="broad_route")  # type: ignore[attr-defined]
Attribution.UNKNOWN = Attribution(solving_phase="phase1", _legacy_value="unknown")  # type: ignore[attr-defined]


@dataclass
class DebugSnapshot:
    """Diagnostic snapshot captured when a challenge attempt fails or times out."""

    completed_steps: List[str]
    last_route: str
    last_evidence: List[str]
    blocker_reason: str
    phase_reached: str
    hints_used: int
    first_hint_round: Optional[int]


@dataclass
class BenchmarkResult:
    """Enhanced benchmark result with attribution and debug information."""

    target_id: str
    success: bool
    flag: Optional[str]
    rounds: int
    time_seconds: float
    expected_route: str
    winning_route: Optional[str]
    expected_scenario: str
    actual_scenario: Optional[str]
    attribution: Union[Attribution, LegacyAttribution]
    phase_reached: str
    hints_used: int
    first_hint_round: Optional[int]
    debug_snapshot: Optional[DebugSnapshot]
