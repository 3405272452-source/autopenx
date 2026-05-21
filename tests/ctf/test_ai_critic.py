"""Unit + property-based tests for AICritic (round 7, task 5.4).

Properties covered:

- **Property 7: AI Critic 提示词完整性**
  *For any* non-empty SharedJournal state, the AI_Critic's prompt builder
  SHALL produce a prompt string containing the journal summary, current
  route, evidence cards, and blocker information.

  **Validates: Requirements 4.2**

- **Property 8: AI Critic LLM 响应解析**
  *For any* well-formed LLM response string containing an action
  recommendation and confidence score, the AI_Critic SHALL parse it into a
  valid CriticReview with all required fields populated.

  **Validates: Requirements 4.3**

- **Property 9: AI Critic 回退保证**
  *For any* type of LLM API failure (timeout, connection error, invalid
  response), the AI_Critic SHALL produce a valid CriticReview by falling
  back to heuristic logic, never raising an unhandled exception.

  **Validates: Requirements 4.5**

Feature: ctf-web-agent-round7
"""
from __future__ import annotations

import asyncio
import json
import tempfile
from typing import Any, Dict, List

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from autopnex.ctf.critic import AICritic, Critic, CriticReview
from autopnex.ctf.fuse_controller import FuseController
from autopnex.ctf.shared_journal import (
    AttemptRecord,
    BlockerRecord,
    EvidenceCard,
    HypothesisRecord,
    SharedJournal,
)
from autopnex.ctf.strategy import StrategyEngine


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _run(coro):
    """Run a coroutine to completion in tests (avoids pytest-asyncio dependency)."""
    return asyncio.run(coro)


def _make_journal(tmpdir: str) -> SharedJournal:
    """Build a fresh SharedJournal pointed at a tmp session directory."""
    return SharedJournal(tmpdir, session_id="test-session")


def _populate_journal(
    journal: SharedJournal,
    *,
    evidence_specs: List[Dict[str, Any]] | None = None,
    blocker_specs: List[Dict[str, Any]] | None = None,
    attempt_specs: List[Dict[str, Any]] | None = None,
    hypothesis_specs: List[Dict[str, Any]] | None = None,
) -> None:
    """Populate the journal with the given records (each may be empty/None)."""
    for i, spec in enumerate(evidence_specs or []):
        journal.log_evidence(
            EvidenceCard(
                id=f"e{i}",
                source=spec.get("source", "http_response"),
                agent=spec.get("agent", "web"),
                route=spec["route"],
                summary=spec["summary"],
                evidence=spec.get("evidence", ""),
                confidence=spec.get("confidence", 0.5),
                next_action=spec.get("next_action", ""),
            )
        )
    for i, spec in enumerate(blocker_specs or []):
        journal.log_blocker(
            BlockerRecord(
                id=f"b{i}",
                description=spec["description"],
                route=spec.get("route", "lfi"),
                evidence=spec.get("evidence", "x" * 50),
                severity=spec.get("severity", "soft"),
                resolved=spec.get("resolved", False),
            )
        )
    for i, spec in enumerate(attempt_specs or []):
        journal.log_attempt(
            AttemptRecord(
                iteration=i + 1,
                tool=spec.get("tool", "http_request"),
                args_hash=spec.get("args_hash", f"h{i}"),
                route=spec.get("route", "lfi"),
                success=spec.get("success", True),
                result_preview=spec.get("result_preview", "ok"),
                new_info=spec.get("new_info", False),
            )
        )
    for i, spec in enumerate(hypothesis_specs or []):
        journal.log_hypothesis(
            HypothesisRecord(
                id=f"hyp{i}",
                text=spec["text"],
                confidence=spec.get("confidence", 0.5),
                status=spec.get("status", "active"),
                route=spec.get("route", "lfi"),
            )
        )


# ===========================================================================
# Unit tests for AICritic
# ===========================================================================


class TestAICriticUnit:
    """Concrete-example unit tests verifying core behavior."""

    def test_build_prompt_contains_required_sections(self):
        critic = AICritic()
        strategy = StrategyEngine()
        strategy.set_route("lfi")
        fuse = FuseController()
        with tempfile.TemporaryDirectory() as tmp:
            journal = _make_journal(tmp)
            _populate_journal(
                journal,
                evidence_specs=[{"route": "lfi", "summary": "found path traversal"}],
                blocker_specs=[{"description": "WAF blocking", "route": "lfi"}],
            )
            prompt = critic._build_prompt(journal, strategy, fuse)

            assert "会话摘要" in prompt
            assert "当前路线" in prompt
            assert "证据卡片" in prompt
            assert "阻塞信息" in prompt
            assert "lfi" in prompt
            assert "found path traversal" in prompt
            assert "WAF blocking" in prompt
            # Output format must instruct LLM to produce JSON
            assert "JSON" in prompt or "json" in prompt
            assert "recommended_next_action" in prompt

    def test_parse_response_raw_json(self):
        critic = AICritic()
        raw = json.dumps(
            {
                "most_likely_route": "ssti",
                "abandon_routes": ["lfi"],
                "is_stuck": False,
                "blocker_is_real": True,
                "recommended_next_action": "test {{7*7}} on /preview",
                "confidence": 0.82,
                "reasoning": "evidence shows jinja2",
            }
        )
        review = critic._parse_response(raw)
        assert review.most_likely_route == "ssti"
        assert review.abandon_routes == ["lfi"]
        assert review.is_stuck is False
        assert review.blocker_is_real is True
        assert review.recommended_next_action == "test {{7*7}} on /preview"
        assert review.confidence == pytest.approx(0.82)
        assert review.reasoning == "evidence shows jinja2"
        assert review.source == "ai"

    def test_parse_response_markdown_fenced_json(self):
        critic = AICritic()
        wrapped = (
            "Here is my analysis:\n"
            "```json\n"
            '{"recommended_next_action": "switch to sqli", "confidence": 0.6}\n'
            "```\n"
            "End."
        )
        review = critic._parse_response(wrapped)
        assert review.recommended_next_action == "switch to sqli"
        assert review.confidence == pytest.approx(0.6)

    def test_parse_response_missing_action_raises(self):
        critic = AICritic()
        bad = json.dumps({"confidence": 0.5})
        with pytest.raises(ValueError):
            critic._parse_response(bad)

    def test_parse_response_invalid_json_raises(self):
        critic = AICritic()
        with pytest.raises(ValueError):
            critic._parse_response("not a json {")

    def test_review_falls_back_when_llm_disabled(self, monkeypatch):
        """If the LLM is unavailable, review() should silently fall back."""
        critic = AICritic()
        strategy = StrategyEngine()
        fuse = FuseController()

        # Force _call_llm to raise so the fallback path is taken
        def _boom(self, prompt: str) -> str:
            raise RuntimeError("llm offline")

        monkeypatch.setattr(AICritic, "_call_llm", _boom)

        with tempfile.TemporaryDirectory() as tmp:
            journal = _make_journal(tmp)
            review = _run(critic.review(journal, strategy, fuse))

        assert isinstance(review, CriticReview)
        assert review.source == "heuristic"
        assert review.recommended_next_action  # heuristic always produces something


# ===========================================================================
# Property 7: Prompt completeness
# ===========================================================================

# Safe alphabets that won't break the prompt formatting.
_SAFE_TEXT = (
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789 _-./"
)

_ROUTE_ALPHABET = "abcdefghijklmnopqrstuvwxyz_"


# A non-empty route id with alphanumeric chars only.
route_id_strategy = st.text(
    alphabet=_ROUTE_ALPHABET, min_size=2, max_size=15
)


def _evidence_spec_strategy() -> st.SearchStrategy[Dict[str, Any]]:
    return st.fixed_dictionaries(
        {
            "route": route_id_strategy,
            "summary": st.text(alphabet=_SAFE_TEXT, min_size=1, max_size=60),
            "confidence": st.floats(min_value=0.0, max_value=1.0),
            "next_action": st.text(alphabet=_SAFE_TEXT, max_size=40),
        }
    )


def _blocker_spec_strategy() -> st.SearchStrategy[Dict[str, Any]]:
    return st.fixed_dictionaries(
        {
            "description": st.text(alphabet=_SAFE_TEXT, min_size=1, max_size=60),
            "route": route_id_strategy,
            "evidence": st.text(alphabet=_SAFE_TEXT, min_size=10, max_size=300),
            "severity": st.sampled_from(["soft", "route", "hard"]),
        }
    )


def _attempt_spec_strategy() -> st.SearchStrategy[Dict[str, Any]]:
    return st.fixed_dictionaries(
        {
            "tool": st.sampled_from(["http_request", "scan_flag", "run_python"]),
            "route": route_id_strategy,
            "success": st.booleans(),
            "new_info": st.booleans(),
        }
    )


class TestPromptCompleteness:
    """**Validates: Requirements 4.2** (Property 7)

    For any non-empty SharedJournal state, ``_build_prompt`` SHALL produce
    a prompt string containing the journal summary, current route,
    evidence cards, and blocker information.
    """

    @given(
        evidence=st.lists(_evidence_spec_strategy(), min_size=1, max_size=6),
        blockers=st.lists(_blocker_spec_strategy(), min_size=0, max_size=3),
        attempts=st.lists(_attempt_spec_strategy(), min_size=0, max_size=5),
        current_route=route_id_strategy,
    )
    @settings(
        max_examples=25,
        deadline=None,
        suppress_health_check=[
            HealthCheck.too_slow,
            HealthCheck.function_scoped_fixture,
        ],
    )
    def test_prompt_contains_required_sections_and_state(
        self,
        evidence: List[Dict[str, Any]],
        blockers: List[Dict[str, Any]],
        attempts: List[Dict[str, Any]],
        current_route: str,
    ) -> None:
        critic = AICritic()
        strategy = StrategyEngine()
        strategy.set_route(current_route)
        fuse = FuseController()

        with tempfile.TemporaryDirectory() as tmp:
            journal = _make_journal(tmp)
            _populate_journal(
                journal,
                evidence_specs=evidence,
                blocker_specs=blockers,
                attempt_specs=attempts,
            )
            prompt = critic._build_prompt(journal, strategy, fuse)

        # ---- Required structural sections (Requirements 4.2) ----
        assert "会话摘要" in prompt, "missing journal summary section"
        assert "当前路线" in prompt, "missing current route section"
        assert "证据卡片" in prompt, "missing evidence cards section"
        assert "阻塞信息" in prompt, "missing blocker information section"

        # ---- Output-format instructions for the LLM ----
        assert "recommended_next_action" in prompt
        assert ("JSON" in prompt) or ("json" in prompt)

        # ---- Journal state must be reflected in the prompt ----
        # Current route appears under "当前路线"
        assert current_route in prompt

        # At least one (most recent five) evidence summary must be embedded.
        recent_evidence_summaries = [
            spec["summary"] for spec in evidence[-5:]
        ]
        assert any(s in prompt for s in recent_evidence_summaries), (
            "no recent evidence summary embedded in prompt"
        )

        # Each recent (last 3) blocker description should appear.
        for spec in blockers[-3:]:
            assert spec["description"] in prompt, (
                f"blocker description {spec['description']!r} not in prompt"
            )


# ===========================================================================
# Property 8: LLM response parsing
# ===========================================================================

# Text values used inside generated JSON payloads. We exclude characters that
# would break JSON (`"`, `\`, control chars) and the markdown fence char so
# our wrapped/unwrapped variants stay parseable.
_JSON_TEXT_ALPHABET = (
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789 _-./"
)

json_text_strategy = st.text(alphabet=_JSON_TEXT_ALPHABET, min_size=1, max_size=80)
json_route_strategy = st.text(
    alphabet="abcdefghijklmnopqrstuvwxyz_", min_size=2, max_size=15
)


def _payload_strategy() -> st.SearchStrategy[Dict[str, Any]]:
    """A well-formed CriticReview-shaped payload.

    Confidence may be any finite float — `_parse_response` is required to
    clamp it to [0, 1].
    """
    return st.fixed_dictionaries(
        {
            "most_likely_route": json_route_strategy,
            "abandon_routes": st.lists(json_route_strategy, max_size=4),
            "is_stuck": st.booleans(),
            "blocker_is_real": st.booleans(),
            "recommended_next_action": json_text_strategy,
            "confidence": st.floats(
                min_value=-5.0,
                max_value=5.0,
                allow_nan=False,
                allow_infinity=False,
            ),
            "reasoning": json_text_strategy,
        }
    )


# Wrapping styles the parser must accept.
wrapping_strategy = st.sampled_from(
    [
        "raw",          # bare JSON string
        "fence_json",   # ```json ... ```
        "fence_plain",  # ``` ... ```
        "embedded",     # surrounded by prose, no fence
    ]
)


def _wrap(payload: Dict[str, Any], style: str) -> str:
    js = json.dumps(payload, ensure_ascii=False)
    if style == "raw":
        return js
    if style == "fence_json":
        return f"Analysis follows.\n```json\n{js}\n```\nDone."
    if style == "fence_plain":
        return f"prefix\n```\n{js}\n```\nsuffix"
    if style == "embedded":
        return f"My recommendation: {js}  -- end of message."
    raise AssertionError(f"unknown style: {style}")


class TestResponseParsing:
    """**Validates: Requirements 4.3** (Property 8)

    For any well-formed LLM response containing the required fields,
    ``_parse_response`` SHALL produce a valid ``CriticReview`` with all
    required fields populated.
    """

    @given(payload=_payload_strategy(), style=wrapping_strategy)
    @settings(
        max_examples=25,
        deadline=None,
        suppress_health_check=[HealthCheck.too_slow],
    )
    def test_parse_response_round_trip(
        self, payload: Dict[str, Any], style: str
    ) -> None:
        critic = AICritic()
        response_text = _wrap(payload, style)

        review = critic._parse_response(response_text)

        # ---- Required field presence ----
        assert isinstance(review, CriticReview)
        assert review.recommended_next_action == payload["recommended_next_action"]

        # ---- All declared fields are propagated ----
        assert review.most_likely_route == payload["most_likely_route"]
        assert review.abandon_routes == payload["abandon_routes"]
        assert review.is_stuck is bool(payload["is_stuck"])
        assert review.blocker_is_real is bool(payload["blocker_is_real"])
        assert review.reasoning == payload["reasoning"]

        # ---- Confidence is clamped into [0, 1] ----
        assert 0.0 <= review.confidence <= 1.0
        expected = max(0.0, min(1.0, float(payload["confidence"])))
        assert review.confidence == pytest.approx(expected)

        # ---- AICritic must mark its source ----
        assert review.source == "ai"

    @given(payload=_payload_strategy())
    @settings(max_examples=15, deadline=None)
    def test_parse_response_handles_missing_optional_fields(
        self, payload: Dict[str, Any]
    ) -> None:
        """Any subset that still includes ``recommended_next_action`` parses."""
        critic = AICritic()
        minimal = {"recommended_next_action": payload["recommended_next_action"]}
        review = critic._parse_response(json.dumps(minimal))

        assert review.recommended_next_action == payload["recommended_next_action"]
        # Defaults applied for missing fields
        assert review.most_likely_route == ""
        assert review.abandon_routes == []
        assert review.is_stuck is False
        assert review.blocker_is_real is True
        assert 0.0 <= review.confidence <= 1.0
        assert review.source == "ai"


# ===========================================================================
# Property 9: LLM failure fallback
# ===========================================================================


# Each entry is a callable that produces a fresh exception instance for the
# property test. We use callables so each example raises a distinct object.
def _make_exception_factories() -> List[Any]:
    return [
        lambda: TimeoutError("simulated timeout"),
        lambda: ConnectionError("simulated connection error"),
        lambda: ValueError("simulated invalid response"),
        lambda: RuntimeError("simulated llm runtime error"),
        lambda: OSError("simulated socket error"),
        lambda: Exception("simulated generic failure"),
    ]


exception_factory_strategy = st.sampled_from(_make_exception_factories())


class TestFallbackGuarantee:
    """**Validates: Requirements 4.5** (Property 9)

    For any LLM failure mode, ``review()`` SHALL produce a valid
    ``CriticReview`` by falling back to heuristic logic, never raising an
    unhandled exception.
    """

    @given(
        exc_factory=exception_factory_strategy,
        evidence=st.lists(_evidence_spec_strategy(), min_size=0, max_size=4),
        blockers=st.lists(_blocker_spec_strategy(), min_size=0, max_size=2),
        current_route=route_id_strategy,
    )
    @settings(
        max_examples=15,
        deadline=None,
        suppress_health_check=[
            HealthCheck.too_slow,
            HealthCheck.function_scoped_fixture,
        ],
    )
    def test_review_never_raises_and_falls_back(
        self,
        exc_factory: Any,
        evidence: List[Dict[str, Any]],
        blockers: List[Dict[str, Any]],
        current_route: str,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        critic = AICritic()
        strategy = StrategyEngine()
        strategy.set_route(current_route)
        fuse = FuseController()

        # Patch _call_llm to always fail with the chosen exception kind.
        def _failing_call(self, prompt: str) -> str:
            raise exc_factory()

        monkeypatch.setattr(AICritic, "_call_llm", _failing_call)

        with tempfile.TemporaryDirectory() as tmp:
            journal = _make_journal(tmp)
            _populate_journal(
                journal,
                evidence_specs=evidence,
                blocker_specs=blockers,
            )
            # MUST NOT raise even though the LLM call always fails.
            review = _run(critic.review(journal, strategy, fuse))

        assert isinstance(review, CriticReview)
        assert review.source == "heuristic", (
            f"expected heuristic fallback, got source={review.source!r}"
        )
        # Heuristic critic always produces some recommendation.
        assert review.recommended_next_action
        assert 0.0 <= review.confidence <= 1.0

    @given(
        bad_response=st.sampled_from(
            [
                "",                              # empty
                "not json at all",               # no JSON
                "{",                             # truncated
                '{"confidence": 0.5}',           # missing required field
                "```json\n{not: valid}\n```",    # malformed inside fence
                json.dumps([1, 2, 3]),           # JSON array, not object
            ]
        ),
    )
    @settings(
        max_examples=10,
        deadline=None,
        suppress_health_check=[
            HealthCheck.too_slow,
            HealthCheck.function_scoped_fixture,
        ],
    )
    def test_review_falls_back_when_response_unparseable(
        self,
        bad_response: str,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A successful LLM call returning unparseable text still falls back."""
        critic = AICritic()
        strategy = StrategyEngine()
        fuse = FuseController()

        def _bad_call(self, prompt: str) -> str:
            return bad_response

        monkeypatch.setattr(AICritic, "_call_llm", _bad_call)

        with tempfile.TemporaryDirectory() as tmp:
            journal = _make_journal(tmp)
            review = _run(critic.review(journal, strategy, fuse))

        assert isinstance(review, CriticReview)
        assert review.source == "heuristic"
        assert review.recommended_next_action
