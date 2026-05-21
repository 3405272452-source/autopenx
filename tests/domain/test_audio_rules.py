"""Property tests for audio domain rules.

**Property 18: 音频 seek 与 AB 循环规则**

**Validates: Requirements 5.2, 5.4, 5.5**

Requirement 5.2: Seek target T must satisfy 0 ≤ T ≤ duration.
Requirement 5.4: AB loop requires Tb > Ta; otherwise reject with
    "B 点必须晚于 A 点".
Requirement 5.5: Locate to question audio start; fallback to group start
    if audio_range is unavailable.

Tests:
1. validate_seek accepts valid range (0 ≤ t ≤ duration)
2. validate_seek rejects out-of-range (t > duration or t < 0)
3. set_ab_loop accepts when tb > ta
4. set_ab_loop rejects when tb ≤ ta
5. resolve_locate uses audio_range when present
6. resolve_locate falls back to group start when audio_range is absent
"""

from __future__ import annotations

from decimal import Decimal

from hypothesis import assume, given, settings
from hypothesis import strategies as st

from cet4_app.domain.audio_rules import (
    ABLoopResult,
    LocateResult,
    ValidateSeekResult,
    resolve_locate,
    set_ab_loop,
    validate_seek,
)
from cet4_app.domain.enums import QuestionType, SectionName
from cet4_app.domain.models.question import AudioRange, Question


# ---------------------------------------------------------------------------
# Helpers: build minimal listening Question fixtures
# ---------------------------------------------------------------------------


def _make_listening_question(
    audio_range: AudioRange | None = None,
) -> Question:
    """Create a minimal valid listening question for testing resolve_locate."""
    return Question(
        id="2024-12-set1-listening-news-01",
        paper_id="paper-2024-12-set1",
        section=SectionName.listening,
        sub_section="news",
        question_type=QuestionType.listening_news,
        prompt="What is the news about?",
        options=["Option A", "Option B", "Option C", "Option D"],
        correct_letter="A",
        reference_answer="A",
        explanation="The answer is A.",
        score=Decimal("7.10"),
        tags=[],
        audio_range=audio_range,
    )


# ---------------------------------------------------------------------------
# Test 1: validate_seek accepts valid range
# ---------------------------------------------------------------------------


@settings(max_examples=100, deadline=None)
@given(
    t=st.floats(min_value=0, max_value=1000),
    duration=st.floats(min_value=0, max_value=1000),
)
def test_validate_seek_accepts_valid_range(t: float, duration: float) -> None:
    """When 0 ≤ t ≤ duration, validate_seek returns ok=True.

    **Validates: Requirements 5.2**
    """
    assume(t <= duration)

    result = validate_seek(t, duration)

    assert isinstance(result, ValidateSeekResult)
    assert result.ok is True


# ---------------------------------------------------------------------------
# Test 2: validate_seek rejects out-of-range
# ---------------------------------------------------------------------------


@settings(max_examples=100, deadline=None)
@given(
    t=st.floats(min_value=-1000, max_value=1000),
    duration=st.floats(min_value=0, max_value=1000),
)
def test_validate_seek_rejects_out_of_range(t: float, duration: float) -> None:
    """When t > duration or t < 0, validate_seek returns ok=False.

    **Validates: Requirements 5.2**
    """
    assume(t > duration or t < 0)

    result = validate_seek(t, duration)

    assert isinstance(result, ValidateSeekResult)
    assert result.ok is False


# ---------------------------------------------------------------------------
# Test 3: set_ab_loop accepts when tb > ta
# ---------------------------------------------------------------------------


@settings(max_examples=100, deadline=None)
@given(
    ta=st.floats(min_value=0, max_value=1000),
    tb=st.floats(min_value=0, max_value=1000),
)
def test_set_ab_loop_accepts_when_tb_gt_ta(ta: float, tb: float) -> None:
    """When tb > ta, set_ab_loop returns ok=True and range is AudioRange.

    **Validates: Requirements 5.4**
    """
    assume(tb > ta)

    result = set_ab_loop(ta, tb)

    assert isinstance(result, ABLoopResult)
    assert result.ok is True
    assert isinstance(result.range, AudioRange)
    assert result.range.start_s == ta
    assert result.range.end_s == tb


# ---------------------------------------------------------------------------
# Test 4: set_ab_loop rejects when tb ≤ ta
# ---------------------------------------------------------------------------


@settings(max_examples=100, deadline=None)
@given(
    ta=st.floats(min_value=0, max_value=1000),
    tb=st.floats(min_value=0, max_value=1000),
)
def test_set_ab_loop_rejects_when_tb_le_ta(ta: float, tb: float) -> None:
    """When tb ≤ ta, set_ab_loop returns ok=False with message="B 点必须晚于 A 点".

    **Validates: Requirements 5.4**
    """
    assume(tb <= ta)

    result = set_ab_loop(ta, tb)

    assert isinstance(result, ABLoopResult)
    assert result.ok is False
    assert result.message == "B 点必须晚于 A 点"


# ---------------------------------------------------------------------------
# Test 5: resolve_locate uses audio_range
# ---------------------------------------------------------------------------


@settings(max_examples=100, deadline=None)
@given(
    start_s=st.floats(min_value=0, max_value=500),
    end_s=st.floats(min_value=0, max_value=1000),
)
def test_resolve_locate_uses_audio_range(start_s: float, end_s: float) -> None:
    """When question has audio_range, position_s = start_s and is_fallback=False.

    **Validates: Requirements 5.5**
    """
    assume(end_s > start_s)

    audio_range = AudioRange(start_s=start_s, end_s=end_s)
    question = _make_listening_question(audio_range=audio_range)

    result = resolve_locate(question)

    assert isinstance(result, LocateResult)
    assert result.position_s == start_s
    assert result.is_fallback is False


# ---------------------------------------------------------------------------
# Test 6: resolve_locate falls back to group start
# ---------------------------------------------------------------------------


@settings(max_examples=100, deadline=None)
@given(
    fallback=st.floats(min_value=0, max_value=1000),
)
def test_resolve_locate_falls_back_to_group_start(fallback: float) -> None:
    """When question has no audio_range + fallback provided, is_fallback=True
    and message contains "题组起点".

    **Validates: Requirements 5.5**
    """
    question = _make_listening_question(audio_range=None)

    result = resolve_locate(question, fallback_group_start_s=fallback)

    assert isinstance(result, LocateResult)
    assert result.is_fallback is True
    assert "题组起点" in result.message
