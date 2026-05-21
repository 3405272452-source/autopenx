"""Property test: Mistake_Book state machine invariants (Property 11).

**Validates: Requirements 9.1, 9.2, 9.3, 9.5, 9.6, 9.8, 9.9**

Uses hypothesis ``RuleBasedStateMachine`` to model the mistake book as a
state machine with four event types:

* ``add_wrong_grade``  — adds/updates an entry from a wrong objective grade
* ``add_manual_entry`` — manually adds an entry with notes ≤ 1000 chars
* ``redo_correct``     — marks a redo as correct (streak increments)
* ``redo_wrong``       — marks a redo as wrong (streak resets, mastered reverts)

After every step, global invariants are asserted:

* For all entries: error_count >= 1
* For all entries: redo_count >= 0
* For all entries: correct_streak >= 0
* For all entries: if mastered then correct_streak >= 2
* For all entries: last_wrong_at >= first_wrong_at
* No duplicate entry_ids
"""

from __future__ import annotations

from datetime import datetime, timedelta
from decimal import Decimal

from hypothesis import settings
from hypothesis import strategies as st
from hypothesis.stateful import (
    Bundle,
    RuleBasedStateMachine,
    initialize,
    invariant,
    rule,
)

from cet4_app.domain.enums import QuestionType, SectionName
from cet4_app.domain.mistake.mistake_book_logic import MistakeBookLogic
from cet4_app.domain.models.mistake_entry import MistakeEntry
from cet4_app.domain.models.question import Question
from cet4_app.domain.models.score_report import QuestionGrade


# ---------------------------------------------------------------------------
# Helpers: lightweight factories for domain objects
# ---------------------------------------------------------------------------

_COUNTER = 0


def _next_id() -> str:
    global _COUNTER
    _COUNTER += 1
    return f"q-{_COUNTER:06d}"


def _make_objective_question(question_id: str, paper_id: str) -> Question:
    """Create a minimal valid objective Question for testing."""
    return Question(
        id=question_id,
        paper_id=paper_id,
        section=SectionName.reading,
        sub_section="careful",
        question_type=QuestionType.reading_careful_choice,
        prompt="What is the answer?",
        options=["Alpha", "Beta", "Gamma", "Delta"],
        correct_letter="A",
        reference_answer="A",
        explanation="",
        score=Decimal("2.00"),
        tags=[],
    )


def _make_wrong_grade(question_id: str, score_max: Decimal) -> QuestionGrade:
    """Create a QuestionGrade representing a wrong objective answer."""
    return QuestionGrade(
        question_id=question_id,
        is_correct=False,
        status="ok",
        earned_score=Decimal("0.00"),
        score_max=score_max,
        reference_answer="A",
        user_answer="B",
    )


# ---------------------------------------------------------------------------
# State machine
# ---------------------------------------------------------------------------


class MistakeBookStateMachine(RuleBasedStateMachine):
    """RuleBasedStateMachine modelling the MistakeBookLogic lifecycle.

    State: a dict of question_id → MistakeEntry (mirrors the book's
    internal state). We also track entry_ids for redo operations.
    """

    def __init__(self) -> None:
        super().__init__()
        self.entries: dict[str, MistakeEntry] = {}
        self.base_time = datetime(2025, 1, 1, 0, 0, 0)
        self.time_offset = 0

    def _now(self) -> datetime:
        """Return a monotonically increasing timestamp."""
        self.time_offset += 1
        return self.base_time + timedelta(seconds=self.time_offset)

    # Bundles to track created question_ids and entry_ids
    question_ids = Bundle("question_ids")
    entry_ids = Bundle("entry_ids")

    @initialize(target=question_ids)
    def seed_first_question(self) -> str:
        """Seed the state machine with at least one question."""
        qid = _next_id()
        paper_id = "paper-001"
        question = _make_objective_question(qid, paper_id)
        grade = _make_wrong_grade(qid, question.score)
        now = self._now()
        MistakeBookLogic.add_from_grade(self.entries, grade, question, now)
        return qid

    @rule(
        target=question_ids,
        paper_idx=st.integers(min_value=1, max_value=5),
    )
    def add_wrong_grade(self, paper_idx: int) -> str:
        """Add a wrong objective grade — creates or updates an entry.

        Invariant: error_count >= 1, entry exists after call.
        """
        qid = _next_id()
        paper_id = f"paper-{paper_idx:03d}"
        question = _make_objective_question(qid, paper_id)
        grade = _make_wrong_grade(qid, question.score)
        now = self._now()

        result = MistakeBookLogic.add_from_grade(
            self.entries, grade, question, now
        )

        # The entry must exist and have error_count >= 1
        assert result is not None
        assert result.error_count >= 1
        assert qid in self.entries
        return qid

    @rule(
        target=question_ids,
        qid=question_ids,
        paper_idx=st.integers(min_value=1, max_value=5),
    )
    def add_duplicate_grade(self, qid: str, paper_idx: int) -> str:
        """Re-grade an existing question as wrong — dedup/cumulate (Req 9.8).

        Invariant: error_count increments, no duplicate entry created.
        """
        paper_id = f"paper-{paper_idx:03d}"
        question = _make_objective_question(qid, paper_id)
        grade = _make_wrong_grade(qid, question.score)
        now = self._now()

        old_count = (
            self.entries[qid].error_count if qid in self.entries else 0
        )

        result = MistakeBookLogic.add_from_grade(
            self.entries, grade, question, now
        )

        if result is not None:
            assert result.error_count == old_count + 1
            assert result.question_id == qid
        return qid

    @rule(
        target=question_ids,
        notes=st.text(min_size=0, max_size=1200),
        paper_idx=st.integers(min_value=1, max_value=5),
    )
    def add_manual_entry(self, notes: str, paper_idx: int) -> str:
        """Manually add an entry with notes (Req 9.3).

        Invariant: notes length ≤ 1000 after truncation.
        """
        qid = _next_id()
        paper_id = f"paper-{paper_idx:03d}"
        now = self._now()

        result = MistakeBookLogic.add_manual(
            self.entries, qid, paper_id, notes, now
        )

        assert result is not None
        assert len(result.notes) <= 1000
        assert result.error_count >= 1
        assert qid in self.entries
        return qid

    @rule(qid=question_ids)
    def redo_correct(self, qid: str) -> None:
        """Mark a redo as correct (Req 9.5, 9.6).

        Invariant: redo_count increments, correct_streak increments,
        if streak >= 2 then mastered=True.
        """
        if qid not in self.entries:
            return

        entry = self.entries[qid]
        entry_id = entry.entry_id
        old_redo = entry.redo_count
        old_streak = entry.correct_streak
        now = self._now()

        result = MistakeBookLogic.mark_redo_result(
            self.entries, entry_id, correct=True, now=now
        )

        assert result.redo_count == old_redo + 1
        assert result.correct_streak == old_streak + 1
        if result.correct_streak >= 2:
            assert result.mastered is True

    @rule(qid=question_ids)
    def redo_wrong(self, qid: str) -> None:
        """Mark a redo as wrong (Req 9.9).

        Invariant: redo_count increments, correct_streak resets to 0,
        mastered reverts to False.
        """
        if qid not in self.entries:
            return

        entry = self.entries[qid]
        entry_id = entry.entry_id
        old_redo = entry.redo_count
        now = self._now()

        result = MistakeBookLogic.mark_redo_result(
            self.entries, entry_id, correct=False, now=now
        )

        assert result.redo_count == old_redo + 1
        assert result.correct_streak == 0
        assert result.mastered is False

    # ------------------------------------------------------------------
    # Global invariants — checked after every step
    # ------------------------------------------------------------------

    @invariant()
    def error_count_always_positive(self) -> None:
        """For all entries: error_count >= 1."""
        for entry in self.entries.values():
            assert entry.error_count >= 1, (
                f"entry {entry.entry_id}: error_count={entry.error_count} < 1"
            )

    @invariant()
    def redo_count_non_negative(self) -> None:
        """For all entries: redo_count >= 0."""
        for entry in self.entries.values():
            assert entry.redo_count >= 0, (
                f"entry {entry.entry_id}: redo_count={entry.redo_count} < 0"
            )

    @invariant()
    def correct_streak_non_negative(self) -> None:
        """For all entries: correct_streak >= 0."""
        for entry in self.entries.values():
            assert entry.correct_streak >= 0, (
                f"entry {entry.entry_id}: correct_streak={entry.correct_streak} < 0"
            )

    @invariant()
    def mastered_implies_streak_ge_2(self) -> None:
        """For all entries: if mastered then correct_streak >= 2."""
        for entry in self.entries.values():
            if entry.mastered:
                assert entry.correct_streak >= 2, (
                    f"entry {entry.entry_id}: mastered=True but "
                    f"correct_streak={entry.correct_streak} < 2"
                )

    @invariant()
    def temporal_ordering(self) -> None:
        """For all entries: last_wrong_at >= first_wrong_at."""
        for entry in self.entries.values():
            assert entry.last_wrong_at >= entry.first_wrong_at, (
                f"entry {entry.entry_id}: last_wrong_at < first_wrong_at"
            )

    @invariant()
    def no_duplicate_entry_ids(self) -> None:
        """No duplicate entry_ids across all entries."""
        entry_ids = [e.entry_id for e in self.entries.values()]
        assert len(entry_ids) == len(set(entry_ids)), (
            "Duplicate entry_ids detected in mistake book"
        )


# ---------------------------------------------------------------------------
# Test runner — hypothesis discovers this via the TestXxx naming convention
# ---------------------------------------------------------------------------


TestMistakeBookStateMachine = MistakeBookStateMachine.TestCase
TestMistakeBookStateMachine.settings = settings(
    max_examples=100,
    stateful_step_count=30,
)
