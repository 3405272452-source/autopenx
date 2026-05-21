"""Unit tests for application/answer_session_service.py.

Tests the AnswerSessionService orchestration:
- Session creation with correct initial state (Req 4.1).
- Answer update overwrites existing answers with timestamp (Req 4.2).
- Draft auto-save every 30 seconds with retry on failure (Req 4.5, 4.6).
- Pause/resume with position tracking and countdown freeze (Req 4.7).
- Mock exam 125-minute countdown, 10/1 min reminders, auto-submit (Req 4.10).
- Submit flow: unanswered check, lock sheet, trigger grading (Req 4.8, 4.9).
- Persistence failure logging (Req 14.4).

Requirements covered: 4.1, 4.2, 4.3, 4.5, 4.6, 4.7, 4.8, 4.9, 4.10, 14.4.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Optional

import pytest

from cet4_app.application.answer_session_service import (
    DRAFT_SAVE_INTERVAL_SECONDS,
    MAX_DRAFT_SAVE_RETRIES,
    MOCK_EXAM_DURATION_MINUTES,
    REMINDER_1_MIN_SECONDS,
    REMINDER_10_MIN_SECONDS,
    SECTION_ORDER,
    AnswerSessionService,
    SessionSignals,
    UnansweredInfo,
)
from cet4_app.domain.enums import SectionName, SessionMode, SheetStatus
from cet4_app.domain.models.answer_sheet import Answer, AnswerSheet


# ---------------------------------------------------------------------------
# Fake implementations for testing
# ---------------------------------------------------------------------------


class FakeAnswerSheetRepo:
    """In-memory fake for AnswerSheetRepository protocol."""

    def __init__(self, *, fail_save: bool = False, fail_count: int = 0) -> None:
        self.sheets: dict[str, AnswerSheet] = {}
        self.drafts: list[AnswerSheet] = []
        self.status_updates: list[tuple[str, SheetStatus]] = []
        self._fail_save = fail_save
        self._fail_count = fail_count
        self._current_fail = 0

    def save_sheet(self, sheet: AnswerSheet) -> None:
        if self._fail_save:
            raise IOError("Disk full")
        self.sheets[sheet.sheet_id] = sheet

    def save_draft(self, sheet: AnswerSheet) -> None:
        if self._fail_count > 0 and self._current_fail < self._fail_count:
            self._current_fail += 1
            raise IOError("Draft save failed: disk full")
        self.drafts.append(sheet)

    def load_sheet_by_id(self, sheet_id: str) -> Optional[AnswerSheet]:
        return self.sheets.get(sheet_id)

    def update_sheet_status(
        self,
        sheet_id: str,
        new_status: SheetStatus,
        *,
        submitted_at: Optional[datetime] = None,
        elapsed_seconds: Optional[int] = None,
    ) -> bool:
        self.status_updates.append((sheet_id, new_status))
        if sheet_id in self.sheets:
            sheet = self.sheets[sheet_id]
            # Rebuild with new status for testing
            now = datetime.now(timezone.utc)
            self.sheets[sheet_id] = AnswerSheet(
                sheet_id=sheet.sheet_id,
                paper_id=sheet.paper_id,
                status=new_status,
                mode=sheet.mode,
                started_at=sheet.started_at,
                submitted_at=submitted_at or sheet.submitted_at,
                mock_deadline=sheet.mock_deadline,
                draft_saved_at=sheet.draft_saved_at,
                updated_at=now,
                elapsed_seconds=(
                    elapsed_seconds
                    if elapsed_seconds is not None
                    else sheet.elapsed_seconds
                ),
                answers=sheet.answers,
            )
            return True
        return False

    def load_latest_draft(self, paper_id: str) -> Optional[AnswerSheet]:
        for sheet in reversed(list(self.sheets.values())):
            if (
                sheet.paper_id == paper_id
                and sheet.status in (SheetStatus.in_progress, SheetStatus.paused)
            ):
                return sheet
        return None


class FakeLogRepo:
    """In-memory fake for LogRepo protocol."""

    def __init__(self) -> None:
        self.logs: list[dict] = []

    def insert_log(
        self,
        level: str,
        message: str,
        context: str = "",
    ) -> str:
        self.logs.append({"level": level, "message": message, "context": context})
        return "log-001"


class FakeSignals:
    """In-memory fake for SessionSignals protocol."""

    def __init__(self) -> None:
        self.draft_saved_timestamps: list[datetime] = []
        self.draft_save_failures: list[tuple[str, int]] = []
        self.countdown_ticks: list[int] = []
        self.reminders: list[int] = []
        self.auto_submit_called: bool = False
        self.paused_called: bool = False
        self.resumed_called: bool = False

    def on_draft_saved(self, timestamp: datetime) -> None:
        self.draft_saved_timestamps.append(timestamp)

    def on_draft_save_failed(self, reason: str, retry_count: int) -> None:
        self.draft_save_failures.append((reason, retry_count))

    def on_countdown_tick(self, remaining_seconds: int) -> None:
        self.countdown_ticks.append(remaining_seconds)

    def on_reminder(self, remaining_minutes: int) -> None:
        self.reminders.append(remaining_minutes)

    def on_auto_submit(self) -> None:
        self.auto_submit_called = True

    def on_session_paused(self) -> None:
        self.paused_called = True

    def on_session_resumed(self) -> None:
        self.resumed_called = True


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_service(
    *,
    fail_save: bool = False,
    fail_count: int = 0,
) -> tuple[AnswerSessionService, FakeAnswerSheetRepo, FakeLogRepo, FakeSignals, list]:
    """Create a service with fake dependencies and a grading callback tracker."""
    repo = FakeAnswerSheetRepo(fail_save=fail_save, fail_count=fail_count)
    log_repo = FakeLogRepo()
    signals = FakeSignals()
    grading_calls: list[str] = []

    service = AnswerSessionService(
        answer_sheet_repo=repo,
        log_repo=log_repo,
        signals=signals,
        grading_callback=lambda sheet_id: grading_calls.append(sheet_id),
    )
    return service, repo, log_repo, signals, grading_calls


def _question_ids() -> list[str]:
    return [
        "q-writing-01",
        "q-listening-01",
        "q-listening-02",
        "q-reading-01",
        "q-translation-01",
    ]


def _question_sections() -> dict[str, SectionName]:
    return {
        "q-writing-01": SectionName.writing,
        "q-listening-01": SectionName.listening,
        "q-listening-02": SectionName.listening,
        "q-reading-01": SectionName.reading,
        "q-translation-01": SectionName.translation,
    }


# ---------------------------------------------------------------------------
# Tests: Session creation (Requirement 4.1)
# ---------------------------------------------------------------------------


class TestStartSession:
    """Tests for AnswerSessionService.start_session."""

    def test_creates_new_sheet_in_progress(self) -> None:
        """start_session creates a sheet with status in_progress (Req 4.1)."""
        service, repo, _, _, _ = _make_service()

        sheet = service.start_session(
            paper_id="paper-001",
            question_ids=_question_ids(),
            question_sections=_question_sections(),
            mode=SessionMode.practice,
        )

        assert sheet.status == SheetStatus.in_progress
        assert sheet.paper_id == "paper-001"
        assert sheet.mode == SessionMode.practice

    def test_persists_sheet_to_repo(self) -> None:
        """start_session saves the sheet to the repository."""
        service, repo, _, _, _ = _make_service()

        sheet = service.start_session(
            paper_id="paper-001",
            question_ids=_question_ids(),
            question_sections=_question_sections(),
        )

        assert sheet.sheet_id in repo.sheets

    def test_mock_exam_sets_deadline(self) -> None:
        """Mock exam mode sets a mock_deadline 125 minutes in the future (Req 4.10)."""
        service, _, _, _, _ = _make_service()

        sheet = service.start_session(
            paper_id="paper-001",
            question_ids=_question_ids(),
            question_sections=_question_sections(),
            mode=SessionMode.mock_exam,
        )

        assert sheet.mock_deadline is not None
        # Deadline should be approximately 125 minutes from now
        expected_delta = timedelta(minutes=MOCK_EXAM_DURATION_MINUTES)
        actual_delta = sheet.mock_deadline - sheet.started_at
        # Allow 2 seconds tolerance for test execution time
        assert abs(actual_delta.total_seconds() - expected_delta.total_seconds()) < 2

    def test_practice_mode_no_deadline(self) -> None:
        """Practice mode does not set a mock_deadline."""
        service, _, _, _, _ = _make_service()

        sheet = service.start_session(
            paper_id="paper-001",
            question_ids=_question_ids(),
            question_sections=_question_sections(),
            mode=SessionMode.practice,
        )

        assert sheet.mock_deadline is None

    def test_service_is_active_after_start(self) -> None:
        """Service reports is_active=True after starting a session."""
        service, _, _, _, _ = _make_service()

        service.start_session(
            paper_id="paper-001",
            question_ids=_question_ids(),
            question_sections=_question_sections(),
        )

        assert service.is_active is True
        assert service.is_paused is False

    def test_is_mock_exam_property(self) -> None:
        """is_mock_exam returns True for mock exam sessions."""
        service, _, _, _, _ = _make_service()

        service.start_session(
            paper_id="paper-001",
            question_ids=_question_ids(),
            question_sections=_question_sections(),
            mode=SessionMode.mock_exam,
        )

        assert service.is_mock_exam is True

    def test_empty_answers_on_start(self) -> None:
        """A new session starts with an empty answers dict."""
        service, _, _, _, _ = _make_service()

        sheet = service.start_session(
            paper_id="paper-001",
            question_ids=_question_ids(),
            question_sections=_question_sections(),
        )

        assert sheet.answers == {}


# ---------------------------------------------------------------------------
# Tests: Answer update (Requirement 4.2, 4.3)
# ---------------------------------------------------------------------------


class TestUpdateAnswer:
    """Tests for AnswerSessionService.update_answer."""

    def test_records_new_answer(self) -> None:
        """update_answer records a new answer for a question (Req 4.2)."""
        service, _, _, _, _ = _make_service()
        service.start_session(
            paper_id="paper-001",
            question_ids=_question_ids(),
            question_sections=_question_sections(),
        )

        service.update_answer("q-listening-01", "A")

        assert service.sheet is not None
        assert "q-listening-01" in service.sheet.answers
        assert service.sheet.answers["q-listening-01"].user_answer == "A"

    def test_overwrites_existing_answer(self) -> None:
        """update_answer overwrites an existing answer (Req 4.2)."""
        service, _, _, _, _ = _make_service()
        service.start_session(
            paper_id="paper-001",
            question_ids=_question_ids(),
            question_sections=_question_sections(),
        )

        service.update_answer("q-listening-01", "A")
        service.update_answer("q-listening-01", "B")

        assert service.sheet is not None
        assert service.sheet.answers["q-listening-01"].user_answer == "B"

    def test_records_timestamp_on_update(self) -> None:
        """update_answer records the last_updated_at timestamp (Req 4.2)."""
        service, _, _, _, _ = _make_service()
        service.start_session(
            paper_id="paper-001",
            question_ids=_question_ids(),
            question_sections=_question_sections(),
        )

        before = datetime.now(timezone.utc)
        service.update_answer("q-reading-01", "C")
        after = datetime.now(timezone.utc)

        answer = service.sheet.answers["q-reading-01"]
        assert before <= answer.last_updated_at <= after

    def test_no_op_when_no_active_session(self) -> None:
        """update_answer does nothing if no session is active."""
        service, _, _, _, _ = _make_service()

        # No session started
        service.update_answer("q-listening-01", "A")

        assert service.sheet is None

    def test_no_op_when_submitted(self) -> None:
        """update_answer does nothing after submission."""
        service, _, _, _, _ = _make_service()
        service.start_session(
            paper_id="paper-001",
            question_ids=_question_ids(),
            question_sections=_question_sections(),
        )
        # Answer all questions and submit
        for qid in _question_ids():
            service.update_answer(qid, "X")
        service.submit(force=True)

        # Try to update after submission
        service.update_answer("q-listening-01", "Z")

        # Should still be "X" (locked)
        assert service.sheet.answers["q-listening-01"].user_answer == "X"
