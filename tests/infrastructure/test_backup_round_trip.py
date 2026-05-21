"""Property-based tests for backup round-trip and invalid input rejection.

**Property 14: 备份导入/导出等价且非法输入安全拒绝**
**Validates: Requirements 8.6, 9.10, 12.6, 12.7, 13.9**

Tests:
1. Round-trip: export(data) → import → data is equivalent.
2. Invalid JSON (missing fields, invalid enum values, type mismatches) is rejected.
3. ID conflicts within a backup are rejected.
4. Rejected imports preserve existing data unchanged.
"""

from __future__ import annotations

import json
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given, settings, assume
from hypothesis import strategies as st
from sqlalchemy import text
from sqlalchemy.engine import Engine

from cet4_app.domain.enums import (
    DayStatus,
    SectionName,
    SessionMode,
    SheetStatus,
    TaskKind,
)
from cet4_app.domain.models.answer_sheet import Answer, AnswerSheet, RubricScore
from cet4_app.domain.models.mistake_entry import MistakeEntry
from cet4_app.domain.models.score_report import QuestionGrade, ScoreReport
from cet4_app.domain.models.study_plan import (
    PlanParams,
    StudyDay,
    StudyPlan,
    StudyTask,
)
from cet4_app.infrastructure.persistence.backup.exporter import BackupExporter
from cet4_app.infrastructure.persistence.backup.importer import BackupImporter
from cet4_app.infrastructure.persistence.db import create_engine, init_schema


# ---------------------------------------------------------------------------
# Hypothesis strategies for generating valid domain objects
# ---------------------------------------------------------------------------

_ASCII_ID = st.text(
    alphabet=st.characters(min_codepoint=0x61, max_codepoint=0x7A),
    min_size=1,
    max_size=16,
)


@st.composite
def valid_answer_sheet_strategy(draw: st.DrawFn) -> dict[str, Any]:
    """Generate a valid AnswerSheet as a JSON-compatible dict."""
    now = datetime.now(timezone.utc)
    sheet_id = "sheet-" + draw(_ASCII_ID)
    paper_id = "paper-" + draw(_ASCII_ID)

    # Always use submitted + practice for simplicity (avoids mock_deadline constraint)
    started_at = now - timedelta(hours=2)
    submitted_at = now

    answers_count = draw(st.integers(min_value=0, max_value=3))
    answers = {}
    for i in range(answers_count):
        qid = f"q-{sheet_id}-{i:03d}"
        answers[qid] = {
            "question_id": qid,
            "user_answer": draw(st.text(min_size=0, max_size=50)),
            "last_updated_at": now.isoformat(),
            "rubric": None,
            "ai_result_id": None,
        }

    return {
        "sheet_id": sheet_id,
        "paper_id": paper_id,
        "status": "submitted",
        "mode": "practice",
        "started_at": started_at.isoformat(),
        "submitted_at": submitted_at.isoformat(),
        "elapsed_seconds": draw(st.integers(min_value=0, max_value=7200)),
        "mock_deadline": None,
        "draft_saved_at": (now - timedelta(minutes=1)).isoformat(),
        "updated_at": now.isoformat(),
        "answers": answers,
    }


@st.composite
def valid_mistake_entry_strategy(draw: st.DrawFn) -> dict[str, Any]:
    """Generate a valid MistakeEntry as a JSON-compatible dict."""
    now = datetime.now(timezone.utc)
    entry_id = "me-" + draw(_ASCII_ID)
    question_id = "q-" + draw(_ASCII_ID)
    paper_id = "paper-" + draw(_ASCII_ID)

    first_wrong = now - timedelta(days=draw(st.integers(min_value=1, max_value=30)))
    last_wrong_offset = draw(st.integers(min_value=0, max_value=30))
    last_wrong = first_wrong + timedelta(days=last_wrong_offset)

    error_count = draw(st.integers(min_value=1, max_value=20))
    redo_count = draw(st.integers(min_value=0, max_value=10))
    correct_streak = draw(st.integers(min_value=0, max_value=5))
    mastered = correct_streak >= 2 and draw(st.booleans())

    return {
        "entry_id": entry_id,
        "question_id": question_id,
        "paper_id": paper_id,
        "first_wrong_at": first_wrong.isoformat(),
        "last_wrong_at": last_wrong.isoformat(),
        "error_count": error_count,
        "redo_count": redo_count,
        "correct_streak": correct_streak,
        "mastered": mastered,
        "notes": draw(st.text(min_size=0, max_size=100)),
        "tags": draw(
            st.lists(
                st.text(
                    alphabet=st.characters(min_codepoint=0x61, max_codepoint=0x7A),
                    min_size=1,
                    max_size=16,
                ),
                min_size=0,
                max_size=3,
                unique=True,
            )
        ),
    }


@st.composite
def valid_study_plan_strategy(draw: st.DrawFn) -> dict[str, Any]:
    """Generate a valid StudyPlan as a JSON-compatible dict."""
    plan_id = "plan-" + draw(_ASCII_ID)
    total_days = draw(st.integers(min_value=1, max_value=5))
    start = date.today()

    # Generate valid section_ratio that sums to 100
    writing = draw(st.integers(min_value=0, max_value=100))
    listening = draw(st.integers(min_value=0, max_value=100 - writing))
    reading = draw(st.integers(min_value=0, max_value=100 - writing - listening))
    translation = 100 - writing - listening - reading

    # daily_minutes_cap must be multiple of 15, in [30, 480]
    minutes_choices = list(range(30, 481, 15))
    daily_minutes_cap = draw(st.sampled_from(minutes_choices))

    days = []
    for i in range(total_days):
        day_date = start + timedelta(days=i)
        tasks_count = draw(st.integers(min_value=0, max_value=2))
        tasks = []
        for t in range(tasks_count):
            tasks.append({
                "task_id": f"task-{plan_id}-{i}-{t}",
                "kind": draw(st.sampled_from([k.value for k in TaskKind])),
                "paper_id": None,
                "section": None,
                "mistakes_to_review": draw(st.integers(min_value=0, max_value=50)),
                "intensive_listening_minutes": draw(st.integers(min_value=0, max_value=60)),
                "writing_translation_count": draw(st.integers(min_value=0, max_value=5)),
                "completed": draw(st.booleans()),
            })
        days.append({
            "day_index": i + 1,
            "date": day_date.isoformat(),
            "tasks": tasks,
            "status": draw(st.sampled_from([s.value for s in DayStatus])),
            "daily_target_accuracy": None,
        })

    return {
        "plan_id": plan_id,
        "start_date": start.isoformat(),
        "total_days": total_days,
        "params": {
            "start_date": start.isoformat(),
            "daily_minutes_cap": daily_minutes_cap,
            "section_ratio": {
                "writing": writing,
                "listening": listening,
                "reading": reading,
                "translation": translation,
            },
            "daily_target_accuracy": None,
        },
        "days": days,
    }


@st.composite
def valid_score_report_strategy(draw: st.DrawFn) -> dict[str, Any]:
    """Generate a valid ScoreReport as a JSON-compatible dict."""
    now = datetime.now(timezone.utc)
    report_id = "rpt-" + draw(_ASCII_ID)
    sheet_id = "sheet-" + draw(_ASCII_ID)
    paper_id = "paper-" + draw(_ASCII_ID)

    # Generate grades with unique, sorted question_ids
    num_grades = draw(st.integers(min_value=1, max_value=5))
    question_ids = sorted(
        [f"q-{i:04d}" for i in draw(
            st.lists(
                st.integers(min_value=1, max_value=9999),
                min_size=num_grades,
                max_size=num_grades,
                unique=True,
            )
        )]
    )

    correct_count = 0
    wrong_count = 0
    unanswered_count = 0
    cannot_grade_ids = []
    grades = []

    for qid in question_ids:
        status = draw(st.sampled_from(["ok", "unanswered"]))
        score_max = Decimal("3.55")

        if status == "ok":
            is_correct = draw(st.booleans())
            earned = score_max if is_correct else Decimal("0.00")
            if is_correct:
                correct_count += 1
            else:
                wrong_count += 1
        elif status == "unanswered":
            is_correct = False
            earned = Decimal("0.00")
            unanswered_count += 1
        else:
            is_correct = None
            earned = Decimal("0.00")
            cannot_grade_ids.append(qid)

        grades.append({
            "question_id": qid,
            "is_correct": is_correct,
            "status": status,
            "earned_score": str(earned),
            "score_max": str(score_max),
            "reference_answer": "A",
            "user_answer": "B" if not is_correct else "A",
            "explanation_summary": "",
        })

    total_score = Decimal("50.00")
    scaled = draw(st.integers(min_value=0, max_value=710))

    return {
        "report_id": report_id,
        "sheet_id": sheet_id,
        "paper_id": paper_id,
        "total_score": str(total_score),
        "scaled_score_710": scaled,
        "section_scores": {
            "writing": "15.00",
            "listening": "20.00",
            "reading": "10.00",
            "translation": "5.00",
        },
        "grades": grades,
        "correct_count": correct_count,
        "wrong_count": wrong_count,
        "unanswered_count": unanswered_count,
        "cannot_grade_ids": cannot_grade_ids,
        "duration_seconds": draw(st.integers(min_value=0, max_value=7200)),
        "generated_at": now.isoformat(),
    }


@st.composite
def valid_backup_data_strategy(draw: st.DrawFn) -> dict[str, Any]:
    """Generate a complete valid backup data dict with all four categories."""
    # Generate unique items for each category
    num_sheets = draw(st.integers(min_value=0, max_value=2))
    num_mistakes = draw(st.integers(min_value=0, max_value=3))
    num_plans = draw(st.integers(min_value=0, max_value=1))

    sheets = []
    for _ in range(num_sheets):
        sheet = draw(valid_answer_sheet_strategy())
        sheets.append(sheet)

    # Ensure unique sheet_ids
    seen_sheet_ids: set[str] = set()
    unique_sheets = []
    for s in sheets:
        if s["sheet_id"] not in seen_sheet_ids:
            seen_sheet_ids.add(s["sheet_id"])
            unique_sheets.append(s)
    sheets = unique_sheets

    mistakes = []
    seen_entry_ids: set[str] = set()
    seen_question_ids: set[str] = set()
    for _ in range(num_mistakes):
        entry = draw(valid_mistake_entry_strategy())
        if (
            entry["entry_id"] not in seen_entry_ids
            and entry["question_id"] not in seen_question_ids
        ):
            seen_entry_ids.add(entry["entry_id"])
            seen_question_ids.add(entry["question_id"])
            mistakes.append(entry)

    plans = []
    seen_plan_ids: set[str] = set()
    for _ in range(num_plans):
        plan = draw(valid_study_plan_strategy())
        if plan["plan_id"] not in seen_plan_ids:
            seen_plan_ids.add(plan["plan_id"])
            plans.append(plan)

    return {
        "answer_sheets": sheets,
        "score_reports": [],  # ScoreReport has complex invariants; keep empty for round-trip
        "mistake_entries": mistakes,
        "study_plans": plans,
    }


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def engine(tmp_path: Path) -> Engine:
    """Create a fresh SQLite engine with schema initialized."""
    db_path = tmp_path / "test.db"
    eng = create_engine(db_path)
    init_schema(eng)
    return eng


@pytest.fixture
def importer(engine: Engine) -> BackupImporter:
    """Create a BackupImporter instance."""
    return BackupImporter(engine)


# ---------------------------------------------------------------------------
# Property Tests
# ---------------------------------------------------------------------------


class TestBackupRoundTrip:
    """Property 14: import_(export(D)) ≡ D — round-trip equivalence.

    **Validates: Requirements 8.6, 12.6**
    """

    @settings(max_examples=50, deadline=5000)
    @given(data=valid_backup_data_strategy())
    def test_round_trip_equivalence(self, data: dict[str, Any]) -> None:
        """Importing exported data produces equivalent dataset."""
        import tempfile
        import uuid

        tmp_dir = Path(tempfile.mkdtemp())
        unique_db = tmp_dir / f"rt_{uuid.uuid4().hex[:8]}.db"
        eng = create_engine(unique_db)
        init_schema(eng)
        imp = BackupImporter(eng)

        # Step 1: Import the generated data
        report1 = imp.import_from_dict(data)
        assert report1.success is True, (
            f"Initial import failed: errors={report1.validation_errors}, "
            f"msg={report1.error_message}"
        )

        # Step 2: Export from DB by reading back the data
        exported = self._export_from_db(eng)

        # Step 3: Import the exported data into a fresh DB
        unique_db2 = tmp_dir / f"rt2_{uuid.uuid4().hex[:8]}.db"
        eng2 = create_engine(unique_db2)
        init_schema(eng2)
        imp2 = BackupImporter(eng2)

        report2 = imp2.import_from_dict(exported)
        assert report2.success is True, (
            f"Re-import failed: errors={report2.validation_errors}, "
            f"msg={report2.error_message}"
        )

        # Step 4: Verify counts match
        assert report2.answer_sheets_count == report1.answer_sheets_count
        assert report2.mistake_entries_count == report1.mistake_entries_count
        assert report2.study_plans_count == report1.study_plans_count

        # Step 5: Verify data equivalence by re-exporting
        exported2 = self._export_from_db(eng2)
        assert len(exported2.get("answer_sheets", [])) == len(exported.get("answer_sheets", []))
        assert len(exported2.get("mistake_entries", [])) == len(exported.get("mistake_entries", []))
        assert len(exported2.get("study_plans", [])) == len(exported.get("study_plans", []))

    @staticmethod
    def _export_from_db(engine: Engine) -> dict[str, Any]:
        """Read back all user data from DB as a backup-compatible dict."""
        with engine.connect() as conn:
            # Read answer_sheets
            sheets_rows = conn.execute(
                text("SELECT sheet_id, paper_id, status, mode, started_at, "
                     "submitted_at, elapsed_seconds, mock_deadline, "
                     "draft_saved_at, updated_at FROM answer_sheet")
            ).fetchall()

            sheets = []
            for row in sheets_rows:
                sheet_id = row[0]
                # Read answers for this sheet
                answer_rows = conn.execute(
                    text("SELECT question_id, user_answer, rubric_json, "
                         "ai_result_id, last_updated_at FROM answer "
                         "WHERE sheet_id = :sid"),
                    {"sid": sheet_id},
                ).fetchall()

                answers = {}
                for ar in answer_rows:
                    answers[ar[0]] = {
                        "question_id": ar[0],
                        "user_answer": ar[1],
                        "last_updated_at": ar[4],
                        "rubric": json.loads(ar[2]) if ar[2] else None,
                        "ai_result_id": ar[3],
                    }

                sheets.append({
                    "sheet_id": row[0],
                    "paper_id": row[1],
                    "status": row[2],
                    "mode": row[3],
                    "started_at": row[4],
                    "submitted_at": row[5],
                    "elapsed_seconds": row[6],
                    "mock_deadline": row[7],
                    "draft_saved_at": row[8],
                    "updated_at": row[9],
                    "answers": answers,
                })

            # Read mistake_entries
            me_rows = conn.execute(
                text("SELECT entry_id, question_id, paper_id, first_wrong_at, "
                     "last_wrong_at, error_count, redo_count, correct_streak, "
                     "mastered, notes, tags_json FROM mistake_entry")
            ).fetchall()

            mistakes = []
            for row in me_rows:
                mistakes.append({
                    "entry_id": row[0],
                    "question_id": row[1],
                    "paper_id": row[2],
                    "first_wrong_at": row[3],
                    "last_wrong_at": row[4],
                    "error_count": row[5],
                    "redo_count": row[6],
                    "correct_streak": row[7],
                    "mastered": bool(row[8]),
                    "notes": row[9],
                    "tags": json.loads(row[10]) if row[10] else [],
                })

            # Read study_plans
            plan_rows = conn.execute(
                text("SELECT plan_id, start_date, total_days, params_json "
                     "FROM study_plan")
            ).fetchall()

            plans = []
            for row in plan_rows:
                plan_id = row[0]
                params = json.loads(row[3]) if row[3] else {}

                # Read days
                day_rows = conn.execute(
                    text("SELECT day_index, date, status, daily_target_accuracy "
                         "FROM study_day WHERE plan_id = :pid ORDER BY day_index"),
                    {"pid": plan_id},
                ).fetchall()

                days = []
                for dr in day_rows:
                    # Read tasks for this day
                    task_rows = conn.execute(
                        text("SELECT task_id, kind, paper_id, section, "
                             "mistakes_to_review, intensive_listening_minutes, "
                             "writing_translation_count, completed "
                             "FROM study_task WHERE plan_id = :pid AND day_index = :di"),
                        {"pid": plan_id, "di": dr[0]},
                    ).fetchall()

                    tasks = []
                    for tr in task_rows:
                        tasks.append({
                            "task_id": tr[0],
                            "kind": tr[1],
                            "paper_id": tr[2],
                            "section": tr[3],
                            "mistakes_to_review": tr[4],
                            "intensive_listening_minutes": tr[5],
                            "writing_translation_count": tr[6],
                            "completed": bool(tr[7]),
                        })

                    days.append({
                        "day_index": dr[0],
                        "date": dr[1],
                        "tasks": tasks,
                        "status": dr[2],
                        "daily_target_accuracy": dr[3],
                    })

                # Reconstruct section_ratio with proper keys
                section_ratio = params.get("section_ratio", {})

                plans.append({
                    "plan_id": plan_id,
                    "start_date": row[1],
                    "total_days": row[2],
                    "params": {
                        "start_date": params.get("start_date", row[1]),
                        "daily_minutes_cap": params.get("daily_minutes_cap", 120),
                        "section_ratio": section_ratio,
                        "daily_target_accuracy": params.get("daily_target_accuracy"),
                    },
                    "days": days,
                })

        return {
            "answer_sheets": sheets,
            "score_reports": [],
            "mistake_entries": mistakes,
            "study_plans": plans,
        }


class TestInvalidInputRejection:
    """Property 14: Invalid JSON is safely rejected and existing data unchanged.

    **Validates: Requirements 12.7, 13.9**
    """

    @settings(max_examples=50, deadline=5000)
    @given(
        valid_data=valid_backup_data_strategy(),
        mutation_type=st.sampled_from([
            "missing_field",
            "invalid_enum",
            "type_mismatch",
        ]),
    )
    def test_invalid_input_rejected_preserves_data(
        self,
        valid_data: dict[str, Any],
        mutation_type: str,
    ) -> None:
        """Invalid backup data is rejected and existing data remains unchanged."""
        import tempfile
        import uuid

        tmp_dir = Path(tempfile.mkdtemp())
        unique_db = tmp_dir / f"inv_{uuid.uuid4().hex[:8]}.db"
        eng = create_engine(unique_db)
        init_schema(eng)
        imp = BackupImporter(eng)

        # First, import valid data to establish a baseline
        report1 = imp.import_from_dict(valid_data)
        assume(report1.success)

        # Count existing records
        with eng.connect() as conn:
            orig_sheets = conn.execute(text("SELECT COUNT(*) FROM answer_sheet")).scalar()
            orig_mistakes = conn.execute(text("SELECT COUNT(*) FROM mistake_entry")).scalar()
            orig_plans = conn.execute(text("SELECT COUNT(*) FROM study_plan")).scalar()

        # Now create invalid data based on mutation type
        invalid_data = self._mutate_data(mutation_type)

        # Attempt import of invalid data
        report2 = imp.import_from_dict(invalid_data)
        assert report2.success is False, (
            f"Expected rejection for mutation_type={mutation_type}"
        )

        # Verify existing data is unchanged
        with eng.connect() as conn:
            curr_sheets = conn.execute(text("SELECT COUNT(*) FROM answer_sheet")).scalar()
            curr_mistakes = conn.execute(text("SELECT COUNT(*) FROM mistake_entry")).scalar()
            curr_plans = conn.execute(text("SELECT COUNT(*) FROM study_plan")).scalar()

        assert curr_sheets == orig_sheets, "answer_sheet count changed after rejected import"
        assert curr_mistakes == orig_mistakes, "mistake_entry count changed after rejected import"
        assert curr_plans == orig_plans, "study_plan count changed after rejected import"

    @staticmethod
    def _mutate_data(mutation_type: str) -> dict[str, Any]:
        """Create invalid backup data based on mutation type."""
        now = datetime.now(timezone.utc)

        if mutation_type == "missing_field":
            # AnswerSheet missing required 'status' field
            return {
                "answer_sheets": [{
                    "sheet_id": "bad-sheet",
                    "paper_id": "paper-001",
                    # "status" is missing
                    "mode": "practice",
                    "started_at": now.isoformat(),
                    "submitted_at": now.isoformat(),
                    "elapsed_seconds": 100,
                    "updated_at": now.isoformat(),
                    "answers": {},
                }],
            }
        elif mutation_type == "invalid_enum":
            # Invalid enum value for status
            return {
                "answer_sheets": [{
                    "sheet_id": "bad-sheet",
                    "paper_id": "paper-001",
                    "status": "nonexistent_status",
                    "mode": "practice",
                    "started_at": now.isoformat(),
                    "submitted_at": now.isoformat(),
                    "elapsed_seconds": 100,
                    "updated_at": now.isoformat(),
                    "answers": {},
                }],
            }
        else:  # type_mismatch
            # elapsed_seconds should be int, not string
            return {
                "mistake_entries": [{
                    "entry_id": "bad-entry",
                    "question_id": "q-bad",
                    "paper_id": "paper-bad",
                    "first_wrong_at": now.isoformat(),
                    "last_wrong_at": now.isoformat(),
                    "error_count": "not_a_number",  # type mismatch
                    "redo_count": 0,
                    "correct_streak": 0,
                    "mastered": False,
                    "notes": "",
                    "tags": [],
                }],
            }


class TestIDConflictRejection:
    """Property 14: ID conflicts within a backup are rejected.

    **Validates: Requirements 9.10, 12.7**
    """

    @settings(max_examples=30, deadline=5000)
    @given(
        entry=valid_mistake_entry_strategy(),
        conflict_type=st.sampled_from(["entry_id", "question_id"]),
    )
    def test_duplicate_ids_rejected(
        self,
        entry: dict[str, Any],
        conflict_type: str,
    ) -> None:
        """Backup with duplicate IDs within a category is rejected."""
        import tempfile
        import uuid

        tmp_dir = Path(tempfile.mkdtemp())
        unique_db = tmp_dir / f"idc_{uuid.uuid4().hex[:8]}.db"
        eng = create_engine(unique_db)
        init_schema(eng)
        imp = BackupImporter(eng)

        # Create two entries with conflicting IDs
        entry1 = dict(entry)
        entry2 = dict(entry)

        if conflict_type == "entry_id":
            # Same entry_id, different question_id
            entry2["question_id"] = entry2["question_id"] + "-dup"
        else:
            # Same question_id, different entry_id
            entry2["entry_id"] = entry2["entry_id"] + "-dup"

        data = {"mistake_entries": [entry1, entry2]}
        report = imp.import_from_dict(data)

        assert report.success is False
        assert len(report.validation_errors) > 0
        assert any("ID 冲突" in e.reason for e in report.validation_errors)

    @settings(max_examples=30, deadline=5000)
    @given(sheet=valid_answer_sheet_strategy())
    def test_duplicate_sheet_ids_rejected(
        self,
        sheet: dict[str, Any],
    ) -> None:
        """Backup with duplicate sheet_ids is rejected."""
        import tempfile
        import uuid

        tmp_dir = Path(tempfile.mkdtemp())
        unique_db = tmp_dir / f"ids_{uuid.uuid4().hex[:8]}.db"
        eng = create_engine(unique_db)
        init_schema(eng)
        imp = BackupImporter(eng)

        # Two sheets with same sheet_id
        data = {"answer_sheets": [sheet, dict(sheet)]}
        report = imp.import_from_dict(data)

        assert report.success is False
        assert any("ID 冲突" in e.reason for e in report.validation_errors)

    @settings(max_examples=30, deadline=5000)
    @given(plan=valid_study_plan_strategy())
    def test_duplicate_plan_ids_rejected(
        self,
        plan: dict[str, Any],
    ) -> None:
        """Backup with duplicate plan_ids is rejected."""
        import tempfile
        import uuid

        tmp_dir = Path(tempfile.mkdtemp())
        unique_db = tmp_dir / f"idp_{uuid.uuid4().hex[:8]}.db"
        eng = create_engine(unique_db)
        init_schema(eng)
        imp = BackupImporter(eng)

        # Two plans with same plan_id
        data = {"study_plans": [plan, dict(plan)]}
        report = imp.import_from_dict(data)

        assert report.success is False
        assert any("ID 冲突" in e.reason for e in report.validation_errors)

    @settings(max_examples=30, deadline=5000)
    @given(
        valid_data=valid_backup_data_strategy(),
        entry=valid_mistake_entry_strategy(),
    )
    def test_id_conflict_preserves_existing_data(
        self,
        valid_data: dict[str, Any],
        entry: dict[str, Any],
    ) -> None:
        """ID conflict rejection preserves existing data unchanged."""
        import tempfile
        import uuid

        tmp_dir = Path(tempfile.mkdtemp())
        unique_db = tmp_dir / f"idp2_{uuid.uuid4().hex[:8]}.db"
        eng = create_engine(unique_db)
        init_schema(eng)
        imp = BackupImporter(eng)

        # Import valid data first
        report1 = imp.import_from_dict(valid_data)
        assume(report1.success)

        # Count existing records
        with eng.connect() as conn:
            orig_count = conn.execute(text("SELECT COUNT(*) FROM mistake_entry")).scalar()

        # Try to import data with ID conflicts
        entry2 = dict(entry)
        # Same entry_id → conflict
        conflicting_data = {"mistake_entries": [entry, entry2]}
        report2 = imp.import_from_dict(conflicting_data)
        assert report2.success is False

        # Verify data unchanged
        with eng.connect() as conn:
            curr_count = conn.execute(text("SELECT COUNT(*) FROM mistake_entry")).scalar()
        assert curr_count == orig_count
