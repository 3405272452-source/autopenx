"""Property tests for the Library_Root filesystem scanner.

**Property 1: 题库扫描覆盖全集并正确分类**
**Validates: Requirements 1.5, 1.6, 1.7, 1.9, 1.10**

For any Library_Root directory tree generated with an arbitrary subset of
files present/missing, the scanner must:
- Always produce exactly 12 Paper records (4 PaperSets × 3 Papers)
- Correctly classify each Paper's status as ok or incomplete
- Accurately reflect MP3 presence via audio_status (available / embedded-in-paper)
- List missing files precisely for incomplete Papers

**Property 2: 非法 Library_Root 被拒绝且原配置保留**
**Validates: Requirements 1.3, 1.8**

For any invalid path (non-existent, not a directory, not readable), the
scanner must raise LibraryRootError with the correct kind and the original
path value, without producing any ScanResult.
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path
from typing import Any

import pytest
from hypothesis import HealthCheck, assume, given, settings
from hypothesis import strategies as st

from cet4_app.domain.enums import AudioStatus, PaperStatus
from cet4_app.domain.errors import LibraryRootError, LibraryRootErrorKind
from cet4_app.infrastructure.fs.scanner import (
    KNOWN_EXAM_PERIODS,
    PaperRecord,
    ScanResult,
    scan,
)


# ---------------------------------------------------------------------------
# Hypothesis strategies for generating fake directory trees
# ---------------------------------------------------------------------------


@st.composite
def fake_library_tree(draw: Any) -> dict[str, dict[int, dict[str, bool]]]:
    """Generate a specification for a fake library directory tree.

    Returns a dict mapping exam_period -> {set_index -> {file_type -> exists}}.
    file_type is one of: "paper_pdf", "answer_pdf", "audio_mp3"
    """
    tree: dict[str, dict[int, dict[str, bool]]] = {}
    for _dir_name, exam_period in KNOWN_EXAM_PERIODS:
        period_files: dict[int, dict[str, bool]] = {}
        for set_index in range(1, 4):
            period_files[set_index] = {
                "paper_pdf": draw(st.booleans()),
                "answer_pdf": draw(st.booleans()),
                "audio_mp3": draw(st.booleans()),
            }
        tree[exam_period] = period_files
    return tree


_COUNTER = 0


def _create_fake_tree(
    base_dir: Path, tree_spec: dict[str, dict[int, dict[str, bool]]]
) -> Path:
    """Materialize a fake directory tree on disk from a tree specification.

    Uses a unique subdirectory per call to avoid interference between
    hypothesis iterations sharing the same tmp_path.
    """
    global _COUNTER
    _COUNTER += 1
    library_root = base_dir / f"cet4_{_COUNTER}"
    library_root.mkdir(parents=True, exist_ok=True)

    for dir_name, exam_period in KNOWN_EXAM_PERIODS:
        period_dir = library_root / dir_name
        period_dir.mkdir(exist_ok=True)

        if exam_period not in tree_spec:
            continue

        for set_index, files in tree_spec[exam_period].items():
            if files.get("paper_pdf", False):
                pdf_file = period_dir / f"第{set_index}套真题.pdf"
                pdf_file.write_bytes(b"%PDF-1.4 fake")

            if files.get("answer_pdf", False):
                answer_file = period_dir / f"第{set_index}套解析.pdf"
                answer_file.write_bytes(b"%PDF-1.4 fake answer")

            if files.get("audio_mp3", False):
                mp3_file = period_dir / f"第{set_index}套听力.mp3"
                mp3_file.write_bytes(b"\xff\xfb\x90\x00" + b"\x00" * 100)

    return library_root


# ---------------------------------------------------------------------------
# Property 1: 题库扫描覆盖全集并正确分类
# ---------------------------------------------------------------------------


@settings(
    max_examples=50,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
@given(tree_spec=fake_library_tree())
def test_scan_always_produces_12_papers(tmp_path: Path, tree_spec: dict) -> None:
    """Scanner always produces exactly 12 Paper records regardless of file presence.

    **Validates: Requirements 1.5, 1.10**

    Requirement 1.10 mandates that all 12 Papers are always present in the
    scan result, even when files are missing (as incomplete placeholders).
    """
    library_root = _create_fake_tree(tmp_path, tree_spec)
    result = scan(library_root)

    # Must have exactly 4 PaperSets
    assert len(result.paper_sets) == 4

    # Each PaperSet must have exactly 3 Papers
    all_papers: list[PaperRecord] = []
    for ps in result.paper_sets:
        assert len(ps.papers) == 3
        all_papers.extend(ps.papers)

    # Total must be 12
    assert len(all_papers) == 12


@settings(
    max_examples=50,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
@given(tree_spec=fake_library_tree())
def test_scan_correctly_classifies_paper_status(tmp_path: Path, tree_spec: dict) -> None:
    """Papers with all required files are 'ok'; those missing files are 'incomplete'.

    **Validates: Requirements 1.9, 1.10**

    A Paper is 'ok' only when both paper_pdf and answer_pdf are present.
    Missing either marks the Paper as 'incomplete' with the missing file
    types listed in missing_files.
    """
    library_root = _create_fake_tree(tmp_path, tree_spec)
    result = scan(library_root)

    for ps in result.paper_sets:
        for paper in ps.papers:
            files_spec = tree_spec[paper.exam_period][paper.set_index]
            has_paper_pdf = files_spec["paper_pdf"]
            has_answer_pdf = files_spec["answer_pdf"]

            if has_paper_pdf and has_answer_pdf:
                assert paper.status == PaperStatus.ok, (
                    f"Paper {paper.paper_id} should be 'ok' when both PDFs present"
                )
                assert paper.missing_files == []
            else:
                assert paper.status == PaperStatus.incomplete, (
                    f"Paper {paper.paper_id} should be 'incomplete' when files missing"
                )
                # Verify missing_files lists the correct types
                if not has_paper_pdf:
                    assert "真题 PDF" in paper.missing_files
                if not has_answer_pdf:
                    assert "答案解析 PDF" in paper.missing_files


@settings(
    max_examples=50,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
@given(tree_spec=fake_library_tree())
def test_scan_audio_status_reflects_mp3_presence(tmp_path: Path, tree_spec: dict) -> None:
    """Audio status accurately reflects MP3 file presence.

    **Validates: Requirements 1.6, 1.7**

    - If MP3 exists: audio_status == 'available'
    - If MP3 missing and paper is a known embedded case: 'embedded-in-paper'
    - Otherwise: 'missing'
    """
    library_root = _create_fake_tree(tmp_path, tree_spec)
    result = scan(library_root)

    # Known embedded cases per scanner implementation
    embedded_cases = {("2024-12", 3), ("2025-06", 3)}

    for ps in result.paper_sets:
        for paper in ps.papers:
            files_spec = tree_spec[paper.exam_period][paper.set_index]
            has_mp3 = files_spec["audio_mp3"]

            if has_mp3:
                assert paper.audio_status == AudioStatus.available, (
                    f"Paper {paper.paper_id}: MP3 exists, expected 'available'"
                )
            elif (paper.exam_period, paper.set_index) in embedded_cases:
                assert paper.audio_status == AudioStatus.embedded_in_paper, (
                    f"Paper {paper.paper_id}: known embedded case, expected 'embedded-in-paper'"
                )
            else:
                assert paper.audio_status == AudioStatus.missing, (
                    f"Paper {paper.paper_id}: no MP3, expected 'missing'"
                )


@settings(
    max_examples=50,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
@given(tree_spec=fake_library_tree())
def test_scan_paper_ids_are_unique_and_well_formed(tmp_path: Path, tree_spec: dict) -> None:
    """All 12 paper_ids are unique and follow the expected format.

    **Validates: Requirements 1.5, 1.6**
    """
    library_root = _create_fake_tree(tmp_path, tree_spec)
    result = scan(library_root)

    all_paper_ids: list[str] = []
    for ps in result.paper_sets:
        for paper in ps.papers:
            all_paper_ids.append(paper.paper_id)
            # Verify format: "{exam_period}-set{set_index}"
            assert paper.paper_id == f"{paper.exam_period}-set{paper.set_index}"

    # All IDs must be unique
    assert len(set(all_paper_ids)) == 12


@settings(
    max_examples=30,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
@given(tree_spec=fake_library_tree())
def test_scan_missing_files_precise(tmp_path: Path, tree_spec: dict) -> None:
    """Missing files list precisely identifies which files are absent.

    **Validates: Requirements 1.9**

    For incomplete papers, missing_files must contain exactly the file types
    that are not present on disk.
    """
    library_root = _create_fake_tree(tmp_path, tree_spec)
    result = scan(library_root)

    for ps in result.paper_sets:
        for paper in ps.papers:
            files_spec = tree_spec[paper.exam_period][paper.set_index]
            expected_missing: list[str] = []

            if not files_spec["paper_pdf"]:
                expected_missing.append("真题 PDF")
            if not files_spec["answer_pdf"]:
                expected_missing.append("答案解析 PDF")

            assert sorted(paper.missing_files) == sorted(expected_missing), (
                f"Paper {paper.paper_id}: expected missing={expected_missing}, "
                f"got {paper.missing_files}"
            )


# ---------------------------------------------------------------------------
# Property 2: 非法 Library_Root 被拒绝且原配置保留
# ---------------------------------------------------------------------------


@settings(
    max_examples=30,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
@given(
    path_suffix=st.text(
        alphabet=st.characters(
            whitelist_categories=("L", "N"),
            whitelist_characters="_-",
        ),
        min_size=1,
        max_size=30,
    )
)
def test_scan_rejects_nonexistent_path(tmp_path: Path, path_suffix: str) -> None:
    """Non-existent paths are rejected with kind='not-found'.

    **Validates: Requirements 1.3, 1.8**
    """
    nonexistent = tmp_path / f"does_not_exist_{path_suffix}"
    # Ensure it truly doesn't exist
    assume(not nonexistent.exists())

    with pytest.raises(LibraryRootError) as exc_info:
        scan(nonexistent)

    err = exc_info.value
    assert err.info.kind == "not-found"
    assert err.info.path == str(nonexistent)


@settings(
    max_examples=20,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
@given(
    content=st.binary(min_size=1, max_size=100),
)
def test_scan_rejects_file_as_library_root(tmp_path: Path, content: bytes) -> None:
    """Regular files (not directories) are rejected with kind='not-a-directory'.

    **Validates: Requirements 1.3, 1.8**
    """
    file_path = tmp_path / "not_a_dir.txt"
    file_path.write_bytes(content)

    with pytest.raises(LibraryRootError) as exc_info:
        scan(file_path)

    err = exc_info.value
    assert err.info.kind == "not-a-directory"
    assert err.info.path == str(file_path)


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="Windows permission model differs from POSIX",
)
def test_scan_rejects_unreadable_directory(tmp_path: Path) -> None:
    """Directories without read permission are rejected with kind='not-readable'.

    **Validates: Requirements 1.3, 1.8**

    Note: This test is skipped on Windows where permission semantics differ.
    """
    unreadable = tmp_path / "no_read"
    unreadable.mkdir()
    # Remove read permission
    unreadable.chmod(0o000)

    try:
        with pytest.raises(LibraryRootError) as exc_info:
            scan(unreadable)

        err = exc_info.value
        assert err.info.kind == "not-readable"
        assert err.info.path == str(unreadable)
    finally:
        # Restore permissions for cleanup
        unreadable.chmod(0o755)


def test_scan_error_contains_original_path(tmp_path: Path) -> None:
    """Error info preserves the exact path string that was submitted.

    **Validates: Requirements 1.3, 1.8**

    The UI needs to echo back the user's submitted path in the error message.
    """
    bad_path = tmp_path / "这是一个不存在的路径_with_unicode"

    with pytest.raises(LibraryRootError) as exc_info:
        scan(bad_path)

    assert exc_info.value.info.path == str(bad_path)


def test_scan_error_kind_is_valid_literal(tmp_path: Path) -> None:
    """Error kind is always one of the three valid LibraryRootErrorKind values.

    **Validates: Requirements 1.3, 1.8**
    """
    valid_kinds: set[LibraryRootErrorKind] = {"not-found", "not-readable", "not-a-directory"}

    # Test not-found
    bad_path = tmp_path / "nonexistent"
    with pytest.raises(LibraryRootError) as exc_info:
        scan(bad_path)
    assert exc_info.value.info.kind in valid_kinds

    # Test not-a-directory
    file_path = tmp_path / "a_file.txt"
    file_path.write_text("hello")
    with pytest.raises(LibraryRootError) as exc_info:
        scan(file_path)
    assert exc_info.value.info.kind in valid_kinds


# ---------------------------------------------------------------------------
# Additional integration-style property tests
# ---------------------------------------------------------------------------


def test_scan_empty_library_root_produces_all_incomplete(tmp_path: Path) -> None:
    """An empty library root (valid dir, no subdirs) produces 12 incomplete papers.

    **Validates: Requirements 1.10**
    """
    empty_root = tmp_path / "empty_cet4"
    empty_root.mkdir()

    result = scan(empty_root)

    assert len(result.paper_sets) == 4
    all_papers = [p for ps in result.paper_sets for p in ps.papers]
    assert len(all_papers) == 12

    # All papers should be incomplete since no files exist
    for paper in all_papers:
        assert paper.status == PaperStatus.incomplete
        assert "真题 PDF" in paper.missing_files
        assert "答案解析 PDF" in paper.missing_files


def test_scan_full_library_root_produces_all_ok(tmp_path: Path) -> None:
    """A fully populated library root produces 12 ok papers.

    **Validates: Requirements 1.5, 1.6, 1.10**
    """
    tree_spec = {}
    for _dir_name, exam_period in KNOWN_EXAM_PERIODS:
        tree_spec[exam_period] = {
            i: {"paper_pdf": True, "answer_pdf": True, "audio_mp3": True}
            for i in range(1, 4)
        }

    library_root = _create_fake_tree(tmp_path, tree_spec)
    result = scan(library_root)

    all_papers = [p for ps in result.paper_sets for p in ps.papers]
    assert len(all_papers) == 12

    for paper in all_papers:
        assert paper.status == PaperStatus.ok
        assert paper.audio_status == AudioStatus.available
        assert paper.missing_files == []


def test_scan_result_has_valid_duration(tmp_path: Path) -> None:
    """Scan result includes a non-negative duration_ms.

    **Validates: Requirements 1.1** (30-second SLA)
    """
    tree_spec = {}
    for _dir_name, exam_period in KNOWN_EXAM_PERIODS:
        tree_spec[exam_period] = {
            i: {"paper_pdf": False, "answer_pdf": False, "audio_mp3": False}
            for i in range(1, 4)
        }

    library_root = _create_fake_tree(tmp_path, tree_spec)
    result = scan(library_root)

    assert result.duration_ms >= 0
    # Should complete well within 30 seconds for a fake tree
    assert result.duration_ms < 30_000
