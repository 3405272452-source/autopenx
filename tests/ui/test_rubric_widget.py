"""Tests for RubricWidget — four-dimension scoring button group.

Requirements: 7.1, 7.6
"""

from __future__ import annotations

import pytest
from PySide6.QtCore import Qt

from cet4_app.ui.widgets.rubric_widget import RubricWidget


@pytest.fixture()
def widget(qtbot):
    """Create a RubricWidget for testing."""
    w = RubricWidget()
    qtbot.addWidget(w)
    w.show()
    return w


class TestRubricWidget:
    """Unit tests for RubricWidget."""

    def test_initial_state_incomplete(self, widget: RubricWidget):
        """Widget starts with no scores selected."""
        assert widget.get_scores() is None
        assert widget.is_complete() is False

    def test_set_scores_programmatically(self, widget: RubricWidget):
        """set_scores fills all dimensions and makes widget complete."""
        scores = {"content": 4, "structure": 3, "language": 5, "word_count": 2}
        widget.set_scores(scores)
        assert widget.is_complete() is True
        assert widget.get_scores() == scores

    def test_partial_scores_not_complete(self, widget: RubricWidget):
        """Widget is not complete if only some dimensions are scored."""
        widget.set_scores({"content": 3, "structure": 2})
        assert widget.is_complete() is False
        assert widget.get_scores() is None

    def test_clear_all_resets(self, widget: RubricWidget):
        """clear_all removes all selections."""
        widget.set_scores({"content": 4, "structure": 3, "language": 5, "word_count": 2})
        assert widget.is_complete() is True
        widget.clear_all()
        assert widget.is_complete() is False
        assert widget.get_scores() is None

    def test_score_changed_signal(self, widget: RubricWidget, qtbot):
        """score_changed signal is emitted when a dimension is scored."""
        with qtbot.waitSignal(widget.score_changed, timeout=1000) as blocker:
            widget.set_scores({"content": 3})
        assert blocker.args == ["content", 3]

    def test_all_scored_signal(self, widget: RubricWidget, qtbot):
        """all_scored signal is emitted when all dimensions are filled."""
        # Set first 3 dimensions without triggering all_scored
        widget.set_scores({"content": 4, "structure": 3, "language": 5})
        assert widget.is_complete() is False

        # Setting the last dimension should trigger all_scored
        with qtbot.waitSignal(widget.all_scored, timeout=1000) as blocker:
            widget.set_scores({"word_count": 2})
        expected = {"content": 4, "structure": 3, "language": 5, "word_count": 2}
        assert blocker.args == [expected]

    def test_score_range_0_to_5(self, widget: RubricWidget):
        """Each dimension accepts values 0 through 5."""
        for score in range(6):
            widget.set_scores({"content": score})
            # After setting, the row should reflect the score
            row = widget._rows["content"]
            assert row.selected_score == score

    def test_overwrite_score(self, widget: RubricWidget):
        """Setting a new score for a dimension overwrites the previous one."""
        widget.set_scores({"content": 2})
        assert widget._rows["content"].selected_score == 2
        widget.set_scores({"content": 5})
        assert widget._rows["content"].selected_score == 5

    def test_four_dimensions_present(self, widget: RubricWidget):
        """Widget has exactly four dimension rows."""
        assert len(widget._rows) == 4
        assert set(widget._rows.keys()) == {"content", "structure", "language", "word_count"}
