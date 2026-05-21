"""Unit tests for FlagEngine.__init__() method."""
import pytest

from autopnex.ctf.flag_engine import FlagEngine


class TestFlagEngineInit:
    """Tests for FlagEngine initialization."""

    def test_default_formats_used_when_none(self):
        """When flag_formats is None, DEFAULT_FORMATS should be used."""
        engine = FlagEngine()
        assert engine._formats == FlagEngine.DEFAULT_FORMATS

    def test_default_formats_is_a_copy(self):
        """The instance _formats should be a copy, not a reference to the class constant."""
        engine = FlagEngine()
        engine._formats.append(("test", r"test\{[^}]+\}"))
        assert len(engine._formats) != len(FlagEngine.DEFAULT_FORMATS)

    def test_custom_formats_with_custom_names(self):
        """When flag_formats is provided, each gets name 'custom_N'."""
        patterns = [r"myctf\{[^}]+\}", r"team\{[^}]+\}"]
        engine = FlagEngine(flag_formats=patterns)
        assert engine._formats == [
            ("custom_0", r"myctf\{[^}]+\}"),
            ("custom_1", r"team\{[^}]+\}"),
        ]

    def test_empty_list_results_in_empty_formats(self):
        """When flag_formats is an empty list, _formats should be empty."""
        engine = FlagEngine(flag_formats=[])
        assert engine._formats == []

    def test_encoding_detection_default_true(self):
        """encoding_detection defaults to True."""
        engine = FlagEngine()
        assert engine._encoding_detection is True

    def test_encoding_detection_set_false(self):
        """encoding_detection can be set to False."""
        engine = FlagEngine(encoding_detection=False)
        assert engine._encoding_detection is False

    def test_invalid_regex_raises_value_error(self):
        """Invalid regex patterns should raise ValueError."""
        with pytest.raises(ValueError, match="无效的正则表达式"):
            FlagEngine(flag_formats=[r"[invalid("])

    def test_valid_regex_does_not_raise(self):
        """Valid regex patterns should not raise."""
        engine = FlagEngine(flag_formats=[r"flag\{[^}]+\}", r"\d+"])
        assert len(engine._formats) == 2

    def test_multiple_invalid_regex_raises_on_first(self):
        """If multiple invalid patterns, raises on the first invalid one."""
        with pytest.raises(ValueError):
            FlagEngine(flag_formats=[r"valid\{[^}]+\}", r"[bad(", r"also[bad"])

    def test_formats_stored_as_list_of_tuples(self):
        """_formats should be a list of (name, pattern) tuples."""
        engine = FlagEngine()
        for item in engine._formats:
            assert isinstance(item, tuple)
            assert len(item) == 2
            name, pattern = item
            assert isinstance(name, str)
            assert isinstance(pattern, str)
