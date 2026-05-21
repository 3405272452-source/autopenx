"""Unit tests for all CTF data models (Task 1.9)."""
import pytest
from pathlib import Path
from unittest.mock import patch

from autopnex.ctf.models import ChallengeType, ChallengeInput, ChallengeProfile


# --- ChallengeType Tests ---


class TestChallengeTypeValues:
    """Test ChallengeType enum values and membership."""

    def test_web_value(self):
        """ChallengeType.WEB has string value 'web'."""
        assert ChallengeType.WEB.value == "web"

    def test_pwn_value(self):
        """ChallengeType.PWN has string value 'pwn'."""
        assert ChallengeType.PWN.value == "pwn"

    def test_crypto_value(self):
        """ChallengeType.CRYPTO has string value 'crypto'."""
        assert ChallengeType.CRYPTO.value == "crypto"

    def test_misc_value(self):
        """ChallengeType.MISC has string value 'misc'."""
        assert ChallengeType.MISC.value == "misc"

    def test_reverse_value(self):
        """ChallengeType.REVERSE has string value 'reverse'."""
        assert ChallengeType.REVERSE.value == "reverse"

    def test_unknown_value(self):
        """ChallengeType.UNKNOWN has string value 'unknown'."""
        assert ChallengeType.UNKNOWN.value == "unknown"

    def test_total_member_count(self):
        """ChallengeType has exactly 6 members."""
        assert len(ChallengeType) == 6

    def test_all_values_are_strings(self):
        """All ChallengeType values are strings."""
        for ct in ChallengeType:
            assert isinstance(ct.value, str)

    def test_lookup_by_value(self):
        """ChallengeType members can be looked up by their string value."""
        assert ChallengeType("web") == ChallengeType.WEB
        assert ChallengeType("pwn") == ChallengeType.PWN
        assert ChallengeType("crypto") == ChallengeType.CRYPTO
        assert ChallengeType("misc") == ChallengeType.MISC
        assert ChallengeType("reverse") == ChallengeType.REVERSE
        assert ChallengeType("unknown") == ChallengeType.UNKNOWN

    def test_invalid_value_raises(self):
        """Looking up an invalid value raises ValueError."""
        with pytest.raises(ValueError):
            ChallengeType("invalid")

    def test_members_are_unique(self):
        """All ChallengeType values are unique."""
        values = [ct.value for ct in ChallengeType]
        assert len(values) == len(set(values))


# --- ChallengeInput Tests ---


class TestChallengeInputCreation:
    """Test ChallengeInput instantiation with valid data."""

    def test_minimal_creation(self):
        """ChallengeInput can be created with only target."""
        ci = ChallengeInput(target="http://example.com")
        assert ci.target == "http://example.com"
        assert ci.description == ""
        assert ci.challenge_type is None
        assert ci.flag_format == r"flag\{[^}]+\}"
        assert ci.attachments == []
        assert ci.hints == []
        assert ci.platform == ""
        assert ci.difficulty == ""

    def test_full_creation(self, tmp_path):
        """ChallengeInput can be created with all fields specified."""
        # Create a temporary attachment file
        attachment = tmp_path / "challenge.py"
        attachment.write_text("print('hello')")

        ci = ChallengeInput(
            target="http://ctf.example.com:8080",
            description="A web challenge with SQL injection",
            challenge_type="web",
            flag_format=r"CTF\{[^}]+\}",
            attachments=[attachment],
            hints=["Try SQL injection", "Check /admin"],
            platform="CTFd",
            difficulty="medium",
        )
        assert ci.target == "http://ctf.example.com:8080"
        assert ci.description == "A web challenge with SQL injection"
        assert ci.challenge_type == "web"
        assert ci.flag_format == r"CTF\{[^}]+\}"
        assert ci.attachments == [attachment]
        assert ci.hints == ["Try SQL injection", "Check /admin"]
        assert ci.platform == "CTFd"
        assert ci.difficulty == "medium"

    def test_target_with_port(self):
        """ChallengeInput accepts target with port number."""
        ci = ChallengeInput(target="nc challenge.ctf.com 9999")
        assert ci.target == "nc challenge.ctf.com 9999"

    def test_custom_flag_format(self):
        """ChallengeInput accepts custom flag format regex."""
        ci = ChallengeInput(target="http://x.com", flag_format=r"HCTF\{[a-z0-9_]+\}")
        assert ci.flag_format == r"HCTF\{[a-z0-9_]+\}"


class TestChallengeInputTargetValidation:
    """Test target field validation (cannot be empty)."""

    def test_empty_target_raises(self):
        """Empty string target raises ValueError."""
        with pytest.raises(ValueError, match="target"):
            ChallengeInput(target="")

    def test_whitespace_only_target_raises(self):
        """Whitespace-only target raises ValueError."""
        with pytest.raises(ValueError, match="target"):
            ChallengeInput(target="   ")

    def test_tab_only_target_raises(self):
        """Tab-only target raises ValueError."""
        with pytest.raises(ValueError, match="target"):
            ChallengeInput(target="\t\t")

    def test_newline_only_target_raises(self):
        """Newline-only target raises ValueError."""
        with pytest.raises(ValueError, match="target"):
            ChallengeInput(target="\n")


class TestChallengeInputFlagFormatValidation:
    """Test flag_format field validation (must be valid regex)."""

    def test_invalid_regex_raises(self):
        """Invalid regex pattern raises ValueError."""
        with pytest.raises(ValueError, match="flag_format"):
            ChallengeInput(target="http://x.com", flag_format="[invalid(")

    def test_unclosed_group_raises(self):
        """Unclosed group in regex raises ValueError."""
        with pytest.raises(ValueError, match="flag_format"):
            ChallengeInput(target="http://x.com", flag_format="(unclosed")

    def test_invalid_quantifier_raises(self):
        """Invalid quantifier in regex raises ValueError."""
        with pytest.raises(ValueError, match="flag_format"):
            ChallengeInput(target="http://x.com", flag_format="*invalid")

    def test_valid_complex_regex(self):
        """Complex but valid regex is accepted."""
        ci = ChallengeInput(
            target="http://x.com",
            flag_format=r"(?:flag|FLAG)\{[a-zA-Z0-9_\-!@#$%^&*()+=,./?]+\}",
        )
        assert ci.flag_format == r"(?:flag|FLAG)\{[a-zA-Z0-9_\-!@#$%^&*()+=,./?]+\}"


class TestChallengeInputAttachmentsValidation:
    """Test attachments field validation (paths must exist)."""

    def test_nonexistent_attachment_raises(self):
        """Non-existent attachment path raises ValueError."""
        with pytest.raises(ValueError, match="附件路径不存在"):
            ChallengeInput(
                target="http://x.com",
                attachments=[Path("/nonexistent/path/file.py")],
            )

    def test_valid_attachment(self, tmp_path):
        """Existing attachment path is accepted."""
        attachment = tmp_path / "source.py"
        attachment.write_text("# source code")
        ci = ChallengeInput(target="http://x.com", attachments=[attachment])
        assert ci.attachments == [attachment]

    def test_multiple_valid_attachments(self, tmp_path):
        """Multiple existing attachment paths are accepted."""
        f1 = tmp_path / "a.py"
        f2 = tmp_path / "b.bin"
        f1.write_text("code")
        f2.write_bytes(b"\x00\x01\x02")
        ci = ChallengeInput(target="http://x.com", attachments=[f1, f2])
        assert len(ci.attachments) == 2

    def test_one_invalid_among_valid_raises(self, tmp_path):
        """If one attachment doesn't exist among valid ones, raises ValueError."""
        valid = tmp_path / "valid.py"
        valid.write_text("ok")
        with pytest.raises(ValueError, match="附件路径不存在"):
            ChallengeInput(
                target="http://x.com",
                attachments=[valid, Path("/no/such/file.txt")],
            )


class TestChallengeInputListFieldIsolation:
    """Test that list fields use independent default instances."""

    def test_attachments_isolation(self):
        """Each instance gets its own attachments list."""
        c1 = ChallengeInput(target="http://a.com")
        c2 = ChallengeInput(target="http://b.com")
        # Don't append a real path since it would fail validation
        # Just verify they are different list objects
        assert c1.attachments is not c2.attachments

    def test_hints_isolation(self):
        """Each instance gets its own hints list."""
        c1 = ChallengeInput(target="http://a.com")
        c2 = ChallengeInput(target="http://b.com")
        c1.hints.append("hint1")
        assert c2.hints == []


# --- ChallengeProfile Tests ---


class TestChallengeProfileCreation:
    """Test ChallengeProfile instantiation with valid data."""

    def test_minimal_creation(self):
        """ChallengeProfile can be created with only challenge_type."""
        profile = ChallengeProfile(challenge_type=ChallengeType.WEB)
        assert profile.challenge_type == ChallengeType.WEB
        assert profile.sub_type == ""
        assert profile.tech_stack == []
        assert profile.potential_vulns == []
        assert profile.key_hints == []
        assert profile.confidence == 0.0
        assert profile.difficulty_estimate == "medium"
        assert profile.similar_challenges == []
        assert profile.raw_analysis == ""

    def test_full_creation(self):
        """ChallengeProfile can be created with all fields specified."""
        profile = ChallengeProfile(
            challenge_type=ChallengeType.CRYPTO,
            sub_type="Crypto-RSA",
            tech_stack=["Python", "SageMath"],
            potential_vulns=["small_e", "common_modulus"],
            key_hints=["e=3", "n is shared"],
            confidence=0.85,
            difficulty_estimate="hard",
            similar_challenges=["challenge_42", "challenge_99"],
            raw_analysis="LLM analysis text here",
        )
        assert profile.challenge_type == ChallengeType.CRYPTO
        assert profile.sub_type == "Crypto-RSA"
        assert profile.tech_stack == ["Python", "SageMath"]
        assert profile.potential_vulns == ["small_e", "common_modulus"]
        assert profile.key_hints == ["e=3", "n is shared"]
        assert profile.confidence == 0.85
        assert profile.difficulty_estimate == "hard"
        assert profile.similar_challenges == ["challenge_42", "challenge_99"]
        assert profile.raw_analysis == "LLM analysis text here"

    def test_all_challenge_types(self):
        """ChallengeProfile accepts all valid ChallengeType enum values."""
        for ct in ChallengeType:
            profile = ChallengeProfile(challenge_type=ct)
            assert profile.challenge_type == ct


class TestChallengeProfileConfidenceValidation:
    """Test confidence field validation (must be in [0.0, 1.0])."""

    def test_confidence_zero(self):
        """confidence=0.0 is valid (lower bound)."""
        profile = ChallengeProfile(challenge_type=ChallengeType.WEB, confidence=0.0)
        assert profile.confidence == 0.0

    def test_confidence_one(self):
        """confidence=1.0 is valid (upper bound)."""
        profile = ChallengeProfile(challenge_type=ChallengeType.WEB, confidence=1.0)
        assert profile.confidence == 1.0

    def test_confidence_mid(self):
        """confidence=0.5 is valid (mid range)."""
        profile = ChallengeProfile(challenge_type=ChallengeType.WEB, confidence=0.5)
        assert profile.confidence == 0.5

    def test_confidence_negative_raises(self):
        """Negative confidence raises ValueError."""
        with pytest.raises(ValueError, match="confidence"):
            ChallengeProfile(challenge_type=ChallengeType.WEB, confidence=-0.1)

    def test_confidence_above_one_raises(self):
        """confidence > 1.0 raises ValueError."""
        with pytest.raises(ValueError, match="confidence"):
            ChallengeProfile(challenge_type=ChallengeType.WEB, confidence=1.1)

    def test_confidence_large_negative_raises(self):
        """Large negative confidence raises ValueError."""
        with pytest.raises(ValueError, match="confidence"):
            ChallengeProfile(challenge_type=ChallengeType.WEB, confidence=-100.0)


class TestChallengeProfileTypeValidation:
    """Test challenge_type field validation (must be ChallengeType enum)."""

    def test_string_type_raises(self):
        """Passing a string instead of ChallengeType raises TypeError."""
        with pytest.raises(TypeError, match="challenge_type"):
            ChallengeProfile(challenge_type="web")  # type: ignore

    def test_int_type_raises(self):
        """Passing an int instead of ChallengeType raises TypeError."""
        with pytest.raises(TypeError, match="challenge_type"):
            ChallengeProfile(challenge_type=1)  # type: ignore

    def test_none_type_raises(self):
        """Passing None instead of ChallengeType raises TypeError."""
        with pytest.raises(TypeError, match="challenge_type"):
            ChallengeProfile(challenge_type=None)  # type: ignore


class TestChallengeProfileListFieldIsolation:
    """Test that list fields use independent default instances."""

    def test_tech_stack_isolation(self):
        """Each instance gets its own tech_stack list."""
        p1 = ChallengeProfile(challenge_type=ChallengeType.WEB)
        p2 = ChallengeProfile(challenge_type=ChallengeType.PWN)
        p1.tech_stack.append("PHP")
        assert p2.tech_stack == []

    def test_potential_vulns_isolation(self):
        """Each instance gets its own potential_vulns list."""
        p1 = ChallengeProfile(challenge_type=ChallengeType.WEB)
        p2 = ChallengeProfile(challenge_type=ChallengeType.WEB)
        p1.potential_vulns.append("SQLi")
        assert p2.potential_vulns == []

    def test_key_hints_isolation(self):
        """Each instance gets its own key_hints list."""
        p1 = ChallengeProfile(challenge_type=ChallengeType.WEB)
        p2 = ChallengeProfile(challenge_type=ChallengeType.WEB)
        p1.key_hints.append("hint1")
        assert p2.key_hints == []

    def test_similar_challenges_isolation(self):
        """Each instance gets its own similar_challenges list."""
        p1 = ChallengeProfile(challenge_type=ChallengeType.WEB)
        p2 = ChallengeProfile(challenge_type=ChallengeType.WEB)
        p1.similar_challenges.append("ch1")
        assert p2.similar_challenges == []


# --- FlagCandidate Tests (Task 1.5) ---

from datetime import datetime, timezone

from autopnex.ctf.models import FlagCandidate


class TestFlagCandidateCreation:
    """Test FlagCandidate instantiation with valid data."""

    def test_minimal_creation(self):
        """FlagCandidate can be created with only value and source."""
        candidate = FlagCandidate(value="flag{test}", source="text_scan")
        assert candidate.value == "flag{test}"
        assert candidate.source == "text_scan"
        assert candidate.confidence == 1.0
        assert candidate.encoding == "plaintext"
        assert candidate.context == ""
        assert candidate.timestamp  # auto-generated, non-empty

    def test_full_creation(self):
        """FlagCandidate can be created with all fields specified."""
        candidate = FlagCandidate(
            value="flag{full_test_2024}",
            source="base64_decode",
            confidence=0.9,
            encoding="base64",
            context="...found flag{full_test_2024} in response...",
            timestamp="2024-01-01T00:00:00+00:00",
        )
        assert candidate.value == "flag{full_test_2024}"
        assert candidate.source == "base64_decode"
        assert candidate.confidence == 0.9
        assert candidate.encoding == "base64"
        assert candidate.context == "...found flag{full_test_2024} in response..."
        assert candidate.timestamp == "2024-01-01T00:00:00+00:00"

    def test_default_confidence_is_one(self):
        """Default confidence is 1.0."""
        candidate = FlagCandidate(value="flag{x}", source="scan")
        assert candidate.confidence == 1.0

    def test_default_encoding_is_plaintext(self):
        """Default encoding is 'plaintext'."""
        candidate = FlagCandidate(value="flag{x}", source="scan")
        assert candidate.encoding == "plaintext"

    def test_timestamp_auto_generated(self):
        """Timestamp is auto-generated as a valid ISO format UTC string."""
        before = datetime.now(timezone.utc)
        candidate = FlagCandidate(value="flag{ts}", source="scan")
        after = datetime.now(timezone.utc)

        # Timestamp should be parseable as ISO format
        ts = datetime.fromisoformat(candidate.timestamp)
        assert before <= ts <= after


class TestFlagCandidateValueValidation:
    """Test value field validation (cannot be empty)."""

    def test_empty_string_raises(self):
        """Empty string value raises ValueError."""
        with pytest.raises(ValueError, match="value"):
            FlagCandidate(value="", source="scan")

    def test_whitespace_only_raises(self):
        """Whitespace-only value raises ValueError."""
        with pytest.raises(ValueError, match="value"):
            FlagCandidate(value="   ", source="scan")

    def test_tab_only_raises(self):
        """Tab-only value raises ValueError."""
        with pytest.raises(ValueError, match="value"):
            FlagCandidate(value="\t\t", source="scan")

    def test_newline_only_raises(self):
        """Newline-only value raises ValueError."""
        with pytest.raises(ValueError, match="value"):
            FlagCandidate(value="\n", source="scan")

    def test_valid_value_with_spaces(self):
        """Value with leading/trailing spaces but non-empty content is valid."""
        candidate = FlagCandidate(value=" flag{ok} ", source="scan")
        assert candidate.value == " flag{ok} "


class TestFlagCandidateConfidenceValidation:
    """Test confidence field validation (must be in [0.0, 1.0])."""

    def test_confidence_zero(self):
        """confidence=0.0 is valid (lower bound)."""
        candidate = FlagCandidate(value="flag{x}", source="s", confidence=0.0)
        assert candidate.confidence == 0.0

    def test_confidence_one(self):
        """confidence=1.0 is valid (upper bound)."""
        candidate = FlagCandidate(value="flag{x}", source="s", confidence=1.0)
        assert candidate.confidence == 1.0

    def test_confidence_mid(self):
        """confidence=0.5 is valid (mid range)."""
        candidate = FlagCandidate(value="flag{x}", source="s", confidence=0.5)
        assert candidate.confidence == 0.5

    def test_confidence_negative_raises(self):
        """Negative confidence raises ValueError."""
        with pytest.raises(ValueError, match="confidence"):
            FlagCandidate(value="flag{x}", source="s", confidence=-0.1)

    def test_confidence_above_one_raises(self):
        """confidence > 1.0 raises ValueError."""
        with pytest.raises(ValueError, match="confidence"):
            FlagCandidate(value="flag{x}", source="s", confidence=1.01)

    def test_confidence_large_negative_raises(self):
        """Large negative confidence raises ValueError."""
        with pytest.raises(ValueError, match="confidence"):
            FlagCandidate(value="flag{x}", source="s", confidence=-50.0)

    def test_confidence_large_positive_raises(self):
        """Large positive confidence raises ValueError."""
        with pytest.raises(ValueError, match="confidence"):
            FlagCandidate(value="flag{x}", source="s", confidence=100.0)


class TestFlagCandidateFieldIndependence:
    """Test that instances have independent field values."""

    def test_timestamp_differs_between_instances(self):
        """Each instance gets its own timestamp (not shared)."""
        c1 = FlagCandidate(value="flag{a}", source="s1")
        c2 = FlagCandidate(value="flag{b}", source="s2")
        # Both should have timestamps, they may or may not differ
        # depending on timing, but they should be independent strings
        assert isinstance(c1.timestamp, str)
        assert isinstance(c2.timestamp, str)

    def test_modifying_one_does_not_affect_other(self):
        """Modifying fields on one instance doesn't affect another."""
        c1 = FlagCandidate(value="flag{a}", source="s1")
        c2 = FlagCandidate(value="flag{b}", source="s2")
        c1.context = "modified"
        assert c2.context == ""


# --- AttackStep Tests (Task 1.6) ---

from autopnex.ctf.models import AttackStep, AttackPlan


class TestAttackStepCreation:
    """Test AttackStep instantiation with valid data."""

    def test_minimal_creation(self):
        """AttackStep can be created with only step_id and tool."""
        step = AttackStep(step_id=1, tool="nmap")
        assert step.step_id == 1
        assert step.tool == "nmap"
        assert step.arguments == {}
        assert step.description == ""
        assert step.expected_outcome == ""
        assert step.depends_on == []
        assert step.priority == 0

    def test_full_creation(self):
        """AttackStep can be created with all fields specified."""
        step = AttackStep(
            step_id=3,
            tool="sqlmap",
            arguments={"url": "http://target.com/login", "param": "id"},
            description="SQL injection on login page",
            expected_outcome="Database dump with flag",
            depends_on=[1, 2],
            priority=5,
        )
        assert step.step_id == 3
        assert step.tool == "sqlmap"
        assert step.arguments == {"url": "http://target.com/login", "param": "id"}
        assert step.description == "SQL injection on login page"
        assert step.expected_outcome == "Database dump with flag"
        assert step.depends_on == [1, 2]
        assert step.priority == 5


class TestAttackStepToolValidation:
    """Test tool field validation (cannot be empty)."""

    def test_empty_tool_raises(self):
        """Empty string tool raises ValueError."""
        with pytest.raises(ValueError, match="tool"):
            AttackStep(step_id=1, tool="")

    def test_whitespace_only_tool_raises(self):
        """Whitespace-only tool raises ValueError."""
        with pytest.raises(ValueError, match="tool"):
            AttackStep(step_id=1, tool="   ")

    def test_tab_only_tool_raises(self):
        """Tab-only tool raises ValueError."""
        with pytest.raises(ValueError, match="tool"):
            AttackStep(step_id=1, tool="\t")

    def test_valid_tool_with_spaces(self):
        """Tool with leading/trailing spaces but non-empty content is valid."""
        step = AttackStep(step_id=1, tool=" nmap ")
        assert step.tool == " nmap "


class TestAttackStepListFieldIsolation:
    """Test that list/dict fields use independent default instances."""

    def test_arguments_isolation(self):
        """Each instance gets its own arguments dict."""
        s1 = AttackStep(step_id=1, tool="nmap")
        s2 = AttackStep(step_id=2, tool="dirb")
        s1.arguments["port"] = 80
        assert s2.arguments == {}

    def test_depends_on_isolation(self):
        """Each instance gets its own depends_on list."""
        s1 = AttackStep(step_id=1, tool="nmap")
        s2 = AttackStep(step_id=2, tool="dirb")
        s1.depends_on.append(0)
        assert s2.depends_on == []


class TestAttackPlanCreation:
    """Test AttackPlan instantiation with valid data."""

    def test_empty_creation(self):
        """AttackPlan can be created with no arguments (all defaults)."""
        plan = AttackPlan()
        assert plan.steps == []
        assert plan.reasoning == ""
        assert plan.estimated_difficulty == "medium"
        assert plan.fallback_strategies == []

    def test_full_creation(self):
        """AttackPlan can be created with all fields specified."""
        steps = [
            AttackStep(step_id=1, tool="nmap", description="Port scan"),
            AttackStep(step_id=2, tool="sqlmap", depends_on=[1]),
        ]
        plan = AttackPlan(
            steps=steps,
            reasoning="Target is a web app, try SQL injection",
            estimated_difficulty="hard",
            fallback_strategies=["Try XSS", "Try LFI"],
        )
        assert len(plan.steps) == 2
        assert plan.reasoning == "Target is a web app, try SQL injection"
        assert plan.estimated_difficulty == "hard"
        assert plan.fallback_strategies == ["Try XSS", "Try LFI"]


class TestAttackPlanIsEmpty:
    """Test AttackPlan.is_empty() method."""

    def test_empty_plan(self):
        """is_empty() returns True when steps list is empty."""
        plan = AttackPlan()
        assert plan.is_empty() is True

    def test_non_empty_plan(self):
        """is_empty() returns False when steps list has items."""
        plan = AttackPlan(steps=[AttackStep(step_id=1, tool="nmap")])
        assert plan.is_empty() is False

    def test_after_clearing_steps(self):
        """is_empty() returns True after clearing steps."""
        plan = AttackPlan(steps=[AttackStep(step_id=1, tool="nmap")])
        plan.steps.clear()
        assert plan.is_empty() is True


class TestAttackPlanNextStep:
    """Test AttackPlan.next_step() method."""

    def test_next_step_empty_history(self):
        """next_step returns first step when history is empty."""
        steps = [
            AttackStep(step_id=1, tool="nmap"),
            AttackStep(step_id=2, tool="sqlmap"),
        ]
        plan = AttackPlan(steps=steps)
        result = plan.next_step([])
        assert result is not None
        assert result.step_id == 1

    def test_next_step_partial_history(self):
        """next_step skips already executed steps."""
        steps = [
            AttackStep(step_id=1, tool="nmap"),
            AttackStep(step_id=2, tool="sqlmap"),
            AttackStep(step_id=3, tool="dirb"),
        ]
        plan = AttackPlan(steps=steps)
        result = plan.next_step([1])
        assert result is not None
        assert result.step_id == 2

    def test_next_step_all_executed(self):
        """next_step returns None when all steps are executed."""
        steps = [
            AttackStep(step_id=1, tool="nmap"),
            AttackStep(step_id=2, tool="sqlmap"),
        ]
        plan = AttackPlan(steps=steps)
        result = plan.next_step([1, 2])
        assert result is None

    def test_next_step_non_sequential_history(self):
        """next_step works with non-sequential execution history."""
        steps = [
            AttackStep(step_id=1, tool="nmap"),
            AttackStep(step_id=2, tool="sqlmap"),
            AttackStep(step_id=3, tool="dirb"),
        ]
        plan = AttackPlan(steps=steps)
        # Step 1 and 3 executed, step 2 should be next
        result = plan.next_step([1, 3])
        assert result is not None
        assert result.step_id == 2

    def test_next_step_empty_plan(self):
        """next_step returns None for an empty plan."""
        plan = AttackPlan()
        result = plan.next_step([])
        assert result is None

    def test_next_step_with_duplicate_history(self):
        """next_step handles duplicate IDs in history gracefully."""
        steps = [
            AttackStep(step_id=1, tool="nmap"),
            AttackStep(step_id=2, tool="sqlmap"),
        ]
        plan = AttackPlan(steps=steps)
        result = plan.next_step([1, 1, 1])
        assert result is not None
        assert result.step_id == 2


class TestAttackPlanListFieldIsolation:
    """Test that list fields use independent default instances."""

    def test_steps_isolation(self):
        """Each instance gets its own steps list."""
        p1 = AttackPlan()
        p2 = AttackPlan()
        p1.steps.append(AttackStep(step_id=1, tool="nmap"))
        assert p2.steps == []

    def test_fallback_strategies_isolation(self):
        """Each instance gets its own fallback_strategies list."""
        p1 = AttackPlan()
        p2 = AttackPlan()
        p1.fallback_strategies.append("Try XSS")
        assert p2.fallback_strategies == []


# --- CTFResult Tests (Task 1.7) ---

from autopnex.ctf.models import CTFResult, CTFProgress


class TestCTFResultCreation:
    """Test CTFResult instantiation with valid data."""

    def test_minimal_success(self):
        """CTFResult can be created with only success=True."""
        result = CTFResult(success=True)
        assert result.success is True
        assert result.flag is None
        assert result.challenge_type is None
        assert result.steps_executed == 0
        assert result.total_duration_ms == 0
        assert result.strategy_used == ""
        assert result.vulnerabilities_found == []
        assert result.error is None
        assert result.solve_log == []

    def test_minimal_failure(self):
        """CTFResult can be created with success=False."""
        result = CTFResult(success=False)
        assert result.success is False

    def test_full_creation(self):
        """CTFResult can be created with all fields specified."""
        result = CTFResult(
            success=True,
            flag="flag{test_flag_2024}",
            challenge_type=ChallengeType.WEB,
            steps_executed=5,
            total_duration_ms=12000,
            strategy_used="SQL injection on login page",
            vulnerabilities_found=["SQLi", "LFI"],
            error=None,
            solve_log=[
                {"tool": "nmap", "success": True, "duration_ms": 2000},
                {"tool": "sqlmap", "success": True, "duration_ms": 5000},
            ],
        )
        assert result.success is True
        assert result.flag == "flag{test_flag_2024}"
        assert result.challenge_type == ChallengeType.WEB
        assert result.steps_executed == 5
        assert result.total_duration_ms == 12000
        assert result.strategy_used == "SQL injection on login page"
        assert result.vulnerabilities_found == ["SQLi", "LFI"]
        assert result.error is None
        assert len(result.solve_log) == 2

    def test_failure_with_error(self):
        """CTFResult failure includes error message."""
        result = CTFResult(
            success=False,
            error="timeout",
            steps_executed=3,
            total_duration_ms=600000,
        )
        assert result.success is False
        assert result.error == "timeout"
        assert result.steps_executed == 3
        assert result.total_duration_ms == 600000


class TestCTFResultValidation:
    """Test CTFResult field validation."""

    def test_steps_executed_zero(self):
        """steps_executed=0 is valid (lower bound)."""
        result = CTFResult(success=False, steps_executed=0)
        assert result.steps_executed == 0

    def test_steps_executed_positive(self):
        """Positive steps_executed is valid."""
        result = CTFResult(success=True, steps_executed=100)
        assert result.steps_executed == 100

    def test_steps_executed_negative_raises(self):
        """Negative steps_executed raises ValueError."""
        with pytest.raises(ValueError, match="steps_executed"):
            CTFResult(success=False, steps_executed=-1)

    def test_total_duration_ms_zero(self):
        """total_duration_ms=0 is valid (lower bound)."""
        result = CTFResult(success=False, total_duration_ms=0)
        assert result.total_duration_ms == 0

    def test_total_duration_ms_positive(self):
        """Positive total_duration_ms is valid."""
        result = CTFResult(success=True, total_duration_ms=999999)
        assert result.total_duration_ms == 999999

    def test_total_duration_ms_negative_raises(self):
        """Negative total_duration_ms raises ValueError."""
        with pytest.raises(ValueError, match="total_duration_ms"):
            CTFResult(success=False, total_duration_ms=-100)


class TestCTFResultListFieldIsolation:
    """Test that list fields use independent default instances."""

    def test_vulnerabilities_found_isolation(self):
        """Each instance gets its own vulnerabilities_found list."""
        r1 = CTFResult(success=True)
        r2 = CTFResult(success=True)
        r1.vulnerabilities_found.append("SQLi")
        assert r2.vulnerabilities_found == []

    def test_solve_log_isolation(self):
        """Each instance gets its own solve_log list."""
        r1 = CTFResult(success=True)
        r2 = CTFResult(success=True)
        r1.solve_log.append({"tool": "nmap"})
        assert r2.solve_log == []


# --- CTFProgress Tests (Task 1.7) ---


class TestCTFProgressCreation:
    """Test CTFProgress instantiation with valid data."""

    def test_minimal_creation(self):
        """CTFProgress can be created with required fields only."""
        progress = CTFProgress(state="ANALYZE", step=1, total_steps=5)
        assert progress.state == "ANALYZE"
        assert progress.step == 1
        assert progress.total_steps == 5
        assert progress.current_action == ""
        assert progress.flags_found == []
        assert progress.elapsed_ms == 0

    def test_full_creation(self):
        """CTFProgress can be created with all fields specified."""
        progress = CTFProgress(
            state="EXPLOIT",
            step=3,
            total_steps=7,
            current_action="Executing SQL injection payload",
            flags_found=["flag{partial_1}"],
            elapsed_ms=45000,
        )
        assert progress.state == "EXPLOIT"
        assert progress.step == 3
        assert progress.total_steps == 7
        assert progress.current_action == "Executing SQL injection payload"
        assert progress.flags_found == ["flag{partial_1}"]
        assert progress.elapsed_ms == 45000

    def test_zero_step_and_total(self):
        """step=0 and total_steps=0 are valid (initial state)."""
        progress = CTFProgress(state="INIT", step=0, total_steps=0)
        assert progress.step == 0
        assert progress.total_steps == 0


class TestCTFProgressValidation:
    """Test CTFProgress field validation."""

    def test_step_negative_raises(self):
        """Negative step raises ValueError."""
        with pytest.raises(ValueError, match="step"):
            CTFProgress(state="ANALYZE", step=-1, total_steps=5)

    def test_total_steps_negative_raises(self):
        """Negative total_steps raises ValueError."""
        with pytest.raises(ValueError, match="total_steps"):
            CTFProgress(state="ANALYZE", step=0, total_steps=-1)

    def test_elapsed_ms_negative_raises(self):
        """Negative elapsed_ms raises ValueError."""
        with pytest.raises(ValueError, match="elapsed_ms"):
            CTFProgress(state="ANALYZE", step=0, total_steps=5, elapsed_ms=-100)

    def test_elapsed_ms_zero(self):
        """elapsed_ms=0 is valid (lower bound)."""
        progress = CTFProgress(state="INIT", step=0, total_steps=0, elapsed_ms=0)
        assert progress.elapsed_ms == 0

    def test_elapsed_ms_positive(self):
        """Positive elapsed_ms is valid."""
        progress = CTFProgress(state="EXPLOIT", step=2, total_steps=5, elapsed_ms=30000)
        assert progress.elapsed_ms == 30000


class TestCTFProgressListFieldIsolation:
    """Test that list fields use independent default instances."""

    def test_flags_found_isolation(self):
        """Each instance gets its own flags_found list."""
        p1 = CTFProgress(state="EXPLOIT", step=1, total_steps=5)
        p2 = CTFProgress(state="EXPLOIT", step=2, total_steps=5)
        p1.flags_found.append("flag{a}")
        assert p2.flags_found == []


# --- StepResult Tests (Task 1.8) ---

from autopnex.ctf.models import StepResult


class TestStepResultCreation:
    """Test StepResult instantiation with valid data."""

    def test_minimal_creation(self):
        """StepResult can be created with only success and tool."""
        result = StepResult(success=True, tool="nmap")
        assert result.success is True
        assert result.tool == "nmap"
        assert result.arguments == {}
        assert result.output == ""
        assert result.duration_ms == 0
        assert result.error is None

    def test_full_creation(self):
        """StepResult can be created with all fields specified."""
        result = StepResult(
            success=True,
            tool="sqlmap",
            arguments={"url": "http://target.com", "param": "id"},
            output="Database dumped successfully\nflag{sql_injection_2024}",
            duration_ms=5000,
            error=None,
        )
        assert result.success is True
        assert result.tool == "sqlmap"
        assert result.arguments == {"url": "http://target.com", "param": "id"}
        assert result.output == "Database dumped successfully\nflag{sql_injection_2024}"
        assert result.duration_ms == 5000
        assert result.error is None

    def test_failure_with_error(self):
        """StepResult failure includes error message."""
        result = StepResult(
            success=False,
            tool="dirb",
            output="",
            duration_ms=1200,
            error="Connection refused",
        )
        assert result.success is False
        assert result.tool == "dirb"
        assert result.error == "Connection refused"
        assert result.duration_ms == 1200

    def test_success_false_no_error(self):
        """StepResult can have success=False without an error message."""
        result = StepResult(success=False, tool="nmap")
        assert result.success is False
        assert result.error is None


class TestStepResultDurationValidation:
    """Test duration_ms field validation (must be >= 0)."""

    def test_duration_ms_zero(self):
        """duration_ms=0 is valid (lower bound)."""
        result = StepResult(success=True, tool="nmap", duration_ms=0)
        assert result.duration_ms == 0

    def test_duration_ms_positive(self):
        """Positive duration_ms is valid."""
        result = StepResult(success=True, tool="nmap", duration_ms=99999)
        assert result.duration_ms == 99999

    def test_duration_ms_negative_raises(self):
        """Negative duration_ms raises ValueError."""
        with pytest.raises(ValueError, match="duration_ms"):
            StepResult(success=True, tool="nmap", duration_ms=-1)

    def test_duration_ms_large_negative_raises(self):
        """Large negative duration_ms raises ValueError."""
        with pytest.raises(ValueError, match="duration_ms"):
            StepResult(success=True, tool="nmap", duration_ms=-10000)


class TestStepResultFieldIsolation:
    """Test that dict fields use independent default instances."""

    def test_arguments_isolation(self):
        """Each instance gets its own arguments dict."""
        r1 = StepResult(success=True, tool="nmap")
        r2 = StepResult(success=True, tool="dirb")
        r1.arguments["port"] = 80
        assert r2.arguments == {}

    def test_modifying_one_does_not_affect_other(self):
        """Modifying fields on one instance doesn't affect another."""
        r1 = StepResult(success=True, tool="nmap")
        r2 = StepResult(success=True, tool="nmap")
        r1.output = "modified"
        assert r2.output == ""
