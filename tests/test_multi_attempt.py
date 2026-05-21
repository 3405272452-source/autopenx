"""多尝试机制单元测试。

验证 MultiAttemptSolver 和 AttemptConfig 的核心功能，包括：
- AttemptConfig 默认值与自定义值 (Task 7.2)
- solve_with_retries() 多尝试循环 (Task 7.3)
- 环境重置逻辑 (Task 7.4)
- 温度调度策略与循环 (Task 7.5)
- 退避延迟机制 (Task 7.6)
"""
from __future__ import annotations

import asyncio
from typing import List, Optional
from unittest.mock import AsyncMock, patch, MagicMock

import pytest

from autopnex.ctf.models import CTFResult, ChallengeType
from autopnex.ctf.multi_attempt import AttemptConfig, MultiAttemptSolver


# ---------------------------------------------------------------------------
# Mock helpers
# ---------------------------------------------------------------------------


class MockController:
    """Mock CTFModeController with configurable solve() results and internal state."""

    def __init__(self, results: List[CTFResult]) -> None:
        self._results = list(results)
        self._call_count = 0

        # Internal state that _reset_environment should clear
        self._current_state: str = "INIT"
        self._steps_executed: int = 0
        self._start_time: Optional[float] = None
        self._total_steps: int = 0
        self._current_action: str = ""
        self._flags_found: List[str] = []

    async def solve(self) -> CTFResult:
        idx = min(self._call_count, len(self._results) - 1)
        result = self._results[idx]
        self._call_count += 1
        # Simulate state changes during solve
        self._current_state = "EXPLOIT"
        self._steps_executed += 1
        self._start_time = 1000.0
        self._current_action = "executing"
        return result


def failed_result(error: str = "max_attempts_exceeded") -> CTFResult:
    return CTFResult(success=False, error=error, steps_executed=1, total_duration_ms=100)


def success_result(flag: str = "flag{test}") -> CTFResult:
    return CTFResult(
        success=True,
        flag=flag,
        challenge_type=ChallengeType.WEB,
        steps_executed=3,
        total_duration_ms=500,
    )


# ---------------------------------------------------------------------------
# Task 7.2: AttemptConfig tests
# ---------------------------------------------------------------------------


class TestAttemptConfigDefaults:
    """Test AttemptConfig dataclass default values."""

    def test_default_max_attempts(self):
        """Default max_attempts is 10."""
        config = AttemptConfig()
        assert config.max_attempts == 10

    def test_default_temperature_schedule(self):
        """Default temperature_schedule is [0.3, 0.5, 0.7, 0.9, 1.0]."""
        config = AttemptConfig()
        assert config.temperature_schedule == [0.3, 0.5, 0.7, 0.9, 1.0]

    def test_default_reset_env_between_attempts(self):
        """Default reset_env_between_attempts is True."""
        config = AttemptConfig()
        assert config.reset_env_between_attempts is True

    def test_default_backoff_factor(self):
        """Default backoff_factor is 1.5."""
        config = AttemptConfig()
        assert config.backoff_factor == 1.5


class TestAttemptConfigCustomValues:
    """Test AttemptConfig with custom values."""

    def test_custom_max_attempts(self):
        """AttemptConfig accepts custom max_attempts."""
        config = AttemptConfig(max_attempts=5)
        assert config.max_attempts == 5

    def test_custom_temperature_schedule(self):
        """AttemptConfig accepts custom temperature_schedule."""
        config = AttemptConfig(temperature_schedule=[0.1, 0.4, 0.8])
        assert config.temperature_schedule == [0.1, 0.4, 0.8]

    def test_custom_reset_env_between_attempts(self):
        """AttemptConfig accepts custom reset_env_between_attempts."""
        config = AttemptConfig(reset_env_between_attempts=False)
        assert config.reset_env_between_attempts is False

    def test_custom_backoff_factor(self):
        """AttemptConfig accepts custom backoff_factor."""
        config = AttemptConfig(backoff_factor=2.0)
        assert config.backoff_factor == 2.0

    def test_all_custom_values(self):
        """AttemptConfig accepts all custom values together."""
        config = AttemptConfig(
            max_attempts=5,
            temperature_schedule=[0.1, 0.5, 1.0],
            reset_env_between_attempts=False,
            backoff_factor=2.0,
        )
        assert config.max_attempts == 5
        assert config.temperature_schedule == [0.1, 0.5, 1.0]
        assert config.reset_env_between_attempts is False
        assert config.backoff_factor == 2.0

    def test_backoff_factor_zero_is_valid(self):
        """backoff_factor=0 is valid (no delay)."""
        config = AttemptConfig(backoff_factor=0.0)
        assert config.backoff_factor == 0.0


class TestAttemptConfigValidation:
    """Test AttemptConfig validation rules."""

    def test_max_attempts_zero_raises(self):
        """max_attempts=0 raises ValueError."""
        with pytest.raises(ValueError, match="max_attempts 必须 >= 1"):
            AttemptConfig(max_attempts=0)

    def test_max_attempts_negative_raises(self):
        """Negative max_attempts raises ValueError."""
        with pytest.raises(ValueError, match="max_attempts 必须 >= 1"):
            AttemptConfig(max_attempts=-1)

    def test_empty_temperature_schedule_raises(self):
        """Empty temperature_schedule raises ValueError."""
        with pytest.raises(ValueError, match="temperature_schedule 不能为空"):
            AttemptConfig(temperature_schedule=[])

    def test_temperature_above_2_raises(self):
        """Temperature > 2.0 raises ValueError."""
        with pytest.raises(ValueError, match="temperature_schedule"):
            AttemptConfig(temperature_schedule=[0.0, 2.1])

    def test_negative_temperature_raises(self):
        """Negative temperature raises ValueError."""
        with pytest.raises(ValueError, match="temperature_schedule"):
            AttemptConfig(temperature_schedule=[-0.1])

    def test_negative_backoff_factor_raises(self):
        """Negative backoff_factor raises ValueError."""
        with pytest.raises(ValueError, match="backoff_factor 必须 >= 0.0"):
            AttemptConfig(backoff_factor=-1.0)


# ---------------------------------------------------------------------------
# Task 7.3: solve_with_retries() tests
# ---------------------------------------------------------------------------


class TestSolveWithRetries:
    """Test MultiAttemptSolver.solve_with_retries() multi-attempt loop."""

    @pytest.mark.asyncio
    async def test_returns_on_first_success(self):
        """Returns the first successful result immediately."""
        controller = MockController([
            failed_result(),
            success_result("flag{found}"),
        ])
        config = AttemptConfig(max_attempts=5, backoff_factor=0.0)
        solver = MultiAttemptSolver(config=config, controller=controller)

        result = await solver.solve_with_retries()

        assert result.success is True
        assert result.flag == "flag{found}"
        assert len(solver.attempt_results) == 2

    @pytest.mark.asyncio
    async def test_exhausts_all_attempts(self):
        """Returns last failure when all attempts are exhausted."""
        controller = MockController([
            failed_result("error_1"),
            failed_result("error_2"),
            failed_result("error_3"),
        ])
        config = AttemptConfig(max_attempts=3, backoff_factor=0.0)
        solver = MultiAttemptSolver(config=config, controller=controller)

        result = await solver.solve_with_retries()

        assert result.success is False
        assert result.error == "error_3"
        assert len(solver.attempt_results) == 3

    @pytest.mark.asyncio
    async def test_single_attempt_success(self):
        """Single attempt that succeeds returns immediately."""
        controller = MockController([success_result("flag{single}")])
        config = AttemptConfig(max_attempts=1, temperature_schedule=[0.5], backoff_factor=0.0)
        solver = MultiAttemptSolver(config=config, controller=controller)

        result = await solver.solve_with_retries()

        assert result.success is True
        assert result.flag == "flag{single}"
        assert len(solver.attempt_results) == 1

    @pytest.mark.asyncio
    async def test_single_attempt_failure(self):
        """Single attempt that fails returns failure."""
        controller = MockController([failed_result("only_error")])
        config = AttemptConfig(max_attempts=1, temperature_schedule=[0.5], backoff_factor=0.0)
        solver = MultiAttemptSolver(config=config, controller=controller)

        result = await solver.solve_with_retries()

        assert result.success is False
        assert result.error == "only_error"

    @pytest.mark.asyncio
    async def test_success_on_last_attempt(self):
        """Success on the last attempt is returned correctly."""
        controller = MockController([
            failed_result(),
            failed_result(),
            success_result("flag{last}"),
        ])
        config = AttemptConfig(max_attempts=3, backoff_factor=0.0)
        solver = MultiAttemptSolver(config=config, controller=controller)

        result = await solver.solve_with_retries()

        assert result.success is True
        assert result.flag == "flag{last}"
        assert len(solver.attempt_results) == 3

    @pytest.mark.asyncio
    async def test_attempt_results_accumulate(self):
        """attempt_results accumulates all completed attempt results."""
        controller = MockController([
            failed_result("e1"),
            failed_result("e2"),
            failed_result("e3"),
        ])
        config = AttemptConfig(max_attempts=3, backoff_factor=0.0)
        solver = MultiAttemptSolver(config=config, controller=controller)

        await solver.solve_with_retries()

        results = solver.attempt_results
        assert len(results) == 3
        assert results[0].error == "e1"
        assert results[1].error == "e2"
        assert results[2].error == "e3"

    @pytest.mark.asyncio
    async def test_attempt_results_is_copy(self):
        """attempt_results returns a copy, not the internal list."""
        controller = MockController([failed_result()])
        config = AttemptConfig(max_attempts=1, temperature_schedule=[0.5], backoff_factor=0.0)
        solver = MultiAttemptSolver(config=config, controller=controller)

        await solver.solve_with_retries()
        results = solver.attempt_results
        results.append(failed_result("injected"))

        # Internal list should not be modified
        assert len(solver.attempt_results) == 1

    @pytest.mark.asyncio
    async def test_handles_exception_in_solve(self):
        """Handles exceptions from controller.solve() gracefully."""

        class ExplodingController:
            _current_state = "INIT"
            _steps_executed = 0
            _start_time = None
            _total_steps = 0
            _current_action = ""
            _flags_found: List[str] = []

            async def solve(self) -> CTFResult:
                raise RuntimeError("connection lost")

        controller = ExplodingController()
        config = AttemptConfig(max_attempts=2, temperature_schedule=[0.5], backoff_factor=0.0)
        solver = MultiAttemptSolver(config=config, controller=controller)

        result = await solver.solve_with_retries()

        assert result.success is False
        assert "connection lost" in result.error


# ---------------------------------------------------------------------------
# Task 7.5: Temperature schedule cycling tests
# ---------------------------------------------------------------------------


class TestTemperatureSchedule:
    """Test _get_temperature() temperature scheduling with cycling."""

    def _make_solver(self, schedule: List[float]) -> MultiAttemptSolver:
        controller = MockController([failed_result()])
        config = AttemptConfig(
            max_attempts=10,
            temperature_schedule=schedule,
            backoff_factor=0.0,
        )
        return MultiAttemptSolver(config=config, controller=controller)

    def test_first_attempt_uses_first_temperature(self):
        """Attempt 0 uses temperature_schedule[0]."""
        solver = self._make_solver([0.3, 0.5, 0.7, 0.9, 1.0])
        assert solver._get_temperature(0) == 0.3

    def test_sequential_temperatures(self):
        """Sequential attempts use sequential temperatures."""
        solver = self._make_solver([0.3, 0.5, 0.7, 0.9, 1.0])
        assert solver._get_temperature(0) == 0.3
        assert solver._get_temperature(1) == 0.5
        assert solver._get_temperature(2) == 0.7
        assert solver._get_temperature(3) == 0.9
        assert solver._get_temperature(4) == 1.0

    def test_cycling_wraps_around(self):
        """Attempt index beyond schedule length wraps around (cycling)."""
        solver = self._make_solver([0.3, 0.5, 0.7])
        # Index 3 should cycle back to index 0
        assert solver._get_temperature(3) == 0.3
        assert solver._get_temperature(4) == 0.5
        assert solver._get_temperature(5) == 0.7
        assert solver._get_temperature(6) == 0.3

    def test_single_temperature_always_same(self):
        """Single-element schedule always returns the same temperature."""
        solver = self._make_solver([0.7])
        for i in range(10):
            assert solver._get_temperature(i) == 0.7

    def test_default_schedule_cycling(self):
        """Default schedule [0.3, 0.5, 0.7, 0.9, 1.0] cycles correctly."""
        controller = MockController([failed_result()])
        config = AttemptConfig(backoff_factor=0.0)
        solver = MultiAttemptSolver(config=config, controller=controller)

        assert solver._get_temperature(0) == 0.3
        assert solver._get_temperature(4) == 1.0
        assert solver._get_temperature(5) == 0.3  # cycles back
        assert solver._get_temperature(9) == 1.0


# ---------------------------------------------------------------------------
# Task 7.4: Environment reset tests
# ---------------------------------------------------------------------------


class TestEnvironmentReset:
    """Test _reset_environment() clears controller internal state."""

    def test_reset_clears_current_state(self):
        """_reset_environment() resets _current_state to 'INIT'."""
        controller = MockController([failed_result()])
        controller._current_state = "EXPLOIT"
        config = AttemptConfig(backoff_factor=0.0)
        solver = MultiAttemptSolver(config=config, controller=controller)

        solver._reset_environment()

        assert controller._current_state == "INIT"

    def test_reset_clears_steps_executed(self):
        """_reset_environment() resets _steps_executed to 0."""
        controller = MockController([failed_result()])
        controller._steps_executed = 5
        config = AttemptConfig(backoff_factor=0.0)
        solver = MultiAttemptSolver(config=config, controller=controller)

        solver._reset_environment()

        assert controller._steps_executed == 0

    def test_reset_clears_start_time(self):
        """_reset_environment() resets _start_time to None."""
        controller = MockController([failed_result()])
        controller._start_time = 12345.0
        config = AttemptConfig(backoff_factor=0.0)
        solver = MultiAttemptSolver(config=config, controller=controller)

        solver._reset_environment()

        assert controller._start_time is None

    def test_reset_clears_total_steps(self):
        """_reset_environment() resets _total_steps to 0."""
        controller = MockController([failed_result()])
        controller._total_steps = 10
        config = AttemptConfig(backoff_factor=0.0)
        solver = MultiAttemptSolver(config=config, controller=controller)

        solver._reset_environment()

        assert controller._total_steps == 0

    def test_reset_clears_current_action(self):
        """_reset_environment() resets _current_action to empty string."""
        controller = MockController([failed_result()])
        controller._current_action = "executing exploit"
        config = AttemptConfig(backoff_factor=0.0)
        solver = MultiAttemptSolver(config=config, controller=controller)

        solver._reset_environment()

        assert controller._current_action == ""

    def test_reset_clears_flags_found(self):
        """_reset_environment() clears _flags_found list."""
        controller = MockController([failed_result()])
        controller._flags_found = ["flag{old1}", "flag{old2}"]
        config = AttemptConfig(backoff_factor=0.0)
        solver = MultiAttemptSolver(config=config, controller=controller)

        solver._reset_environment()

        assert controller._flags_found == []

    @pytest.mark.asyncio
    async def test_reset_called_between_attempts(self):
        """Environment is reset between attempts when reset_env_between_attempts=True."""
        controller = MockController([failed_result(), failed_result()])
        config = AttemptConfig(
            max_attempts=2,
            reset_env_between_attempts=True,
            backoff_factor=0.0,
        )
        solver = MultiAttemptSolver(config=config, controller=controller)

        # Patch _reset_environment to track calls
        reset_calls = []
        original_reset = solver._reset_environment

        def tracking_reset():
            reset_calls.append(True)
            original_reset()

        solver._reset_environment = tracking_reset

        await solver.solve_with_retries()

        assert len(reset_calls) == 2  # Called before each attempt

    @pytest.mark.asyncio
    async def test_no_reset_when_disabled(self):
        """Environment is NOT reset when reset_env_between_attempts=False."""
        controller = MockController([failed_result(), failed_result()])
        config = AttemptConfig(
            max_attempts=2,
            reset_env_between_attempts=False,
            backoff_factor=0.0,
        )
        solver = MultiAttemptSolver(config=config, controller=controller)

        # Patch _reset_environment to track calls
        reset_calls = []
        original_reset = solver._reset_environment

        def tracking_reset():
            reset_calls.append(True)
            original_reset()

        solver._reset_environment = tracking_reset

        await solver.solve_with_retries()

        assert len(reset_calls) == 0  # Never called


# ---------------------------------------------------------------------------
# Task 7.6: Backoff timing tests (mock asyncio.sleep)
# ---------------------------------------------------------------------------


class TestBackoffTiming:
    """Test backoff delay mechanism between failed attempts."""

    @pytest.mark.asyncio
    async def test_backoff_delays_between_failures(self):
        """Backoff delays are applied between failed attempts."""
        controller = MockController([
            failed_result(),
            failed_result(),
            failed_result(),
        ])
        config = AttemptConfig(
            max_attempts=3,
            backoff_factor=1.5,
            temperature_schedule=[0.5],
        )
        solver = MultiAttemptSolver(config=config, controller=controller)

        with patch("autopnex.ctf.multi_attempt.asyncio.sleep", new_callable=AsyncMock) as mock_sleep:
            await solver.solve_with_retries()

            # After attempt 0 fails: delay = 1.5^0 = 1.0
            # After attempt 1 fails: delay = 1.5^1 = 1.5
            # After attempt 2 fails: no delay (last attempt)
            assert mock_sleep.call_count == 2
            mock_sleep.assert_any_call(1.0)   # 1.5^0
            mock_sleep.assert_any_call(1.5)   # 1.5^1

    @pytest.mark.asyncio
    async def test_no_backoff_after_success(self):
        """No backoff delay after a successful attempt."""
        controller = MockController([success_result()])
        config = AttemptConfig(
            max_attempts=3,
            backoff_factor=1.5,
            temperature_schedule=[0.5],
        )
        solver = MultiAttemptSolver(config=config, controller=controller)

        with patch("autopnex.ctf.multi_attempt.asyncio.sleep", new_callable=AsyncMock) as mock_sleep:
            await solver.solve_with_retries()

            mock_sleep.assert_not_called()

    @pytest.mark.asyncio
    async def test_no_backoff_when_factor_is_zero(self):
        """No backoff delay when backoff_factor is 0."""
        controller = MockController([
            failed_result(),
            failed_result(),
            failed_result(),
        ])
        config = AttemptConfig(
            max_attempts=3,
            backoff_factor=0.0,
            temperature_schedule=[0.5],
        )
        solver = MultiAttemptSolver(config=config, controller=controller)

        with patch("autopnex.ctf.multi_attempt.asyncio.sleep", new_callable=AsyncMock) as mock_sleep:
            await solver.solve_with_retries()

            mock_sleep.assert_not_called()

    @pytest.mark.asyncio
    async def test_backoff_exponential_growth(self):
        """Backoff delay grows exponentially with backoff_factor=2.0."""
        controller = MockController([
            failed_result(),
            failed_result(),
            failed_result(),
            failed_result(),
        ])
        config = AttemptConfig(
            max_attempts=4,
            backoff_factor=2.0,
            temperature_schedule=[0.5],
        )
        solver = MultiAttemptSolver(config=config, controller=controller)

        with patch("autopnex.ctf.multi_attempt.asyncio.sleep", new_callable=AsyncMock) as mock_sleep:
            await solver.solve_with_retries()

            # Delays: 2^0=1, 2^1=2, 2^2=4 (no delay after last)
            assert mock_sleep.call_count == 3
            calls = [c.args[0] for c in mock_sleep.call_args_list]
            assert calls == [1.0, 2.0, 4.0]

    @pytest.mark.asyncio
    async def test_no_backoff_after_last_failure(self):
        """No backoff delay after the last failed attempt."""
        controller = MockController([failed_result(), failed_result()])
        config = AttemptConfig(
            max_attempts=2,
            backoff_factor=1.5,
            temperature_schedule=[0.5],
        )
        solver = MultiAttemptSolver(config=config, controller=controller)

        with patch("autopnex.ctf.multi_attempt.asyncio.sleep", new_callable=AsyncMock) as mock_sleep:
            await solver.solve_with_retries()

            # Only 1 delay (after first failure, not after last)
            assert mock_sleep.call_count == 1
            mock_sleep.assert_called_once_with(1.0)  # 1.5^0
