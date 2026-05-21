from __future__ import annotations

import tempfile

from autopnex.ctf.fuse_controller import FuseController, FuseDecision
from autopnex.ctf.shared_journal import SharedJournal
from autopnex.ctf.strategy import StrategyEngine


class TestFuseController:
    def test_no_fuse_on_empty(self):
        fuse = FuseController()
        strategy = StrategyEngine()
        with tempfile.TemporaryDirectory() as tmp:
            journal = SharedJournal(tmp)
            decision = fuse.check(strategy, journal, iteration=1)
            assert decision.level == "none"

    def test_repeat_action_soft_fuse(self):
        fuse = FuseController(repeat_threshold=2)
        strategy = StrategyEngine()
        with tempfile.TemporaryDirectory() as tmp:
            journal = SharedJournal(tmp)
            args = {"url": "http://example.com", "method": "GET"}

            fuse.check(strategy, journal, tool_name="http_request", tool_args=args, iteration=1)
            decision = fuse.check(strategy, journal, tool_name="http_request", tool_args=args, iteration=2)
            assert decision.level == "soft"
            assert decision.fuse_type == "repeat_action"

    def test_route_budget_fuse(self):
        fuse = FuseController()
        strategy = StrategyEngine(helper_budget_per_route=1)
        with tempfile.TemporaryDirectory() as tmp:
            journal = SharedJournal(tmp)
            strategy.set_route("lfi")
            # Exhaust route budget
            strategy._routes["lfi"].attempts = 1
            strategy._routes["lfi"].exhausted = True
            decision = fuse.check(strategy, journal)
            assert decision.level == "route"
            assert decision.fuse_type == "route_budget"

    def test_all_routes_exhausted_hard_fuse(self):
        from autopnex.ctf.strategy import RouteBudget
        fuse = FuseController()
        strategy = StrategyEngine(helper_budget_per_route=1)
        # Exhaust every default route
        for route in strategy.DEFAULT_WEB_ROUTES:
            budget = RouteBudget(route_id=route, max_attempts=1)
            budget.attempts = 1
            budget.exhausted = True
            strategy._routes[route] = budget
        strategy.set_route("lfi")
        with tempfile.TemporaryDirectory() as tmp:
            journal = SharedJournal(tmp)
            decision = fuse.check(strategy, journal)
            assert decision.level == "hard"

    def test_error_pattern_fuse(self):
        fuse = FuseController(error_repeat_limit=2, repeat_threshold=10)
        strategy = StrategyEngine()
        with tempfile.TemporaryDirectory() as tmp:
            journal = SharedJournal(tmp)

            class MockResult:
                error_type = "network"
                raw_output = {"x": 1}

            fuse.check(strategy, journal, action_result=MockResult())
            MockResult.raw_output = {"x": 2}
            decision = fuse.check(strategy, journal, action_result=MockResult())
            assert decision.level == "route"
            assert decision.fuse_type == "error_pattern"

    def test_apply_to_journal(self):
        fuse = FuseController()
        strategy = StrategyEngine()
        with tempfile.TemporaryDirectory() as tmp:
            journal = SharedJournal(tmp)
            decision = FuseDecision(
                level="route",
                fuse_type="route_budget",
                reason="exhausted",
                route_id="lfi",
                suggestion="switch",
            )
            fuse.apply_to_journal(decision, journal, strategy)
            assert len(journal.blockers) == 1
            assert journal.blockers[0].severity == "route"
