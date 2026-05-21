from __future__ import annotations

import tempfile

from autopnex.ctf.critic import Critic
from autopnex.ctf.fuse_controller import FuseController
from autopnex.ctf.shared_journal import EvidenceCard, SharedJournal
from autopnex.ctf.strategy import StrategyEngine


class TestCritic:
    def test_review_empty_session(self):
        critic = Critic()
        strategy = StrategyEngine()
        fuse = FuseController()
        with tempfile.TemporaryDirectory() as tmp:
            journal = SharedJournal(tmp)
            review = critic.review(journal, strategy, fuse)
            assert review.recommended_next_action
            assert review.confidence >= 0.0

    def test_detect_stuck(self):
        critic = Critic()
        strategy = StrategyEngine()
        fuse = FuseController()
        with tempfile.TemporaryDirectory() as tmp:
            journal = SharedJournal(tmp)
            # Simulate 6 attempts with no new info
            from autopnex.ctf.shared_journal import AttemptRecord
            for i in range(6):
                journal.log_attempt(
                    AttemptRecord(
                        iteration=i + 1,
                        tool="http_request",
                        args_hash=f"hash{i}",
                        route="lfi",
                        success=True,
                        result_preview="404",
                        new_info=False,
                    )
                )
            review = critic.review(journal, strategy, fuse)
            assert review.is_stuck
            assert "切换" in review.recommended_next_action or "终止" in review.recommended_next_action

    def test_pick_best_route(self):
        critic = Critic()
        strategy = StrategyEngine()
        fuse = FuseController()
        with tempfile.TemporaryDirectory() as tmp:
            journal = SharedJournal(tmp)
            journal.log_evidence(
                EvidenceCard(
                    id="e1",
                    source="body",
                    agent="web",
                    route="jwt",
                    summary="JWT found",
                    evidence="eyJ...",
                    confidence=0.9,
                    next_action="decode",
                )
            )
            journal.log_evidence(
                EvidenceCard(
                    id="e2",
                    source="body",
                    agent="web",
                    route="lfi",
                    summary="nothing",
                    evidence="",
                    confidence=0.1,
                    next_action="",
                )
            )
            review = critic.review(journal, strategy, fuse)
            assert review.most_likely_route == "jwt"

    def test_write_to_journal(self):
        critic = Critic()
        strategy = StrategyEngine()
        fuse = FuseController()
        with tempfile.TemporaryDirectory() as tmp:
            journal = SharedJournal(tmp)
            review = critic.review(journal, strategy, fuse)
            critic.write_to_journal(review, journal)
            assert len(journal.hypotheses) >= 1
            assert (Path(tmp) / "shared" / "next_actions.md").exists()


from pathlib import Path
