from __future__ import annotations

import json
import tempfile
from pathlib import Path

from autopnex.ctf.shared_journal import (
    AttemptRecord,
    BlockerRecord,
    EvidenceCard,
    HypothesisRecord,
    SharedJournal,
)


class TestSharedJournal:
    def test_session_dir_created(self):
        with tempfile.TemporaryDirectory() as tmp:
            journal = SharedJournal(tmp, session_id="abc123")
            assert (Path(tmp) / "shared").exists()
            assert journal.session_id == "abc123"

    def test_log_attempt(self):
        with tempfile.TemporaryDirectory() as tmp:
            journal = SharedJournal(tmp)
            record = AttemptRecord(
                iteration=1,
                tool="http_request",
                args_hash="deadbeef",
                route="lfi",
                success=True,
                result_preview="200 OK",
                new_info=True,
            )
            journal.log_attempt(record)
            attempts = journal.attempts
            assert len(attempts) == 1
            assert attempts[0].tool == "http_request"

    def test_log_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            journal = SharedJournal(tmp)
            card = EvidenceCard(
                id="e1",
                source="http_response",
                agent="web",
                route="sqli",
                summary="SQL error leaked",
                evidence="syntax error near '",
                confidence=0.85,
                next_action="try UNION SELECT",
            )
            journal.log_evidence(card)
            assert len(journal.evidence_cards) == 1
            assert journal.evidence_cards[0].confidence == 0.85

    def test_log_blocker(self):
        with tempfile.TemporaryDirectory() as tmp:
            journal = SharedJournal(tmp)
            blocker = BlockerRecord(
                id="b1",
                description="Route exhausted",
                route="lfi",
                evidence="no flag after 5 attempts",
                severity="route",
            )
            journal.log_blocker(blocker)
            assert len(journal.blockers) == 1
            assert journal.blockers[0].severity == "route"

    def test_build_critic_context(self):
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
            ctx = journal.build_critic_context()
            assert "审查上下文" in ctx
            assert "JWT found" in ctx

    def test_persists_to_disk(self):
        with tempfile.TemporaryDirectory() as tmp:
            journal = SharedJournal(tmp)
            journal.log_attempt(
                AttemptRecord(
                    iteration=1,
                    tool="scan_flag",
                    args_hash="hash",
                    route="source_hint",
                    success=True,
                    result_preview="no flag",
                    new_info=False,
                )
            )
            assert (Path(tmp) / "shared" / "attempts.jsonl").exists()
            lines = (Path(tmp) / "shared" / "attempts.jsonl").read_text().strip().split("\n")
            assert len(lines) == 1
            data = json.loads(lines[0])
            assert data["tool"] == "scan_flag"
