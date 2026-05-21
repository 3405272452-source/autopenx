from __future__ import annotations

import tempfile

from autopnex.ctf.consensus import Consensus
from autopnex.ctf.shared_journal import EvidenceCard, SharedJournal
from autopnex.ctf.task_queue import TaskQueue


class TestConsensus:
    def test_empty_decision(self):
        q = TaskQueue()
        c = Consensus(q)
        decision = c.decide()
        assert decision.verdict == "continue"
        assert decision.confidence == 0.0

    def test_flag_found_verdict(self):
        q = TaskQueue()
        c = Consensus(q)
        c.ingest(
            worker_id="w1",
            role="exploit",
            task_id="t1",
            result={"flag": "flag{test}"},
            confidence=1.0,
        )
        decision = c.decide()
        assert decision.verdict == "flag_found"
        assert decision.flag == "flag{test}"
        assert decision.primary_worker == "w1"

    def test_verified_flag(self):
        q = TaskQueue()
        c = Consensus(q)
        c.ingest(
            worker_id="w1",
            role="exploit",
            task_id="t1",
            result={"flag": "flag{same}"},
            confidence=1.0,
        )
        c.ingest(
            worker_id="w2",
            role="support",
            task_id="t2",
            result={"found_flag": "flag{same}"},
            confidence=0.95,
        )
        decision = c.decide()
        assert decision.verdict == "verified_flag"
        assert decision.flag == "flag{same}"

    def test_evidence_verdict(self):
        q = TaskQueue()
        with tempfile.TemporaryDirectory() as tmp:
            journal = SharedJournal(tmp)
            c = Consensus(q, shared_journal=journal)
            c.ingest(
                worker_id="w1",
                role="recon",
                task_id="t1",
                result={"evidence_score": 0.8},
                evidence=[
                    EvidenceCard(
                        id="e1",
                        source="body",
                        agent="web",
                        route="jwt",
                        summary="JWT found",
                        evidence="eyJ...",
                        confidence=0.85,
                        next_action="decode",
                    ),
                ],
                confidence=0.8,
            )
            decision = c.decide()
            assert decision.verdict == "evidence"
            assert decision.confidence == 0.8
            assert decision.primary_worker == "w1"

    def test_route_suggestion(self):
        q = TaskQueue()
        c = Consensus(q)
        c.ingest(
            worker_id="w1",
            role="recon",
            task_id="t1",
            result={"new_route": "idor"},
            confidence=0.5,
        )
        decision = c.decide()
        assert decision.verdict == "route_suggestion"
        assert "idor" in decision.next_action

    def test_blocker_verdict(self):
        q = TaskQueue()
        c = Consensus(q)
        c.ingest(
            worker_id="w1",
            role="exploit",
            task_id="t1",
            result={"blocker": "WAF blocked all payloads"},
            confidence=0.2,
        )
        c.ingest(
            worker_id="w2",
            role="exploit",
            task_id="t2",
            result={"blocker": "rate limit exceeded"},
            confidence=0.2,
        )
        decision = c.decide()
        assert decision.verdict == "blocker"
        assert len(decision.blockers) == 2

    def test_ingest_from_queue(self):
        q = TaskQueue()
        c = Consensus(q)
        t1 = q.submit(kind="exploit", route="lfi", payload={})
        q.lease(worker_id="w1")
        q.complete(t1, result={"flag": "flag{from_queue}"})

        ingested = c.ingest_from_queue()
        assert ingested == 1
        decision = c.decide()
        assert decision.verdict == "flag_found"
        assert decision.flag == "flag{from_queue}"

    def test_reset(self):
        q = TaskQueue()
        c = Consensus(q)
        c.ingest(
            worker_id="w1",
            role="exploit",
            task_id="t1",
            result={"flag": "flag{test}"},
            confidence=1.0,
        )
        c.reset()
        decision = c.decide()
        assert decision.verdict == "continue"
