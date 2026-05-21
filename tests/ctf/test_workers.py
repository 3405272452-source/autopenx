"""Tests for Phase 6 multi-agent workers."""
from __future__ import annotations

import time
from pathlib import Path
from typing import Any, Dict, Optional
from unittest.mock import MagicMock

import pytest

from autopnex.ctf.agent_pool import AgentPool
from autopnex.ctf.critic import Critic
from autopnex.ctf.fuse_controller import FuseController
from autopnex.ctf.shared_journal import SharedJournal
from autopnex.ctf.strategy import StrategyEngine
from autopnex.ctf.task_queue import TaskQueue
from autopnex.ctf.tool_router import ToolRouter
from autopnex.ctf.workers import (
    BaseCTFWorker,
    CriticWorker,
    ReconWorker,
    ReverseCryptoWorker,
    WebExploitWorker,
    WorkerContext,
)


@pytest.fixture
def mock_tool_router() -> MagicMock:
    router = MagicMock(spec=ToolRouter)
    router.execute.return_value = {}
    return router


@pytest.fixture
def mock_flag_engine() -> MagicMock:
    import re
    from autopnex.ctf.models import FlagCandidate

    engine = MagicMock()

    def _scan(text: str):
        matches = re.findall(r"flag\{[^}]+\}", text or "")
        if matches:
            return [
                FlagCandidate(
                    value=m,
                    source="mock",
                    confidence=1.0,
                    encoding="plaintext",
                    context="",
                )
                for m in matches
            ]
        return []

    engine.scan.side_effect = _scan
    return engine


@pytest.fixture
def worker_ctx(mock_tool_router: MagicMock, mock_flag_engine: MagicMock, tmp_path: Path) -> WorkerContext:
    journal = SharedJournal(str(tmp_path / "journal"), session_id="test")
    strategy = StrategyEngine()
    session = MagicMock()
    return WorkerContext(
        target="http://localhost:5000",
        session=session,
        tool_router=mock_tool_router,
        journal=journal,
        strategy=strategy,
        flag_engine=mock_flag_engine,
        runtime_config=MagicMock(),
        critic=None,
        fuse=None,
    )


@pytest.fixture
def agent_pool_and_queue():
    queue = TaskQueue()
    pool = AgentPool(task_queue=queue, max_llm_workers=1, max_tool_workers=2)
    return pool, queue


# ---------------------------------------------------------------------------
# Base / lifecycle
# ---------------------------------------------------------------------------

def test_worker_starts_and_stops(agent_pool_and_queue, worker_ctx):
    pool, queue = agent_pool_and_queue
    wid = pool.register(role="recon")
    worker = ReconWorker(wid, "recon", pool, queue, worker_ctx, poll_interval=0.1)
    worker.start()
    assert worker.is_alive()
    worker.stop(timeout=1.0)
    assert not worker.is_alive()


def test_recon_worker_claims_and_executes_task(agent_pool_and_queue, worker_ctx, mock_tool_router):
    pool, queue = agent_pool_and_queue
    mock_tool_router.execute.return_value = {
        "body": '<form action="/login"><input name="user"></form>',
        "status_code": 200,
        "headers": {"Server": "nginx"},
    }
    wid = pool.register(role="recon")
    worker = ReconWorker(wid, "recon", pool, queue, worker_ctx, poll_interval=0.1)
    worker.start()

    tid = queue.submit(
        kind="recon",
        route="initial_probe",
        payload={"url": "http://localhost:5000", "method": "GET"},
        priority=10,
    )

    # Wait for worker to pick up the task
    for _ in range(50):
        task = queue.get_task(tid)
        if task and task.status == "completed":
            break
        time.sleep(0.05)

    worker.stop(timeout=1.0)

    task = queue.get_task(tid)
    assert task is not None
    assert task.status == "completed"
    result = task.result or {}
    assert result.get("has_forms") is True
    assert result.get("status_code") == 200


def test_web_exploit_worker_executes_payload(agent_pool_and_queue, worker_ctx, mock_tool_router):
    pool, queue = agent_pool_and_queue
    mock_tool_router.execute.return_value = {
        "body": "flag{worker_found_it}",
        "status_code": 200,
    }
    wid = pool.register(role="exploit")
    worker = WebExploitWorker(wid, "exploit", pool, queue, worker_ctx, poll_interval=0.1)
    worker.start()

    tid = queue.submit(
        kind="exploit",
        route="lfi",
        payload={"url": "http://localhost:5000/?page=flag", "method": "GET"},
        priority=10,
    )

    for _ in range(50):
        task = queue.get_task(tid)
        if task and task.status == "completed":
            break
        time.sleep(0.05)

    worker.stop(timeout=1.0)

    task = queue.get_task(tid)
    assert task is not None
    assert task.status == "completed"
    result = task.result or {}
    assert result.get("flag") == "flag{worker_found_it}"


def test_reverse_crypto_worker_analyzes_file(agent_pool_and_queue, worker_ctx, mock_tool_router, tmp_path: Path):
    pool, queue = agent_pool_and_queue
    # file_analyze returns some metadata
    mock_tool_router.execute.side_effect = lambda name, args: {
        "file_analyze": {"mime": "application/x-elf", "size": 1024},
        "run_python": {"stdout": '{"strings": "flag{in_strings}"}', "stderr": ""},
    }.get(name, {})

    wid = pool.register(role="support")
    worker = ReverseCryptoWorker(wid, "support", pool, queue, worker_ctx, poll_interval=0.1)
    worker.start()

    tid = queue.submit(
        kind="support",
        route="file_analysis",
        payload={"file_path": str(tmp_path / "fake.bin")},
        priority=5,
    )

    for _ in range(50):
        task = queue.get_task(tid)
        if task and task.status == "completed":
            break
        time.sleep(0.05)

    worker.stop(timeout=1.0)

    task = queue.get_task(tid)
    assert task is not None
    assert task.status == "completed"
    result = task.result or {}
    # Should contain file_analysis key
    assert "file_analysis" in result


def test_consensus_ingests_worker_output(agent_pool_and_queue, worker_ctx, mock_tool_router):
    pool, queue = agent_pool_and_queue
    mock_tool_router.execute.return_value = {
        "body": "flag{consensus_test}",
        "status_code": 200,
    }
    wid = pool.register(role="exploit")
    worker = WebExploitWorker(wid, "exploit", pool, queue, worker_ctx, poll_interval=0.1)
    worker.start()

    tid = queue.submit(
        kind="exploit",
        route="sqli",
        payload={"url": "http://localhost:5000/?id=1", "method": "GET"},
        priority=10,
    )

    # Wait for completion
    for _ in range(50):
        task = queue.get_task(tid)
        if task and task.status == "completed":
            break
        time.sleep(0.05)

    worker.stop(timeout=1.0)

    # Now ingest into consensus
    from autopnex.ctf.consensus import Consensus
    consensus = Consensus(task_queue=queue, shared_journal=worker_ctx.journal)
    ingested = consensus.ingest_from_queue()
    assert ingested >= 1

    decision = consensus.decide()
    assert decision.verdict == "flag_found"
    assert decision.flag == "flag{consensus_test}"


def test_critic_worker_runs_review(agent_pool_and_queue, worker_ctx, mock_tool_router):
    pool, queue = agent_pool_and_queue
    # Wire up real Critic + Fuse so review can execute
    worker_ctx.critic = Critic()
    worker_ctx.fuse = FuseController()
    # Seed journal with an attempt so critic has something to review
    worker_ctx.journal.log_timeline("test attempt")

    wid = pool.register(role="critic")
    worker = CriticWorker(wid, "critic", pool, queue, worker_ctx, poll_interval=0.1)
    worker.start()

    tid = queue.submit(
        kind="critic",
        route="review",
        payload={},
        priority=3,
    )

    for _ in range(50):
        task = queue.get_task(tid)
        if task and task.status == "completed":
            break
        time.sleep(0.05)

    worker.stop(timeout=1.0)

    task = queue.get_task(tid)
    assert task is not None
    assert task.status == "completed"
    result = task.result or {}
    # CriticReview fields
    assert "most_likely_route" in result
    assert "recommended_next_action" in result
