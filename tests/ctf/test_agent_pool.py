from __future__ import annotations

from autopnex.ctf.agent_pool import AgentPool
from autopnex.ctf.task_queue import TaskQueue


class TestAgentPool:
    def test_register_and_retire(self):
        q = TaskQueue()
        pool = AgentPool(q)
        wid = pool.register(role="recon")
        assert wid.startswith("recon-")
        assert pool.get_worker(wid).role == "recon"
        assert pool.retire(wid)
        assert pool.get_worker(wid).status == "retired"

    def test_claim_and_complete_task(self):
        q = TaskQueue()
        pool = AgentPool(q)
        wid = pool.register(role="exploit")
        tid = q.submit(kind="exploit", route="lfi", payload={})

        task = pool.claim_task(wid, allowed_kinds={"exploit"})
        assert task is not None
        assert task.id == tid
        assert pool.get_worker(wid).status == "working"

        ok = pool.complete_task(wid, tid, result={"found": True})
        assert ok
        assert pool.get_worker(wid).status == "idle"
        assert pool.get_worker(wid).tasks_completed == 1

    def test_workers_by_role(self):
        q = TaskQueue()
        pool = AgentPool(q)
        r1 = pool.register(role="recon")
        r2 = pool.register(role="recon")
        e1 = pool.register(role="exploit")
        assert len(pool.workers_by_role("recon")) == 2
        assert len(pool.workers_by_role("exploit")) == 1

    def test_resource_locks(self):
        q = TaskQueue()
        pool = AgentPool(q)
        w1 = pool.register(role="exploit")
        w2 = pool.register(role="exploit")

        assert pool.acquire_lock("target_write_lock", w1, blocking=True, timeout=1)
        assert pool.get_worker(w1).locks_held == {"target_write_lock"}
        # Second worker should not acquire immediately
        assert not pool.acquire_lock("target_write_lock", w2, blocking=True, timeout=0.1)

        assert pool.release_lock("target_write_lock", w1)
        assert pool.get_worker(w1).locks_held == set()

    def test_llm_and_tool_semaphores(self):
        q = TaskQueue()
        pool = AgentPool(q, max_llm_workers=1, max_tool_workers=1)
        w1 = pool.register(role="exploit")
        w2 = pool.register(role="exploit")

        assert pool.acquire_llm(w1, blocking=True, timeout=1)
        assert not pool.acquire_llm(w2, blocking=True, timeout=0.1)
        pool.release_llm(w1)
        assert pool.acquire_llm(w2, blocking=True, timeout=1)
        pool.release_llm(w2)

    def test_stale_worker_detection(self):
        q = TaskQueue()
        pool = AgentPool(q, heartbeat_timeout=0.01)
        w1 = pool.register(role="recon")
        import time
        time.sleep(0.02)
        stale = pool.check_stale_workers()
        assert w1 in stale
        assert pool.get_worker(w1).status == "stalled"

    def test_summary(self):
        q = TaskQueue()
        pool = AgentPool(q)
        pool.register(role="recon")
        pool.register(role="exploit")
        summary = pool.get_summary()
        assert summary["total_workers"] == 2
        assert summary["active"] == 2
