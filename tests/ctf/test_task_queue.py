from __future__ import annotations

from autopnex.ctf.task_queue import CTFTask, TaskQueue


class TestTaskQueue:
    def test_submit_and_lease(self):
        q = TaskQueue()
        tid = q.submit(kind="recon", route="source_hint", payload={"url": "http://test"})
        assert tid
        assert q.pending_count() == 1

        task = q.lease(worker_id="w1")
        assert task is not None
        assert task.status == "leased"
        assert task.leased_by == "w1"
        assert q.pending_count() == 0
        assert q.leased_count() == 1

    def test_complete_with_flag_cancels_all(self):
        q = TaskQueue()
        t1 = q.submit(kind="exploit", route="lfi", payload={"path": "/flag"})
        t2 = q.submit(kind="recon", route="sqli", payload={"q": "test"})

        ok = q.complete(t1, result={"flag": "flag{found}"})
        assert ok
        assert q.flag_found == "flag{found}"
        assert q.is_cancelled
        assert q.get_task(t2).status == "cancelled"

    def test_priority_ordering(self):
        q = TaskQueue()
        low = q.submit(kind="recon", route="brute_force", payload={}, priority=1)
        high = q.submit(kind="exploit", route="lfi", payload={}, priority=10)
        mid = q.submit(kind="exploit", route="sqli", payload={}, priority=5)

        first = q.lease(worker_id="w1")
        assert first.id == high
        second = q.lease(worker_id="w1")
        assert second.id == mid
        third = q.lease(worker_id="w1")
        assert third.id == low

    def test_cancel_by_route(self):
        q = TaskQueue()
        q.submit(kind="exploit", route="lfi", payload={})
        q.submit(kind="exploit", route="lfi", payload={})
        q.submit(kind="recon", route="sqli", payload={})

        count = q.cancel_by_route("lfi", reason="pivoting")
        assert count == 2
        assert q.pending_count() == 1

    def test_fail_task(self):
        q = TaskQueue()
        tid = q.submit(kind="exploit", route="lfi", payload={})
        q.lease(worker_id="w1")
        ok = q.fail(tid, error="timeout")
        assert ok
        task = q.get_task(tid)
        assert task.status == "failed"
        assert task.result["error"] == "timeout"

    def test_summary(self):
        q = TaskQueue()
        t1 = q.submit(kind="recon", route="a", payload={})
        t2 = q.submit(kind="exploit", route="b", payload={})
        q.lease(worker_id="w1")
        q.complete(t2)
        summary = q.get_summary()
        assert summary["total"] == 2
        assert summary["pending"] == 0
        assert summary["leased"] == 1  # t1 still leased
        assert summary["completed"] == 1
