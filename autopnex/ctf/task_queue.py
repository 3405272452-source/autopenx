"""CTF Task Queue - distributes work across multiple agent workers.

A thread-safe task queue that supports:
* Task states: pending, leased, completed, failed, cancelled
* Lease timeout with automatic reclamation
* Bulk cancellation when a flag is found
* Priority ordering (flag-critical > exploit > recon)
"""
from __future__ import annotations

import logging
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

log = logging.getLogger("autopnex.ctf.task_queue")


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class CTFTask:
    """A unit of work dispatched to an agent worker."""

    id: str
    kind: str  # recon | exploit | analyze | verify | support
    route: str  # attack route or analysis target
    payload: Dict[str, Any]
    priority: int = 0  # higher = more urgent
    created_at: float = field(default_factory=time.time)
    leased_at: Optional[float] = None
    leased_by: Optional[str] = None  # worker/agent id
    completed_at: Optional[float] = None
    result: Optional[Dict[str, Any]] = None
    status: str = "pending"  # pending | leased | completed | failed | cancelled

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind,
            "route": self.route,
            "priority": self.priority,
            "status": self.status,
            "created_at": self.created_at,
            "leased_at": self.leased_at,
            "leased_by": self.leased_by,
            "completed_at": self.completed_at,
            "result": self.result,
        }


# ---------------------------------------------------------------------------
# TaskQueue
# ---------------------------------------------------------------------------

class TaskQueue:
    """Thread-safe task queue for CTF multi-agent coordination.

    Usage:
        q = TaskQueue()
        q.submit(kind="recon", route="source_hint", payload={"url": "..."})
        task = q.lease(worker_id="agent-1", lease_seconds=30)
        ...worker executes task...
        q.complete(task.id, result={"flag": "flag{...}"})
    """

    def __init__(self, default_lease_seconds: float = 60.0) -> None:
        self._lock = threading.RLock()
        self._tasks: Dict[str, CTFTask] = {}
        self._pending: List[str] = []  # ordered list of task ids
        self._default_lease_seconds = default_lease_seconds
        self._flag_found: Optional[str] = None
        self._cancelled = False

    # -- submission ---------------------------------------------------------

    def submit(
        self,
        kind: str,
        route: str,
        payload: Dict[str, Any],
        priority: int = 0,
        task_id: Optional[str] = None,
    ) -> str:
        """Submit a new task. Returns task id."""
        with self._lock:
            if self._cancelled:
                log.warning("Queue cancelled, dropping task %s/%s", kind, route)
                return ""

            tid = task_id or f"task-{uuid.uuid4().hex[:8]}"
            task = CTFTask(
                id=tid,
                kind=kind,
                route=route,
                payload=payload,
                priority=priority,
            )
            self._tasks[tid] = task
            self._insert_by_priority(tid)
            log.debug("Task submitted: %s (%s/%s, priority=%d)", tid, kind, route, priority)
            return tid

    def submit_many(self, tasks: List[Dict[str, Any]]) -> List[str]:
        """Batch submit tasks. Each dict must contain kind, route, payload."""
        ids: List[str] = []
        for t in tasks:
            ids.append(self.submit(
                kind=t["kind"],
                route=t["route"],
                payload=t["payload"],
                priority=t.get("priority", 0),
            ))
        return ids

    # -- leasing ------------------------------------------------------------

    def lease(
        self,
        worker_id: str,
        lease_seconds: Optional[float] = None,
        allowed_kinds: Optional[Set[str]] = None,
        allowed_routes: Optional[Set[str]] = None,
    ) -> Optional[CTFTask]:
        """Lease the highest-priority pending task to a worker.

        Returns None if no matching pending task is available.
        """
        with self._lock:
            if self._cancelled:
                return None

            self._reclaim_expired()

            for tid in list(self._pending):
                task = self._tasks.get(tid)
                if not task or task.status != "pending":
                    continue
                if allowed_kinds and task.kind not in allowed_kinds:
                    continue
                if allowed_routes and task.route not in allowed_routes:
                    continue

                # Lease it
                task.status = "leased"
                task.leased_at = time.time()
                task.leased_by = worker_id
                self._pending.remove(tid)
                log.debug("Task %s leased to %s", tid, worker_id)
                return task

            return None

    def extend_lease(self, task_id: str, extra_seconds: float) -> bool:
        """Extend a leased task's deadline."""
        with self._lock:
            task = self._tasks.get(task_id)
            if task and task.status == "leased" and task.leased_at:
                task.leased_at = time.time() + extra_seconds
                return True
            return False

    # -- completion ---------------------------------------------------------

    def complete(self, task_id: str, result: Optional[Dict[str, Any]] = None) -> bool:
        """Mark a task as completed."""
        with self._lock:
            task = self._tasks.get(task_id)
            if not task or task.status not in ("leased", "pending"):
                return False
            task.status = "completed"
            task.completed_at = time.time()
            task.result = result or {}
            # If result contains flag, propagate cancellation
            flag = self._extract_flag(result)
            if flag:
                self._flag_found = flag
                self._cancel_all("flag_found")
            log.debug("Task %s completed (flag=%s)", task_id, bool(flag))
            return True

    def fail(self, task_id: str, error: Optional[str] = None) -> bool:
        """Mark a task as failed."""
        with self._lock:
            task = self._tasks.get(task_id)
            if not task or task.status not in ("leased", "pending"):
                return False
            task.status = "failed"
            task.completed_at = time.time()
            task.result = {"error": error or "unknown"}
            log.debug("Task %s failed: %s", task_id, error)
            return True

    def cancel(self, task_id: str, reason: str = "") -> bool:
        """Cancel a single pending or leased task."""
        with self._lock:
            task = self._tasks.get(task_id)
            if not task or task.status not in ("pending", "leased"):
                return False
            task.status = "cancelled"
            task.result = {"cancelled": True, "reason": reason}
            if task.id in self._pending:
                self._pending.remove(task.id)
            log.debug("Task %s cancelled: %s", task_id, reason)
            return True

    def cancel_by_route(self, route: str, reason: str = "") -> int:
        """Cancel all pending/leased tasks for a given route."""
        with self._lock:
            count = 0
            for task in list(self._tasks.values()):
                if task.route == route and task.status in ("pending", "leased"):
                    self.cancel(task.id, reason)
                    count += 1
            return count

    def cancel_all(self, reason: str = "") -> int:
        """Cancel every pending/leased task."""
        with self._lock:
            return self._cancel_all(reason)

    # -- queries ------------------------------------------------------------

    @property
    def flag_found(self) -> Optional[str]:
        return self._flag_found

    @property
    def is_cancelled(self) -> bool:
        return self._cancelled

    def get_task(self, task_id: str) -> Optional[CTFTask]:
        with self._lock:
            return self._tasks.get(task_id)

    def pending_count(self) -> int:
        with self._lock:
            return sum(1 for t in self._tasks.values() if t.status == "pending")

    def leased_count(self) -> int:
        with self._lock:
            return sum(1 for t in self._tasks.values() if t.status == "leased")

    def counts(self) -> Dict[str, int]:
        with self._lock:
            counts: Dict[str, int] = {}
            for t in self._tasks.values():
                counts[t.status] = counts.get(t.status, 0) + 1
            return counts

    def list_tasks(
        self,
        status: Optional[str] = None,
        route: Optional[str] = None,
        kind: Optional[str] = None,
    ) -> List[CTFTask]:
        with self._lock:
            result: List[CTFTask] = []
            for t in self._tasks.values():
                if status and t.status != status:
                    continue
                if route and t.route != route:
                    continue
                if kind and t.kind != kind:
                    continue
                result.append(t)
            return result

    def get_summary(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "total": len(self._tasks),
                "pending": self.pending_count(),
                "leased": self.leased_count(),
                "completed": sum(1 for t in self._tasks.values() if t.status == "completed"),
                "failed": sum(1 for t in self._tasks.values() if t.status == "failed"),
                "cancelled": sum(1 for t in self._tasks.values() if t.status == "cancelled"),
                "flag_found": self._flag_found is not None,
                "flag": self._flag_found,
            }

    # -- internal helpers ---------------------------------------------------

    def _insert_by_priority(self, task_id: str) -> None:
        """Insert task id into _pending maintaining descending priority order."""
        task = self._tasks[task_id]
        inserted = False
        for i, existing_id in enumerate(self._pending):
            existing = self._tasks.get(existing_id)
            if existing and task.priority > existing.priority:
                self._pending.insert(i, task_id)
                inserted = True
                break
        if not inserted:
            self._pending.append(task_id)

    def _reclaim_expired(self) -> None:
        """Return expired leased tasks to pending."""
        now = time.time()
        timeout = self._default_lease_seconds
        for task in list(self._tasks.values()):
            if task.status == "leased" and task.leased_at:
                if now - task.leased_at > timeout:
                    log.warning("Task %s lease expired, reclaiming", task.id)
                    task.status = "pending"
                    task.leased_at = None
                    task.leased_by = None
                    self._insert_by_priority(task.id)

    def _cancel_all(self, reason: str) -> int:
        count = 0
        for task in list(self._tasks.values()):
            if task.status in ("pending", "leased"):
                task.status = "cancelled"
                task.result = {"cancelled": True, "reason": reason}
                if task.id in self._pending:
                    self._pending.remove(task.id)
                count += 1
        self._cancelled = True
        log.info("Cancelled %d tasks (%s)", count, reason)
        return count

    @staticmethod
    def _extract_flag(result: Optional[Dict[str, Any]]) -> Optional[str]:
        if not result:
            return None
        if result.get("flag"):
            return str(result["flag"])
        if result.get("success") and result.get("found_flag"):
            return str(result["found_flag"])
        return None
