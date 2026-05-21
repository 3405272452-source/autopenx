"""CTF Agent Pool - manages multi-worker agent lifecycle and concurrency.

Provides:
* Worker role registration (recon / exploit / support / coordinator)
* LLM concurrency control
* Tool concurrency control
* Resource locks (target writes, cookies, uploads, routes)
* Worker lifecycle (register, heartbeat, retire)
"""
from __future__ import annotations

import logging
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

from .task_queue import CTFTask, TaskQueue

log = logging.getLogger("autopnex.ctf.agent_pool")


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class WorkerState:
    """Runtime state of a single agent worker."""

    worker_id: str
    role: str  # recon | exploit | support | coordinator | critic
    status: str = "idle"  # idle | working | stalled | retired
    current_task: Optional[str] = None
    last_heartbeat: float = field(default_factory=time.time)
    tasks_completed: int = 0
    tasks_failed: int = 0
    llm_calls: int = 0
    tool_calls: int = 0
    locks_held: Set[str] = field(default_factory=set)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "worker_id": self.worker_id,
            "role": self.role,
            "status": self.status,
            "current_task": self.current_task,
            "tasks_completed": self.tasks_completed,
            "tasks_failed": self.tasks_failed,
            "llm_calls": self.llm_calls,
            "tool_calls": self.tool_calls,
            "locks_held": sorted(self.locks_held),
        }


# ---------------------------------------------------------------------------
# Concurrency locks
# ---------------------------------------------------------------------------

class ResourceLocks:
    """Named resource locks for CTF target operations.

    Prevents race conditions when multiple workers interact with:
    * The same target endpoint (writes)
    * Session cookies (authentication state)
    * File uploads
    * Attack route selection
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._locks: Dict[str, threading.Lock] = {}
        self._holders: Dict[str, str] = {}  # lock_name -> worker_id

    def acquire(self, name: str, worker_id: str, blocking: bool = True, timeout: float = -1) -> bool:
        """Acquire a named lock on behalf of a worker."""
        with self._lock:
            if name not in self._locks:
                self._locks[name] = threading.Lock()
            lock = self._locks[name]

        acquired = lock.acquire(blocking=blocking, timeout=timeout if timeout > 0 else -1)
        if acquired:
            with self._lock:
                self._holders[name] = worker_id
        return acquired

    def release(self, name: str, worker_id: str) -> bool:
        """Release a named lock. Must be held by the same worker."""
        with self._lock:
            if self._holders.get(name) != worker_id:
                log.warning("Worker %s tried to release lock %s held by %s", worker_id, name, self._holders.get(name))
                return False
            self._holders[name] = ""
        lock = self._locks.get(name)
        if lock:
            try:
                lock.release()
                return True
            except RuntimeError:
                pass
        return False

    def release_all(self, worker_id: str) -> None:
        """Release all locks held by a worker (e.g., on retirement)."""
        with self._lock:
            for name, holder in list(self._holders.items()):
                if holder == worker_id:
                    self._holders[name] = ""
                    lock = self._locks.get(name)
                    if lock:
                        try:
                            while lock.locked():
                                lock.release()
                        except RuntimeError:
                            pass

    def is_held(self, name: str) -> bool:
        with self._lock:
            return bool(self._holders.get(name))

    def holder(self, name: str) -> str:
        with self._lock:
            return self._holders.get(name, "")


# ---------------------------------------------------------------------------
# AgentPool
# ---------------------------------------------------------------------------

class AgentPool:
    """Manages a pool of CTF agent workers with concurrency and lock control.

    Usage:
        pool = AgentPool(max_llm_workers=2, max_tool_workers=5)
        wid = pool.register(role="recon")
        task = pool.claim_task(wid, allowed_kinds={"recon"})
        ...execute...
        pool.complete_task(wid, task.id, result={})
    """

    def __init__(
        self,
        task_queue: TaskQueue,
        max_llm_workers: int = 2,
        max_tool_workers: int = 5,
        heartbeat_timeout: float = 120.0,
    ) -> None:
        self._queue = task_queue
        self._max_llm_workers = max_llm_workers
        self._max_tool_workers = max_tool_workers
        self._heartbeat_timeout = heartbeat_timeout

        self._lock = threading.RLock()
        self._workers: Dict[str, WorkerState] = {}
        self._llm_semaphore = threading.Semaphore(max_llm_workers)
        self._tool_semaphore = threading.Semaphore(max_tool_workers)
        self._locks = ResourceLocks()

    # -- worker lifecycle ---------------------------------------------------

    def register(self, role: str, worker_id: Optional[str] = None) -> str:
        """Register a new worker. Returns the worker id."""
        wid = worker_id or f"{role}-{uuid.uuid4().hex[:6]}"
        with self._lock:
            if wid in self._workers:
                raise ValueError(f"Worker {wid} already registered")
            self._workers[wid] = WorkerState(worker_id=wid, role=role)
            log.info("Worker registered: %s (role=%s)", wid, role)
            return wid

    def heartbeat(self, worker_id: str) -> bool:
        """Update worker heartbeat. Returns False if unknown."""
        with self._lock:
            w = self._workers.get(worker_id)
            if not w:
                return False
            w.last_heartbeat = time.time()
            return True

    def retire(self, worker_id: str) -> bool:
        """Retire a worker and release all its locks."""
        with self._lock:
            w = self._workers.get(worker_id)
            if not w:
                return False
            w.status = "retired"
            self._locks.release_all(worker_id)
            log.info("Worker retired: %s", worker_id)
            return True

    def mark_stalled(self, worker_id: str, reason: str = "") -> bool:
        """Mark a worker as stalled (e.g., lease timeout, exception)."""
        with self._lock:
            w = self._workers.get(worker_id)
            if not w:
                return False
            w.status = "stalled"
            self._locks.release_all(worker_id)
            log.warning("Worker %s marked stalled: %s", worker_id, reason)
            return True

    # -- task claiming ------------------------------------------------------

    def claim_task(
        self,
        worker_id: str,
        allowed_kinds: Optional[Set[str]] = None,
        allowed_routes: Optional[Set[str]] = None,
        lease_seconds: Optional[float] = None,
    ) -> Optional[CTFTask]:
        """Claim a task from the queue for this worker."""
        with self._lock:
            w = self._workers.get(worker_id)
            if not w or w.status == "retired":
                return None

        task = self._queue.lease(
            worker_id=worker_id,
            lease_seconds=lease_seconds,
            allowed_kinds=allowed_kinds,
            allowed_routes=allowed_routes,
        )
        if task:
            with self._lock:
                w.status = "working"
                w.current_task = task.id
            log.debug("Worker %s claimed task %s", worker_id, task.id)
        return task

    def complete_task(
        self,
        worker_id: str,
        task_id: str,
        result: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Mark a worker's task as completed."""
        with self._lock:
            w = self._workers.get(worker_id)
            if not w:
                return False
            w.status = "idle"
            w.current_task = None
            w.tasks_completed += 1

        ok = self._queue.complete(task_id, result)
        if ok:
            log.debug("Worker %s completed task %s", worker_id, task_id)
        return ok

    def fail_task(self, worker_id: str, task_id: str, error: Optional[str] = None) -> bool:
        """Mark a worker's task as failed."""
        with self._lock:
            w = self._workers.get(worker_id)
            if not w:
                return False
            w.status = "idle"
            w.current_task = None
            w.tasks_failed += 1

        ok = self._queue.fail(task_id, error)
        if ok:
            log.debug("Worker %s failed task %s: %s", worker_id, task_id, error)
        return ok

    # -- concurrency control ------------------------------------------------

    def acquire_llm(self, worker_id: str, blocking: bool = True, timeout: float = -1) -> bool:
        """Acquire an LLM slot."""
        acquired = self._llm_semaphore.acquire(blocking=blocking, timeout=timeout if timeout > 0 else None)
        if acquired:
            with self._lock:
                w = self._workers.get(worker_id)
                if w:
                    w.llm_calls += 1
        return acquired

    def release_llm(self, worker_id: str) -> None:
        """Release an LLM slot."""
        try:
            self._llm_semaphore.release()
        except ValueError:
            pass

    def acquire_tool(self, worker_id: str, blocking: bool = True, timeout: float = -1) -> bool:
        """Acquire a tool execution slot."""
        acquired = self._tool_semaphore.acquire(blocking=blocking, timeout=timeout if timeout > 0 else None)
        if acquired:
            with self._lock:
                w = self._workers.get(worker_id)
                if w:
                    w.tool_calls += 1
        return acquired

    def release_tool(self, worker_id: str) -> None:
        """Release a tool execution slot."""
        try:
            self._tool_semaphore.release()
        except ValueError:
            pass

    # -- resource locks -----------------------------------------------------

    def acquire_lock(self, name: str, worker_id: str, blocking: bool = True, timeout: float = -1) -> bool:
        """Acquire a named resource lock."""
        acquired = self._locks.acquire(name, worker_id, blocking=blocking, timeout=timeout)
        if acquired:
            with self._lock:
                w = self._workers.get(worker_id)
                if w:
                    w.locks_held.add(name)
        return acquired

    def release_lock(self, name: str, worker_id: str) -> bool:
        """Release a named resource lock."""
        ok = self._locks.release(name, worker_id)
        if ok:
            with self._lock:
                w = self._workers.get(worker_id)
                if w:
                    w.locks_held.discard(name)
        return ok

    def release_all_locks(self, worker_id: str) -> None:
        """Release all locks held by a worker."""
        self._locks.release_all(worker_id)
        with self._lock:
            w = self._workers.get(worker_id)
            if w:
                w.locks_held.clear()

    # -- queries ------------------------------------------------------------

    def get_worker(self, worker_id: str) -> Optional[WorkerState]:
        with self._lock:
            return self._workers.get(worker_id)

    def workers_by_role(self, role: str) -> List[WorkerState]:
        with self._lock:
            return [w for w in self._workers.values() if w.role == role and w.status != "retired"]

    def active_workers(self) -> List[WorkerState]:
        with self._lock:
            return [w for w in self._workers.values() if w.status not in ("retired",)]

    def idle_workers(self) -> List[WorkerState]:
        with self._lock:
            return [w for w in self._workers.values() if w.status == "idle"]

    def check_stale_workers(self) -> List[str]:
        """Find workers whose heartbeat has expired."""
        stale: List[str] = []
        now = time.time()
        with self._lock:
            for w in self._workers.values():
                if w.status == "retired":
                    continue
                if now - w.last_heartbeat > self._heartbeat_timeout:
                    stale.append(w.worker_id)
        for wid in stale:
            self.mark_stalled(wid, reason="heartbeat timeout")
        return stale

    def get_summary(self) -> Dict[str, Any]:
        with self._lock:
            workers = list(self._workers.values())
            return {
                "total_workers": len(workers),
                "active": sum(1 for w in workers if w.status != "retired"),
                "idle": sum(1 for w in workers if w.status == "idle"),
                "working": sum(1 for w in workers if w.status == "working"),
                "stalled": sum(1 for w in workers if w.status == "stalled"),
                "llm_available": self._llm_semaphore._value,  # type: ignore[attr-defined]
                "tool_available": self._tool_semaphore._value,  # type: ignore[attr-defined]
                "locks_held": {k: v for k, v in self._locks._holders.items() if v},
            }
