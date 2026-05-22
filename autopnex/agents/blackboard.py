"""Thread-safe wrapper around StateFindings for multi-agent access."""
from __future__ import annotations

import threading
from typing import Any, Callable, Dict, List

from ..state_machine.findings import StateFindings


class Blackboard:
    """Shared data store that serialises concurrent agent reads/writes.

    All mutations go through :meth:`write` which acquires an ``RLock`` so
    nested calls from the same thread are safe.  Subscribers are notified
    **outside** the lock to prevent deadlocks in callback chains.
    """

    def __init__(self, findings: StateFindings) -> None:
        self._findings = findings
        self._lock = threading.RLock()
        self._subscribers: List[Callable[..., Any]] = []

    # -- read ---------------------------------------------------------------

    def snapshot(self) -> Dict[str, Any]:
        """Return a compact, read-only view of current findings."""
        with self._lock:
            return self._findings.compact_snapshot()

    def full_findings(self) -> StateFindings:
        """Direct reference — prefer :meth:`snapshot` for read-only access."""
        return self._findings

    # -- write --------------------------------------------------------------

    def write(self, mutation_fn: Callable[[StateFindings], Any]) -> Any:
        """Execute *mutation_fn* under the lock and notify subscribers.

        The callable receives the raw :class:`StateFindings` and may return an
        arbitrary value that is forwarded to the caller.
        """
        with self._lock:
            result = mutation_fn(self._findings)
        self._notify("write", result=result)
        return result

    # -- pub/sub ------------------------------------------------------------

    def subscribe(self, callback: Callable[..., Any]) -> None:
        """Register a callback ``(event, **payload) -> None``."""
        self._subscribers.append(callback)

    def _notify(self, event: str, **payload: Any) -> None:
        for cb in self._subscribers:
            try:
                cb(event, **payload)
            except Exception:  # noqa: BLE001
                pass
