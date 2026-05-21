"""CTF Consensus - merges multi-agent outputs into a unified decision.

Priority order:
1. flag_found          – a worker found the flag
2. verified_flag       – flag confirmed by second worker / verifier
3. high_confidence_evidence – strong evidence card from any worker
4. new_route_suggestion      – a worker discovered a promising new attack route
5. blocker                   – all workers agree the target is blocked

The Consensus module is read-only with respect to agents; it consumes
TaskQueue results and SharedJournal evidence to produce a single
recommendation for the Coordinator.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .shared_journal import EvidenceCard, SharedJournal
from .task_queue import TaskQueue

log = logging.getLogger("autopnex.ctf.consensus")


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class WorkerOutput:
    """Structured output from a single agent worker."""

    worker_id: str
    role: str
    task_id: str
    result: Dict[str, Any] = field(default_factory=dict)
    evidence: List[EvidenceCard] = field(default_factory=list)
    confidence: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "worker_id": self.worker_id,
            "role": self.role,
            "task_id": self.task_id,
            "result": self.result,
            "evidence_count": len(self.evidence),
            "confidence": self.confidence,
        }


@dataclass
class ConsensusDecision:
    """Unified decision produced by merging all worker outputs."""

    verdict: str  # flag_found | verified_flag | evidence | route_suggestion | blocker | continue
    confidence: float
    primary_worker: str = ""
    flag: Optional[str] = None
    summary: str = ""
    next_action: str = ""
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    blockers: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "verdict": self.verdict,
            "confidence": self.confidence,
            "primary_worker": self.primary_worker,
            "flag": self.flag,
            "summary": self.summary,
            "next_action": self.next_action,
            "evidence": self.evidence,
            "blockers": self.blockers,
        }


# ---------------------------------------------------------------------------
# Consensus
# ---------------------------------------------------------------------------

class Consensus:
    """Merges outputs from multiple CTF agent workers.

    Usage:
        c = Consensus(task_queue, shared_journal)
        c.ingest(worker_id="w1", role="exploit", task_id="t1", result={...})
        decision = c.decide()
    """

    # Priority thresholds
    FLAG_CONFIDENCE = 1.0
    VERIFY_CONFIDENCE = 0.95
    EVIDENCE_THRESHOLD = 0.7
    ROUTE_THRESHOLD = 0.4

    def __init__(
        self,
        task_queue: TaskQueue,
        shared_journal: Optional[SharedJournal] = None,
    ) -> None:
        self._queue = task_queue
        self._journal = shared_journal
        self._outputs: List[WorkerOutput] = []
        self._lock = __import__("threading").RLock()

    # -- ingestion ----------------------------------------------------------

    def ingest(
        self,
        worker_id: str,
        role: str,
        task_id: str,
        result: Optional[Dict[str, Any]] = None,
        evidence: Optional[List[EvidenceCard]] = None,
        confidence: float = 0.0,
    ) -> None:
        """Record a worker's output for consensus evaluation."""
        with self._lock:
            self._outputs.append(
                WorkerOutput(
                    worker_id=worker_id,
                    role=role,
                    task_id=task_id,
                    result=result or {},
                    evidence=list(evidence or []),
                    confidence=confidence,
                )
            )

    def ingest_from_queue(self) -> int:
        """Scan completed tasks in the queue and ingest their results.

        Returns number of newly ingested outputs.
        """
        completed = self._queue.list_tasks(status="completed")
        ingested = 0
        for task in completed:
            if not task.result:
                continue
            # Avoid duplicate ingestion by checking if we already have this task_id
            with self._lock:
                if any(o.task_id == task.id for o in self._outputs):
                    continue
            self.ingest(
                worker_id=task.leased_by or "unknown",
                role=task.kind,
                task_id=task.id,
                result=task.result,
                confidence=self._score_task_result(task.result),
            )
            ingested += 1
        return ingested

    def reset(self) -> None:
        """Clear all ingested outputs (e.g., after a decision is acted upon)."""
        with self._lock:
            self._outputs.clear()

    # -- decision -----------------------------------------------------------

    def decide(self) -> ConsensusDecision:
        """Merge all worker outputs and return a unified decision."""
        with self._lock:
            if not self._outputs:
                return ConsensusDecision(
                    verdict="continue",
                    confidence=0.0,
                    summary="尚无 worker 输出",
                    next_action="等待 worker 完成任务",
                )

            # 1. Check for verified flag (two workers agree on same flag) first
            verified = self._verify_flag()
            if verified:
                return ConsensusDecision(
                    verdict="verified_flag",
                    confidence=self.VERIFY_CONFIDENCE,
                    primary_worker=verified["worker_id"],
                    flag=verified["flag"],
                    summary=f"多名 worker 一致确认 flag: {verified['flag']}",
                    next_action="终止并返回已验证 flag",
                )

            # 2. Check for flag_found (single worker reports a flag)
            flag, worker = self._find_flag()
            if flag:
                return ConsensusDecision(
                    verdict="flag_found",
                    confidence=self.FLAG_CONFIDENCE,
                    primary_worker=worker,
                    flag=flag,
                    summary=f"Worker {worker} 发现 flag",
                    next_action="终止所有任务并返回 flag",
                )

            # 3. Collect high-confidence evidence
            high_evidence = self._collect_high_evidence()
            if high_evidence:
                best = high_evidence[0]
                return ConsensusDecision(
                    verdict="evidence",
                    confidence=best.confidence,
                    primary_worker=best.worker_id,
                    summary=f"Worker {best.worker_id} 提供高置信度证据",
                    next_action=f"继续深挖路线: {best.result.get('route', 'unknown')}",
                    evidence=[e.to_dict() for e in best.evidence[:3]],
                )

            # 4. Check for promising route suggestions
            route = self._find_new_route()
            if route:
                return ConsensusDecision(
                    verdict="route_suggestion",
                    confidence=route["confidence"],
                    primary_worker=route["worker_id"],
                    summary=f"Worker {route['worker_id']} 发现新路线: {route['route']}",
                    next_action=f"尝试路线: {route['route']}",
                )

            # 5. Check for unanimous blockers
            blockers = self._collect_blockers()
            if blockers and len(blockers) >= 2:
                return ConsensusDecision(
                    verdict="blocker",
                    confidence=0.5,
                    summary=f"多名 worker 报告阻塞: {blockers[0][:80]}",
                    next_action="触发 Critic 审查或切换高阶策略",
                    blockers=blockers,
                )

            # Default: continue
            avg_confidence = sum(o.confidence for o in self._outputs) / len(self._outputs)
            return ConsensusDecision(
                verdict="continue",
                confidence=avg_confidence,
                summary=f"已收集 {len(self._outputs)} 条 worker 输出，继续执行",
                next_action="继续当前任务分配",
            )

    def get_best_evidence(self) -> Optional[WorkerOutput]:
        """Return the worker output with the highest confidence evidence."""
        with self._lock:
            if not self._outputs:
                return None
            return max(self._outputs, key=lambda o: o.confidence)

    def get_all_flags(self) -> List[str]:
        """Return all unique flags mentioned in outputs."""
        flags: List[str] = []
        with self._lock:
            for o in self._outputs:
                flag = o.result.get("flag") or o.result.get("found_flag")
                if flag and flag not in flags:
                    flags.append(str(flag))
        return flags

    # -- internal helpers ---------------------------------------------------

    def _find_flag(self) -> tuple[Optional[str], str]:
        """Return (flag, worker_id) if any worker found a flag."""
        for o in self._outputs:
            flag = o.result.get("flag") or o.result.get("found_flag")
            if flag:
                return str(flag), o.worker_id
        return None, ""

    def _verify_flag(self) -> Optional[Dict[str, Any]]:
        """If two workers report the same flag, return verification info."""
        flags: Dict[str, List[str]] = {}
        for o in self._outputs:
            flag = o.result.get("flag") or o.result.get("found_flag")
            if flag:
                flags.setdefault(str(flag), []).append(o.worker_id)
        for flag, workers in flags.items():
            if len(workers) >= 2:
                return {"flag": flag, "worker_id": workers[0], "verifiers": workers[1:]}
        return None

    def _collect_high_evidence(self) -> List[WorkerOutput]:
        """Return outputs with confidence >= EVIDENCE_THRESHOLD, sorted desc."""
        result = [o for o in self._outputs if o.confidence >= self.EVIDENCE_THRESHOLD]
        result.sort(key=lambda o: o.confidence, reverse=True)
        return result

    def _find_new_route(self) -> Optional[Dict[str, Any]]:
        """Look for route suggestions in results."""
        best: Optional[Dict[str, Any]] = None
        for o in self._outputs:
            route = o.result.get("new_route") or o.result.get("suggested_route")
            if route:
                conf = o.confidence or self.ROUTE_THRESHOLD
                if best is None or conf > best["confidence"]:
                    best = {
                        "route": str(route),
                        "confidence": conf,
                        "worker_id": o.worker_id,
                    }
        return best

    def _collect_blockers(self) -> List[str]:
        """Collect unique blocker descriptions from outputs."""
        blockers: List[str] = []
        seen: set[str] = set()
        for o in self._outputs:
            b = o.result.get("blocker") or o.result.get("error")
            if b and b not in seen:
                blockers.append(str(b))
                seen.add(str(b))
        return blockers

    @staticmethod
    def _score_task_result(result: Dict[str, Any]) -> float:
        """Heuristic confidence score for a task result."""
        if result.get("flag") or result.get("found_flag"):
            return 1.0
        if result.get("verified"):
            return 0.95
        if result.get("evidence_score"):
            return float(result["evidence_score"])
        if result.get("new_route"):
            return 0.5
        if result.get("blocker"):
            return 0.2
        return 0.3
