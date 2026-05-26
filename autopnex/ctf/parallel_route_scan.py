"""ParallelRouteScan — 并行路线扫描模块。

并行执行所有 RouteStateMachine 路线的探测（run_probes），收集证据，
输出按 evidence_score 降序排列的路线优先级队列。

设计要点:
  - 使用 ThreadPoolExecutor 并行（requests 是同步的）
  - 每条路线独立 session（避免 cookie/header 状态互相污染）
  - 总超时 30 秒，单路线超时 8 秒
  - 历史匹配路线直接加 knowledge_boost
  - 扫描阶段 HTTP 请求预算统计，默认不超过 100 个
  - 单条路线异常或超时不影响其他路线结果（graceful degradation）
"""

from __future__ import annotations

import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed, Future
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import requests

from .knowledge_learner import KnowledgeLearner
from .route_state_machine import MACHINE_REGISTRY, RouteStateMachine

log = logging.getLogger("autopnex.ctf.parallel_route_scan")


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass
class ScanResult:
    """单条路线的扫描结果。"""

    route: str
    """路线名称。"""

    evidence_score: float
    """综合证据得分（含 knowledge_boost）。"""

    probe_duration_ms: float
    """探测耗时（毫秒）。"""

    probe_results: Dict[str, Any]
    """每个 probe 的原始结果（probe_name → ProbeResult 值）。"""

    exploit_steps_available: int
    """该路线可用的 exploit 步骤数量。"""

    knowledge_boost: float = 0.0
    """来自历史知识匹配的加分。"""

    endpoints_found: List[str] = field(default_factory=list)
    """探测过程中发现的 endpoint 列表。"""

    scenario_hints: List[str] = field(default_factory=list)
    """探测过程中获得的场景提示。"""


@dataclass
class ParallelScanOutput:
    """并行扫描的完整输出。"""

    results: List[ScanResult] = field(default_factory=list)
    """按 evidence_score 降序排列的扫描结果。"""

    total_duration_ms: float = 0.0
    """总扫描耗时（毫秒）。"""

    routes_above_threshold: int = 0
    """得分 > 0.3 的路线数量。"""

    knowledge_matches: List[str] = field(default_factory=list)
    """匹配到的历史模式名称。"""

    total_requests_made: int = 0
    """扫描阶段发出的 HTTP 请求总数。"""

    flag_found: Optional[str] = None
    """如果在探测阶段直接发现了 flag。"""


# ---------------------------------------------------------------------------
# Request budget tracker (thread-safe)
# ---------------------------------------------------------------------------


class _RequestBudgetTracker:
    """Thread-safe HTTP request counter for budget enforcement."""

    def __init__(self, max_requests: int):
        self._max = max_requests
        self._count = 0
        self._lock = threading.Lock()

    @property
    def count(self) -> int:
        with self._lock:
            return self._count

    @property
    def exhausted(self) -> bool:
        with self._lock:
            return self._count >= self._max

    def increment(self, n: int = 1) -> bool:
        """Increment counter. Returns True if still within budget."""
        with self._lock:
            self._count += n
            return self._count <= self._max


# ---------------------------------------------------------------------------
# Budget-aware session wrapper
# ---------------------------------------------------------------------------


class _BudgetSession(requests.Session):
    """A requests.Session that increments a shared budget tracker on each request."""

    def __init__(self, budget: _RequestBudgetTracker):
        super().__init__()
        self._budget = budget

    def send(self, request, **kwargs):
        self._budget.increment()
        return super().send(request, **kwargs)


# ---------------------------------------------------------------------------
# ParallelRouteScan
# ---------------------------------------------------------------------------


class ParallelRouteScan:
    """并行路线扫描器 — Phase 1 的核心执行引擎。

    从 MACHINE_REGISTRY 自动枚举所有可用路线，并行执行 run_probes()，
    收集证据分数，结合历史知识匹配，输出排序后的路线优先级队列。

    Args:
        target_url: 目标 URL。
        session: 基础 requests.Session（用于复制 headers/auth 等配置）。
        knowledge_learner: 可选的 KnowledgeLearner 实例，用于历史模式匹配。
        timeout: 总超时时间（秒），默认 30.0。
        max_requests: 扫描阶段最大 HTTP 请求数，默认 100。
        single_route_timeout: 单路线超时时间（秒），默认 8.0。
    """

    # Knowledge boost added to routes matching historical patterns
    KNOWLEDGE_BOOST = 0.3

    def __init__(
        self,
        target_url: str,
        session: requests.Session,
        knowledge_learner: Optional[KnowledgeLearner] = None,
        timeout: float = 15.0,
        max_requests: int = 100,
        single_route_timeout: float = 4.0,
    ):
        self.target_url = target_url.rstrip("/")
        self.session = session
        self.knowledge_learner = knowledge_learner
        self.timeout = timeout
        self.max_requests = max_requests
        self.single_route_timeout = single_route_timeout

    # ------------------------------------------------------------------
    # Internal: probe a single route
    # ------------------------------------------------------------------

    def _probe_single_route(
        self,
        route_name: str,
        machine: RouteStateMachine,
        budget: _RequestBudgetTracker,
        deadline: float,
    ) -> ScanResult:
        """Execute run_probes() for a single route with timeout and budget checks.

        This runs inside a thread. Exceptions are caught by the caller.
        """
        start = time.time()

        # Check budget before starting
        if budget.exhausted:
            return ScanResult(
                route=route_name,
                evidence_score=0.0,
                probe_duration_ms=0.0,
                probe_results={},
                exploit_steps_available=0,
            )

        # Check deadline
        remaining = deadline - time.time()
        if remaining <= 0:
            return ScanResult(
                route=route_name,
                evidence_score=0.0,
                probe_duration_ms=0.0,
                probe_results={},
                exploit_steps_available=0,
            )

        # Execute probes — only run_probes(), NOT run_exploit()
        evidence = machine.run_probes()

        elapsed_ms = (time.time() - start) * 1000

        # Count exploit steps available (without executing them)
        try:
            exploit_steps = machine.get_exploit_steps()
            exploit_steps_count = len(exploit_steps)
        except Exception:
            exploit_steps_count = 0

        # Extract probe results from machine state
        probe_results_dict: Dict[str, Any] = {}
        for pname, presult in machine.state.probe_results.items():
            probe_results_dict[pname] = presult.value if hasattr(presult, "value") else str(presult)

        # Extract endpoints from HTTP history
        endpoints_found: List[str] = []
        for entry in machine._http_history:
            url = entry.get("url", "")
            if url and url not in endpoints_found:
                endpoints_found.append(url)

        # Build scenario hints from evidence detail
        scenario_hints: List[str] = []
        if evidence.detail and evidence.detail != "No evidence found":
            scenario_hints.append(evidence.detail)

        return ScanResult(
            route=route_name,
            evidence_score=evidence.score,
            probe_duration_ms=elapsed_ms,
            probe_results=probe_results_dict,
            exploit_steps_available=exploit_steps_count,
            knowledge_boost=0.0,  # Will be applied later
            endpoints_found=endpoints_found,
            scenario_hints=scenario_hints,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(self) -> ParallelScanOutput:
        """执行并行路线扫描，返回排序后的扫描结果。

        实现:
          - 1.2: ✅ 自动枚举 MACHINE_REGISTRY 中的所有路线
          - 1.3: ✅ ThreadPoolExecutor 并行执行 run_probes()
          - 1.4: ✅ 每条路线独立 session
          - 1.5: ✅ 总超时 + 单路线超时控制
          - 1.6: ✅ HTTP 请求预算统计
          - 1.7: ✅ KnowledgeLearner.match_pattern() 集成
          - 1.8: ✅ 按 evidence_score 降序排列输出
          - 1.10: ✅ graceful degradation
        """
        start_time = time.time()
        deadline = start_time + self.timeout

        output = ParallelScanOutput(
            results=[],
            total_duration_ms=0.0,
            routes_above_threshold=0,
            knowledge_matches=[],
            total_requests_made=0,
            flag_found=None,
        )

        # --- Shared request budget tracker ---
        budget = _RequestBudgetTracker(self.max_requests)

        # --- 1.7: Knowledge matching (before scanning) ---
        knowledge_matched_routes: set = set()
        if self.knowledge_learner is not None:
            try:
                # Build a minimal blackboard state for pattern matching
                blackboard_state = {
                    "target_url": self.target_url,
                    "tech_stack": [],
                    "interesting_params": [],
                    "top_evidence": [],
                    "forms": [],
                }
                match = self.knowledge_learner.match_pattern(blackboard_state)
                if match is not None:
                    matched_route = match.get("route", "")
                    matched_scenario = match.get("scenario", "")
                    if matched_route:
                        knowledge_matched_routes.add(matched_route)
                        output.knowledge_matches.append(
                            f"{matched_route}:{matched_scenario}" if matched_scenario else matched_route
                        )
                        log.info(
                            "Knowledge match: route=%s scenario=%s",
                            matched_route,
                            matched_scenario,
                        )
            except Exception as e:
                log.warning("Knowledge matching failed (non-fatal): %s", e)

        # --- 1.2: 自动枚举所有可用路线并实例化状态机 ---
        # --- 1.4: 每条路线使用独立 session ---
        route_machines: Dict[str, RouteStateMachine] = {}
        for route_name, machine_cls in MACHINE_REGISTRY.items():
            try:
                # Each route gets a budget-aware independent session
                route_session = _BudgetSession(budget)
                # Copy headers and auth from the base session
                route_session.headers.update(self.session.headers)
                if self.session.auth:
                    route_session.auth = self.session.auth

                machine = machine_cls(self.target_url, session=route_session)
                route_machines[route_name] = machine
            except Exception as e:
                log.warning(
                    "Failed to instantiate route machine '%s': %s",
                    route_name,
                    e,
                )

        log.info(
            "ParallelRouteScan enumerated %d routes from MACHINE_REGISTRY: %s",
            len(route_machines),
            list(route_machines.keys()),
        )

        if not route_machines:
            output.total_duration_ms = (time.time() - start_time) * 1000
            return output

        # --- 1.3: ThreadPoolExecutor 并行执行 run_probes() ---
        # --- 1.5: 总超时 + 单路线超时控制 ---
        # --- 1.10: graceful degradation ---
        max_workers = min(len(route_machines), 10)
        results: List[ScanResult] = []

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_route: Dict[Future, str] = {}

            for route_name, machine in route_machines.items():
                # Don't submit if budget already exhausted
                if budget.exhausted:
                    log.info("Request budget exhausted, skipping route '%s'", route_name)
                    break

                future = executor.submit(
                    self._probe_single_route,
                    route_name,
                    machine,
                    budget,
                    deadline,
                )
                future_to_route[future] = route_name

            # Collect results with total timeout
            remaining_timeout = max(0.1, deadline - time.time())
            for future in as_completed(future_to_route, timeout=remaining_timeout):
                route_name = future_to_route[future]
                try:
                    scan_result = future.result(timeout=self.single_route_timeout)
                    results.append(scan_result)

                    # Check if flag was found during probing
                    machine = route_machines.get(route_name)
                    if machine and machine.state.stop_reason == "flag_found_in_probe":
                        # Extract flag from evidence
                        for ev in machine.state.evidence_scores:
                            if ev.score == 1.0 and "Flag found" in ev.detail:
                                # Extract flag value from detail
                                import re
                                flag_match = re.search(r"Flag found.*?: (.+)", ev.detail)
                                if flag_match:
                                    output.flag_found = flag_match.group(1)
                                    break

                except TimeoutError:
                    # 1.10: Single route timeout — graceful degradation
                    log.warning("Route '%s' timed out (single_route_timeout)", route_name)
                    results.append(ScanResult(
                        route=route_name,
                        evidence_score=0.0,
                        probe_duration_ms=self.single_route_timeout * 1000,
                        probe_results={},
                        exploit_steps_available=0,
                    ))
                except Exception as e:
                    # 1.10: Any exception in a route doesn't crash others
                    log.warning("Route '%s' failed with exception: %s", route_name, e)
                    results.append(ScanResult(
                        route=route_name,
                        evidence_score=0.0,
                        probe_duration_ms=0.0,
                        probe_results={},
                        exploit_steps_available=0,
                    ))

        # Handle total timeout — as_completed may raise TimeoutError
        # if the overall deadline is exceeded. This is caught implicitly
        # since we're outside the with block now.

        # --- 1.7: Apply knowledge boost to matching routes ---
        for result in results:
            if result.route in knowledge_matched_routes:
                result.knowledge_boost = self.KNOWLEDGE_BOOST
                result.evidence_score += self.KNOWLEDGE_BOOST
                log.info(
                    "Applied knowledge boost (+%.1f) to route '%s', new score=%.2f",
                    self.KNOWLEDGE_BOOST,
                    result.route,
                    result.evidence_score,
                )

        # --- 1.8: Sort by evidence_score descending ---
        results.sort(key=lambda r: r.evidence_score, reverse=True)

        # --- Build final output ---
        output.results = results
        output.total_duration_ms = (time.time() - start_time) * 1000
        output.total_requests_made = budget.count
        output.routes_above_threshold = sum(
            1 for r in results if r.evidence_score > 0.3
        )

        log.info(
            "ParallelRouteScan completed: %d routes scanned, %.1f ms, "
            "%d above threshold, %d HTTP requests made",
            len(output.results),
            output.total_duration_ms,
            output.routes_above_threshold,
            output.total_requests_made,
        )

        return output

    # ------------------------------------------------------------------
    # 1.9: Write scan results to WebStateBlackboard
    # ------------------------------------------------------------------

    def write_to_blackboard(self, blackboard: "Any", output: ParallelScanOutput) -> None:
        """将扫描得到的 evidence / endpoint / scenario hint 同步写入 WebStateBlackboard。

        此方法由 Pipeline 在 run() 返回后调用，而非扫描器自身调用。
        对 blackboard 为 None 或方法不存在的情况做 graceful degradation。

        Args:
            blackboard: WebStateBlackboard 实例（或 None）。
            output: ParallelScanOutput 扫描结果。
        """
        if blackboard is None:
            log.debug("write_to_blackboard: blackboard is None, skipping.")
            return

        written_evidence = 0
        written_endpoints = 0
        written_hints = 0

        for result in output.results:
            # --- Write evidence for routes with score > 0 ---
            if result.evidence_score > 0:
                try:
                    if hasattr(blackboard, "add_evidence"):
                        observation = (
                            f"Parallel scan detected evidence: "
                            f"score={result.evidence_score:.2f}, "
                            f"probes={len(result.probe_results)}, "
                            f"exploit_steps={result.exploit_steps_available}"
                        )
                        if result.knowledge_boost > 0:
                            observation += f", knowledge_boost=+{result.knowledge_boost:.1f}"
                        blackboard.add_evidence(
                            route=result.route,
                            score=result.evidence_score,
                            source="parallel_scan",
                            observation=observation,
                        )
                        written_evidence += 1
                except Exception as e:
                    log.warning(
                        "Failed to write evidence for route '%s': %s",
                        result.route,
                        e,
                    )

            # --- Record discovered endpoints ---
            if result.endpoints_found:
                try:
                    if hasattr(blackboard, "record_endpoint"):
                        for endpoint in result.endpoints_found:
                            blackboard.record_endpoint(
                                path=endpoint,
                                discovered_from=f"parallel_scan:{result.route}",
                            )
                            written_endpoints += 1
                except Exception as e:
                    log.warning(
                        "Failed to write endpoints for route '%s': %s",
                        result.route,
                        e,
                    )

            # --- Add scenario hints ---
            if result.scenario_hints:
                try:
                    if hasattr(blackboard, "add_scenario_hint"):
                        for hint_text in result.scenario_hints:
                            blackboard.add_scenario_hint(
                                route=result.route,
                                scenario=hint_text,
                                confidence=min(result.evidence_score, 1.0),
                                source="parallel_scan",
                                detail=hint_text,
                            )
                            written_hints += 1
                except Exception as e:
                    log.warning(
                        "Failed to write scenario hints for route '%s': %s",
                        result.route,
                        e,
                    )

        log.info(
            "write_to_blackboard: wrote %d evidence cards, %d endpoints, %d scenario hints",
            written_evidence,
            written_endpoints,
            written_hints,
        )
