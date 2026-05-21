"""Sequential executor for attack chains with checkpointing and approval gates."""
from __future__ import annotations

import copy
import logging
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional

from ..tools.base import ToolRegistry, ToolResult
from .attack_graph import AttackChain, AttackEdge, AttackGraph, EdgeStatus
from .findings import StateFindings

logger = logging.getLogger(__name__)

ApprovalCallback = Callable[[AttackEdge], bool]
ProgressCallback = Callable[[str, int, int, str], None]

MAX_RETRIES = 2


@dataclass
class Checkpoint:
    checkpoint_id: str
    chain_id: str
    step_idx: int
    edge_id: str
    graph_snapshot: Dict[str, Any] = field(default_factory=dict)
    findings_snapshot: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ChainExecutor:
    """Walks an :class:`AttackChain` edge-by-edge, executing each tool step."""

    def __init__(
        self,
        graph: AttackGraph,
        findings: StateFindings,
        *,
        approval_cb: Optional[ApprovalCallback] = None,
        progress_cb: Optional[ProgressCallback] = None,
    ) -> None:
        self.graph = graph
        self.findings = findings
        self.approval_cb = approval_cb
        self.progress_cb = progress_cb
        self.checkpoints: List[Checkpoint] = []

    # ------------------------------------------------------------------
    def execute_chain(self, chain_id: str) -> Dict[str, Any]:
        chain = self.graph.chains.get(chain_id)
        if chain is None:
            return {"success": False, "error": f"chain {chain_id} not found"}

        chain.status = "running"
        results: List[Dict[str, Any]] = []

        for idx, edge_id in enumerate(chain.edges):
            edge = self.graph.edges.get(edge_id)
            if edge is None:
                results.append({"step": idx, "error": "edge_not_found", "edge_id": edge_id})
                chain.status = "failed"
                break

            self._create_checkpoint(chain_id, idx, edge_id)
            chain.current_step = idx
            self._emit_progress(chain_id, idx, len(chain.edges), f"executing {edge.tool}")

            if edge.requires_approval and not self._request_approval(edge):
                edge.status = EdgeStatus.BLOCKED
                chain.status = "blocked"
                results.append({"step": idx, "status": "blocked", "edge_id": edge_id})
                break

            if not self.graph.preconditions_met(edge):
                edge.status = EdgeStatus.BLOCKED
                chain.status = "blocked"
                results.append({"step": idx, "status": "preconditions_unmet", "edge_id": edge_id})
                break

            step_result = self._execute_edge(edge)
            results.append({"step": idx, "edge_id": edge_id, **step_result})

            if not step_result.get("success"):
                chain.status = "failed"
                break

            target_node = self.graph.nodes.get(edge.target_id)
            if target_node and target_node.obtained_at is None:
                target_node.obtained_at = datetime.utcnow().isoformat() + "Z"
        else:
            chain.status = "completed"

        self._emit_progress(chain_id, len(chain.edges), len(chain.edges), chain.status)
        return {"chain_id": chain_id, "status": chain.status, "steps": results}

    # ------------------------------------------------------------------
    def _execute_edge(self, edge: AttackEdge) -> Dict[str, Any]:
        edge.status = EdgeStatus.VALIDATED
        for attempt in range(1, MAX_RETRIES + 1):
            tool_result = ToolRegistry.execute(edge.tool, edge.tool_arguments)
            if tool_result.success:
                edge.status = EdgeStatus.EXECUTED
                artifact = self.findings.add_artifact(
                    parent_ref=None,
                    phase="exploit",
                    tool=edge.tool,
                    kind="chain_step",
                    summary=tool_result.summary,
                    raw_output_excerpt=tool_result.raw_output,
                    metadata=tool_result.parsed_data,
                )
                edge.evidence_artifact_id = artifact.artifact_id
                return {"success": True, "attempt": attempt, "summary": tool_result.summary}
            logger.warning("edge %s attempt %d failed: %s", edge.edge_id, attempt, tool_result.error)

        edge.status = EdgeStatus.FAILED
        return {"success": False, "attempt": MAX_RETRIES, "error": tool_result.error}

    # ------------------------------------------------------------------
    def _create_checkpoint(self, chain_id: str, step_idx: int, edge_id: str) -> Checkpoint:
        cp = Checkpoint(
            checkpoint_id=uuid.uuid4().hex[:12],
            chain_id=chain_id,
            step_idx=step_idx,
            edge_id=edge_id,
            graph_snapshot=self.graph.to_dict(),
            findings_snapshot=self.findings.to_dict(),
        )
        self.checkpoints.append(cp)
        edge = self.graph.edges.get(edge_id)
        if edge:
            edge.checkpoint_id = cp.checkpoint_id
        return cp

    # ------------------------------------------------------------------
    def _request_approval(self, edge: AttackEdge) -> bool:
        if self.approval_cb is None:
            logger.info("no approval callback — auto-approving edge %s", edge.edge_id)
            return True
        return self.approval_cb(edge)

    def _emit_progress(self, chain_id: str, step: int, total: int, message: str) -> None:
        if self.progress_cb:
            self.progress_cb(chain_id, step, total, message)
