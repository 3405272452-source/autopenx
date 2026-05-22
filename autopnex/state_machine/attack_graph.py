"""Directed attack graph for multi-step exploitation chains."""
from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set


class NodeType(Enum):
    ASSET = "asset"
    VULNERABILITY = "vulnerability"
    CAPABILITY = "capability"


class EdgeStatus(Enum):
    THEORETICAL = "theoretical"
    VALIDATED = "validated"
    EXECUTED = "executed"
    FAILED = "failed"
    BLOCKED = "blocked"


@dataclass
class AttackNode:
    node_id: str
    node_type: NodeType
    label: str
    finding_key: Optional[str] = None
    asset_type: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    obtained_at: Optional[str] = None


@dataclass
class AttackEdge:
    edge_id: str
    source_id: str
    target_id: str
    tool: str
    tool_arguments: Dict[str, Any] = field(default_factory=dict)
    status: EdgeStatus = EdgeStatus.THEORETICAL
    preconditions: List[str] = field(default_factory=list)
    risk_level: str = "medium"
    requires_approval: bool = False
    evidence_artifact_id: Optional[str] = None
    checkpoint_id: Optional[str] = None


@dataclass
class AttackChain:
    chain_id: str
    name: str
    description: str = ""
    edges: List[str] = field(default_factory=list)
    status: str = "planned"
    current_step: int = 0
    mitre_tactics: List[str] = field(default_factory=list)
    max_impact: str = "HIGH"


class AttackGraph:
    """In-memory directed graph tracking multi-step attack paths."""

    def __init__(self) -> None:
        self.nodes: Dict[str, AttackNode] = {}
        self.edges: Dict[str, AttackEdge] = {}
        self.chains: Dict[str, AttackChain] = {}

    def add_node(
        self,
        node_type: NodeType,
        label: str,
        *,
        node_id: Optional[str] = None,
        finding_key: Optional[str] = None,
        asset_type: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AttackNode:
        nid = node_id or uuid.uuid4().hex[:12]
        node = AttackNode(
            node_id=nid,
            node_type=node_type,
            label=label,
            finding_key=finding_key,
            asset_type=asset_type,
            metadata=metadata or {},
        )
        self.nodes[nid] = node
        return node

    def add_edge(
        self,
        source_id: str,
        target_id: str,
        tool: str,
        *,
        edge_id: Optional[str] = None,
        tool_arguments: Optional[Dict[str, Any]] = None,
        status: EdgeStatus = EdgeStatus.THEORETICAL,
        preconditions: Optional[List[str]] = None,
        risk_level: str = "medium",
        requires_approval: bool = False,
    ) -> AttackEdge:
        eid = edge_id or uuid.uuid4().hex[:12]
        edge = AttackEdge(
            edge_id=eid,
            source_id=source_id,
            target_id=target_id,
            tool=tool,
            tool_arguments=tool_arguments or {},
            status=status,
            preconditions=preconditions or [],
            risk_level=risk_level,
            requires_approval=requires_approval,
        )
        self.edges[eid] = edge
        return edge

    def add_chain(
        self,
        name: str,
        edge_ids: List[str],
        *,
        chain_id: Optional[str] = None,
        description: str = "",
        mitre_tactics: Optional[List[str]] = None,
        max_impact: str = "HIGH",
    ) -> AttackChain:
        cid = chain_id or uuid.uuid4().hex[:12]
        chain = AttackChain(
            chain_id=cid,
            name=name,
            description=description,
            edges=list(edge_ids),
            mitre_tactics=mitre_tactics or [],
            max_impact=max_impact,
        )
        self.chains[cid] = chain
        return chain

    def reachable_from(self, node_id: str) -> List[AttackEdge]:
        return [e for e in self.edges.values() if e.source_id == node_id]

    def preconditions_met(self, edge: AttackEdge) -> bool:
        obtained = self.obtained_assets()
        return all(pre in obtained for pre in edge.preconditions)

    def executable_edges(self) -> List[AttackEdge]:
        return [
            e
            for e in self.edges.values()
            if e.status in (EdgeStatus.THEORETICAL, EdgeStatus.VALIDATED)
            and self.preconditions_met(e)
        ]

    def obtained_assets(self) -> Set[str]:
        return {
            n.node_id
            for n in self.nodes.values()
            if n.obtained_at is not None
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "nodes": {nid: asdict(n) for nid, n in self.nodes.items()},
            "edges": {eid: asdict(e) for eid, e in self.edges.items()},
            "chains": {cid: asdict(c) for cid, c in self.chains.items()},
        }
