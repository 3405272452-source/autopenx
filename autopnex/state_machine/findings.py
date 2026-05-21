"""Global findings store shared across state-machine transitions."""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Any, Dict, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from .attack_graph import AttackGraph


SEVERITY_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
STATUS_ORDER = {"suspected": 0, "confirmed": 1, "exploitable": 2, "exploited": 3}


@dataclass
class Finding:
    """Concrete vulnerability / observation."""

    title: str
    severity: str = "INFO"
    status: str = "confirmed"  # suspected | confirmed | exploitable | exploited
    category: str = "misc"  # recon / scan / sqli / xss / ssrf / cmdi / exploit ...
    description: str = ""
    evidence: str = ""
    url: Optional[str] = None
    parameter: Optional[str] = None
    payload: Optional[str] = None
    tool: Optional[str] = None
    recommendation: str = ""
    attack_node_id: Optional[str] = None
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ToolInvocation:
    state: str
    tool: str
    task_ref: Optional[str]
    arguments: Dict[str, Any]
    success: bool
    summary: str
    duration_ms: int
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")


@dataclass
class TaskItem:
    ref: str
    phase: str
    tool: str
    title: str
    arguments: Dict[str, Any]
    status: str = "todo"  # todo | pending_approval | done | ruled_out | blocked
    note: str = ""
    risk_level: str = "medium"
    required_capability: Optional[str] = None
    finding_key: Optional[str] = None
    priority_score: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class EvidenceArtifact:
    artifact_id: str
    parent_ref: Optional[str]
    phase: str
    tool: str
    kind: str
    summary: str
    content_hash: str
    raw_output_excerpt: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class StateFindings:
    target: str
    started_at: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")

    # Recon
    open_ports: List[Dict[str, Any]] = field(default_factory=list)
    technologies: List[str] = field(default_factory=list)
    subdomains: List[str] = field(default_factory=list)

    # Scan
    discovered_paths: List[str] = field(default_factory=list)
    interesting_files: List[Dict[str, Any]] = field(default_factory=list)
    forms: List[Dict[str, Any]] = field(default_factory=list)
    parameters: List[Dict[str, Any]] = field(default_factory=list)  # {url, name, method}

    # Findings & exploitation
    findings: List[Finding] = field(default_factory=list)
    exploit_evidence: List[Dict[str, Any]] = field(default_factory=list)
    evidence_artifacts: List[EvidenceArtifact] = field(default_factory=list)

    # Attack graph (lazy-init to avoid circular import at class definition time)
    attack_graph: Any = field(default=None)

    def __post_init__(self) -> None:
        if self.attack_graph is None:
            from .attack_graph import AttackGraph
            self.attack_graph = AttackGraph()

    # Trace
    tool_invocations: List[ToolInvocation] = field(default_factory=list)
    state_log: List[Dict[str, Any]] = field(default_factory=list)
    phase_tasks: Dict[str, List[TaskItem]] = field(default_factory=dict)
    phase_notes: Dict[str, str] = field(default_factory=dict)

    # ---- helpers -----------------------------------------------------
    def add_finding(self, finding: Finding) -> Finding:
        # De-duplicate by (title, url, parameter)
        key = (finding.title, finding.url, finding.parameter)
        for existing in self.findings:
            if (existing.title, existing.url, existing.parameter) == key:
                if STATUS_ORDER.get(finding.status, 0) > STATUS_ORDER.get(existing.status, 0):
                    existing.status = finding.status
                if SEVERITY_ORDER.get(finding.severity.upper(), 0) > SEVERITY_ORDER.get(existing.severity.upper(), 0):
                    existing.severity = finding.severity
                for attr in ("description", "payload", "tool", "recommendation", "category", "cwe_id", "owasp_category", "cvss_score", "cvss_vector"):
                    value = getattr(finding, attr)
                    if value and not getattr(existing, attr):
                        setattr(existing, attr, value)
                if finding.evidence and finding.evidence not in existing.evidence:
                    existing.evidence = "\n".join(part for part in [existing.evidence, finding.evidence] if part)
                return existing
        self.findings.append(finding)
        return finding

    def add_parameter(self, url: str, name: str, method: str = "GET") -> None:
        entry = {"url": url, "name": name, "method": method.upper()}
        if entry not in self.parameters:
            self.parameters.append(entry)

    def add_path(self, path: str) -> None:
        if path and path not in self.discovered_paths:
            self.discovered_paths.append(path)

    def record_invocation(
        self,
        state: str,
        tool: str,
        arguments: Dict[str, Any],
        result: Any,
        *,
        task_ref: Optional[str] = None,
    ) -> None:
        self.tool_invocations.append(
            ToolInvocation(
                state=state,
                tool=tool,
                task_ref=task_ref,
                arguments=arguments,
                success=getattr(result, "success", False),
                summary=getattr(result, "summary", ""),
                duration_ms=getattr(result, "duration_ms", 0),
            )
        )

    def log_state(self, state: str, message: str, level: str = "info") -> None:
        self.state_log.append(
            {
                "state": state,
                "message": message,
                "level": level,
                "timestamp": datetime.utcnow().isoformat() + "Z",
            }
        )

    def sync_phase_tasks(self, phase: str, tasks: List[TaskItem]) -> None:
        previous = {task.ref: task for task in self.phase_tasks.get(phase, [])}
        merged: List[TaskItem] = []
        for task in tasks:
            current = previous.get(task.ref)
            if current:
                task.status = current.status
                task.note = current.note or task.note
                task.risk_level = current.risk_level or task.risk_level
                task.required_capability = current.required_capability or task.required_capability
                task.finding_key = current.finding_key or task.finding_key
            merged.append(task)
        self.phase_tasks[phase] = merged

    def mark_task(self, phase: str, task_ref: str, status: str, note: str = "") -> None:
        for task in self.phase_tasks.get(phase, []):
            if task.ref != task_ref:
                continue
            task.status = status
            if note:
                task.note = note
            return

    def phase_task_list(self, phase: str, *, only_open: bool = False) -> List[TaskItem]:
        tasks = list(self.phase_tasks.get(phase, []))
        if only_open:
            tasks = [task for task in tasks if task.status == "todo"]
        return tasks

    def phase_task_snapshot(self, phase: str, *, limit: int = 20) -> List[Dict[str, Any]]:
        tasks = self.phase_task_list(phase)[:limit]
        return [task.to_dict() for task in tasks]

    def set_phase_note(self, phase: str, note: str) -> None:
        self.phase_notes[phase] = note

    def add_artifact(
        self,
        *,
        parent_ref: Optional[str],
        phase: str,
        tool: str,
        kind: str,
        summary: str,
        raw_output_excerpt: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> EvidenceArtifact:
        metadata = metadata or {}
        artifact_id = hashlib.sha1(  # noqa: S324
            json.dumps(
                {
                    "parent_ref": parent_ref,
                    "phase": phase,
                    "tool": tool,
                    "kind": kind,
                    "summary": summary,
                    "raw_output_excerpt": raw_output_excerpt,
                    "metadata": metadata,
                },
                ensure_ascii=False,
                sort_keys=True,
                default=str,
            ).encode("utf-8")
        ).hexdigest()[:16]
        for artifact in self.evidence_artifacts:
            if artifact.artifact_id == artifact_id:
                return artifact
        artifact = EvidenceArtifact(
            artifact_id=artifact_id,
            parent_ref=parent_ref,
            phase=phase,
            tool=tool,
            kind=kind,
            summary=summary,
            content_hash=artifact_id,
            raw_output_excerpt=raw_output_excerpt[:1200],
            metadata=metadata,
        )
        self.evidence_artifacts.append(artifact)
        return artifact

    # ---- summary -----------------------------------------------------
    def sorted_findings(self) -> List[Finding]:
        return sorted(
            self.findings,
            key=lambda f: (SEVERITY_ORDER.get(f.severity.upper(), 0), STATUS_ORDER.get(f.status, 0)),
            reverse=True,
        )

    def to_dict(self) -> Dict[str, Any]:
        d = {
            "target": self.target,
            "started_at": self.started_at,
            "open_ports": self.open_ports,
            "technologies": self.technologies,
            "subdomains": self.subdomains,
            "discovered_paths": self.discovered_paths,
            "interesting_files": self.interesting_files,
            "forms": self.forms,
            "parameters": self.parameters,
            "findings": [f.to_dict() for f in self.sorted_findings()],
            "exploit_evidence": self.exploit_evidence,
            "evidence_artifacts": [artifact.to_dict() for artifact in self.evidence_artifacts],
            "tool_invocations": [asdict(t) for t in self.tool_invocations],
            "state_log": self.state_log,
            "phase_tasks": {phase: [task.to_dict() for task in tasks] for phase, tasks in self.phase_tasks.items()},
            "phase_notes": self.phase_notes,
            "attack_graph": self.attack_graph.to_dict() if self.attack_graph else {},
        }
        return d

    def compact_snapshot(self) -> Dict[str, Any]:
        """Trimmed view suitable for feeding back into the LLM each iteration."""
        return {
            "target": self.target,
            "open_ports": self.open_ports[:15],
            "technologies": self.technologies[:15],
            "subdomains": self.subdomains[:15],
            "discovered_paths": self.discovered_paths[:30],
            "interesting_files": self.interesting_files[:15],
            "forms_count": len(self.forms),
            "parameters": self.parameters[:20],
            "findings": [
                {
                    "title": f.title,
                    "severity": f.severity,
                    "status": f.status,
                    "category": f.category,
                    "url": f.url,
                    "parameter": f.parameter,
                    "cwe_id": f.cwe_id,
                    "owasp_category": f.owasp_category,
                    "cvss_score": f.cvss_score,
                }
                for f in self.sorted_findings()
            ],
            "recent_tool_invocations": [
                {
                    "state": inv.state,
                    "tool": inv.tool,
                    "task_ref": inv.task_ref,
                    "success": inv.success,
                    "summary": inv.summary,
                }
                for inv in self.tool_invocations[-10:]
            ],
            "phase_notes": dict(self.phase_notes),
        }
