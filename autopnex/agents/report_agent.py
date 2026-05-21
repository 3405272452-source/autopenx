"""Report specialist — generates the final penetration-test report."""
from __future__ import annotations

import logging
import time
from typing import List

from ..state_machine.findings import TaskItem
from .base import AgentResult, AgentStatus, BaseAgent, register_agent

log = logging.getLogger("autopnex.agents.report")


@register_agent
class ReportAgent(BaseAgent):
    name = "ReportAgent"
    tool_categories: list = []

    async def execute(self, tasks: List[TaskItem]) -> AgentResult:
        self.status = AgentStatus.RUNNING
        self._emit("phase_start", phase="REPORT", task_count=len(tasks))
        start = time.perf_counter_ns()

        snapshot = self.blackboard.snapshot()
        findings_obj = self.blackboard.full_findings()

        report_data = {
            "target": findings_obj.target,
            "started_at": findings_obj.started_at,
            "findings": [f.to_dict() for f in findings_obj.sorted_findings()],
            "exploit_evidence": findings_obj.exploit_evidence,
            "evidence_artifacts": [a.to_dict() for a in findings_obj.evidence_artifacts],
            "open_ports": findings_obj.open_ports,
            "technologies": findings_obj.technologies,
            "subdomains": findings_obj.subdomains,
            "discovered_paths": findings_obj.discovered_paths,
        }

        def _mutate(findings):
            findings.log_state("REPORT", "Multi-agent report generated")
            findings.set_phase_note("REPORT", f"Report contains {len(report_data['findings'])} findings")

        self.blackboard.write(_mutate)

        self._emit(
            "report_generated",
            findings_count=len(report_data["findings"]),
            artifact_count=len(report_data["evidence_artifacts"]),
        )

        self.status = AgentStatus.DONE
        self._emit("phase_done", phase="REPORT", completed=1, failed=0)
        return self._timed_result(start, completed=1, failed=0)
