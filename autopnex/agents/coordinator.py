"""Pipeline coordinator that dispatches tasks to specialist agents."""
from __future__ import annotations

import logging
from typing import Any, Callable, Dict, List, Optional

from config.settings import RuntimeConfig
from ..state_machine.findings import StateFindings, TaskItem
from .blackboard import Blackboard
from .base import AgentResult, BaseAgent

log = logging.getLogger("autopnex.agents.coordinator")


PHASE_AGENT_MAP: Dict[str, str] = {
    "RECON": "ReconAgent",
    "SCAN": "ScanAgent",
    "VULN_DETECT": "VulnDetectAgent",
    "EXPLOIT": "ExploitAgent",
    "REPORT": "ReportAgent",
}

PHASE_ORDER = ("RECON", "SCAN", "VULN_DETECT", "EXPLOIT", "REPORT")


class Coordinator:
    """Drives the multi-agent pipeline by delegating each phase to its
    specialist agent.

    The coordinator owns the planning logic (reused from the state-machine's
    ``_plan_phase_tasks``) and the phase-to-agent dispatch.
    """

    def __init__(
        self,
        blackboard: Blackboard,
        agents: Dict[str, BaseAgent],
        *,
        config: RuntimeConfig,
        max_iter_per_state: int = 6,
        progress_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
    ) -> None:
        self.blackboard = blackboard
        self.agents = agents
        self.config = config
        self.max_iter_per_state = max_iter_per_state
        self._progress_cb = progress_callback or (lambda _e: None)

    # -- public API ---------------------------------------------------------

    async def run_pipeline(self, target: str) -> StateFindings:
        """Execute the full PTES pipeline across specialist agents."""
        self._emit("pipeline_start", target=target)

        for phase in PHASE_ORDER:
            self._emit("phase_enter", phase=phase)
            tasks = self._plan_phase(phase, target)

            self.blackboard.write(
                lambda f, ph=phase, ts=tasks: f.sync_phase_tasks(ph, ts)
            )
            self._emit("phase_tasks_synced", phase=phase, task_count=len(tasks))

            agent_name = PHASE_AGENT_MAP.get(phase)
            agent = self.agents.get(agent_name) if agent_name else None

            if agent is None:
                log.warning("No agent registered for phase %s (%s)", phase, agent_name)
                self._emit("phase_skip", phase=phase, reason="no_agent")
                continue

            result: AgentResult = await agent.execute(tasks)
            self._handle_result(phase, result)
            self._emit("phase_exit", phase=phase, result=result.__dict__)

        self._emit("pipeline_done")
        return self.blackboard.full_findings()

    # -- planning -----------------------------------------------------------

    def _plan_phase(self, phase: str, target: str) -> List[TaskItem]:
        """Produce task items for a given phase.

        This mirrors ``PenTestStateMachine._plan_phase_tasks`` so the same
        tools are scheduled regardless of single-agent vs multi-agent mode.
        """
        findings = self.blackboard.full_findings()
        host = _target_host(target)

        if phase == "RECON":
            tasks = [
                TaskItem(ref="recon:port_scan", phase=phase, tool="port_scan", title="TCP port scan", arguments={"target": target}),
                TaskItem(ref="recon:tech_detect", phase=phase, tool="tech_detect", title="Technology detection", arguments={"target": target}),
                TaskItem(ref="recon:subdomain_find", phase=phase, tool="subdomain_find", title="Subdomain enumeration", arguments={"domain": host, "limit": 30}),
            ]
            if self.config.allow_external_tools:
                tasks.append(
                    TaskItem(
                        ref="recon:nmap_scan", phase=phase, tool="nmap_scan",
                        title="Nmap service scan",
                        arguments={"target": target, "top_ports": 100},
                        risk_level="medium", required_capability="active_scan",
                    )
                )
            return tasks

        if phase == "SCAN":
            tasks = [
                TaskItem(ref="scan:web_scan", phase=phase, tool="web_scan", title="Sensitive file scan", arguments={"target": target}),
                TaskItem(ref="scan:dir_buster", phase=phase, tool="dir_buster", title="Directory brute-force", arguments={"target": target}),
                TaskItem(ref="scan:crawl", phase=phase, tool="crawl", title="Crawl pages and parameters", arguments={"target": target, "max_pages": 20, "max_depth": 2}),
            ]
            if self.config.allow_external_tools:
                tasks.extend([
                    TaskItem(
                        ref="scan:ffuf_scan", phase=phase, tool="ffuf_scan",
                        title="ffuf content discovery",
                        arguments={"target": target},
                        risk_level="medium", required_capability="active_scan",
                    ),
                    TaskItem(
                        ref="scan:burp_proxy_scan", phase=phase, tool="burp_proxy_scan",
                        title="Burp proxy replay",
                        arguments={"target": target, "method": "GET"},
                        risk_level="medium", required_capability="active_scan",
                    ),
                ])
            return tasks

        if phase == "VULN_DETECT":
            tasks: List[TaskItem] = []
            for idx, param in enumerate(findings.parameters[:12]):
                base_args = {"url": param["url"], "parameter": param["name"], "method": param.get("method", "GET")}
                for tool in ("sqli_detect", "xss_detect", "cmdi_detect", "ssrf_detect"):
                    tasks.append(
                        TaskItem(
                            ref=f"vuln:{tool}:{idx}", phase=phase, tool=tool,
                            title=f"{tool} on {param['name']}",
                            arguments=base_args,
                        )
                    )
                if self.config.allow_external_tools:
                    tasks.append(
                        TaskItem(
                            ref=f"vuln:sqlmap_scan:{idx}", phase=phase, tool="sqlmap_scan",
                            title=f"sqlmap confirm {param['name']}",
                            arguments=base_args,
                            risk_level="high", required_capability="active_scan",
                        )
                    )
            return tasks

        if phase == "EXPLOIT":
            tasks = []
            for idx, finding in enumerate(findings.sorted_findings()):
                if finding.status not in {"confirmed", "exploitable", "exploited"}:
                    continue
                task_status = "todo" if self.config.exploit_enabled else "pending_approval"
                finding_key = f"{finding.title}|{finding.url or ''}|{finding.parameter or ''}"
                if finding.category == "sqli":
                    tasks.append(
                        TaskItem(
                            ref=f"exploit:sqli:{idx}", phase=phase, tool="sqli_exploit",
                            title="SQLi exploitation",
                            arguments={"url": finding.url, "parameter": finding.parameter, "method": "GET"},
                            status=task_status, risk_level="high",
                            required_capability="exploit", finding_key=finding_key,
                        )
                    )
                elif finding.payload and finding.url:
                    tasks.append(
                        TaskItem(
                            ref=f"exploit:replay:{idx}", phase=phase, tool="finding_replay",
                            title=f"Replay: {finding.title}",
                            arguments={
                                "url": finding.url, "parameter": finding.parameter,
                                "payload": finding.payload, "method": "GET",
                                "finding_title": finding.title,
                            },
                            status=task_status, risk_level="high",
                            required_capability="exploit", finding_key=finding_key,
                        )
                    )
            return tasks

        if phase == "REPORT":
            return []

        return []

    # -- result handling ----------------------------------------------------

    def _handle_result(self, phase: str, result: AgentResult) -> None:
        log.info(
            "Phase %s finished: %d completed, %d failed in %d ms",
            phase, result.tasks_completed, result.tasks_failed, result.duration_ms,
        )
        if result.error:
            self.blackboard.write(
                lambda f, ph=phase, err=result.error: f.log_state(ph, f"Agent error: {err}", level="error")
            )

    # -- events -------------------------------------------------------------

    def _emit(self, event: str, **payload: Any) -> None:
        data = {"event": event, **payload}
        try:
            self._progress_cb(data)
        except Exception:  # noqa: BLE001
            log.debug("coordinator progress callback error", exc_info=True)


def _target_host(target: str) -> str:
    from urllib.parse import urlparse
    return urlparse(target if "://" in target else f"http://{target}").hostname or target
