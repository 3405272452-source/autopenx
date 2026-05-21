"""Penetration-test finite state machine orchestrating LLM + tool invocations."""
from __future__ import annotations

import asyncio
import logging
from typing import Any, Callable, Dict, List, Optional

from config.settings import RuntimeConfig, settings
from ..knowledge_base.vuln_patterns import SEVERITY_REMEDIATION, VULN_PATTERNS
from ..orchestrator import LLMOrchestrator, ReActStep
from ..tools.base import ToolResult
from .findings import Finding, StateFindings, TaskItem
from .ingester import ingest_tool_result


log = logging.getLogger("autopnex.fsm")


STATES = ["INIT", "RECON", "SCAN", "VULN_DETECT", "EXPLOIT", "REPORT", "DONE"]
NEXT_STATE = {
    "INIT": "RECON",
    "RECON": "SCAN",
    "SCAN": "VULN_DETECT",
    "VULN_DETECT": "EXPLOIT",
    "EXPLOIT": "REPORT",
    "REPORT": "DONE",
}


class PenTestStateMachine:
    """Drives the 5-phase PTES pipeline."""

    def __init__(
        self,
        target: str,
        orchestrator: Optional[LLMOrchestrator] = None,
        *,
        multi_agent: bool = False,
        max_iter_per_state: Optional[int] = None,
        progress_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
    ):
        self.target = target
        self.orchestrator = orchestrator or LLMOrchestrator()
        self.runtime: RuntimeConfig = getattr(self.orchestrator, "runtime_config", None) or settings.snapshot()
        self.multi_agent = multi_agent
        self.max_iter = max_iter_per_state or settings.max_iter_per_state
        self.findings = StateFindings(target=target)
        self.state = "INIT"
        self.steps: List[ReActStep] = []
        self._progress_cb = progress_callback or (lambda _e: None)
        if hasattr(self.orchestrator, "set_event_callback"):
            self.orchestrator.set_event_callback(self._forward_orchestrator_event)

    # ------------------------------------------------------------------
    def _emit(self, event: str, **payload: Any) -> None:
        data = {"event": event, "state": self.state, **payload}
        try:
            self._progress_cb(data)
        except Exception:  # noqa: BLE001
            log.debug("progress callback error", exc_info=True)

    def _forward_orchestrator_event(self, payload: Dict[str, Any]) -> None:
        event_name = payload.get("event", "tool_event")
        event_payload = {k: v for k, v in payload.items() if k != "event"}
        self._emit(event_name, **event_payload)

    # ------------------------------------------------------------------
    def run(self) -> StateFindings:
        if self.multi_agent:
            return self._run_multi_agent()
        return self._run_single_agent()

    def _run_single_agent(self) -> StateFindings:
        self._emit(
            "start",
            target=self.target,
            mode=self.orchestrator.mode,
            max_iter_per_state=self.max_iter,
        )
        self.findings.log_state("INIT", f"Pipeline started against {self.target} (mode={self.orchestrator.mode})")

        # INIT → Authenticate if login endpoint configured
        self._try_auto_login()

        # INIT → RECON (no LLM needed)
        self.state = NEXT_STATE["INIT"]

        for phase in ("RECON", "SCAN", "VULN_DETECT", "EXPLOIT"):
            self.state = phase
            self.orchestrator.reset_for_state(phase)
            self._prepare_phase(phase)
            self._emit("state_enter")
            self.findings.log_state(phase, f"Entering state {phase}")
            self._run_phase(phase)
            self._emit("state_exit")

        # REPORT
        self.state = "REPORT"
        self._emit("state_enter")
        self.findings.log_state("REPORT", "Entering state REPORT")
        self._emit("state_exit")

        self.state = "DONE"
        self.findings.log_state("DONE", "Pipeline finished")
        self._emit("done", findings=self.findings.to_dict())
        return self.findings

    def _run_multi_agent(self) -> StateFindings:
        from ..agents.blackboard import Blackboard
        from ..agents.coordinator import Coordinator
        from ..agents.base import all_agent_classes

        self._emit(
            "start",
            target=self.target,
            mode="multi_agent",
            max_iter_per_state=self.max_iter,
        )
        self.findings.log_state("INIT", f"Multi-agent pipeline started against {self.target}")

        blackboard = Blackboard(self.findings)
        max_concurrent = getattr(self.runtime, "max_concurrent_tools", 4)

        agents = {}
        for name, cls in all_agent_classes().items():
            agents[name] = cls(blackboard, self.runtime, max_concurrent=max_concurrent)

        coordinator = Coordinator(
            blackboard,
            agents,
            config=self.runtime,
            max_iter_per_state=self.max_iter,
            progress_callback=self._progress_cb,
        )

        loop = asyncio.new_event_loop()
        try:
            result_findings = loop.run_until_complete(coordinator.run_pipeline(self.target))
        finally:
            loop.close()

        self.findings = result_findings
        self.state = "DONE"
        self.findings.log_state("DONE", "Multi-agent pipeline finished")
        self._emit("done", findings=self.findings.to_dict())
        return self.findings

    def _effective_max_iter(self, phase: str) -> int:
        task_count = len(self.findings.phase_task_list(phase, only_open=True))
        return max(self.max_iter, task_count + 2)

    # ------------------------------------------------------------------
    def _run_phase(self, phase: str) -> None:
        open_tasks = self.findings.phase_task_list(phase, only_open=True)
        if not open_tasks:
            pending = [t for t in self.findings.phase_task_list(phase) if t.status == "pending_approval"]
            if pending:
                self._emit(
                    "phase_blocked",
                    phase=phase,
                    reason="all_tasks_pending_approval",
                    pending_count=len(pending),
                )
                self.findings.log_state(phase, f"All {len(pending)} tasks require approval — skipping phase", level="warn")
                return
        effective_max = self._effective_max_iter(phase)
        for iteration in range(1, effective_max + 1):
            snapshot = {
                "target": self.target,
                **self.findings.compact_snapshot(),
                "phase_tasks": self.findings.phase_task_snapshot(phase, limit=50),
            }
            known_finding_keys = self._finding_keys()
            known_statuses = self._finding_status_map()
            step = self.orchestrator.step(phase, snapshot, iteration, effective_max)
            self.steps.append(step)

            if step.tool:
                result: ToolResult = getattr(step, "_tool_result", None)  # type: ignore[attr-defined]
                if result is not None:
                    self.findings.record_invocation(phase, step.tool, step.arguments, result, task_ref=step.task_ref)
                    self._ingest_tool_result(phase, step.tool, step.arguments, result)
                    self.findings.mark_task(phase, step.task_ref or "", "done", result.summary)
                    artifact = self.findings.add_artifact(
                        parent_ref=step.task_ref,
                        phase=phase,
                        tool=step.tool,
                        kind="tool_result",
                        summary=result.summary,
                        raw_output_excerpt=result.raw_output,
                        metadata={"arguments": step.arguments, "success": result.success},
                    )
                    self._emit("artifact_ingested", artifact=artifact.to_dict())
                new_findings = self._new_findings(known_finding_keys)
                self._emit_finding_status_events(known_statuses)
                self._emit(
                    "react_step",
                    iteration=iteration,
                    tool=step.tool,
                    task_ref=step.task_ref,
                    arguments=step.arguments,
                    action=step.action,
                    reasoning=step.reasoning,
                    tool_summary=step.tool_summary,
                    tool_success=step.tool_success,
                    tool_duration_ms=step.tool_duration_ms,
                    tool_error=step.tool_error,
                    raw_output_excerpt=step.raw_output_excerpt,
                    parsed_data=step.parsed_data,
                    findings_count=len(self.findings.findings),
                    new_findings_count=len(new_findings),
                )
                if new_findings:
                    self._emit(
                        "finding_update",
                        iteration=iteration,
                        tool=step.tool,
                        findings_count=len(self.findings.findings),
                        new_findings=new_findings,
                    )
                self._emit_performance_snapshot()
                continue

            self._emit(
                "react_step",
                iteration=iteration,
                tool=step.tool,
                arguments=step.arguments,
                action=step.action,
                reasoning=step.reasoning,
                tool_summary=step.tool_summary,
                findings_count=len(self.findings.findings),
                new_findings_count=0,
                decision_error=step.decision_error,
            )

            if step.action in ("advance", "done"):
                break

        else:
            self.findings.log_state(phase, f"Max iterations ({effective_max}) reached — advancing", level="warn")

    # ------------------------------------------------------------------
    def _ingest_tool_result(
        self,
        phase: str,
        tool: str,
        arguments: Dict[str, Any],
        result: ToolResult,
    ) -> None:
        ingest_tool_result(self.findings, phase=phase, tool=tool, arguments=arguments, result=result)
        if tool == "sqli_exploit" and result.parsed_data.get("success"):
            self._mark_finding_status("SQL injection", result.parsed_data.get("url"), result.parsed_data.get("parameter"), "exploited")
        if tool == "finding_replay" and result.parsed_data.get("success"):
            self._mark_finding_status(
                result.parsed_data.get("finding_title"),
                result.parsed_data.get("url"),
                result.parsed_data.get("parameter"),
                "exploited",
            )

    # ------------------------------------------------------------------
    @property
    def severity_remediation(self) -> Dict[str, str]:
        return SEVERITY_REMEDIATION

    def _finding_keys(self) -> List[tuple[str, Optional[str], Optional[str]]]:
        return [(f.title, f.url, f.parameter) for f in self.findings.findings]

    def _new_findings(self, previous_keys: List[tuple[str, Optional[str], Optional[str]]]) -> List[Dict[str, Any]]:
        previous = set(previous_keys)
        return [
            finding.to_dict()
            for finding in self.findings.sorted_findings()
            if (finding.title, finding.url, finding.parameter) not in previous
        ]

    def _finding_status_map(self) -> Dict[tuple[str, Optional[str], Optional[str]], str]:
        return {(f.title, f.url, f.parameter): f.status for f in self.findings.findings}

    def _emit_finding_status_events(self, previous: Dict[tuple[str, Optional[str], Optional[str]], str]) -> None:
        for finding in self.findings.findings:
            key = (finding.title, finding.url, finding.parameter)
            before = previous.get(key)
            if before is None or before != finding.status:
                event_name = "finding_confirmed" if finding.status == "confirmed" else "finding_status_changed"
                self._emit(event_name, finding=finding.to_dict())

    def _emit_performance_snapshot(self) -> None:
        invocations = self.findings.tool_invocations
        total_duration = sum(inv.duration_ms for inv in invocations)
        self._emit(
            "performance_snapshot",
            total_invocations=len(invocations),
            total_duration_ms=total_duration,
            average_duration_ms=int(total_duration / len(invocations)) if invocations else 0,
            findings_count=len(self.findings.findings),
            artifact_count=len(self.findings.evidence_artifacts),
        )

    def _prepare_phase(self, phase: str) -> None:
        tasks = self._plan_phase_tasks(phase)
        self.findings.sync_phase_tasks(phase, tasks)
        self._emit("phase_tasks_synced", phase=phase, tasks=[task.to_dict() for task in tasks])
        if phase == "EXPLOIT":
            planned = [task.to_dict() for task in tasks]
            if planned:
                self._emit("exploit_planned", tasks=planned)
                if not self.runtime.exploit_enabled:
                    self._emit("approval_required", required_capability="exploit", tasks=planned)

    def _plan_phase_tasks(self, phase: str) -> List[TaskItem]:
        if phase == "RECON":
            tasks = [
                TaskItem(ref="recon:port_scan", phase=phase, tool="port_scan", title="TCP 端口快速扫描", arguments={"target": self.target}),
                TaskItem(ref="recon:tech_detect", phase=phase, tool="tech_detect", title="识别技术栈与安全响应头", arguments={"target": self.target}),
                TaskItem(ref="recon:subdomain_find", phase=phase, tool="subdomain_find", title="被动子域名枚举", arguments={"domain": self._target_host(), "limit": 30}),
                TaskItem(ref="recon:headers_audit", phase=phase, tool="headers_audit", title="安全响应头全面审计", arguments={"target": self.target}),
            ]
            if self.runtime.allow_external_tools:
                tasks.append(
                    TaskItem(
                        ref="recon:nmap_scan",
                        phase=phase,
                        tool="nmap_scan",
                        title="Nmap 高吞吐端口与服务识别",
                        arguments={"target": self.target, "top_ports": 100},
                        risk_level="medium",
                        required_capability="active_scan",
                    )
                )
            # Docker-backed: gowitness screenshots
            if getattr(self.runtime, "docker_enabled", False):
                tasks.append(
                    TaskItem(
                        ref="recon:gowitness",
                        phase=phase,
                        tool="gowitness",
                        title="目标页面截图 (gowitness)",
                        arguments={"target": self.target},
                        risk_level="low",
                        required_capability="active_scan",
                    )
                )
            return tasks

        if phase == "SCAN":
            tasks = [
                TaskItem(ref="scan:web_scan", phase=phase, tool="web_scan", title="敏感文件与响应头扫描", arguments={"target": self.target}),
                TaskItem(ref="scan:dir_buster", phase=phase, tool="dir_buster", title="内置目录爆破", arguments={"target": self.target}),
                TaskItem(ref="scan:crawl", phase=phase, tool="crawl", title="页面与参数爬取", arguments={"target": self.target, "max_pages": 20, "max_depth": 2}),
                TaskItem(ref="scan:js_analyze", phase=phase, tool="js_analyze", title="JavaScript 安全分析", arguments={"target": self.target}),
            ]
            if self.runtime.allow_external_tools:
                tasks.extend(
                    [
                        TaskItem(
                            ref="scan:ffuf_scan",
                            phase=phase,
                            tool="ffuf_scan",
                            title="ffuf 高速内容发现",
                            arguments={"target": self.target},
                            risk_level="medium",
                            required_capability="active_scan",
                        ),
                        TaskItem(
                            ref="scan:burp_proxy_scan",
                            phase=phase,
                            tool="burp_proxy_scan",
                            title="通过 Burp 代理重放目标请求",
                            arguments={"target": self.target, "method": "GET"},
                            risk_level="medium",
                            required_capability="active_scan",
                        ),
                    ]
                )
            return tasks

        if phase == "VULN_DETECT":
            tasks: List[TaskItem] = []
            for index, parameter in enumerate(self.findings.parameters[:12]):
                base_args = {"url": parameter["url"], "parameter": parameter["name"], "method": parameter.get("method", "GET")}
                for tool in ("sqli_detect", "xss_detect", "cmdi_detect", "ssrf_detect"):
                    tasks.append(
                        TaskItem(
                            ref=f"vuln:{tool}:{index}",
                            phase=phase,
                            tool=tool,
                            title=f"{tool} 检测 {parameter['name']}",
                            arguments=base_args,
                        )
                    )
                ctf_args = {"url": parameter["url"], "param": parameter["name"], "method": parameter.get("method", "GET")}
                for tool in ("ssti_detect", "lfi_detect", "unserialize_detect"):
                    tasks.append(
                        TaskItem(
                            ref=f"vuln:{tool}:{index}",
                            phase=phase,
                            tool=tool,
                            title=f"{tool} CTF 专项检测 {parameter['name']}",
                            arguments=ctf_args,
                            risk_level="medium",
                        )
                    )
                if self.runtime.allow_external_tools:
                    tasks.append(
                        TaskItem(
                            ref=f"vuln:sqlmap_scan:{index}",
                            phase=phase,
                            tool="sqlmap_scan",
                            title=f"sqlmap 定向确认 {parameter['name']}",
                            arguments=base_args,
                            risk_level="high",
                            required_capability="active_scan",
                        )
                    )
            # Advanced fuzzing on discovered parameters
            for index, parameter in enumerate(self.findings.parameters[:6]):
                tasks.append(
                    TaskItem(
                        ref=f"vuln:param_fuzzer:{index}",
                        phase=phase,
                        tool="param_fuzzer",
                        title=f"高级参数 Fuzz {parameter['name']}",
                        arguments={"url": parameter["url"], "parameter": parameter["name"], "method": parameter.get("method", "GET")},
                        risk_level="medium",
                    )
                )
            # IDOR testing
            tasks.append(
                TaskItem(
                    ref="vuln:idor_test",
                    phase=phase,
                    tool="idor_test",
                    title="IDOR 自动发现与测试",
                    arguments={"target": self.target},
                    risk_level="high",
                    required_capability="exploit",
                )
            )
            # Rate limit & race condition testing
            tasks.append(
                TaskItem(
                    ref="vuln:rate_limit_test",
                    phase=phase,
                    tool="rate_limit_test",
                    title="限速与竞态条件测试",
                    arguments={"target": self.target, "action": "burst", "requests_count": 30},
                    risk_level="medium",
                )
            )
            # Business logic audit
            tasks.append(
                TaskItem(
                    ref="vuln:logic_audit",
                    phase=phase,
                    tool="logic_audit",
                    title="业务逻辑漏洞审计",
                    arguments={"target": self.target},
                    risk_level="medium",
                )
            )
            # Docker-backed: nuclei template scan
            if getattr(self.runtime, "docker_enabled", False):
                tasks.append(
                    TaskItem(
                        ref="vuln:nuclei_scan",
                        phase=phase,
                        tool="nuclei_scan",
                        title="Nuclei 模板扫描",
                        arguments={"target": self.target},
                        risk_level="high",
                        required_capability="active_scan",
                    )
                )
            return tasks

        if phase == "EXPLOIT":
            tasks = []
            for index, finding in enumerate(self.findings.sorted_findings()):
                if finding.status not in {"confirmed", "exploitable", "exploited"}:
                    continue
                task_status = "todo" if self.runtime.exploit_enabled else "pending_approval"
                finding_key = f"{finding.title}|{finding.url or ''}|{finding.parameter or ''}"
                if finding.category == "sqli":
                    tasks.append(
                        TaskItem(
                            ref=f"exploit:sqli:{index}",
                            phase=phase,
                            tool="sqli_exploit",
                            title="SQLi 利用与数据库指纹提取",
                            arguments={"url": finding.url, "parameter": finding.parameter, "method": "GET"},
                            status=task_status,
                            risk_level="high",
                            required_capability="exploit",
                            finding_key=finding_key,
                        )
                    )
                elif finding.category == "xss":
                    tasks.append(
                        TaskItem(
                            ref=f"exploit:xss:{index}",
                            phase=phase,
                            tool="xss_exploit",
                            title="XSS 利用与 Cookie 可见性验证",
                            arguments={"url": finding.url, "parameter": finding.parameter, "method": "GET"},
                            status=task_status,
                            risk_level="high",
                            required_capability="exploit",
                            finding_key=finding_key,
                        )
                    )
                elif finding.payload and finding.url:
                    tasks.append(
                        TaskItem(
                            ref=f"exploit:replay:{index}",
                            phase=phase,
                            tool="finding_replay",
                            title=f"重放已确认漏洞载荷：{finding.title}",
                            arguments={
                                "url": finding.url,
                                "parameter": finding.parameter,
                                "payload": finding.payload,
                                "method": "GET",
                                "finding_title": finding.title,
                            },
                            status=task_status,
                            risk_level="high",
                            required_capability="exploit",
                            finding_key=finding_key,
                        )
                    )

            task_status = "todo" if self.runtime.exploit_enabled else "pending_approval"

            # --- Browser test: SPA deep testing ---
            if getattr(self.runtime, "browser_testing", True):
                tasks.append(
                    TaskItem(
                        ref="exploit:browser_test",
                        phase=phase,
                        tool="browser_test",
                        title="浏览器自动化深度测试 (SPA/XSS/DOM)",
                        arguments={"target": self.target},
                        status=task_status,
                        risk_level="high",
                        required_capability="exploit",
                    )
                )

            tasks.append(
                TaskItem(
                    ref="exploit:flag_reader",
                    phase=phase,
                    tool="flag_reader",
                    title="CTF 常见 Flag 路径读取与验证",
                    arguments={"url": self.target},
                    status=task_status,
                    risk_level="high",
                    required_capability="exploit",
                )
            )

            # --- Docker-backed: hydra brute force ---
            if getattr(self.runtime, "docker_enabled", False):
                _login_keywords_hydra = {"login", "signin", "auth"}
                for form in self.findings.forms:
                    form_action = (form.get("action") or "").lower()
                    field_names = " ".join(f.get("name", "") for f in form.get("fields", [])).lower()
                    if any(kw in form_action or kw in field_names for kw in _login_keywords_hydra):
                        tasks.append(
                            TaskItem(
                                ref="exploit:hydra_crack",
                                phase=phase,
                                tool="hydra_crack",
                                title="Hydra 暴力破解",
                                arguments={"target": form.get("action") or self.target, "service": "http-post-form"},
                                status=task_status,
                                risk_level="high",
                                required_capability="exploit",
                            )
                        )
                        break

            # --- Auth bypass: probe login-like forms with default credentials ---
            _login_keywords = {"login", "signin", "auth", "session"}
            auth_bypass_count = 0
            for form in self.findings.forms:
                if auth_bypass_count >= 2:
                    break
                form_action = (form.get("action") or "").lower()
                field_names = " ".join(f.get("name", "") for f in form.get("fields", [])).lower()
                if any(kw in form_action or kw in field_names for kw in _login_keywords):
                    form_url = form.get("action") or self.target
                    tasks.append(
                        TaskItem(
                            ref=f"exploit:auth_bypass:{auth_bypass_count}",
                            phase=phase,
                            tool="auth_bypass",
                            title="认证绕过与默认凭证测试",
                            arguments={"url": form_url},
                            status=task_status,
                            risk_level="high",
                            required_capability="exploit",
                        )
                    )
                    auth_bypass_count += 1

            # --- File upload exploit: probe forms with file input fields ---
            file_upload_count = 0
            for form in self.findings.forms:
                if file_upload_count >= 2:
                    break
                has_file = any(
                    f.get("type", "").lower() == "file" for f in form.get("fields", [])
                ) or (form.get("enctype") or "").lower() == "multipart/form-data"
                if has_file:
                    form_url = form.get("action") or self.target
                    tasks.append(
                        TaskItem(
                            ref=f"exploit:file_upload:{file_upload_count}",
                            phase=phase,
                            tool="file_upload_exploit",
                            title="文件上传漏洞利用",
                            arguments={"url": form_url},
                            status=task_status,
                            risk_level="high",
                            required_capability="exploit",
                        )
                    )
                    file_upload_count += 1

            # --- Privilege escalation: IDOR on user/object-reference parameters ---
            _idor_keywords = {"id", "user", "uid", "account", "profile", "role"}
            privesc_count = 0
            for param in self.findings.parameters:
                if privesc_count >= 2:
                    break
                param_name = (param.get("name") or "").lower()
                if any(kw in param_name for kw in _idor_keywords):
                    tasks.append(
                        TaskItem(
                            ref=f"exploit:privesc:{privesc_count}",
                            phase=phase,
                            tool="privilege_escalation",
                            title="IDOR / 权限提升测试",
                            arguments={"url": self.target},
                            status=task_status,
                            risk_level="high",
                            required_capability="exploit",
                        )
                    )
                    privesc_count += 1

            return tasks
        return []

    def _target_host(self) -> str:
        from urllib.parse import urlparse

        return urlparse(self.target if "://" in self.target else f"http://{self.target}").hostname or self.target

    def _try_auto_login(self) -> None:
        """Attempt automatic login if a login endpoint is configured."""
        from ..tools._http import login_before_scan

        login_ep = self.runtime.login_endpoint
        if not login_ep:
            return

        cred_str = self.runtime.login_credentials or "admin:password,admin:admin,root:root"
        credentials = []
        for pair in cred_str.split(","):
            pair = pair.strip()
            if ":" in pair:
                u, p = pair.split(":", 1)
                credentials.append((u.strip(), p.strip()))

        self._emit("login_attempt", target=self.target, endpoint=login_ep)
        success, msg = login_before_scan(
            target=self.target,
            login_endpoint=login_ep,
            username_field=self.runtime.login_username_field or "username",
            password_field=self.runtime.login_password_field or "password",
            credentials_list=credentials or None,
            csrf_field=self.runtime.csrf_field or None,
        )
        if success:
            self.findings.log_state("INIT", f"Auto-login succeeded: {msg}")
            self._emit("login_success", message=msg)
        else:
            self.findings.log_state("INIT", f"Auto-login failed: {msg}", level="warn")
            self._emit("login_failed", message=msg)

    def _mark_finding_status(self, title: str | None, url: str | None, parameter: str | None, status: str) -> None:
        for finding in self.findings.findings:
            if finding.title == title and finding.url == url and finding.parameter == parameter:
                finding.status = status
                return
