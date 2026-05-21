"""Background scan runner used by the FastAPI web UI.

Each scan is run in a worker thread; progress events are pushed into a queue so
the API can stream them via Server-Sent Events.
"""
from __future__ import annotations

import json
import queue
import threading
import uuid
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Deque, Dict, Optional

from config.settings import RuntimeConfig, settings
from ..orchestrator import LLMOrchestrator
from ..orchestrator.llm_client import LLMClient
from ..report import ReportGenerator
from ..state_machine import PenTestStateMachine
from ..state_machine.findings import StateFindings


REPORTS_DIR = Path("reports")
REPORTS_DIR.mkdir(exist_ok=True)


@dataclass
class ScanJob:
    id: str
    target: str
    mock: bool
    runtime_config: RuntimeConfig
    status: str = "pending"  # pending | running | done | error
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    events: "queue.Queue[Dict[str, Any]]" = field(default_factory=queue.Queue)
    # 防止长任务时事件无限累积导致 OOM/进程被系统结束；超限丢弃最旧记录（不影响实时 SSE）
    history: Deque[Dict[str, Any]] = field(
        default_factory=lambda: deque(maxlen=10_000)
    )
    findings: Optional[StateFindings] = None
    error: Optional[str] = None
    markdown_path: Optional[str] = None
    html_path: Optional[str] = None
    thread: Optional[threading.Thread] = None
    orchestrator_mode: Optional[str] = None
    _event_seq: int = 0

    def push(self, event: Dict[str, Any]) -> None:
        self._event_seq += 1
        event = {"ts": datetime.utcnow().isoformat() + "Z", "seq": self._event_seq, **event}
        self.history.append(event)
        self.events.put(event)


class ScanManager:
    def __init__(self) -> None:
        self._jobs: Dict[str, ScanJob] = {}
        self._lock = threading.Lock()

    def start(
        self,
        target: str,
        *,
        mock: bool = False,
        max_iter: Optional[int] = None,
        runtime_config: Optional[RuntimeConfig] = None,
    ) -> ScanJob:
        runtime = runtime_config or settings.snapshot()
        job = ScanJob(id=uuid.uuid4().hex[:12], target=target, mock=mock, runtime_config=runtime)
        with self._lock:
            self._jobs[job.id] = job
        thread = threading.Thread(
            target=self._run, args=(job, max_iter), daemon=True, name=f"scan-{job.id}"
        )
        job.thread = thread
        thread.start()
        return job

    def get(self, job_id: str) -> Optional[ScanJob]:
        return self._jobs.get(job_id)

    def list(self) -> list:
        return [
            {
                "id": j.id,
                "target": j.target,
                "status": j.status,
                "created_at": j.created_at,
                "findings_count": len(j.findings.findings) if j.findings else 0,
                "mode": j.orchestrator_mode or ("mock" if j.mock or not j.runtime_config.has_llm else "llm"),
            }
            for j in self._jobs.values()
        ]

    # ------------------------------------------------------------------
    def _run(self, job: ScanJob, max_iter: Optional[int]) -> None:
        job.status = "running"
        job.push(
            {
                "event": "job_running",
                "mode": "mock" if job.mock or not job.runtime_config.has_llm else "llm",
                "config": job.runtime_config.to_client_dict(),
            }
        )
        try:
            client = LLMClient(
                api_key=job.runtime_config.deepseek_api_key,
                base_url=job.runtime_config.deepseek_base_url,
                model=job.runtime_config.deepseek_model,
            )
            orchestrator = LLMOrchestrator(mock=job.mock, client=client, runtime_config=job.runtime_config)
            fsm = PenTestStateMachine(
                target=job.target,
                orchestrator=orchestrator,
                max_iter_per_state=max_iter or job.runtime_config.max_iter_per_state,
                progress_callback=job.push,
            )
            findings = fsm.run()
            job.findings = findings
            job.orchestrator_mode = orchestrator.mode

            job.push({"event": "report_generating", "message": "正在生成渗透测试报告..."})

            generator = ReportGenerator(client, mode=orchestrator.mode)
            md_path = REPORTS_DIR / f"{job.id}.md"
            html_path = REPORTS_DIR / f"{job.id}.html"
            generator.save(findings, md_path, html_path)
            job.markdown_path = str(md_path)
            job.html_path = str(html_path)
            job.status = "done"
            job.push(
                {
                    "event": "job_done",
                    "mode": orchestrator.mode,
                    "findings_count": len(findings.findings),
                    "markdown_path": str(md_path),
                    "html_path": str(html_path),
                }
            )
        except Exception as exc:  # noqa: BLE001
            job.status = "error"
            job.error = f"{exc.__class__.__name__}: {exc}"
            job.push({"event": "job_error", "error": job.error})


manager = ScanManager()


def event_to_sse(event: Dict[str, Any]) -> str:
    seq = event.get("seq", "")
    return f"id: {seq}\ndata: {json.dumps(event, ensure_ascii=False, default=str)}\n\n"
