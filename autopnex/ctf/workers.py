"""CTF Worker implementations for multi-agent concurrency (Phase 6).

Provides concrete worker classes that run in background threads,
claim tasks from the AgentPool/TaskQueue, and feed results back
into the Consensus layer.

Usage (from CTFReActAgent):
    context = WorkerContext(target=..., session=..., tool_router=..., ...)
    recon = ReconWorker(wid, agent_pool, task_queue, context)
    recon.start()
    ...submit tasks...
    recon.stop()
"""
from __future__ import annotations

import json
import logging
import re
import threading
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional

from .agent_pool import AgentPool
from .critic import Critic
from .fuse_controller import FuseController
from .shared_journal import SharedJournal
from .strategy import StrategyEngine
from .task_queue import CTFTask, TaskQueue
from .tool_router import ToolRouter

log = logging.getLogger("autopnex.ctf.workers")


# ---------------------------------------------------------------------------
# WorkerContext
# ---------------------------------------------------------------------------

@dataclass
class WorkerContext:
    """Injectable dependencies for workers."""

    target: str
    session: Any  # requests.Session
    tool_router: ToolRouter
    journal: SharedJournal
    strategy: StrategyEngine
    flag_engine: Any  # FlagEngine
    runtime_config: Any  # RuntimeConfig
    critic: Optional[Critic] = None
    fuse: Optional[FuseController] = None

    def check_flag(self, text: str) -> Optional[str]:
        """Scan text for flags via FlagEngine."""
        if not text:
            return None
        candidates = self.flag_engine.scan(text)
        if candidates:
            return candidates[0].value
        return None


# ---------------------------------------------------------------------------
# BaseCTFWorker
# ---------------------------------------------------------------------------

class BaseCTFWorker(threading.Thread):
    """Background thread that claims tasks and executes them."""

    def __init__(
        self,
        worker_id: str,
        role: str,
        agent_pool: AgentPool,
        task_queue: TaskQueue,
        context: WorkerContext,
        poll_interval: float = 0.5,
    ) -> None:
        super().__init__(name=f"CTFWorker-{role}-{worker_id[:6]}", daemon=True)
        self.worker_id = worker_id
        self.role = role
        self.agent_pool = agent_pool
        self.task_queue = task_queue
        self.ctx = context
        self.poll_interval = poll_interval
        self._shutdown_event = threading.Event()

    def stop(self, timeout: float = 5.0) -> None:
        """Signal stop and join thread."""
        self._shutdown_event.set()
        self.join(timeout=timeout)
        if self.is_alive():
            log.warning("Worker %s did not stop within %.1fs", self.worker_id, timeout)

    def run(self) -> None:
        log.info("Worker %s started (role=%s)", self.worker_id, self.role)
        while not self._shutdown_event.is_set():
            try:
                task = self.agent_pool.claim_task(
                    self.worker_id,
                    allowed_kinds={self.role},
                    lease_seconds=30.0,
                )
            except Exception as exc:  # noqa: BLE001
                log.warning("Worker %s claim_task error: %s", self.worker_id, exc)
                time.sleep(self.poll_interval)
                continue

            if not task:
                time.sleep(self.poll_interval)
                continue

            try:
                result = self._execute_task(task)
                self.agent_pool.complete_task(self.worker_id, task.id, result)
            except Exception as exc:
                log.exception("Worker %s task %s failed: %s", self.worker_id, task.id, exc)
                self.agent_pool.fail_task(self.worker_id, task.id, str(exc))

        log.info("Worker %s stopped", self.worker_id)

    def _execute_task(self, task: CTFTask) -> Dict[str, Any]:
        raise NotImplementedError


# ---------------------------------------------------------------------------
# ReconWorker
# ---------------------------------------------------------------------------

class ReconWorker(BaseCTFWorker):
    """Independent reconnaissance: forms, JS, headers, endpoints, crypto hints."""

    def _execute_task(self, task: CTFTask) -> Dict[str, Any]:
        payload = task.payload
        url = payload.get("url", self.ctx.target)
        method = payload.get("method", "GET")
        allow_redirects = payload.get("allow_redirects", True)

        # Execute via tool_router so the same session / interceptors apply
        result = self.ctx.tool_router.execute(
            "http_request",
            {
                "url": url,
                "method": method,
                "allow_redirects": allow_redirects,
            },
        )

        body = str(result.get("body") or "")
        headers = result.get("headers", {})
        status = result.get("status_code")

        findings: Dict[str, Any] = {
            "url": url,
            "status_code": status,
        }

        # Form discovery
        if "<form" in body.lower():
            findings["has_forms"] = True
            # Extract form actions
            actions = re.findall(r'<form[^>]+action=["\']?([^"\'>\s]+)', body, re.IGNORECASE)
            if actions:
                findings["form_actions"] = list(set(actions))

        # JS references
        js_refs = re.findall(r'src=["\']?([^"\'>\s]+\.js)', body, re.IGNORECASE)
        if js_refs:
            findings["js_references"] = list(set(js_refs))

        # API endpoints
        api_patterns = re.findall(r'["\'](/api/[^"\'\s]+)["\']', body)
        if api_patterns:
            findings["api_endpoints"] = list(set(api_patterns))

        # Crypto / encoding hints
        from .diagnostics import extract_crypto_hints
        crypto = extract_crypto_hints(body)
        if crypto:
            findings["crypto_hints"] = crypto

        # Check flag
        flag = self.ctx.check_flag(body)
        if flag:
            findings["flag"] = flag

        # Server technology hints
        server = headers.get("Server") or headers.get("X-Powered-By")
        if server:
            findings["server_tech"] = server

        return findings


# ---------------------------------------------------------------------------
# WebExploitWorker
# ---------------------------------------------------------------------------

class WebExploitWorker(BaseCTFWorker):
    """Authorized route execution: runs exploit payloads in parallel."""

    def _execute_task(self, task: CTFTask) -> Dict[str, Any]:
        payload = task.payload
        url = payload.get("url", self.ctx.target)
        method = payload.get("method", "GET")
        params = payload.get("params")
        data = payload.get("data")
        headers = payload.get("headers")
        route = task.route

        tool_args: Dict[str, Any] = {
            "url": url,
            "method": method,
        }
        if params is not None:
            tool_args["params"] = params
        if data is not None:
            tool_args["data"] = data
        if headers is not None:
            tool_args["headers"] = headers

        result = self.ctx.tool_router.execute("http_request", tool_args)
        body = str(result.get("body") or "")

        findings: Dict[str, Any] = {
            "url": url,
            "status_code": result.get("status_code"),
            "route": route,
        }

        # Flag check
        flag = self.ctx.check_flag(body)
        if flag:
            findings["flag"] = flag

        # Error-based detection helpers
        lowered = body.lower()
        if "sql" in lowered and ("error" in lowered or "syntax" in lowered):
            findings["sql_error"] = True
        if "warning" in lowered and "include" in lowered:
            findings["lfi_hint"] = True

        return findings


# ---------------------------------------------------------------------------
# ReverseCryptoWorker
# ---------------------------------------------------------------------------

class ReverseCryptoWorker(BaseCTFWorker):
    """Local attachment / token analysis without touching the live target."""

    def _execute_task(self, task: CTFTask) -> Dict[str, Any]:
        payload = task.payload
        file_path = payload.get("file_path")

        if not file_path:
            return {"error": "no file_path in payload"}

        # Run file_analyze tool
        analysis = self.ctx.tool_router.execute(
            "file_analyze", {"file_path": file_path}
        )

        findings: Dict[str, Any] = {
            "file_path": file_path,
            "file_analysis": analysis,
        }

        # Try strings extraction via run_python (pure-Python fallback safe)
        try:
            py_result = self.ctx.tool_router.execute(
                "run_python",
                {
                    "code": (
                        "import subprocess, json, sys\n"
                        f"try:\n"
                        f"    r = subprocess.run(['strings', '{file_path}'], capture_output=True, text=True, timeout=10)\n"
                        f"    out = r.stdout[:3000]\n"
                        f"except Exception as e:\n"
                        f"    out = str(e)\n"
                        f"print(json.dumps({{'strings': out}}))\n"
                    ),
                },
            )
            strings_out = ""
            if isinstance(py_result, dict):
                stdout = py_result.get("stdout", "")
                try:
                    parsed = json.loads(stdout)
                    strings_out = parsed.get("strings", "")
                except Exception:
                    strings_out = stdout
            findings["strings_preview"] = strings_out[:1000]

            # Flag in strings
            flag = self.ctx.check_flag(strings_out)
            if flag:
                findings["flag"] = flag

            # Crypto hints
            from .diagnostics import extract_crypto_hints
            crypto = extract_crypto_hints(strings_out)
            if crypto:
                findings["crypto_hints"] = crypto
        except Exception as exc:  # noqa: BLE001
            findings["strings_error"] = str(exc)

        return findings


# ---------------------------------------------------------------------------
# CriticWorker
# ---------------------------------------------------------------------------

class CriticWorker(BaseCTFWorker):
    """Periodic read-only review of the shared journal."""

    def _execute_task(self, task: CTFTask) -> Dict[str, Any]:
        if not self.ctx.critic or not self.ctx.fuse:
            return {"error": "critic or fuse not available in context"}

        review = self.ctx.critic.review(
            self.ctx.journal,
            self.ctx.strategy,
            self.ctx.fuse,
        )
        # Persist into journal
        self.ctx.critic.write_to_journal(review, self.ctx.journal)

        return {
            "most_likely_route": review.most_likely_route,
            "is_stuck": review.is_stuck,
            "abandon_routes": review.abandon_routes,
            "recommended_next_action": review.recommended_next_action,
            "confidence": review.confidence,
        }
