"""CTF Action Runtime - wraps tool execution with retry, classification, and cost tracking.

All actions must produce a uniform result structure:
- success
- category
- raw_output
- parsed_observations
- error_type
- retryable
- cost
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

log = logging.getLogger("autopnex.ctf.action_runtime")


@dataclass
class ActionResult:
    """Standardised action execution result."""

    success: bool = False
    category: str = "unknown"  # tool_result, error, timeout, network_error, etc.
    raw_output: Dict[str, Any] = field(default_factory=dict)
    parsed_observations: str = ""
    error_type: Optional[str] = None  # param_error, permission, environment, network, target, route_error
    retryable: bool = False
    cost: float = 0.0  # seconds
    attempts: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "category": self.category,
            "raw_output": self.raw_output,
            "parsed_observations": self.parsed_observations,
            "error_type": self.error_type,
            "retryable": self.retryable,
            "cost": self.cost,
            "attempts": self.attempts,
        }


class ActionRuntime:
    """Wraps tool execution with timeout, retry, and failure classification."""

    def __init__(
        self,
        tool_router: Any,
        max_retries: int = 2,
        base_timeout: float = 30.0,
    ):
        self.tool_router = tool_router
        self.max_retries = max_retries
        self.base_timeout = base_timeout
        self._history: List[Dict[str, Any]] = []

    # -- execution ---------------------------------------------------------

    def run(
        self,
        tool_name: str,
        tool_args: Dict[str, Any],
        *,
        timeout: Optional[float] = None,
        retryable: Optional[bool] = None,
    ) -> ActionResult:
        """Execute a tool with optional retry and standardised output."""
        start = time.time()
        attempts = 0
        last_error = ""
        raw_output: Dict[str, Any] = {}

        effective_timeout = timeout or self.base_timeout
        is_retryable = retryable if retryable is not None else self._is_retryable_by_default(tool_name)

        for attempt in range(1, self.max_retries + 1):
            attempts = attempt
            try:
                raw_output = self.tool_router.execute(tool_name, tool_args)
                break
            except Exception as exc:  # noqa: BLE001
                last_error = f"{exc.__class__.__name__}: {exc}"
                log.warning("Action %s attempt %d failed: %s", tool_name, attempt, last_error)
                if not is_retryable or attempt >= self.max_retries:
                    break
                time.sleep(0.5 * attempt)
        else:
            # Loop completed without break => all retries exhausted
            pass

        elapsed = time.time() - start
        result = self._classify(tool_name, raw_output, last_error, elapsed, attempts)
        self._history.append({
            "tool": tool_name,
            "args": tool_args,
            "result": result.to_dict(),
        })
        return result

    # -- classification ----------------------------------------------------

    def _classify(
        self,
        tool_name: str,
        raw_output: Dict[str, Any],
        last_error: str,
        elapsed: float,
        attempts: int,
    ) -> ActionResult:
        if "error" in raw_output and raw_output.get("error"):
            error_str = str(raw_output["error"])
            error_type, retryable = self._classify_error(error_str, tool_name)
            return ActionResult(
                success=False,
                category="error",
                raw_output=raw_output,
                parsed_observations=error_str,
                error_type=error_type,
                retryable=retryable,
                cost=elapsed,
                attempts=attempts,
            )

        if last_error:
            error_type, retryable = self._classify_error(last_error, tool_name)
            return ActionResult(
                success=False,
                category="error",
                raw_output={"error": last_error},
                parsed_observations=last_error,
                error_type=error_type,
                retryable=retryable,
                cost=elapsed,
                attempts=attempts,
            )

        # Success path
        observations = self._extract_observations(tool_name, raw_output)
        return ActionResult(
            success=True,
            category="tool_result",
            raw_output=raw_output,
            parsed_observations=observations,
            cost=elapsed,
            attempts=attempts,
        )

    @staticmethod
    def _classify_error(error_str: str, tool_name: str) -> tuple:
        """Return (error_type, retryable)."""
        lowered = error_str.lower()

        # Network / connectivity
        network_markers = ["timeout", "connection", "dns", "unreachable", "refused", "reset"]
        if any(m in lowered for m in network_markers):
            return "network", True

        # Permission / auth
        permission_markers = ["permission denied", "access denied", "forbidden", "unauthorized", "401", "403"]
        if any(m in lowered for m in permission_markers):
            return "permission", False

        # Environment / missing deps
        env_markers = ["not found", "missing", "no module", "cannot find", "not installed", "binary not found"]
        if any(m in lowered for m in env_markers):
            return "environment", True

        # Parameter / user error
        param_markers = ["required", "invalid", "bad request", "malformed", "missing argument"]
        if any(m in lowered for m in param_markers):
            return "param_error", False

        # Target-side issue
        target_markers = ["500", "502", "503", "504", "internal server error", "service unavailable"]
        if any(m in lowered for m in target_markers):
            return "target", True

        # Default
        return "route_error", False

    @staticmethod
    def _extract_observations(tool_name: str, raw_output: Dict[str, Any]) -> str:
        """Build a concise observation string from tool output."""
        if tool_name == "http_request":
            parts = [f"status={raw_output.get('status_code', '?')}"]
            loc = raw_output.get("location", "")
            if loc:
                parts.append(f"location={loc}")
            body_preview = str(raw_output.get("body", ""))[:200]
            parts.append(f"body_preview={body_preview!r}")
            return " | ".join(parts)

        if tool_name == "run_python":
            stdout = str(raw_output.get("stdout", ""))[:300]
            stderr = str(raw_output.get("stderr", ""))[:200]
            return f"stdout={stdout!r} stderr={stderr!r}"

        # Generic fallback
        preview = str(raw_output)[:500]
        return preview

    @staticmethod
    def _is_retryable_by_default(tool_name: str) -> bool:
        """Determine whether a tool is retryable by default."""
        retryable_tools = {
            "http_request",
            "run_python",
            "run_tool_script",
            "ctf_knowledge_search",
        }
        return tool_name in retryable_tools
