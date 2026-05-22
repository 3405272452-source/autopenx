"""Tool abstraction: BaseTool, ToolResult, ToolRegistry.

Each concrete tool subclasses ``BaseTool`` and registers itself via
``@ToolRegistry.register``. The registry exposes OpenAI-compatible tool schemas
for LLM function calling.
"""
from __future__ import annotations

import time
import traceback
import shutil
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Type

from config.settings import RuntimeConfig, settings
from ..policy import _has_scope


@dataclass
class ToolResult:
    """Unified return value for every tool."""

    success: bool
    tool: str
    summary: str = ""
    raw_output: str = ""
    parsed_data: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    duration_ms: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_llm_message(self, max_raw: int = 2000) -> str:
        """Compact representation fed back to the LLM as tool result."""
        payload: Dict[str, Any] = {
            "success": self.success,
            "summary": self.summary,
            "parsed_data": self.parsed_data,
        }
        if self.error:
            payload["error"] = self.error
        raw = (self.raw_output or "")[:max_raw]
        if raw:
            payload["raw_output_excerpt"] = raw
        import json

        return json.dumps(payload, ensure_ascii=False, default=str)


class BaseTool(ABC):
    """Abstract tool. Concrete tools implement ``_run`` plus the meta methods."""

    category: str = "misc"  # recon | scan | vuln | exploit | report
    external_binary: Optional[str] = None
    managed_external: bool = False
    required_capability: Optional[str] = None
    requires_exploit_enabled: bool = False

    @property
    @abstractmethod
    def name(self) -> str: ...

    @property
    @abstractmethod
    def description(self) -> str: ...

    @abstractmethod
    def parameters_schema(self) -> Dict[str, Any]:
        """Return JSON schema for tool parameters (OpenAI function-calling format)."""

    @abstractmethod
    def _run(self, **kwargs: Any) -> ToolResult: ...

    # ------------------------------------------------------------------
    def availability(self, runtime_config: Optional[RuntimeConfig] = None) -> Dict[str, Any]:
        runtime = runtime_config or settings.effective()
        is_external = bool(self.external_binary)
        binary_path = shutil.which(self.external_binary) if self.external_binary else None
        installed = True if not is_external else bool(binary_path)
        allowed = True if not is_external else runtime.allow_external_tools
        required_capability = self.required_capability or ("exploit" if self.requires_exploit_enabled else None)
        scope_allowed = True if not required_capability else _has_scope(runtime.approved_scopes, required_capability)
        exploit_allowed = True if not self.requires_exploit_enabled else runtime.exploit_enabled
        enabled = installed and allowed and scope_allowed and exploit_allowed
        if not is_external:
            reason = "builtin"
        elif not installed:
            reason = f"missing_binary:{self.external_binary}"
        elif not allowed:
            reason = "disabled_by_runtime_config"
        elif not scope_allowed:
            reason = f"missing_capability:{required_capability}"
        elif not exploit_allowed:
            reason = "exploit_disabled_by_runtime_config"
        else:
            reason = "enabled"
        return {
            "name": self.name,
            "category": self.category,
            "external": is_external,
            "binary": self.external_binary,
            "binary_path": binary_path,
            "installed": installed,
            "allowed": allowed,
            "required_capability": required_capability,
            "scope_allowed": scope_allowed,
            "exploit_allowed": exploit_allowed,
            "enabled": enabled,
            "reason": reason,
        }

    def execute(self, *, runtime_config: Optional[RuntimeConfig] = None, **kwargs: Any) -> ToolResult:
        availability = self.availability(runtime_config)
        if not availability["enabled"]:
            return ToolResult(
                success=False,
                tool=self.name,
                summary=f"Tool unavailable: {availability['reason']}",
                error=str(availability["reason"]),
            )
        start = time.perf_counter()
        try:
            with settings.use_runtime(runtime_config):
                result = self._run(**kwargs)
        except Exception as exc:  # noqa: BLE001
            result = ToolResult(
                success=False,
                tool=self.name,
                summary=f"Tool crashed: {exc}",
                error=f"{exc.__class__.__name__}: {exc}\n{traceback.format_exc(limit=3)}",
            )
        result.duration_ms = int((time.perf_counter() - start) * 1000)
        result.tool = self.name
        return result

    def openai_schema(self) -> Dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters_schema(),
            },
        }


class ToolRegistry:
    _tools: Dict[str, BaseTool] = {}

    @classmethod
    def register(cls, tool_cls: Type[BaseTool]) -> Type[BaseTool]:
        instance = tool_cls()
        if instance.name in cls._tools:
            # Allow re-registration for hot reload in notebooks/tests.
            cls._tools[instance.name] = instance
        else:
            cls._tools[instance.name] = instance
        return tool_cls

    @classmethod
    def get(cls, name: str) -> Optional[BaseTool]:
        return cls._tools.get(name)

    @classmethod
    def all(cls) -> List[BaseTool]:
        return list(cls._tools.values())

    @classmethod
    def by_category(cls, category: str) -> List[BaseTool]:
        return [t for t in cls._tools.values() if t.category == category]

    @classmethod
    def openai_schemas(
        cls,
        categories: Optional[List[str]] = None,
        runtime_config: Optional[RuntimeConfig] = None,
    ) -> List[Dict[str, Any]]:
        tools = cls.all() if not categories else [t for t in cls.all() if t.category in categories]
        return [t.openai_schema() for t in tools if t.availability(runtime_config)["enabled"]]

    @classmethod
    def execute(
        cls,
        name: str,
        arguments: Dict[str, Any],
        runtime_config: Optional[RuntimeConfig] = None,
    ) -> ToolResult:
        tool = cls.get(name)
        if tool is None:
            return ToolResult(
                success=False,
                tool=name,
                summary=f"Unknown tool: {name}",
                error="tool_not_registered",
            )
        return tool.execute(runtime_config=runtime_config, **(arguments or {}))

    @classmethod
    def capabilities(cls, runtime_config: Optional[RuntimeConfig] = None) -> List[Dict[str, Any]]:
        return [t.availability(runtime_config) for t in cls.all() if t.external_binary or t.managed_external]

    @classmethod
    def clear(cls) -> None:  # pragma: no cover - used in tests
        cls._tools.clear()


def register(tool_cls: Type[BaseTool]) -> Type[BaseTool]:
    """Convenience alias: ``@register``."""
    return ToolRegistry.register(tool_cls)
